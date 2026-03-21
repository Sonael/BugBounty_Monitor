import traceback
import fnmatch
import uuid
import os
import json
from datetime import datetime, date

from . import celery, db
from .models import Project, Domain, Vulnerability, ScanHistory, Port

from .scanner import (
    find_subdomains, check_alive, scan_nuclei_bulk,
    scan_crawling_xss_bulk, scan_sqlmap_bulk,
    scan_naabu_bulk, run_dig_info, send_discord_embed,
    scan_ffuf, scan_cmseek, get_first_seen_crtsh
)



# ---------------------------------------------------------------------------
# App cache — create_app() é chamado apenas UMA VEZ por processo worker
# (via @worker_init signal em __init__.py). O cache evita overhead por task.
# ---------------------------------------------------------------------------
_flask_app = None


# ---------------------------------------------------------------------------
# worker_init — processo PAI, antes do fork
# Ativa redirect de stdout para que filhos herdem via fork
# ---------------------------------------------------------------------------
try:
    from celery.signals import worker_init

    @worker_init.connect
    def on_worker_init(**kwargs):
        from celery import current_app as _app
        _app.conf.worker_redirect_stdouts       = True
        _app.conf.worker_redirect_stdouts_level = 'INFO'

except Exception:
    pass

# ---------------------------------------------------------------------------
# worker_process_init — cada processo FILHO, apos o fork
# Reseta sessao SQLAlchemy herdada do pai (evita ResourceClosedError)
# ---------------------------------------------------------------------------
try:
    from celery.signals import worker_process_init

    @worker_process_init.connect
    def on_worker_process_init(**kwargs):
        try:
            from app import db as _db
            _db.engine.dispose()
            _db.session.remove()
        except Exception:
            pass

except Exception:
    pass


def _get_app():
    """
    Retorna o Flask app cacheado.
    Se não existir (ex: execução fora do worker), cria um novo.
    """
    global _flask_app
    if _flask_app is None:
        from app import create_app
        _flask_app = create_app()
    return _flask_app


# ---------------------------------------------------------------------------
# Helpers internos
# ---------------------------------------------------------------------------

def _open_history(project_id: int, task_id: str, mode: str):
    """
    Cria registro de ScanHistory no início do scan.
    Retorna None silenciosamente se a tabela não existir (migrations pendentes).
    NUNCA lança exceção — o scan deve continuar independentemente.
    """
    try:
        h = ScanHistory(project_id=project_id, task_id=task_id,
                        mode=mode, status='running', started_at=datetime.utcnow())
        db.session.add(h)
        db.session.commit()
        return h
    except Exception as e:
        db.session.rollback()
        print(f"[HISTORY] Aviso: tabela scan_history indisponível, ignorando: {type(e).__name__}")
        return None


def _close_history(history, status: str, **metrics):
    """Fecha o registro de histórico. Ignora silenciosamente se history for None."""
    if history is None:
        return
    try:
        history.finished_at = datetime.utcnow()
        history.status = status
        for k, v in metrics.items():
            if hasattr(history, k):
                setattr(history, k, v)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[HISTORY] Falha ao fechar histórico: {e}")


def _write_ports(domain_obj: Domain, port_string: str):
    """
    Salva portas no campo texto (compatibilidade) E na tabela Port (normalizada).
    Opera somente se domain_obj.id já existir (após flush).
    """
    if not port_string:
        return
    domain_obj.open_ports = port_string
    if not domain_obj.id:
        return
    for p_str in port_string.split(','):
        p_num = p_str.strip()
        if p_num.isdigit():
            try:
                exists = Port.query.filter_by(
                    domain_id=domain_obj.id, port_number=int(p_num)
                ).first()
                if not exists:
                    db.session.add(Port(domain_id=domain_obj.id, port_number=int(p_num)))
            except Exception as e:
                print(f"[PORTS] Falha ao salvar porta {p_num} em {domain_obj.name}: {e}")


# ---------------------------------------------------------------------------
# Task principal
# ---------------------------------------------------------------------------

@celery.task(bind=True)
def run_scan_task(self, project_id, mode='full'):
    app = _get_app()

    with app.app_context():
        # Garante sessao limpa antes de qualquer query
        try:
            db.session.remove()
            db.session.close()
        except Exception:
            pass

        try:
            project = Project.query.get(project_id)
        except Exception as e:
            print(f"[WORKER CRITICAL] Falha ao carregar projeto {project_id}: {e}")
            try:
                db.session.rollback()
                db.session.remove()
                project = Project.query.get(project_id)
            except Exception as e2:
                print(f"[WORKER CRITICAL] Falha definitiva: {e2}")
                return
        if not project:
            print(f"[WORKER] Projeto ID {project_id} não encontrado!")
            return

        # Bloqueia apenas se já existe OUTRO task ID ativo no banco.
        # current_task_id == self.request.id → esta é a task certa, continua.
        # current_task_id == None → race condition resolvida (web pré-salva agora).
        if (project.current_task_id
                and project.current_task_id != self.request.id
                and project.scan_status in ['Rodando', 'Na fila']):
            print(f"[WORKER] IGNORADO: {project.name} ja tem task {project.current_task_id}, esta e {self.request.id}.")
            return "Duplicata ignorada"

        history = _open_history(project_id, self.request.id, mode)

        # Inicializa recon_metrics com zeros — será preenchido pela fase recon
        # se ela rodar. Garante que o vuln scan puro não quebre ao fechar o histórico.
        recon_metrics = {
            'new_domains':   0,
            'alive_hosts':   0,
            'total_domains': 0,
            'summary_recon': None,
        }

        try:
            print(f"[WORKER] Iniciando task — Projeto: {project.name} | Modo: {mode}")

            project.current_task_id = self.request.id
            project.scan_status = "Rodando"
            project.last_scan_date = datetime.utcnow()
            db.session.commit()

            blacklist = [l.strip() for l in (project.out_of_scope or "").splitlines() if l.strip()]

            # ==============================================================
            # FASE 1 — RECON
            # ==============================================================
            if mode in ['recon', 'full', 'baseline']:
                print(f"[WORKER] --- FASE RECON ({mode}) ---")

                # 1. Coleta subdomínios
                found_subs = []
                if project.discovery_enabled:
                    target_clean = (project.target_url
                                    .replace('https://', '').replace('http://', '')
                                    .split('/')[0])
                    seeds = {target_clean}
                    if project.in_scope:
                        for line in project.in_scope.splitlines():
                            c = line.strip().replace('https://', '').replace('http://', '').split('/')[0]
                            if c:
                                seeds.add(c)

                    print(f"[WORKER] {len(seeds)} sementes: {seeds}")
                    all_discovered = set()

                    for idx, seed in enumerate(seeds, 1):
                        msg = f"1/4 Coletando ({idx}/{len(seeds)}): {seed}"
                        project.scan_message = msg
                        db.session.commit()
                        try:
                            all_discovered.update(find_subdomains(seed))
                        except Exception as e:
                            print(f"[WORKER] Subfinder/Amass falhou em {seed}: {e}")

                    for d in Domain.query.filter_by(project_id=project.id).all():
                        all_discovered.add(d.name)
                    found_subs = list(all_discovered)
                else:
                    print("[WORKER] Discovery DESATIVADO.")
                    project.scan_message = "1/4 Carregando lista de alvos..."
                    db.session.commit()
                    found_subs = [d.name for d in Domain.query.filter_by(project_id=project.id).all()]

                # 2. Filtragem Out-of-Scope
                found_subs = [
                    sub for sub in found_subs
                    if not any(
                        fnmatch.fnmatch(sub, bl) or
                        ('*' not in bl and (sub == bl or sub.endswith('.' + bl)))
                        for bl in blacklist
                    )
                ]
                print(f"[WORKER] Lista final: {len(found_subs)} domínios.")

                # 3. HTTPX — confirma hosts vivos ANTES do Naabu
                if found_subs:
                    project.scan_message = f"2/4 Verificando {len(found_subs)} subdomínios (HTTPX)..."
                    db.session.commit()
                    try:
                        alive_data = check_alive(found_subs)
                    except Exception as e:
                        print(f"[WORKER] HTTPX falhou: {e}")
                        alive_data = []
                else:
                    alive_data = []

                # 4. Naabu — apenas hosts confirmados pelo HTTPX
                seen_alive = set()
                alive_hosts_for_naabu = []
                for item in alive_data:
                    c = item['url'].replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
                    if c and c not in seen_alive:
                        seen_alive.add(c)
                        alive_hosts_for_naabu.append(c)

                naabu_data = {}
                if alive_hosts_for_naabu:
                    project.scan_message = f"3/4 Escaneando portas em {len(alive_hosts_for_naabu)} hosts (Naabu)..."
                    db.session.commit()
                    temp_naabu = f"subs_naabu_{project.id}_{uuid.uuid4().hex}.txt"
                    try:
                        with open(temp_naabu, 'w') as f:
                            f.write("\n".join(alive_hosts_for_naabu))
                        naabu_data = scan_naabu_bulk(temp_naabu)
                    except Exception as e:
                        print(f"[WORKER] Naabu falhou: {e}")
                    finally:
                        if os.path.exists(temp_naabu):
                            os.remove(temp_naabu)

                # Mapas de lookup
                status_map = {}
                tech_map   = {}
                ip_map     = {}
                url_map    = {}
                for item in alive_data:
                    c = item['url'].replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
                    status_map[c] = item['status']
                    tech_map[c]   = item.get('tech', [])
                    ip_map[c]     = item.get('ip')
                    url_map[c]    = item['url']

                domain_map  = {d.name: d for d in Domain.query.filter_by(project_id=project.id).all()}
                new_count   = 0
                total_paths = 0
                new_alive_subs = []  # para notificação real-time

                project.scan_message = "4/4 Processando Alvos (DNS + Fuzzing + SSL)..."
                db.session.commit()

                # 5. Atualização, DNS, Fuzzing
                for sub in found_subs:
                    domain_obj = domain_map.get(sub)
                    is_new     = domain_obj is None

                    if is_new:
                        domain_obj = Domain(name=sub, project_id=project.id)

                    if mode == 'baseline' and not project.vuln_scan_enabled:
                        domain_obj.scanned_vulns = True

                    code = int(status_map[sub]) if status_map.get(sub) is not None else 0
                    domain_obj.status_code = code

                    if mode == 'recon' and is_new and code in [200, 201, 202, 204, 301, 302, 307, 308]:
                        try:
                            crt_date = get_first_seen_crtsh(sub)
                            if crt_date:
                                domain_obj.creation_date = crt_date
                        except Exception as e:
                            print(f"[WORKER] crt.sh falhou em {sub}: {e}")

                    tech_list = tech_map.get(sub, [])
                    if tech_list:
                        domain_obj.technologies = ", ".join(tech_list)

                    domain_obj.ip_address = ip_map.get(sub)

                    # Flush para ter domain_obj.id antes de escrever portas
                    if is_new:
                        db.session.add(domain_obj)
                        db.session.flush()
                        new_count += 1

                    # Portas (tabela normalizada + campo texto)
                    port_str = naabu_data.get(sub)
                    if port_str:
                        _write_ports(domain_obj, port_str)

                    if code > 0 or domain_obj.open_ports:
                        try:
                            domain_obj.dns_info = run_dig_info(sub)
                        except Exception as e:
                            print(f"[WORKER] DIG falhou em {sub}: {e}")

                    # Fuzzing
                    should_fuzz = (
                        (mode == 'baseline' and project.fuzzing_enabled) or
                        (mode != 'baseline' and (is_new or not project.discovery_enabled))
                    )
                    if should_fuzz and code in [200, 201, 202, 204, 301, 302, 307, 308, 403]:
                        target_url = url_map.get(sub, f"https://{sub}")
                        print(f"[WORKER] Fuzzing em: {sub}")
                        try:
                            cms = scan_cmseek(target_url)
                            if cms:
                                domain_obj.technologies = (
                                    f"{domain_obj.technologies}, {cms}"
                                    if domain_obj.technologies else cms
                                )
                        except Exception as e:
                            print(f"[WORKER] CMSeeK falhou em {sub}: {e}")

                        try:
                            f_res = scan_ffuf(target_url)
                            if f_res:
                                paths_list   = [item['raw_path'] for item in f_res]
                                subset       = paths_list[:15]
                                if len(paths_list) > 15:
                                    subset.append(f"[+{len(paths_list) - 15} outros]")
                                new_paths_str = ", ".join(subset)
                                if domain_obj.discovered_paths:
                                    combined = list(set(
                                        domain_obj.discovered_paths.split(", ") +
                                        new_paths_str.split(", ")
                                    ))
                                    domain_obj.discovered_paths = ", ".join(combined[:15])
                                else:
                                    domain_obj.discovered_paths = new_paths_str
                                total_paths += len(paths_list)
                        except Exception as e:
                            print(f"[WORKER] FFuf falhou em {sub}: {e}")

                    # Marca novos subs vivos para notificação
                    if is_new and code in [200, 201, 202, 204, 301, 302, 307, 308, 403]:
                        new_alive_subs.append(sub)

                db.session.commit()

                # Notificação real-time (novos alvos vivos, durante o scan)
                if new_alive_subs and mode in ['recon', 'full']:
                    try:
                        preview = new_alive_subs[:10]
                        extras  = len(new_alive_subs) - len(preview)
                        body    = "\n".join(f"• `{s}`" for s in preview)
                        if extras > 0:
                            body += f"\n• _(+{extras} mais)_"
                        send_discord_embed(
                            title=f"🆕 Novos Alvos Descobertos: {project.name}",
                            description=f"**{len(new_alive_subs)}** novos subdomínios ativos.\n\n{body}",
                            fields=[
                                {"name": "🔍 Modo",       "value": mode,                   "inline": True},
                                {"name": "🌐 Novos Vivos", "value": str(len(new_alive_subs)), "inline": True},
                            ],
                            color_hex=0x1abc9c,
                        )
                    except Exception as e:
                        print(f"[NOTIFY] Notificação real-time: {e}")

                # Métricas HTTP
                c_2xx = sum(1 for i in alive_data if 200 <= int(i.get('status') or 0) < 300)
                c_3xx = sum(1 for i in alive_data if 300 <= int(i.get('status') or 0) < 400)
                c_4xx = sum(1 for i in alive_data if 400 <= int(i.get('status') or 0) < 500)
                c_5xx = sum(1 for i in alive_data if 500 <= int(i.get('status') or 0) < 600)

                try:
                    send_discord_embed(
                        title=f"📡 {mode.upper()}: {project.name}",
                        description=f"Reconhecimento concluído. Discovery: {'ON' if project.discovery_enabled else 'OFF'}",
                        fields=[
                            {"name": "🌐 Total",          "value": str(len(found_subs)), "inline": True},
                            {"name": "🆕 Novos DB",        "value": str(new_count),       "inline": True},
                            {"name": "⚡ Vivos",           "value": str(len(alive_data)), "inline": True},
                            {"name": "📂 Paths",           "value": str(total_paths),     "inline": True},
                            {"name": "---",                "value": "\u200b",             "inline": False},
                            {"name": "✅ 2xx",             "value": str(c_2xx),           "inline": True},
                            {"name": "➡️ 3xx",             "value": str(c_3xx),           "inline": True},
                            {"name": "🚫 4xx",             "value": str(c_4xx),           "inline": True},
                            {"name": "🔥 5xx",             "value": str(c_5xx),           "inline": True},
                        ],
                        color_hex=0x00ff00 if new_count > 0 else 0x3498db,
                    )
                except Exception as e:
                    print(f"[NOTIFY] Embed Recon: {e}")

                total_domains_now = Domain.query.filter_by(project_id=project.id).count()

                # Persiste métricas da fase recon para uso no _close_history final
                # (necessário para modo 'full' e 'baseline+vuln' onde o histórico
                # só é fechado ao final do vuln scan)
                recon_metrics = {
                    'new_domains':    new_count,
                    'alive_hosts':    len(alive_data),
                    'total_domains':  total_domains_now,
                    'summary_recon':  json.dumps({
                        'c_2xx': c_2xx, 'c_3xx': c_3xx,
                        'c_4xx': c_4xx, 'c_5xx': c_5xx,
                    }),
                }

                if mode == 'recon' or (mode == 'baseline' and not project.vuln_scan_enabled):
                    _close_history(history, 'completed',
                                   new_domains=recon_metrics['new_domains'],
                                   total_domains=recon_metrics['total_domains'],
                                   alive_hosts=recon_metrics['alive_hosts'],
                                   summary=recon_metrics['summary_recon'])
                    project.scan_status = "Concluído"
                    project.scan_message = f"Recon finalizado. {new_count} novos ativos."
                    db.session.commit()
                    print("[WORKER] Fase RECON finalizada.")
                    dispatch_next_pending()
                    return "Recon OK"

            # ==============================================================
            # FASE 2 — VULN SCAN
            # ==============================================================
            run_vuln_phase = (
                (mode == 'baseline' and project.vuln_scan_enabled) or
                mode == 'vuln' or
                (mode == 'full' and project.vuln_scan_recon_enabled)
            )

            if run_vuln_phase:
                print("[WORKER] --- FASE VULN SCAN ---")

                # Escaneia TODOS os domínios vivos não verificados — independente de quando
                # foram descobertos. Isso garante que o contador "pendentes" sempre zera
                # ao final do scan de vulnerabilidades.
                targets = Domain.query.filter(
                    Domain.project_id == project.id,
                    Domain.scanned_vulns == False,
                    Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308]),
                ).all()

                if not targets:
                    print("[WORKER] Nenhum alvo pendente para Vuln Scan.")
                    # Marca todos os demais como verificados para zerar o contador
                    Domain.query.filter(
                        Domain.project_id == project.id,
                        Domain.scanned_vulns == False,
                    ).update({Domain.scanned_vulns: True}, synchronize_session=False)
                    db.session.commit()
                    try:
                        send_discord_embed(
                            title=f"💤 Scan Vuln: {project.name}",
                            description="Nenhum alvo novo para escanear.",
                            fields=[{"name": "Status", "value": "Todos já verificados", "inline": True}],
                            color_hex=0x95a5a6,
                        )
                    except Exception as e:
                        print(f"[NOTIFY] {e}")

                    _close_history(history, 'completed',
                                   new_domains=recon_metrics.get('new_domains', 0),
                                   alive_hosts=recon_metrics.get('alive_hosts', 0),
                                   total_domains=Domain.query.filter_by(project_id=project.id).count(),
                                   summary=recon_metrics.get('summary_recon'))
                    project.scan_status = "Concluído"
                    project.scan_message = "Nenhum alvo válido pendente."
                    db.session.commit()
                    dispatch_next_pending()
                    return "Scan Finalizado (Sem novos alvos)"

                print(f"[WORKER] Alvos: {len(targets)}")

                target_file = f"targets_proj_{project.id}.txt"
                with open(target_file, "w") as f:
                    for d in targets:
                        f.write(f"https://{d.name}\n")

                try:
                    project.scan_message = f"Rodando Nuclei ({len(targets)} domínios)..."
                    db.session.commit()
                    nuclei_vulns = scan_nuclei_bulk(target_file)
                    process_vulns(nuclei_vulns, project.id)

                    project.scan_message = "Rodando Katana + GAU + Dalfox..."
                    db.session.commit()
                    xss_vulns = scan_crawling_xss_bulk(target_file)
                    process_vulns(xss_vulns, project.id)

                    sqli_vulns = scan_sqlmap_bulk(target_file)
                    process_vulns(sqli_vulns, project.id)

                    for d in targets:
                        d.scanned_vulns = True

                    # Marca também domínios não-vivos que nunca serão escaneados
                    # para zerar completamente o contador "pendentes" do card
                    Domain.query.filter(
                        Domain.project_id == project.id,
                        Domain.scanned_vulns == False,
                    ).update({Domain.scanned_vulns: True}, synchronize_session=False)

                    total_vulns = len(nuclei_vulns) + len(xss_vulns) + len(sqli_vulns)

                    try:
                        if total_vulns > 0:
                            send_discord_embed(
                                title=f"🚨 VULNERABILIDADES: {project.name}",
                                description="Falhas encontradas.",
                                fields=[
                                    {"name": "🔥 Total",   "value": str(total_vulns),       "inline": False},
                                    {"name": "☢️ Nuclei", "value": str(len(nuclei_vulns)),  "inline": True},
                                    {"name": "⚠️ XSS",   "value": str(len(xss_vulns)),     "inline": True},
                                    {"name": "💉 SQLi",   "value": str(len(sqli_vulns)),    "inline": True},
                                ],
                                color_hex=0xff0000,
                            )
                        else:
                            send_discord_embed(
                                title=f"✅ Scan Limpo: {project.name}",
                                description="Nenhuma vulnerabilidade crítica.",
                                fields=[{"name": "Status", "value": "Seguro", "inline": True}],
                                color_hex=0x00ff00,
                            )
                    except Exception as e:
                        print(f"[NOTIFY] Embed vuln: {e}")

                    total_domains_now = Domain.query.filter_by(project_id=project.id).count()
                    _close_history(history, 'completed',
                                   new_domains=recon_metrics.get('new_domains', 0),
                                   alive_hosts=recon_metrics.get('alive_hosts', 0),
                                   new_vulns=total_vulns,
                                   total_domains=total_domains_now,
                                   summary=json.dumps({
                                       'recon':  json.loads(recon_metrics['summary_recon']) if recon_metrics.get('summary_recon') else {},
                                       'nuclei': len(nuclei_vulns),
                                       'xss':    len(xss_vulns),
                                       'sqli':   len(sqli_vulns),
                                   }))

                    project.scan_status = "Concluído"
                    project.scan_message = f"Finalizado. {total_vulns} vulns."
                    db.session.commit()
                    print(f"[WORKER] Task finalizada. Vulns: {total_vulns}")
                    dispatch_next_pending()

                finally:
                    if os.path.exists(target_file):
                        os.remove(target_file)

        except Exception as e:
            db.session.rollback()
            print(f"[WORKER CRITICAL] {traceback.format_exc()}")
            try:
                _close_history(history, 'error',
                               summary=json.dumps({'error': str(e)[:500]}))
            except Exception:
                pass
            proj = Project.query.get(project_id)
            if proj:
                proj.scan_status = "Erro"
                proj.scan_message = f"Erro: {str(e)[:100]}"
                db.session.commit()
            try:
                dispatch_next_pending()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Dispatcher — acorda o próximo projeto pendente quando um slot abre
# ---------------------------------------------------------------------------

def dispatch_next_pending():
    """
    Chamado ao final de cada scan quando um slot abre.
    Usa um mutex Redis para garantir que apenas UM worker por vez
    execute o despacho — elimina a race condition entre ForkPoolWorker-1
    e ForkPoolWorker-2 que terminam simultaneamente.
    """
    from celery import uuid as celery_uuid
    import redis as redis_lib

    MAX_CONCURRENT = int(os.environ.get('GLOBAL_SCAN_CONCURRENCY', 2))
    LOCK_KEY   = 'dispatch_lock'
    LOCK_TTL   = 15  # segundos — evita deadlock se o processo morrer

    # ── Tenta adquirir o mutex Redis ────────────────────────────────────────
    try:
        r = redis_lib.Redis(
            host=os.environ.get('REDIS_HOST', 'redis'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=1  # mesmo db do cache Python
        )
        # SET NX EX: só seta se a chave não existir (atômico no Redis)
        acquired = r.set(LOCK_KEY, '1', nx=True, ex=LOCK_TTL)
    except Exception as e:
        print(f"[QUEUE] Redis indisponível para mutex: {e} — usando fallback sem lock.")
        acquired = True
        r = None

    if not acquired:
        print("[QUEUE] Outro worker ja esta despachando. Ignorando.")
        return

    try:
        # ── Seção crítica — somente um worker por vez ───────────────────────
        # Conta Rodando + Na fila COM task_id (já despachados mas não iniciados)
        ativos = Project.query.filter(
            db.or_(
                Project.scan_status == 'Rodando',
                db.and_(
                    Project.scan_status == 'Na fila',
                    Project.current_task_id.isnot(None)
                )
            )
        ).count()

        slots_livres = MAX_CONCURRENT - ativos

        if slots_livres <= 0:
            print(f"[QUEUE] {ativos}/{MAX_CONCURRENT} slots ocupados. Aguardando.")
            return

        # Pega os próximos na fila passiva (sem task_id)
        pendentes = Project.query.filter(
            Project.scan_status == 'Na fila',
            Project.current_task_id == None
        ).order_by(Project.id.asc()).limit(slots_livres).all()

        if not pendentes:
            print("[QUEUE] Fila global vazia — nenhum projeto pendente.")
            return

        for proximo in pendentes:
            # Recupera o modo salvo no scan_message (ex: "mode:recon")
            mode = 'full'
            if proximo.scan_message and proximo.scan_message.startswith('mode:'):
                mode = proximo.scan_message.split(':', 1)[1].strip()

            task_id = celery_uuid()
            proximo.current_task_id = task_id
            proximo.scan_message = f'Aguardando worker ({mode})...'
            db.session.flush()
            run_scan_task.apply_async(args=[proximo.id, mode], task_id=task_id)
            print(f"[QUEUE] Despachado: {proximo.name} (mode={mode}) → task {task_id}")

        db.session.commit()

    finally:
        # ── Libera o mutex sempre, mesmo em caso de exceção ─────────────────
        if r:
            try:
                r.delete(LOCK_KEY)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# process_vulns
# ---------------------------------------------------------------------------

def process_vulns(vuln_list, project_id):
    """Mapeia URLs vulneráveis para o Domain ID e persiste as vulnerabilidades."""
    if not vuln_list:
        return

    print(f"[WORKER] Mapeando {len(vuln_list)} vulnerabilidades...")
    domain_cache = {d.name: d.id for d in Domain.query.filter_by(project_id=project_id).all()}
    saved = dupes = 0

    for v in vuln_list:
        host_url = v.get('host', '')
        if not host_url:
            continue

        clean = host_url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        dom_id = domain_cache.get(clean)

        if not dom_id:
            try:
                nd = Domain(name=clean, project_id=project_id,
                            scanned_vulns=True, status_code=200,
                            technologies="Descoberto via Vuln Scan")
                db.session.add(nd)
                db.session.flush()
                dom_id = nd.id
                domain_cache[clean] = dom_id
            except Exception as e:
                print(f"[WORKER] Falha ao criar domínio {clean}: {e}")
                continue

        if dom_id:
            exists = Vulnerability.query.filter_by(
                domain_id=dom_id, description=v['description']
            ).first()
            if not exists:
                db.session.add(Vulnerability(
                    tool=v['tool'], severity=v['severity'],
                    description=v['description'], domain_id=dom_id,
                ))
                saved += 1
            else:
                dupes += 1

    db.session.commit()
    print(f"[WORKER] Salvas: {saved} | Duplicadas: {dupes}")


# ---------------------------------------------------------------------------
# Scan Diário
# ---------------------------------------------------------------------------

@celery.task
def run_daily_scan(mode='full'):
    from .models import SystemState

    app = _get_app()
    with app.app_context():
        today = date.today()

        state = SystemState.query.get(1)
        if not state:
            state = SystemState(id=1)
            db.session.add(state)
            db.session.commit()

        if state.last_daily_scan == today:
            print("[SCHEDULER] Scan diario ja executado hoje.")
            return

        state.last_daily_scan = today
        db.session.commit()

        from celery import uuid as celery_uuid

        for proj in Project.query.all():
            if proj.scan_status == 'Rodando':
                continue
            if proj.scan_status == 'Na fila' and proj.current_task_id:
                print(f"[SCHEDULER] Pular {proj.name}: ja na fila.")
                continue

            # Pré-gera task ID e salva ANTES do dispatch (evita race condition)
            task_id = celery_uuid()
            proj.current_task_id = task_id
            proj.scan_status = 'Na fila'
            proj.scan_message = 'Aguardando início (Agendado)...'
            db.session.flush()
            run_scan_task.apply_async(args=[proj.id, mode], task_id=task_id)
            print(f"[SCHEDULER] Agendado {proj.name} - task {task_id}")

        db.session.commit()