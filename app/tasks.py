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


# create_app() é caro — cacheamos a instância por processo worker.
_flask_app = None


try:
    from celery.signals import worker_process_init

    @worker_process_init.connect
    def on_worker_process_init(**kwargs):
        """Reseta a sessão SQLAlchemy herdada do pai após o fork.

        Sem isso o worker filho herda conexões do pool do pai e gera
        ResourceClosedError esporádicos nas primeiras queries.
        """
        try:
            from app import db as _db
            _db.engine.dispose()
            _db.session.remove()
        except Exception:
            pass

except Exception:
    pass


def _get_app():
    """Retorna o Flask app cacheado por processo, criando-o se necessário."""
    global _flask_app
    if _flask_app is None:
        from app import create_app
        _flask_app = create_app()
    return _flask_app


def _open_history(project_id: int, task_id: str, mode: str):
    """Cria registro de ScanHistory no início do scan.

    Retorna None silenciosamente se a tabela não existir (migrations pendentes).
    Nunca lança exceção — o scan deve continuar independentemente.
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
    """Fecha o registro de histórico com status final e métricas. No-op se history=None."""
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
    """Persiste portas no campo texto + na tabela Port (normalizada).

    Requer domain_obj.id já materializado (chame flush antes).
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


@celery.task(bind=True)
def run_scan_task(self, project_id, mode='full'):
    """Task principal de scan. Modos: recon | vuln | full | baseline."""
    app = _get_app()

    with app.app_context():
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
            print(f"[WORKER] Projeto ID {project_id} nao encontrado!")
            return

        # Detecção de duplicata: outro task_id ativo no banco para este projeto.
        # current_task_id == self.request.id → esta é a task certa, continua.
        # current_task_id == None → fila passiva, continua.
        if (project.current_task_id
                and project.current_task_id != self.request.id
                and project.scan_status in ['Rodando', 'Na fila']):
            print(f"[WORKER] IGNORADO: {project.name} ja tem task {project.current_task_id}, esta e {self.request.id}.")
            return "Duplicata ignorada"

        history = _open_history(project_id, self.request.id, mode)

        # Inicializado com zeros para o caso de vuln-puro (sem fase recon).
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

            # === FASE 1 — RECON ===
            if mode in ['recon', 'full', 'baseline']:
                print(f"[WORKER] --- FASE RECON ({mode}) ---")

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

                found_subs = [
                    sub for sub in found_subs
                    if not any(
                        fnmatch.fnmatch(sub, bl) or
                        ('*' not in bl and (sub == bl or sub.endswith('.' + bl)))
                        for bl in blacklist
                    )
                ]
                print(f"[WORKER] Lista final: {len(found_subs)} domínios.")

                # HTTPX antes do Naabu — só escaneia portas de hosts vivos.
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
                new_alive_subs = []

                project.scan_message = "4/4 Processando Alvos (DNS + Fuzzing + SSL)..."
                db.session.commit()

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

                    # Flush para ter domain_obj.id antes de gravar portas.
                    if is_new:
                        db.session.add(domain_obj)
                        db.session.flush()
                        new_count += 1

                    port_str = naabu_data.get(sub)
                    if port_str:
                        _write_ports(domain_obj, port_str)

                    if code > 0 or domain_obj.open_ports:
                        try:
                            domain_obj.dns_info = run_dig_info(sub)
                        except Exception as e:
                            print(f"[WORKER] DIG falhou em {sub}: {e}")

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

                    if is_new and code in [200, 201, 202, 204, 301, 302, 307, 308, 403]:
                        new_alive_subs.append(sub)

                db.session.commit()

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
                            {"name": "---",                "value": "​",             "inline": False},
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

                # Em modos 'full'/'baseline+vuln' o histórico só fecha após o vuln scan.
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

            # === FASE 2 — VULN SCAN ===
            run_vuln_phase = (
                (mode == 'baseline' and project.vuln_scan_enabled) or
                mode == 'vuln' or
                (mode == 'full' and project.vuln_scan_recon_enabled)
            )

            if run_vuln_phase:
                print("[WORKER] --- FASE VULN SCAN ---")

                # Escaneia todos os domínios vivos não verificados, independente
                # de quando foram descobertos — garante que o contador "pendentes"
                # zere ao final do scan.
                targets = Domain.query.filter(
                    Domain.project_id == project.id,
                    Domain.scanned_vulns == False,
                    Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308, 403]),
                ).all()

                if not targets:
                    print("[WORKER] Nenhum alvo pendente para Vuln Scan.")
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

                target_file = f"targets_proj_{project.id}_{uuid.uuid4().hex}.txt"
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

                    # Marca também não-vivos para zerar o contador "pendentes" do card.
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


def dispatch_next_pending():
    """Acorda o próximo projeto da fila passiva quando um slot abre.

    Usa mutex Redis (compartilhado com routes.py) para garantir que apenas
    UM processo execute o despacho — elimina race condition entre workers
    que terminam simultaneamente.
    """
    from celery import uuid as celery_uuid
    import redis as redis_lib

    MAX_CONCURRENT = int(os.environ.get('GLOBAL_SCAN_CONCURRENCY', 2))
    LOCK_KEY   = 'dispatch_lock'
    LOCK_TTL   = 15

    try:
        r = redis_lib.Redis(
            host=os.environ.get('REDIS_HOST', 'redis'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=1
        )
        acquired = r.set(LOCK_KEY, '1', nx=True, ex=LOCK_TTL)
    except Exception as e:
        print(f"[QUEUE] Redis indisponível para mutex: {e} — usando fallback sem lock.")
        acquired = True
        r = None

    if not acquired:
        print("[QUEUE] Outro worker ja esta despachando. Ignorando.")
        return

    try:
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

        pendentes = Project.query.filter(
            Project.scan_status == 'Na fila',
            Project.current_task_id.is_(None)
        ).order_by(Project.id.asc()).limit(slots_livres).all()

        if not pendentes:
            print("[QUEUE] Fila global vazia — nenhum projeto pendente.")
            return

        for proximo in pendentes:
            # O modo é preservado em scan_message como "mode:xxx".
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
        if r:
            try:
                r.delete(LOCK_KEY)
            except Exception:
                pass


def process_vulns(vuln_list, project_id):
    """Persiste vulnerabilidades mapeando o host de volta para o Domain.

    Dedup é feito por (tool, severity, description) — descrição igual mas
    ferramentas diferentes são vulnerabilidades distintas.
    """
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
                domain_id=dom_id,
                tool=v['tool'],
                severity=v['severity'],
                description=v['description'],
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


@celery.task
def run_daily_scan(mode='full'):
    """Agenda diariamente (Celery Beat) o scan de todos os projetos.

    Idempotente: usa SystemState.last_daily_scan para garantir 1x por dia.
    Despacha respeitando GLOBAL_SCAN_CONCURRENCY — o resto vai para fila passiva.
    """
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

        MAX_CONCURRENT = int(os.environ.get('GLOBAL_SCAN_CONCURRENCY', 2))

        elegiveis = [
            p for p in Project.query.order_by(Project.id.asc()).all()
            if not (p.scan_status == 'Rodando' or
                    (p.scan_status == 'Na fila' and p.current_task_id))
        ]

        for proj in elegiveis:
            proj.scan_status = 'Na fila'
            proj.scan_message = f'mode:{mode}'
            proj.current_task_id = None
        db.session.commit()

        ativos = Project.query.filter(
            db.or_(
                Project.scan_status == 'Rodando',
                db.and_(
                    Project.scan_status == 'Na fila',
                    Project.current_task_id.isnot(None),
                ),
            )
        ).count()

        slots = max(0, MAX_CONCURRENT - ativos)

        for proj in elegiveis[:slots]:
            task_id = celery_uuid()
            proj.current_task_id = task_id
            proj.scan_message = f'Aguardando worker ({mode}, agendado)...'
            db.session.flush()
            run_scan_task.apply_async(args=[proj.id, mode], task_id=task_id)
            print(f"[SCHEDULER] Despachado {proj.name} - task {task_id}")

        db.session.commit()
        print(f"[SCHEDULER] {len(elegiveis[:slots])} despachado(s), "
              f"{max(0, len(elegiveis) - slots)} aguardando slot.")
