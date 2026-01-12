from . import celery, db
from .models import Project, Domain, Vulnerability
from .scanner import (
    find_subdomains, check_alive, scan_nuclei_bulk, 
    scan_crawling_xss_bulk, scan_sqlmap_bulk, 
    scan_naabu_bulk, run_dig_info, send_discord_embed,
    scan_ffuf, scan_cmseek, get_first_seen_crtsh
)
from datetime import datetime
import os
import traceback
import fnmatch

@celery.task(bind=True)
def run_scan_task(self, project_id, mode='full'):
    from app import create_app
    app = create_app()
    
    with app.app_context():
        project = Project.query.get(project_id)
        if not project: 
            print(f"[WORKER ERROR] Projeto ID {project_id} não encontrado!")
            return

        try:
            print(f"[WORKER] Iniciando task para Projeto: {project.name} (Modo: {mode})")
            
            project.current_task_id = self.request.id 
            project.scan_status = "Rodando"
            project.last_scan_date = datetime.utcnow()
            db.session.commit()

            # Prepara a Blacklist (Out of Scope)
            blacklist = [line.strip() for line in (project.out_of_scope or "").splitlines() if line.strip()]

            # ==============================================================================
            # FASE 1: RECON (Coleta + Portas + DNS + Status + FUZZING)
            # ==============================================================================
            if mode in ['recon', 'full', 'baseline']:
                print(f"[WORKER] --- Iniciando Fase RECON({mode}) ---")
                
                # --- 1. COLETA DE SUBDOMÍNIOS ---
                found_subs = []
                
                if project.discovery_enabled:
                    # Passo A: Definir Sementes (APENAS Raízes)
                    # 1. Alvo Principal
                    target_clean = project.target_url.replace('https://', '').replace('http://', '').split('/')[0]
                    seeds = {target_clean}
                    
                    # 2. Adiciona APENAS o que está escrito no campo "In Scope" (Manual)
                    # Isso evita o loop de re-escanear subdomínios já descobertos
                    if project.in_scope:
                        for line in project.in_scope.splitlines():
                            line = line.strip()
                            if line:
                                # Limpa protocolo se houver
                                clean_manual = line.replace('https://', '').replace('http://', '').split('/')[0]
                                seeds.add(clean_manual)
                    
                    total_seeds = len(seeds)
                    print(f"[WORKER] Discovery ATIVADO. {total_seeds} sementes raízes: {seeds}")
                    
                    all_discovered = set()
                    
                    # Passo B: Rodar Subfinder/Amass nas sementes raízes
                    for idx, seed in enumerate(seeds, 1):
                        msg = f"1/4 Coletando ({idx}/{total_seeds}): {seed}"
                        print(f"[WORKER] {msg}")
                        project.scan_message = msg
                        db.session.commit()
                        
                        seed_results = find_subdomains(seed)
                        all_discovered.update(seed_results)
                    
                    # Passo C: Merge Inteligente
                    # Adicionamos os domínios que já existem no banco à lista de resultados
                    # Motivo: Para que eles passem pelas fases seguintes (HTTPX/Naabu) mesmo que o Subfinder não os ache hoje.
                    current_domains_db = Domain.query.filter_by(project_id=project.id).all()
                    for d in current_domains_db:
                        all_discovered.add(d.name)
                    
                    found_subs = list(all_discovered)

                else:
                    # Modo Manual (Sem Discovery)
                    print("[WORKER] Discovery DESATIVADO. Usando apenas banco de dados.")
                    project.scan_message = "1/4 Carregando lista de alvos..."
                    db.session.commit()
                    current_domains = Domain.query.filter_by(project_id=project.id).all()
                    found_subs = [d.name for d in current_domains]

                # --- 2. FILTRAGEM (OUT OF SCOPE) ---
                final_subs = []
                for sub in found_subs:
                    is_blocked = False
                    for bl in blacklist:
                        # Regra Wildcard (*)
                        if fnmatch.fnmatch(sub, bl):
                            is_blocked = True
                            break
                        # Regra Sufixo
                        if '*' not in bl:
                            if sub == bl or sub.endswith("." + bl):
                                is_blocked = True
                                break
                    if not is_blocked:
                        final_subs.append(sub)

                found_subs = final_subs 
                print(f"[WORKER] Lista final para análise: {len(found_subs)} domínios.")
                
                # --- 3. NAABU (PORT SCAN) ---
                if found_subs:
                    project.scan_message = "2/4 Verificando Portas Abertas (Naabu)..."
                    db.session.commit()
                    
                    temp_subs_file = f"subs_naabu_{project.id}.txt"
                    with open(temp_subs_file, 'w') as f:
                        f.write("\n".join(found_subs))
                    
                    naabu_data = scan_naabu_bulk(temp_subs_file)
                    if os.path.exists(temp_subs_file): os.remove(temp_subs_file)
                else:
                    naabu_data = {}

                # --- 4. HTTPX (LIVE CHECK) ---
                if found_subs:
                    project.scan_message = f"3/4 Verificando {len(found_subs)} subdomínios (HTTPX)..."
                    db.session.commit()
                    alive_data = check_alive(found_subs)
                else:
                    alive_data = []
                
                # Mapeamento de dados para acesso rápido
                status_map = {}
                tech_map = {}
                ip_map = {} 
                url_map = {}
                
                for item in alive_data:
                    clean = item['url'].replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
                    status_map[clean] = item['status']
                    tech_map[clean] = item.get('tech', [])
                    ip_map[clean] = item.get('ip')
                    url_map[clean] = item['url'] 

                domain_map = {d.name: d for d in Domain.query.filter_by(project_id=project.id).all()}
                
                new_count = 0
                total_paths_found = 0 

                project.scan_message = "4/4 Processando Alvos (DNS + Fuzzing + SSL Cert Data)..."
                db.session.commit()

                # --- 5. ATUALIZAÇÃO E FUZZING ---
                for sub in found_subs:
                    domain_obj = domain_map.get(sub)
                    is_new_entry = False
                    
                    if not domain_obj:
                        domain_obj = Domain(name=sub, project_id=project.id)
                        is_new_entry = True
                        
                    if mode == 'baseline':
                        if not project.vuln_scan_enabled:
                            domain_obj.scanned_vulns = True

                    val = status_map.get(sub)
                    code = int(val) if val is not None else 0
                    domain_obj.status_code = code
                    
                    if mode == 'recon' and is_new_entry and code in [200, 201, 202, 204, 301, 302, 307, 308]:
                        # Pode ser um processo lento, então só roda quando necessário
                        crt_date = get_first_seen_crtsh(sub)
                        if crt_date:
                            domain_obj.creation_date = crt_date

                    tech_list = tech_map.get(sub, [])
                    if tech_list:
                        domain_obj.technologies = ", ".join(tech_list)
                    
                    domain_obj.ip_address = ip_map.get(sub)
                    domain_obj.open_ports = naabu_data.get(sub)
                    
                    # Resolve DNS se ativo ou com porta aberta
                    if code > 0 or domain_obj.open_ports:
                        domain_obj.dns_info = run_dig_info(sub)
                    
                    # --- LÓGICA DE FUZZING OTIMIZADA ---
                    should_fuzz = False
                    
                    # REGRA 1: Modo Baseline
                    if mode == 'baseline':
                        if project.fuzzing_enabled:
                            should_fuzz = True
                        
                        # REGRA 2: Outros Modos (Recon/Full)
                    else:
                        if is_new_entry:
                            should_fuzz = True
                        # REGRA 3: Scan Manual (Descoberta Off)
                        elif not project.discovery_enabled:
                            should_fuzz = True

                    allowed_codes = [200, 201, 202, 204, 301, 302, 307, 308, 403]
                    
                    if should_fuzz and code in allowed_codes:
                        target_url = url_map.get(sub, f"https://{sub}")
                        print(f"[WORKER] Rodando Fuzzing em: {sub}")
                        
                        # CMSeeK
                        cms_found = scan_cmseek(target_url)
                        if cms_found:
                            if domain_obj.technologies:
                                domain_obj.technologies += f", {cms_found}"
                            else:
                                domain_obj.technologies = cms_found
                        
                        # FFuf
                        f_res = scan_ffuf(target_url)
                        if f_res:
                            paths_list = [item['raw_path'] for item in f_res]
                            # Lógica de merge de paths
                            if len(paths_list) > 15:
                                subset = paths_list[:15]
                                subset.append(f"[+{len(paths_list)-15} outros]")
                                final_str = ", ".join(subset)
                            else:
                                final_str = ", ".join(paths_list)
                            
                            if domain_obj.discovered_paths:
                                # Merge simples para não duplicar visualmente
                                existing_paths = domain_obj.discovered_paths.split(", ")
                                combined = list(set(existing_paths + final_str.split(", ")))
                                domain_obj.discovered_paths = ", ".join(combined[:15])
                            else:
                                domain_obj.discovered_paths = final_str
                            
                            total_paths_found += len(paths_list)
                    
                    if is_new_entry:
                        db.session.add(domain_obj)
                        new_count += 1
                
                db.session.commit()
                
                # --- MÉTRICAS HTTP ---
                c_2xx = sum(1 for i in alive_data if 200 <= int(i.get('status') or 0) < 300)
                c_3xx = sum(1 for i in alive_data if 300 <= int(i.get('status') or 0) < 400)
                c_4xx = sum(1 for i in alive_data if 400 <= int(i.get('status') or 0) < 500)
                c_5xx = sum(1 for i in alive_data if 500 <= int(i.get('status') or 0) < 600)

                # --- NOTIFICAÇÃO ---
                try:
                    recon_fields = [
                        {"name": "🌐 Total Analisado", "value": str(len(found_subs)), "inline": True},
                        {"name": "🆕 Novos DB", "value": str(new_count), "inline": True},
                        {"name": "⚡ Vivos (HTTPX)", "value": str(len(alive_data)), "inline": True},
                        {"name": "📂 Paths (Fuzzing)", "value": str(total_paths_found), "inline": True}, 
                        
                        {"name": "--- Detalhamento HTTP ---", "value": "\u200b", "inline": False},
                        
                        {"name": "✅ 200 OK", "value": str(c_2xx), "inline": True},
                        {"name": "➡️ REDIRECT", "value": str(c_3xx), "inline": True},
                        {"name": "🚫 CLIENT ERR", "value": str(c_4xx), "inline": True},
                        {"name": "🔥 SERVER ERR", "value": str(c_5xx), "inline": True}
                    ]
                    color = 0x00ff00 if new_count > 0 else 0x3498db
                    
                    send_discord_embed(
                        title=f"📡 {mode.upper()}: {project.name}",
                        description=f"Reconhecimento concluído. (Discovery: {'ON' if project.discovery_enabled else 'OFF'})",
                        fields=recon_fields,
                        color_hex=color
                    )
                except Exception as e:
                    print(f"[NOTIFY ERROR] Erro ao enviar Embed de Recon: {e}")

                should_stop = False
                if mode == 'recon':
                    should_stop = True
                elif mode == 'baseline' and not project.vuln_scan_enabled:
                    should_stop = True

                if should_stop:
                    project.scan_status = "Concluído"
                    project.scan_message = f"Recon finalizado. {new_count} novos ativos."
                    db.session.commit()
                    print("[WORKER] Fase RECON finalizada com sucesso.")
                    return "Recon OK"
            # ==============================================================================
            # FASE 2: VULN SCAN (BATCH PROCESSING)
            # ==============================================================================
            run_vuln_phase = False
                        
            if mode == 'baseline':
                if project.vuln_scan_enabled:
                    run_vuln_phase = True
                else:
                    print(f"[WORKER] SKIP: Vuln Scan desativado para Baseline no projeto {project.name}.")

            elif mode in ['full', 'vuln']:
                if mode == 'vuln':
                    run_vuln_phase = True
                elif mode == 'full':
                    if project.vuln_scan_recon_enabled:
                        run_vuln_phase = True
                    else:
                        print(f"[WORKER] SKIP: Vuln Scan desativado para Full/Recon no projeto {project.name}.")
        

            if run_vuln_phase:
                print("[WORKER] --- Iniciando Fase VULN SCAN (Batch) ---")
                
                # 1. Cria a QUERY BASE (Sem .all() ainda)
                # Isso cria um objeto de consulta, não a lista de resultados
                query = Domain.query.filter(
                    Domain.project_id == project.id,
                    Domain.scanned_vulns == False,
                    Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
                )
                
                # 2. Aplica o filtro de DATA apenas se NÃO for Baseline
                if mode != 'baseline':
                    query = query.filter(Domain.first_seen >= project.last_scan_date)
                
                # 3. Agora sim executa a query final e pega a lista
                targets = query.all()
                
                if not targets:
                    print("[WORKER] Nenhum alvo pendente com Status OK para Vuln Scan.")
                    try:
                        send_discord_embed(
                            title=f"💤 Scan Vuln: {project.name}",
                            description="Scan finalizado sem ações.",
                            fields=[
                                {"name": "Status", "value": "Nenhum alvo novo", "inline": True},
                                {"name": "Detalhe", "value": "Todos os domínios ativos já foram verificados anteriormente.", "inline": False}
                            ],
                            color_hex=0x95a5a6 # Cinza (Info/Neutro)
                        )
                    except Exception as e:
                        print(f"[NOTIFY ERROR] Erro ao enviar Embed: {e}")
                    # ----------------------------------------

                    project.scan_status = "Concluído"
                    project.scan_message = "Nenhum alvo válido pendente."
                    db.session.commit()
                    return "Scan Finalizado (Sem novos alvos)"

                print(f"[WORKER] Alvos qualificados para Vuln Scan: {len(targets)}")

                target_file = f"targets_proj_{project.id}.txt"
                with open(target_file, "w") as f:
                    for d in targets:
                        f.write(f"https://{d.name}\n")
                
                try:
                    # 1. Nuclei
                    project.scan_message = f"Rodando Nuclei em Lote ({len(targets)} domínios)..."
                    db.session.commit()
                    nuclei_vulns = scan_nuclei_bulk(target_file)
                    process_vulns(nuclei_vulns, project.id)

                    # 2. XSS + GAU
                    project.scan_message = f"Rodando Katana + GAU + Dalfox..."
                    db.session.commit()
                    xss_vulns = scan_crawling_xss_bulk(target_file)
                    process_vulns(xss_vulns, project.id)

                    # 3. SQLMap
                    sqli_vulns = scan_sqlmap_bulk(target_file)
                    process_vulns(sqli_vulns, project.id)

                    # 4. Atualizar Status Final
                    print("[WORKER] Marcando domínios como escaneados...")
                    for d in targets:
                        d.scanned_vulns = True
                    
                    total_vulns = len(nuclei_vulns) + len(xss_vulns) + len(sqli_vulns)
                    
                    # --- NOTIFICAÇÃO DISCORD (VULNERABILIDADES) ---
                    try:
                        if total_vulns > 0:
                            vuln_fields = [
                                {"name": "🔥 Total", "value": str(total_vulns), "inline": False},
                                {"name": "☢️ Nuclei", "value": str(len(nuclei_vulns)), "inline": True},
                                {"name": "⚠️ XSS/Arquivos", "value": str(len(xss_vulns)), "inline": True},
                                {"name": "💉 SQLi", "value": str(len(sqli_vulns)), "inline": True}
                            ]
                            send_discord_embed(
                                title=f"🚨 VULNERABILIDADES: {project.name}",
                                description="Falhas de segurança encontradas.",
                                fields=vuln_fields,
                                color_hex=0xff0000
                            )
                        else:
                            send_discord_embed(
                                title=f"✅ Scan Limpo: {project.name}",
                                description="Nenhuma vulnerabilidade crítica detectada.",
                                fields=[{"name": "Status", "value": "Seguro", "inline": True}],
                                color_hex=0x00ff00
                            )
                    except Exception as e:
                        print(f"[NOTIFY ERROR] Erro ao enviar Embed: {e}")

                    project.scan_status = "Concluído"
                    project.scan_message = f"Finalizado. {total_vulns} vulns."
                    db.session.commit()
                    print(f"[WORKER] Tarefa finalizada. Total Vulns: {total_vulns}")

                finally:
                    if os.path.exists(target_file): os.remove(target_file)

        except Exception as e:
            db.session.rollback()
            print(f"[WORKER CRITICAL ERROR] {traceback.format_exc()}")
            project_check = Project.query.get(project_id)
            if project_check:
                project_check.scan_status = "Erro"
                project_check.scan_message = f"Erro: {str(e)[:100]}"
                db.session.commit()

def process_vulns(vuln_list, project_id):
    """Mapeia URLs vulneráveis de volta para o Domain ID"""
    if not vuln_list: return
    
    print(f"[WORKER PROCESSING] Mapeando {len(vuln_list)} vulnerabilidades...")
    
    domain_cache = {}
    all_domains = Domain.query.filter_by(project_id=project_id).all()
    for d in all_domains:
        domain_cache[d.name] = d.id
        
    count_saved = 0
    count_dupe = 0
    
    for v in vuln_list:
        host_url = v.get('host', '')
        if not host_url: continue

        clean_host = host_url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        
        dom_id = domain_cache.get(clean_host)
        
        if not dom_id:
            if clean_host in domain_cache:
                dom_id = domain_cache[clean_host]
            else:
                try:
                    new_dynamic_domain = Domain(
                        name=clean_host, 
                        project_id=project_id,
                        scanned_vulns=True, 
                        status_code=200,
                        technologies="Descoberto via Vuln Scan"
                    )
                    db.session.add(new_dynamic_domain)
                    db.session.commit()
                    dom_id = new_dynamic_domain.id
                    domain_cache[clean_host] = dom_id
                except: continue
                
        if dom_id:
            exists = Vulnerability.query.filter_by(domain_id=dom_id, description=v['description']).first()
            if not exists:
                new_vuln = Vulnerability(
                    tool=v['tool'], severity=v['severity'],
                    description=v['description'], domain_id=dom_id
                )
                db.session.add(new_vuln)
                count_saved += 1
            else:
                count_dupe += 1
    
    db.session.commit()
    print(f"[WORKER PROCESSING] Salvas: {count_saved} | Duplicadas: {count_dupe}")

@celery.task
def run_daily_scan(mode='full'):
    from app import create_app
    from .models import Project
    # Importante: Importar o db para salvar as alterações
    from . import db 
    
    app = create_app()
    with app.app_context():
        projects = Project.query.all()
        for proj in projects:
            # 1. Dispara a tarefa para a fila
            task = run_scan_task.delay(proj.id, mode=mode)
            
            # 2. SALVA O ID IMEDIATAMENTE (A Correção é Aqui)
            # Isso garante que o botão "Parar" consiga encontrar e matar a tarefa na fila
            proj.current_task_id = task.id
            proj.scan_status = 'Na fila'
            proj.scan_message = 'Aguardando início (Agendado)...'
            
            # Commit a cada iteração ou em grupos para garantir persistência rápida
            db.session.commit()