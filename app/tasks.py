from . import celery, db
from .models import Project, Domain, Vulnerability
from .scanner import (
    find_subdomains, check_alive, scan_nuclei_bulk, 
    scan_crawling_xss_bulk, scan_sqlmap_bulk, 
    scan_naabu_bulk, run_dig_info, send_discord_embed,
    scan_ffuf, scan_cmseek
)
from datetime import datetime
import os
import traceback

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
            
            project.scan_status = "Rodando"
            project.last_scan_date = datetime.utcnow()
            db.session.commit()

            # ==============================================================================
            # FASE 1: RECON (Coleta + Portas + DNS + Status + FUZZING EM NOVOS)
            # ==============================================================================
            if mode in ['recon', 'full', 'baseline']:
                print("[WORKER] --- Iniciando Fase RECON ---")
                project.scan_message = "1/4 Coletando Subdomínios (Subfinder | Amass)"
                db.session.commit()

                found_subs = find_subdomains(project.target_url)
                print(f"[WORKER] Recon encontrou {len(found_subs)} domínios.")
                
                # --- NAABU ---
                project.scan_message = "2/4 Verificando Portas Abertas (Naabu)..."
                db.session.commit()
                
                temp_subs_file = f"subs_naabu_{project.id}.txt"
                with open(temp_subs_file, 'w') as f:
                    f.write("\n".join(found_subs))
                
                naabu_data = scan_naabu_bulk(temp_subs_file)
                if os.path.exists(temp_subs_file): os.remove(temp_subs_file)

                # --- HTTPX ---
                project.scan_message = f"3/4 Verificando {len(found_subs)} subdomínios (HTTPX)..."
                db.session.commit()
                
                alive_data = check_alive(found_subs)
                print(f"[WORKER] HTTPX retornou dados de {len(alive_data)} domínios vivos.")
                
                status_map = {}
                tech_map = {}
                ip_map = {} 
                url_map = {} # Mapeia dominio -> url completa (https://...)
                
                for item in alive_data:
                    clean = item['url'].replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
                    status_map[clean] = item['status']
                    tech_map[clean] = item.get('tech', [])
                    ip_map[clean] = item.get('ip')
                    url_map[clean] = item['url'] # Salva a URL correta para o Fuzzing

                existing_domains = {d.name for d in project.domains}
                new_count = 0
                total_paths_found = 0 # Contador para o Discord

                project.scan_message = "4/4 Processando Novos Alvos (DNS + Fuzzing)..."
                db.session.commit()

                for sub in found_subs:
                    if sub not in existing_domains:
                        is_scanned = True if mode == 'baseline' else False
                        
                        val = status_map.get(sub)
                        code = int(val) if val is not None else 0
                        
                        tech_list = tech_map.get(sub, [])
                        tech_str = ", ".join(tech_list) if tech_list else None
                        
                        ip_addr = ip_map.get(sub)
                        ports_str = naabu_data.get(sub)
                        
                        dns_str = None
                        if code > 0 or ports_str:
                            dns_str = run_dig_info(sub)
                        
                        # --- LÓGICA DE FUZZING ---
                        fuzz_paths_str = None
                        
                        allowed_codes = [200, 201, 202, 204, 301, 302, 307, 308]
                        
                        # Só roda fuzzing se estiver nesse range [200, 201, 202, 204, 301, 302, 307, 308] e não for apenas baseline
                        if code in allowed_codes and mode != 'baseline':
                            target_url = url_map.get(sub, f"https://{sub}")
                            print(f"[WORKER] Novo alvo detectado: {sub}. Iniciando Fuzzing rápido...")
                            
                            # Roda o CMSeeK para enriquecer tecnologia
                            cms_found = scan_cmseek(target_url)
                            
                            # Se achou algo, adiciona à string de tecnologias existente
                            if cms_found:
                                if tech_str:
                                    tech_str += f", {cms_found}"
                                else:
                                    tech_str = cms_found
                            
                            # Roda o FFuf
                            f_res = scan_ffuf(target_url)
                            if f_res:
                                paths_list = [item['raw_path'] for item in f_res]
                                fuzz_paths_str = ", ".join(paths_list)
                                total_paths_found += len(paths_list)
                        
                        new_dom = Domain(
                            name=sub, project_id=project.id, 
                            scanned_vulns=is_scanned, status_code=code,
                            technologies=tech_str,
                            ip_address=ip_addr,
                            open_ports=ports_str,
                            dns_info=dns_str,
                            discovered_paths=fuzz_paths_str
                        )
                        db.session.add(new_dom)
                        new_count += 1
                
                db.session.commit()
                print(f"[WORKER] {new_count} novos domínios salvos no banco.")

                # --- CÁLCULO DE ESTATÍSTICAS PARA O DISCORD ---
                c_2xx = 0
                c_3xx = 0
                c_4xx = 0
                c_5xx = 0
                
                for item in alive_data:
                    try:
                        code = int(item.get('status', 0))
                        if 200 <= code < 300: c_2xx += 1
                        elif 300 <= code < 400: c_3xx += 1
                        elif 400 <= code < 500: c_4xx += 1
                        elif 500 <= code < 600: c_5xx += 1
                    except: pass

                # --- NOTIFICAÇÃO DISCORD ---
                try:
                    recon_fields = [
                        {"name": "🌐 Total", "value": str(len(found_subs)), "inline": True},
                        {"name": "🆕 Novos", "value": str(new_count), "inline": True},
                        {"name": "⚡ Vivos", "value": str(len(alive_data)), "inline": True},
                        {"name": "📂 Paths (Fuzzing)", "value": str(total_paths_found), "inline": True}, 
                        
                        
                        {"name": "--- Detalhamento HTTP ---", "value": "\u200b", "inline": False},
                        
                        
                        {"name": "✅ 200 OK", "value": str(c_2xx), "inline": True},
                        {"name": "➡️ REDIRECT", "value": str(c_3xx), "inline": True},
                        {"name": "🚫 CLIENT ERR", "value": str(c_4xx), "inline": True},
                        {"name": "🔥 SERVER ERR", "value": str(c_5xx), "inline": True}
                    ]
                    
                    color = 0x3498db 
                    if new_count > 0: color = 0x00ff00 

                    send_discord_embed(
                        title=f"📡 Recon: {project.name}",
                        description=f"Reconhecimento concluído.",
                        fields=recon_fields,
                        color_hex=color
                    )
                except Exception as e:
                    print(f"[NOTIFY ERROR] Erro ao enviar Embed de Recon: {e}")

                if mode in ['recon', 'baseline']:
                    project.scan_status = "Concluído"
                    project.scan_message = f"Recon finalizado. {new_count} novos ativos."
                    db.session.commit()
                    print("[WORKER] Fase RECON finalizada com sucesso.")
                    return "Recon OK"

            # ==============================================================================
            # FASE 2: VULN SCAN (BATCH PROCESSING)
            # ==============================================================================
            if mode in ['vuln', 'full']:
                print("[WORKER] --- Iniciando Fase VULN SCAN (Batch) ---")
                
                targets = Domain.query.filter(
                    Domain.project_id == project.id,
                    Domain.scanned_vulns == False,
                    Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
                ).all()
                
                if not targets:
                    print("[WORKER] Nenhum alvo pendente com Status 200.")
                    project.scan_status = "Concluído"
                    project.scan_message = "Nenhum alvo válido pendente."
                    db.session.commit()
                    return "Scan Finalizado (Sem novos alvos)"

                print(f"[WORKER] Alvos qualificados: {len(targets)}")

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
                    # sqli_vulns = []
                    

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
def run_daily_scan():
    from app import create_app
    from .models import Project
    app = create_app()
    with app.app_context():
        projects = Project.query.all()
        for proj in projects:
            run_scan_task.delay(proj.id, mode='full')