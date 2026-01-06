import subprocess
import json
import os
import uuid
import csv
import urllib.request
from datetime import datetime

# --- Função Utilitária de Comando com Debug ---
def run_command(command, timeout=None):
    """Roda um comando no shell e retorna a saída, com MUITO debug."""
    try:
        print(f"[CMD EXEC] {command}")
        
        # Timeout padrão de 1 hora para processos longos (batch)
        timeout = timeout if timeout else 3600 
        
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        
        # Se tiver erro na saída de erro (stderr), mostra no log
        if result.stderr and "level=error" in result.stderr:
            print(f"[CMD ERROR] Stderr detectado: {result.stderr[:200]}...")
            
        return result.stdout.splitlines()
        
    except subprocess.TimeoutExpired:
        print(f"[CMD TIMEOUT] O comando morreu por demora: {command}")
        return []
    except Exception as e:
        print(f"[CMD CRASH] Exceção ao rodar comando: {e}")
        return []

# --- Funções Individuais (Recon) ---

def find_subdomains(target_domain):
    """
    Fluxo Unificado: Subfinder + Amass -> Deduplicação.
    Retorna uma lista limpa de subdomínios únicos (sem IPs, CIDRs ou ASNs).
    """
    print(f"[SCANNER] Iniciando Recon Híbrido (Subfinder + Amass) para {target_domain}...")
    
    unique_id = uuid.uuid4().hex
    file_subfinder = f"raw_subfinder_{unique_id}.txt"
    file_amass = f"raw_amass_{unique_id}.txt"
    
    subs_set = set() # Set para garantir unicidade

    try:
        # 1. Rodar Subfinder
        print(f"[SCANNER] 1/2 Rodando Subfinder...")
        cmd_sub = f"subfinder -d {target_domain} -silent -t 100 -all -o {file_subfinder}"
        run_command(cmd_sub, timeout=1800)
        
        # 2. Rodar Amass (Modo Passivo)
        print(f"[SCANNER] 2/2 Rodando Amass (Passive)...")
        cmd_amass = f"amass enum -passive -d {target_domain} -noalts -timeout 29 -o {file_amass}" 
        run_command(cmd_amass, timeout=1800)

        # 3. Processar e Deduplicar (Lógica Unificada)
        for filename in [file_subfinder, file_amass]:
            if os.path.exists(filename):
                with open(filename, 'r') as f:
                    for line in f:
                        # Limpa espaços e pega apenas a primeira coluna (remove infos extras do Amass)
                        clean_line = line.strip().split(' ')[0]
                        
                        # --- FILTROS DE LIMPEZA (CRÍTICO) ---
                        if not clean_line: continue
                        
                        # 1. Ignora Faixas CIDR (ex: 34.240.0.0/12)
                        # Isso evita que o Naabu escaneie milhões de IPs
                        if '/' in clean_line: continue
                        
                        # 2. Ignora Wildcards (ex: *.site.com)
                        if '*' in clean_line: continue
                        
                        # 3. Ignora ASNs (números puros, ex: 16509)
                        if clean_line.isdigit(): continue
                        
                        # 4. Regra de Ouro: Tem que ter pelo menos um ponto para ser domínio
                        if '.' not in clean_line: continue

                        # (Opcional) Ignora endereços IPv6 brutos se não quiser escanear ipv6
                        if ':' in clean_line: continue 
                        
                        # 5. Tem que terminar com o domínio alvo (evita subdomínios falsos)
                        if not clean_line.endswith(target_domain): continue

                        subs_set.add(clean_line)

    except Exception as e:
        print(f"[SCANNER ERROR] Erro durante o Recon: {e}")
    
    finally:
        # Limpeza dos arquivos temporários
        if os.path.exists(file_subfinder): os.remove(file_subfinder)
        if os.path.exists(file_amass): os.remove(file_amass)
    
    unique_list = list(subs_set)
    print(f"[SCANNER] Recon finalizado. {len(unique_list)} subdomínios válidos encontrados.")
    return unique_list

def check_alive(subdomains_list):
    if not subdomains_list: return []
    
    filename = f"temp_subs_{uuid.uuid4().hex}.txt"
    parsed = []
    
    try:
        with open(filename, "w") as f:
            f.write("\n".join(subdomains_list))
        
        print(f"[SCANNER] Rodando HTTPX em {len(subdomains_list)} alvos...")
        
        cmd = f"/usr/local/bin/pd-httpx -l {filename} -json -silent -sc -td -probe -ip -threads 50"
        results = run_command(cmd, timeout=1800)
        
        print(f"[SCANNER] HTTPX finalizado. {len(results)} respostas capturadas.")
        
        for line in results:
            try:
                data = json.loads(line)
                if data.get('url'):
                    # Capturar o IP (httpx retorna lista em 'a')
                    ips = data.get('a', []) 
                    primary_ip = ips[0] if ips else None
                    
                    parsed.append({
                        'url': data.get('url'),
                        'status': data.get('status_code'),
                        'tech': data.get('tech', []),
                        'ip': primary_ip 
                    })
            except: continue
    finally:
        if os.path.exists(filename): os.remove(filename)
    return parsed

# --- FUNÇÕES BULK (LOTE) ---

def scan_nuclei_bulk(targets_file):
    """
    Roda o Nuclei lendo uma lista de URLs de um arquivo.
    """
    print(f"[SCANNER BULK] Iniciando Nuclei em Lote no arquivo: {targets_file}")
    
    # Arquivo temporário para saída JSON
    output_nuclei = f"nuclei_res_{uuid.uuid4().hex}.json"
    
    # Comando Nuclei Otimizado (Inclui 'exposure' para achar .git e 'misconfig')
    cmd = f"nuclei -l {targets_file} -tags cve2023,cve2024,misconfig,exposure,tech,panel -s info,low,medium,high,critical -j -silent -timeout 2 -c 80 -o {output_nuclei}"
    
    run_command(cmd, timeout=7200)
    
    vulns = []
    
    if os.path.exists(output_nuclei):
        print(f"[SCANNER BULK] Lendo resultados do Nuclei em {output_nuclei}...")
        try:
            with open(output_nuclei, 'r') as f:
                for line in f:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        vulns.append({
                            'host': data.get('host'),
                            'tool': 'Nuclei',
                            'name': data.get('info', {}).get('name'),
                            'severity': data.get('info', {}).get('severity'),
                            'description': f"Matcher: {data.get('matcher-name')} | URL: {data.get('matched-at')}"
                        })
                    except Exception as e:
                        print(f"[SCANNER JSON ERROR] Falha ao ler linha do Nuclei: {e}")
                        continue
        except Exception as e:
            print(f"[SCANNER ERROR] Erro fatal lendo arquivo Nuclei: {e}")
        finally:
            os.remove(output_nuclei)
    else:
        print("[SCANNER BULK] Nuclei terminou sem criar arquivo de saída.")
            
    print(f"[SCANNER BULK] Nuclei terminou. {len(vulns)} vulnerabilidades potenciais achadas.")
    return vulns

def scan_crawling_xss_bulk(targets_file):
    """
    Roda em 3 etapas integradas: Katana + GAU -> Dalfox
    """
    print(f"[SCANNER BULK] Iniciando Pipeline Katana + GAU -> Dalfox no arquivo: {targets_file}")
    
    temp_urls_file = f"crawl_urls_{uuid.uuid4().hex}.txt"
    output_xss = f"xss_{uuid.uuid4().hex}.json"
    
    vulns = []

    try:
        # --- ETAPA 1: CRAWLING ATIVO (KATANA) ---
        print(f"[SCANNER BULK] 1/3 Rodando Katana (Crawler)...")
        cmd_katana = f"katana -list {targets_file} -d 2 -jc -silent -o {temp_urls_file}"
        run_command(cmd_katana, timeout=3600)

        # --- ETAPA 2: CRAWLING PASSIVO (GAU - HISTÓRICO) ---
        print(f"[SCANNER BULK] 2/3 Rodando GAU para enriquecer com URLs arquivadas...")
        # Usa 'cat' para ler o arquivo de alvos e passar pro GAU
        cmd_gau = f"cat {targets_file} | gau --blacklist png,jpg,jpeg,gif,css,svg,woff,woff2 >> {temp_urls_file}"
        run_command(cmd_gau, timeout=1800)

        if not os.path.exists(temp_urls_file) or os.path.getsize(temp_urls_file) == 0:
            print("[SCANNER BULK] Katana e GAU não encontraram nenhuma URL.")
            return []

        # Conta linhas totais
        with open(temp_urls_file) as f:
            count = sum(1 for line in f)
        print(f"[SCANNER BULK] Total de URLs coletadas (Katana + GAU): {count}. Iniciando Dalfox...")

        # --- ETAPA 3: SCANNING (DALFOX) ---
        print(f"[SCANNER BULK] 3/3 Rodando Dalfox...")
        
        cmd_dalfox = f"dalfox file {temp_urls_file} --format json --silence --skip-bav -o {output_xss}"
        run_command(cmd_dalfox, timeout=3600)

        # --- PROCESSAR RESULTADOS ---
        if os.path.exists(output_xss):
            print(f"[SCANNER BULK] Lendo resultados do Dalfox...")
            try:
                with open(output_xss, 'r') as f:
                    content = f.read()
                    
                    if content.strip() == "[{}]":
                         print("[SCANNER BULK] Dalfox retornou objeto vazio (Falso Positivo). Ignorando.")
                         return []

                    if content.strip().startswith('['):
                        data_list = json.loads(content)
                        for data in data_list:
                            parsed = parse_dalfox_json(data)
                            if parsed['host']: vulns.append(parsed)
                    else:
                        lines = content.splitlines()
                        for line in lines:
                            if not line.strip(): continue
                            try:
                                data = json.loads(line)
                                parsed = parse_dalfox_json(data)
                                if parsed['host']: vulns.append(parsed)
                            except: continue
            except Exception as e:
                print(f"[SCANNER ERROR] Erro lendo JSON do Dalfox: {e}")
        else:
            print("[SCANNER BULK] Dalfox terminou sem gerar arquivo de saída.")

    except Exception as e:
        print(f"[SCANNER CRITICAL] Erro no pipeline XSS: {e}")

    finally:
        if os.path.exists(temp_urls_file): os.remove(temp_urls_file)
        if os.path.exists(output_xss): os.remove(output_xss)
            
    print(f"[SCANNER BULK] XSS Scan terminou. {len(vulns)} falhas encontradas.")
    return vulns

def scan_sqlmap_bulk(targets_file):
    """
    Pipeline: Katana (qurl) -> SQLMap (Smart)
    """
    print(f"[SCANNER BULK] Iniciando Pipeline Katana -> SQLMap no arquivo: {targets_file}")
    
    params_file = f"sql_params_{uuid.uuid4().hex}.txt"
    results_csv = f"sqlmap_res_{uuid.uuid4().hex}.csv"
    
    vulns = []

    try:
        # 1. Encontrar URLs com parâmetros
        print("[SCANNER BULK] 1/2 Buscando parâmetros expostos com Katana...")
        cmd_katana = f"katana -list {targets_file} -d 2 -silent -f qurl -o {params_file}"
        run_command(cmd_katana, timeout=3600)
        
        if not os.path.exists(params_file) or os.path.getsize(params_file) == 0:
            print("[SCANNER BULK] Nenhuma URL parametrizada encontrada para teste de SQLi.")
            return []

        # 2. Rodar SQLMap
        print("[SCANNER BULK] 2/2 Rodando SQLMap (Smart Mode)...")
        cmd_sqlmap = f"sqlmap -m {params_file} --batch --random-agent --risk=1 --level=1 --smart --results-file={results_csv}"
        run_command(cmd_sqlmap, timeout=7200)

        # 3. Ler Resultados CSV
        if os.path.exists(results_csv):
            print("[SCANNER BULK] Lendo resultados do SQLMap...")
            try:
                with open(results_csv, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 6:
                            if "Target URL" in str(row[0]): continue
                            vulns.append({
                                'host': row[0],
                                'tool': 'SQLMap',
                                'severity': 'Critical',
                                'name': f"SQL Injection ({row[4]})",
                                'description': f"Param: {row[2]} | Payload: {row[5]}"
                            })
            except Exception as e:
                print(f"[SCANNER ERROR] Erro lendo CSV do SQLMap: {e}")
        else:
             print("[SCANNER BULK] SQLMap terminou sem confirmar vulnerabilidades.")

    except Exception as e:
        print(f"[SCANNER CRITICAL] Erro no pipeline SQLMap: {e}")
    
    finally:
        if os.path.exists(params_file): os.remove(params_file)
        if os.path.exists(results_csv): os.remove(results_csv)

    print(f"[SCANNER BULK] SQLMap terminou. {len(vulns)} falhas encontradas.")
    return vulns

def parse_dalfox_json(data):
    """
    Parser robusto para o JSON do Dalfox.
    """
    print(f"[SCANNER DEBUG] JSON Bruto Dalfox: {data}")

    host = data.get('url') or data.get('target') or data.get('poc') or ""
    payload = data.get('payload') or "Payload genérico"
    param = data.get('param') or "Parâmetro desconhecido"
    
    sev = data.get('severity', 'High')
    if isinstance(sev, str):
        sev = sev.capitalize()

    return {
        'host': host,
        'tool': 'Dalfox',
        'severity': sev, 
        'name': f"Cross-Site Scripting ({data.get('type', 'XSS')})",
        'description': f"Payload: {payload} em {param}"
    }

def scan_naabu_bulk(targets_file):
    """
    Roda Naabu em lista de domínios.
    """
    print(f"[SCANNER] Iniciando Naabu (Port Scan) no arquivo: {targets_file}")
    
    cmd = f"naabu -list {targets_file} -top-ports 100 -json -silent"
    results = run_command(cmd, timeout=1800)
    
    port_map = {}
    
    for line in results:
        try:
            data = json.loads(line)
            host = data.get('host')
            port = data.get('port')
            if host and port:
                if host not in port_map:
                    port_map[host] = []
                port_map[host].append(str(port))
        except: continue
        
    final_map = {k: ", ".join(v) for k, v in port_map.items()}
    print(f"[SCANNER] Naabu finalizado. {len(final_map)} hosts com portas abertas.")
    return final_map

def run_dig_info(domain):
    """
    Roda DIG para pegar CNAME e MX.
    """
    info = []
    try:
        cname = subprocess.run(f"dig +short CNAME {domain}", shell=True, capture_output=True, text=True).stdout.strip()
        if cname: info.append(f"CNAME: {cname}")
            
        mx = subprocess.run(f"dig +short MX {domain}", shell=True, capture_output=True, text=True).stdout.strip()
        if mx:
            first_mx = mx.split('\n')[0].split(' ')[-1] 
            info.append(f"MX: {first_mx}")
    except Exception: return None

    return " | ".join(info) if info else None
        
def send_discord_embed(title, description, fields, color_hex):
    """
    Envia notificação para Discord.
    """
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        print("[NOTIFY ERROR] Variável DISCORD_WEBHOOK_URL não configurada.")
        return

    embed_data = {
        "username": "BugBounty Bot",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [
            {
                "title": title,
                "description": description,
                "color": color_hex,
                "fields": fields,
                "footer": {"text": "🔎 BugBounty Scanner • Automático"},
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }

    try:
        data = json.dumps(embed_data).encode('utf-8')
        req = urllib.request.Request(
            webhook_url, 
            data=data, 
            headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as response:
            print(f"[NOTIFY] Embed enviado! Status: {response.getcode()}")
            
    except Exception as e:
        print(f"[NOTIFY ERROR] Falha ao enviar Embed: {e}")

# --- FERRAMENTAS ADICIONAIS (GAU, CMSEEK, FFUF) ---

def scan_gau(target_domain):
    """
    Busca URLs no WaybackMachine, AlienVault, etc. (Função Standalone).
    Ótimo para achar endpoints de API esquecidos.
    """
    print(f"[SCANNER] Rodando GAU (Archives) em {target_domain}...")
    output_file = f"gau_{uuid.uuid4().hex}.txt"
    
    # --blacklist ignora imagens e fontes para não poluir
    cmd = f"gau {target_domain} --blacklist png,jpg,jpeg,gif,css,svg,woff,woff2 --o {output_file}"
    run_command(cmd, timeout=1800)
    
    urls = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                urls = list(set([line.strip() for line in f if line.strip()]))
            os.remove(output_file)
        except: pass
    
    print(f"[SCANNER] GAU encontrou {len(urls)} URLs históricas.")
    return urls

def scan_cmseek(target_url):
    """
    Detecta qual CMS o site usa lendo o JSON de resultado oficial.
    """
    print(f"[SCANNER] Rodando CMSeeK em {target_url}...")
    
    # 1. Rodar o comando
    # --batch: Executa sem perguntar nada
    cmd = f"python3 /opt/CMSeeK/cmseek.py -u {target_url} --batch --random-agent"
    run_command(cmd, timeout=1800)
    
    # 2. Descobrir o caminho do arquivo JSON gerado
    # Extrair apenas o hostname da URL (ex: https://site.com -> site.com)
    from urllib.parse import urlparse
    
    hostname = ""
    try:
        parsed = urlparse(target_url)
        hostname = parsed.netloc # Pega 'site.com' ou 'site.com:8080'
        if not hostname: 
            # Fallback caso a URL venha sem https://
            hostname = target_url.split('/')[0]
    except:
        hostname = target_url

    # Caminho padrão onde o CMSeeK salva os resultados no Docker
    # O CMSeeK cria uma pasta com o nome do host dentro de Result
    result_file = f"/opt/CMSeeK/Result/{hostname}/cms.json"
    
    # 3. Ler o JSON e extrair o CMS
    if os.path.exists(result_file):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
                
                # O JSON costuma ter a chave 'cms_name'
                cms_name = data.get('cms_name')
                
                # Se achou algo válido (CMSeeK às vezes retorna vazio ou null)
                if cms_name and cms_name.lower() != 'null':
                    version = data.get('cms_version')
                    
                    # Retorna "WordPress 6.0" ou apenas "Joomla"
                    if version and version != '0.0.0':
                        return f"{cms_name} {version}"
                    return cms_name
                    
        except Exception as e:
            print(f"[SCANNER ERROR] Erro lendo JSON do CMSeeK: {e}")
            
    return None

def scan_ffuf(target_url):
    """
    Tenta descobrir diretórios ocultos. Retorna 'raw_path' para salvar no domínio.
    """
    print(f"[SCANNER] Rodando FFuf (Fuzzing) em {target_url}...")
    output_file = f"ffuf_{uuid.uuid4().hex}.json"
    

    cmd = f"ffuf -u {target_url}/FUZZ -w /opt/wordlists/common.txt -mc 200,204,301,302,307,403 -o {output_file} -of json -s -t 50 -ac"
    
    run_command(cmd, timeout=1800) 
    
    found_paths = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
                for res in data.get('results', []):
                    path_found = res.get('input', {}).get('FUZZ')
                    full_url = f"{target_url}/{path_found}"
                    
                    found_paths.append({
                        'host': full_url,
                        'raw_path': f"/{path_found}",
                        'tool': 'FFuf',
                        'severity': 'Info', 
                        'name': 'Directory Discovered',
                        'description': f"Path: /{path_found} | Status: {res.get('status')} | Size: {res.get('length')}"
                    })
            os.remove(output_file)
        except Exception as e:
            print(f"[SCANNER ERROR] Falha lendo FFuf JSON: {e}")
        
    print(f"[SCANNER] FFuf encontrou {len(found_paths)} caminhos.")
    return found_paths