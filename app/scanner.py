import subprocess
import json
import os
import uuid
import csv
import re
import urllib.request
from datetime import datetime
import requests


# ---------------------------------------------------------------------------
# Sanitização de Input
# ---------------------------------------------------------------------------

_SAFE_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')
_SAFE_SCHEME_RE = re.compile(r'^https?://')


def _sanitize_domain(value: str) -> str:
    clean = value.strip().replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    if not _SAFE_DOMAIN_RE.match(clean):
        raise ValueError(f"[SECURITY] Domínio com caracteres inválidos bloqueado: {value!r}")
    return clean


def _sanitize_url(value: str) -> str:
    value = value.strip()
    if not _SAFE_SCHEME_RE.match(value):
        raise ValueError(f"[SECURITY] URL com esquema inválido bloqueada: {value!r}")
    from urllib.parse import urlparse
    host = urlparse(value).netloc.split(':')[0]
    if not _SAFE_DOMAIN_RE.match(host):
        raise ValueError(f"[SECURITY] URL com host inválido bloqueada: {value!r}")
    return value


# ---------------------------------------------------------------------------
# Redis — cache para chamadas externas lentas
# ---------------------------------------------------------------------------

_redis_client = None


def _get_redis():
    """
    Retorna conexão Redis para cache (db=1, separado do Celery que usa db=0).
    Falha silenciosamente se Redis não estiver disponível.
    """
    global _redis_client
    if _redis_client is None:
        try:
            import redis
            redis_host = os.environ.get('REDIS_HOST', 'redis')
            _redis_client = redis.Redis(
                host=redis_host, port=6379, db=1, decode_responses=True,
                socket_connect_timeout=2, socket_timeout=2,
            )
            _redis_client.ping()
        except Exception as e:
            print(f"[CACHE] Redis indisponível: {e}")
            _redis_client = None
    return _redis_client


# ---------------------------------------------------------------------------
# Execução de comandos externos
# ---------------------------------------------------------------------------

def run_command(command, timeout=None):
    """
    Executa um comando shell e retorna linhas de stdout.

    Nota: shell=True é mantido intencionalmente porque muitos comandos
    do pipeline usam operadores de shell (pipes |, redirecionamentos >>).
    Todos os inputs passam por _sanitize_domain / _sanitize_url antes
    de chegarem aqui.
    """
    try:
        print(f"[CMD] {command}")
        timeout = timeout or 3600
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        if result.stderr and "level=error" in result.stderr:
            print(f"[CMD STDERR] {result.stderr[:300]}")
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"[CMD TIMEOUT] Comando expirou: {command[:120]}")
        return []
    except Exception as e:
        print(f"[CMD ERROR] {e}")
        return []


# ---------------------------------------------------------------------------
# Recon — Subdomínios
# ---------------------------------------------------------------------------

def find_subdomains(target_domain):
    target_domain = _sanitize_domain(target_domain)
    print(f"[SCANNER] Recon Híbrido (Subfinder + Amass) para {target_domain}")

    uid = uuid.uuid4().hex
    file_subfinder = f"raw_subfinder_{uid}.txt"
    file_amass     = f"raw_amass_{uid}.txt"
    subs_set       = set()

    try:
        print("[SCANNER] 1/2 Rodando Subfinder...")
        run_command(f"subfinder -d {target_domain} -silent -t 100 -all -o {file_subfinder}", timeout=1800)

        print("[SCANNER] 2/2 Rodando Amass (Passive)...")
        run_command(f"amass enum -passive -d {target_domain} -noalts -timeout 29 -o {file_amass}", timeout=1800)

        for filename in [file_subfinder, file_amass]:
            if not os.path.exists(filename):
                continue
            with open(filename, 'r') as f:
                for line in f:
                    cl = line.strip().split(' ')[0]
                    if not cl: continue
                    if '/' in cl: continue
                    if '*' in cl: continue
                    if cl.isdigit(): continue
                    if '.' not in cl: continue
                    if ':' in cl: continue
                    if not cl.endswith(target_domain): continue
                    subs_set.add(cl)

    except Exception as e:
        print(f"[SCANNER] Erro no Recon: {e}")
    finally:
        for fn in [file_subfinder, file_amass]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except Exception as e:
                    print(f"[SCANNER] Falha ao remover {fn}: {e}")

    result = list(subs_set)
    print(f"[SCANNER] Recon finalizado: {len(result)} subdomínios.")
    return result


def check_alive(subdomains_list):
    if not subdomains_list:
        return []

    filename = f"temp_subs_{uuid.uuid4().hex}.txt"
    parsed   = []

    try:
        with open(filename, "w") as f:
            f.write("\n".join(subdomains_list))

        print(f"[SCANNER] HTTPX em {len(subdomains_list)} alvos...")
        cmd     = f"/usr/local/bin/pd-httpx -l {filename} -json -silent -sc -td -probe -ip -threads 50"
        results = run_command(cmd, timeout=1800)
        print(f"[SCANNER] HTTPX: {len(results)} respostas.")

        for line in results:
            try:
                data = json.loads(line)
                if data.get('url'):
                    ips = data.get('a', [])
                    parsed.append({
                        'url':    data['url'],
                        'status': data.get('status_code'),
                        'tech':   data.get('tech', []),
                        'ip':     ips[0] if ips else None,
                    })
            except Exception as e:
                print(f"[SCANNER] Linha HTTPX inválida: {e}")
    finally:
        if os.path.exists(filename):
            try:
                os.remove(filename)
            except Exception as e:
                print(f"[SCANNER] Falha ao remover {filename}: {e}")

    return parsed


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

def scan_nuclei_bulk(targets_file):
    print(f"[SCANNER] Nuclei em lote: {targets_file}")
    output = f"nuclei_res_{uuid.uuid4().hex}.json"

    cmd = (
        f"nuclei -l {targets_file} "
        f"-tags cve2023,cve2024,cve2025,cve2026,misconfig,exposure,tech,panel "
        f"-s low,medium,high,critical -j -silent -timeout 2 -c 80 -o {output}"
    )
    run_command(cmd, timeout=7200)

    vulns = []
    if os.path.exists(output):
        try:
            with open(output, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)

                        info        = data.get('info', {})
                        template_id = data.get('template-id', '')
                        matcher     = data.get('matcher-name', '')
                        matched_at  = data.get('matched-at', '')
                        extracted   = data.get('extracted-results', [])

                        # Nome: prefere info.name, cai no template-id como fallback
                        name = info.get('name') or template_id or 'Nuclei Finding'

                        # Descarta findings sem URL e sem dados extraídos —
                        # não têm informação suficiente para ser acionáveis
                        if not matched_at and not extracted:
                            print(f"[SCANNER] Nuclei: descartado finding sem URL — template: {template_id}")
                            continue

                        # Monta descrição com todos os campos disponíveis
                        parts = []

                        if matcher:
                            parts.append(f"Matcher: {matcher}")

                        if template_id:
                            parts.append(f"Template: {template_id}")

                        if matched_at:
                            parts.append(f"URL: {matched_at}")

                        if extracted:
                            parts.append(f"Extraído: {', '.join(str(x) for x in extracted[:5])}")

                        # Descrição do template (ex: "SSL certificate uses weak cipher")
                        template_desc = info.get('description', '')
                        if template_desc and len(parts) < 4:
                            parts.append(f"Detalhe: {template_desc[:200]}")

                        description = ' | '.join(parts)

                        vulns.append({
                            'host':        data.get('host'),
                            'tool':        'Nuclei',
                            'name':        name,
                            'severity':    info.get('severity'),
                            'description': description,
                        })
                    except Exception as e:
                        print(f"[SCANNER] Linha Nuclei inválida: {e}")
        except Exception as e:
            print(f"[SCANNER] Erro ao ler Nuclei output: {e}")
        finally:
            try:
                os.remove(output)
            except Exception:
                pass
    else:
        print("[SCANNER] Nuclei: sem arquivo de saída.")

    print(f"[SCANNER] Nuclei: {len(vulns)} achados.")
    return vulns


# ---------------------------------------------------------------------------
# XSS Pipeline: Katana + GAU → Dalfox
# ---------------------------------------------------------------------------

def scan_crawling_xss_bulk(targets_file):
    print(f"[SCANNER] Katana + GAU → Dalfox: {targets_file}")
    temp_urls = f"crawl_urls_{uuid.uuid4().hex}.txt"
    output_xss = f"xss_{uuid.uuid4().hex}.json"
    vulns = []

    try:
        print("[SCANNER] 1/3 Katana...")
        run_command(f"katana -list {targets_file} -d 2 -jc -silent -o {temp_urls}", timeout=3600)

        print("[SCANNER] 2/3 GAU...")
        run_command(
            f"cat {targets_file} | gau --blacklist png,jpg,jpeg,gif,css,svg,woff,woff2 >> {temp_urls}",
            timeout=1800,
        )

        if not os.path.exists(temp_urls) or os.path.getsize(temp_urls) == 0:
            print("[SCANNER] Katana+GAU: sem URLs.")
            return []

        with open(temp_urls) as f:
            count = sum(1 for _ in f)
        print(f"[SCANNER] 3/3 Dalfox em {count} URLs...")
        run_command(
            f"dalfox file {temp_urls} --format json --silence --skip-bav -o {output_xss}",
            timeout=3600,
        )

        if os.path.exists(output_xss):
            try:
                with open(output_xss, 'r') as f:
                    content = f.read()
                if content.strip() == "[{}]":
                    return []
                if content.strip().startswith('['):
                    for data in json.loads(content):
                        p = parse_dalfox_json(data)
                        if p['host']:
                            vulns.append(p)
                else:
                    for line in content.splitlines():
                        if not line.strip():
                            continue
                        try:
                            p = parse_dalfox_json(json.loads(line))
                            if p['host']:
                                vulns.append(p)
                        except Exception as e:
                            print(f"[SCANNER] Dalfox linha inválida: {e}")
            except Exception as e:
                print(f"[SCANNER] Dalfox output inválido: {e}")

    except Exception as e:
        print(f"[SCANNER] Pipeline XSS falhou: {e}")
    finally:
        for fn in [temp_urls, output_xss]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except Exception:
                    pass

    print(f"[SCANNER] XSS: {len(vulns)} achados.")
    return vulns


# ---------------------------------------------------------------------------
# SQLMap Pipeline
# ---------------------------------------------------------------------------

def scan_sqlmap_bulk(targets_file):
    print(f"[SCANNER] Katana → SQLMap: {targets_file}")
    params_file  = f"sql_params_{uuid.uuid4().hex}.txt"
    results_csv  = f"sqlmap_res_{uuid.uuid4().hex}.csv"
    vulns = []

    try:
        print("[SCANNER] 1/2 Katana (qurl)...")
        run_command(
            f"katana -list {targets_file} -d 2 -silent -f qurl -o {params_file}",
            timeout=3600,
        )

        if not os.path.exists(params_file) or os.path.getsize(params_file) == 0:
            print("[SCANNER] SQLMap: sem parâmetros encontrados.")
            return []

        print("[SCANNER] 2/2 SQLMap...")
        run_command(
            f"sqlmap -m {params_file} --batch --random-agent --risk=1 --level=1 "
            f"--smart --results-file={results_csv}",
            timeout=7200,
        )

        if os.path.exists(results_csv):
            try:
                with open(results_csv, 'r') as f:
                    for row in csv.reader(f):
                        if len(row) >= 6 and "Target URL" not in str(row[0]):
                            vulns.append({
                                'host':        row[0],
                                'tool':        'SQLMap',
                                'severity':    'Critical',
                                'name':        f"SQL Injection ({row[4]})",
                                'description': f"Param: {row[2]} | Payload: {row[5]}",
                            })
            except Exception as e:
                print(f"[SCANNER] SQLMap CSV inválido: {e}")
        else:
            print("[SCANNER] SQLMap: sem vulnerabilidades confirmadas.")

    except Exception as e:
        print(f"[SCANNER] Pipeline SQLMap falhou: {e}")
    finally:
        for fn in [params_file, results_csv]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except Exception:
                    pass

    print(f"[SCANNER] SQLMap: {len(vulns)} achados.")
    return vulns


def parse_dalfox_json(data):
    host    = data.get('url') or data.get('target') or data.get('poc') or ""
    payload = data.get('payload') or "Payload genérico"
    param   = data.get('param') or "Parâmetro desconhecido"
    sev     = data.get('severity', 'High')
    if isinstance(sev, str):
        sev = sev.capitalize()
    return {
        'host':        host,
        'tool':        'Dalfox',
        'severity':    sev,
        'name':        f"Cross-Site Scripting ({data.get('type', 'XSS')})",
        'description': f"Payload: {payload} em {param}",
    }


# ---------------------------------------------------------------------------
# Naabu — Port Scan com Chunking
# ---------------------------------------------------------------------------

NAABU_CHUNK_SIZE    = int(os.environ.get('NAABU_CHUNK_SIZE', 500))
NAABU_CHUNK_TIMEOUT = int(os.environ.get('NAABU_CHUNK_TIMEOUT', 600))
NAABU_RATE          = int(os.environ.get('NAABU_RATE', 1000))


def scan_naabu_bulk(targets_file, chunk_size=None, chunk_timeout=None, rate=None):
    """
    Roda Naabu em lotes (chunks) para evitar timeout em projetos com 8000+ hosts.

    Configuração via .env:
      NAABU_CHUNK_SIZE    (padrão 500)  — hosts por lote
      NAABU_CHUNK_TIMEOUT (padrão 600)  — segundos de timeout por lote
      NAABU_RATE          (padrão 1000) — pacotes/s
    """
    chunk_size    = chunk_size    or NAABU_CHUNK_SIZE
    chunk_timeout = chunk_timeout or NAABU_CHUNK_TIMEOUT
    rate          = rate          or NAABU_RATE

    try:
        with open(targets_file, 'r') as f:
            all_hosts = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"[SCANNER] Naabu: falha ao ler alvos: {e}")
        return {}

    if not all_hosts:
        return {}

    chunks       = [all_hosts[i:i + chunk_size] for i in range(0, len(all_hosts), chunk_size)]
    total_chunks = len(chunks)
    print(f"[SCANNER] Naabu: {len(all_hosts)} hosts em {total_chunks} lotes de {chunk_size}.")

    port_map = {}

    for idx, chunk in enumerate(chunks, 1):
        chunk_file = f"naabu_chunk_{uuid.uuid4().hex}.txt"
        print(f"[SCANNER] Naabu lote {idx}/{total_chunks} ({len(chunk)} hosts)...")

        try:
            with open(chunk_file, 'w') as f:
                f.write("\n".join(chunk))

            cmd = (
                f"naabu -list {chunk_file} "
                f"-top-ports 100 -rate {rate} -retries 1 -timeout 5 "
                f"-json -silent"
            )
            results = run_command(cmd, timeout=chunk_timeout)

            chunk_ports = 0
            for line in results:
                try:
                    data = json.loads(line)
                    host = data.get('host') or data.get('ip')
                    port = data.get('port')
                    if host and port:
                        port_map.setdefault(host, []).append(str(port))
                        chunk_ports += 1
                except Exception as e:
                    print(f"[SCANNER] Naabu linha inválida: {e}")

            print(f"[SCANNER] Lote {idx}/{total_chunks}: {chunk_ports} portas.")

        except Exception as e:
            print(f"[SCANNER] Lote {idx}/{total_chunks} falhou: {e}")
        finally:
            if os.path.exists(chunk_file):
                try:
                    os.remove(chunk_file)
                except Exception:
                    pass

    final_map = {host: ", ".join(ports) for host, ports in port_map.items()}
    print(f"[SCANNER] Naabu finalizado: {len(final_map)} hosts com portas abertas.")
    return final_map


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def run_dig_info(domain):
    try:
        domain = _sanitize_domain(domain)
    except ValueError as e:
        print(str(e))
        return None
    info = []
    try:
        cname = subprocess.run(
            f"dig +short CNAME {domain}", shell=True, capture_output=True, text=True
        ).stdout.strip()
        if cname:
            info.append(f"CNAME: {cname}")

        mx = subprocess.run(
            f"dig +short MX {domain}", shell=True, capture_output=True, text=True
        ).stdout.strip()
        if mx:
            info.append(f"MX: {mx.split(chr(10))[0].split(' ')[-1]}")
    except Exception as e:
        print(f"[SCANNER] DIG falhou em {domain}: {e}")
        return None

    return " | ".join(info) if info else None


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------

def send_discord_embed(title, description, fields, color_hex):
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
    if not webhook_url:
        print("[NOTIFY] DISCORD_WEBHOOK_URL não configurada.")
        return

    payload = {
        "username": "BugBounty Bot",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [{
            "title":       title,
            "description": description,
            "color":       color_hex,
            "fields":      fields,
            "footer":      {"text": "🔎 BugBounty Scanner • Automático"},
            "timestamp":   datetime.utcnow().isoformat(),
        }],
    }
    try:
        data = json.dumps(payload).encode('utf-8')
        req  = urllib.request.Request(
            webhook_url, data=data,
            headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'},
        )
        with urllib.request.urlopen(req) as resp:
            print(f"[NOTIFY] Discord: {resp.getcode()}")
    except Exception as e:
        print(f"[NOTIFY] Falha no Discord: {e}")


# ---------------------------------------------------------------------------
# GAU, CMSeeK, FFuf
# ---------------------------------------------------------------------------

def scan_gau(target_domain):
    print(f"[SCANNER] GAU em {target_domain}...")
    output = f"gau_{uuid.uuid4().hex}.txt"
    run_command(
        f"gau {target_domain} --blacklist png,jpg,jpeg,gif,css,svg,woff,woff2 --o {output}",
        timeout=1800,
    )
    urls = []
    if os.path.exists(output):
        try:
            with open(output, 'r') as f:
                urls = list(set(l.strip() for l in f if l.strip()))
        except Exception as e:
            print(f"[SCANNER] GAU output inválido: {e}")
        finally:
            try:
                os.remove(output)
            except Exception:
                pass
    print(f"[SCANNER] GAU: {len(urls)} URLs.")
    return urls


def scan_cmseek(target_url):
    try:
        target_url = _sanitize_url(target_url)
    except ValueError as e:
        print(str(e))
        return None

    print(f"[SCANNER] CMSeeK em {target_url}...")
    run_command(
        f"python3 /opt/CMSeeK/cmseek.py -u {target_url} --batch --random-agent",
        timeout=1800,
    )

    from urllib.parse import urlparse
    try:
        hostname = urlparse(target_url).netloc or target_url.split('/')[0]
    except Exception:
        hostname = target_url

    result_file = f"/opt/CMSeeK/Result/{hostname}/cms.json"
    if os.path.exists(result_file):
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
            cms = data.get('cms_name')
            if cms and cms.lower() != 'null':
                ver = data.get('cms_version')
                return f"{cms} {ver}" if ver and ver != '0.0.0' else cms
        except Exception as e:
            print(f"[SCANNER] CMSeeK JSON inválido: {e}")
    return None


# Tempo máximo por scan FFuf — configurável via .env
FFUF_MAXTIME = int(os.environ.get('FFUF_MAXTIME', 90))   # segundos por host


def scan_ffuf(target_url):
    try:
        target_url = _sanitize_url(target_url)
    except ValueError as e:
        print(str(e))
        return []

    print(f"[SCANNER] FFuf em {target_url} (max {FFUF_MAXTIME}s)...")
    output = f"ffuf_{uuid.uuid4().hex}.json"
    run_command(
        f"ffuf -u {target_url}/FUZZ -w /opt/wordlists/common.txt "
        f"-mc 200,204,301,302,307,403 -o {output} -of json -s "
        f"-t 40 -ac "
        f"-timeout 8 "           # timeout de conexão por requisição (segundos)
        f"-maxtime {FFUF_MAXTIME} "   # para o scan inteiro após N segundos
        f"-maxtime-job {FFUF_MAXTIME}",  # para cada job individual
        timeout=FFUF_MAXTIME + 15,   # processo tem +15s de margem antes do SIGKILL
    )

    paths = []
    if os.path.exists(output):
        try:
            with open(output, 'r') as f:
                data = json.load(f)
            for res in data.get('results', []):
                path = res.get('input', {}).get('FUZZ')
                paths.append({
                    'host':        f"{target_url}/{path}",
                    'raw_path':    f"/{path}",
                    'tool':        'FFuf',
                    'severity':    'Info',
                    'name':        'Directory Discovered',
                    'description': f"Path: /{path} | Status: {res.get('status')} | Size: {res.get('length')}",
                })
        except Exception as e:
            print(f"[SCANNER] FFuf output inválido: {e}")
        finally:
            try:
                os.remove(output)
            except Exception:
                pass

    print(f"[SCANNER] FFuf: {len(paths)} caminhos.")
    return paths


# ---------------------------------------------------------------------------
# crt.sh — com cache Redis (30 dias)
# ---------------------------------------------------------------------------

_CRTSH_CACHE_TTL = 60 * 60 * 24 * 30  # 30 dias


def get_first_seen_crtsh(subdomain: str):
    """
    Consulta crt.sh para data do certificado mais antigo.
    Resultado cacheado no Redis por 30 dias para evitar rate limiting.
    Retorna string 'YYYY-MM-DD' ou None.
    """
    cache_key = f"crtsh:{subdomain}"

    # Tenta cache
    try:
        r = _get_redis()
        if r:
            cached = r.get(cache_key)
            if cached is not None:
                print(f"[CACHE] crt.sh hit: {subdomain}")
                return cached if cached != '__null__' else None
    except Exception as e:
        print(f"[CACHE] Redis get falhou: {e}")

    # Consulta real
    result = None
    print(f"[SCANNER] crt.sh para {subdomain}...")
    try:
        url = f"https://crt.sh/?q={subdomain}&output=json"
        r_http = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
        if r_http.status_code == 200 and r_http.content:
            dates = sorted(entry['not_before'] for entry in r_http.json())
            if dates:
                result = dates[0].split('T')[0]
                print(f"[SCANNER] crt.sh {subdomain}: {result}")
    except Exception as e:
        print(f"[SCANNER] crt.sh falhou em {subdomain}: {e}")

    # Salva no cache (incluindo resultado None como sentinela)
    try:
        r = _get_redis()
        if r:
            r.setex(cache_key, _CRTSH_CACHE_TTL, result if result else '__null__')
    except Exception as e:
        print(f"[CACHE] Redis set falhou: {e}")

    return result