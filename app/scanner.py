import subprocess
import json
import os
import uuid
import csv
import re
import urllib.request
from datetime import datetime
import requests


_SAFE_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')
_SAFE_SCHEME_RE = re.compile(r'^https?://')


def _sanitize_domain(value: str) -> str:
    """Extrai e valida hostname. Lança ValueError se contiver caracteres perigosos."""
    clean = value.strip().replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    if not _SAFE_DOMAIN_RE.match(clean):
        raise ValueError(f"[SECURITY] Domínio com caracteres inválidos bloqueado: {value!r}")
    return clean


def _sanitize_url(value: str) -> str:
    """Valida URL completa (http/https) e retorna inalterada. Lança ValueError se inválida."""
    value = value.strip()
    if not _SAFE_SCHEME_RE.match(value):
        raise ValueError(f"[SECURITY] URL com esquema inválido bloqueada: {value!r}")
    from urllib.parse import urlparse
    host = urlparse(value).netloc.split(':')[0]
    if not _SAFE_DOMAIN_RE.match(host):
        raise ValueError(f"[SECURITY] URL com host inválido bloqueada: {value!r}")
    return value


_redis_client = None


def _get_redis():
    """Retorna conexão Redis (db=1) para cache, ou None se indisponível.

    Cliente é cacheado por processo. Db 0 é o broker Celery.
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


def run_command(command, timeout=None):
    """Executa comando shell e retorna linhas de stdout.

    shell=True é mantido porque os comandos usam pipes/redirects.
    O input passa por _sanitize_domain/_sanitize_url antes — não aceitar
    aqui input não-sanitizado.
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


SUBFINDER_THREADS  = int(os.environ.get('SUBFINDER_THREADS', 100))
AMASS_TIMEOUT      = int(os.environ.get('AMASS_TIMEOUT', 29))   # em MINUTOS (não segundos)
HTTPX_THREADS      = int(os.environ.get('HTTPX_THREADS', 50))
HTTPX_RATE_LIMIT   = int(os.environ.get('HTTPX_RATE_LIMIT', 150))

NAABU_CHUNK_SIZE    = int(os.environ.get('NAABU_CHUNK_SIZE', 500))
NAABU_CHUNK_TIMEOUT = int(os.environ.get('NAABU_CHUNK_TIMEOUT', 600))
NAABU_RATE          = int(os.environ.get('NAABU_RATE', 1000))
NAABU_TOP_PORTS     = int(os.environ.get('NAABU_TOP_PORTS', 100))
NAABU_RETRIES       = int(os.environ.get('NAABU_RETRIES', 1))
NAABU_PKT_TIMEOUT   = int(os.environ.get('NAABU_PKT_TIMEOUT', 5))
NAABU_EXCLUDE_CDN   = os.environ.get('NAABU_EXCLUDE_CDN', 'true').lower() in ('1', 'true', 'yes')

NUCLEI_TAGS        = os.environ.get(
    'NUCLEI_TAGS',
    'cve,misconfig,exposure,tech,panel,xss,sqli,lfi,ssrf,rce,oast,takeover,default-login,fuzzing'
)
NUCLEI_SEVERITY    = os.environ.get('NUCLEI_SEVERITY', 'info,low,medium,high,critical')
NUCLEI_CONCURRENCY = int(os.environ.get('NUCLEI_CONCURRENCY', 50))
NUCLEI_TIMEOUT     = int(os.environ.get('NUCLEI_TIMEOUT', 10))
NUCLEI_RETRIES     = int(os.environ.get('NUCLEI_RETRIES', 2))
NUCLEI_RATE_LIMIT  = int(os.environ.get('NUCLEI_RATE_LIMIT', 150))
INTERACTSH_URL     = os.environ.get('INTERACTSH_URL', '').strip()

KATANA_DEPTH       = int(os.environ.get('KATANA_DEPTH', 3))
KATANA_IGNORE_QUERY = os.environ.get('KATANA_IGNORE_QUERY', 'true').lower() in ('1', 'true', 'yes')

DALFOX_TIMEOUT     = int(os.environ.get('DALFOX_TIMEOUT', 10))
DALFOX_BLIND_URL   = os.environ.get('DALFOX_BLIND_URL', INTERACTSH_URL).strip()

SQLMAP_RISK        = int(os.environ.get('SQLMAP_RISK', 2))
SQLMAP_LEVEL       = int(os.environ.get('SQLMAP_LEVEL', 3))
SQLMAP_THREADS     = int(os.environ.get('SQLMAP_THREADS', 4))
SQLMAP_TECHNIQUE   = os.environ.get('SQLMAP_TECHNIQUE', 'BEU')   # sem 'T' (time-based, lento)
SQLMAP_TAMPER      = os.environ.get('SQLMAP_TAMPER', '').strip()
SQLMAP_DELAY       = float(os.environ.get('SQLMAP_DELAY', 0))    # segundos entre requests
SQLMAP_TIME_SEC    = int(os.environ.get('SQLMAP_TIME_SEC', 10))

FFUF_MAXTIME       = int(os.environ.get('FFUF_MAXTIME', 90))
FFUF_WORDLIST      = os.environ.get('FFUF_WORDLIST', '/opt/wordlists/raft-medium-directories.txt')
FFUF_RECURSION     = int(os.environ.get('FFUF_RECURSION', 1))

GAU_BLACKLIST      = os.environ.get(
    'GAU_BLACKLIST',
    'png,jpg,jpeg,gif,css,svg,woff,woff2,ico,ttf,eot'
)

CMSEEK_MAX_HOSTS   = int(os.environ.get('CMSEEK_MAX_HOSTS', 50))

# Caps de URLs após dedup — sem isso, alvos grandes geram 50k+ URLs e o
# vuln scan estoura o timeout sem produzir resultado útil.
MAX_DALFOX_URLS    = int(os.environ.get('MAX_DALFOX_URLS', 10000))
MAX_SQLMAP_URLS    = int(os.environ.get('MAX_SQLMAP_URLS', 5000))

# Quando true, o Naabu escaneia TODOS os subdomínios — não só os marcados
# alive pelo HTTPX 80/443. Captura hosts respondendo só em portas alternativas
# (admin panels em :8080/:8443) ao custo de 5-10× mais tempo de scan.
NAABU_FULL_SWEEP   = os.environ.get('NAABU_FULL_SWEEP', 'false').lower() in ('1', 'true', 'yes')


def find_subdomains(target_domain):
    """Coleta subdomínios via Subfinder + Amass (passivo).

    Configs de API keys vêm de /root/.config/subfinder/provider-config.yaml
    e /root/.config/amass/config.ini se montadas via docker volume.
    """
    target_domain = _sanitize_domain(target_domain)
    print(f"[SCANNER] Recon Híbrido (Subfinder + Amass) para {target_domain}")

    uid = uuid.uuid4().hex
    file_subfinder = f"raw_subfinder_{uid}.txt"
    file_amass     = f"raw_amass_{uid}.txt"
    subs_set       = set()

    try:
        print("[SCANNER] 1/2 Rodando Subfinder...")
        run_command(f"subfinder -d {target_domain} -silent -t {SUBFINDER_THREADS} -all -o {file_subfinder}", timeout=1800)

        # AMASS_TIMEOUT é em MINUTOS no Amass v4 — confunde quem espera segundos.
        print(f"[SCANNER] 2/2 Rodando Amass (Passive, timeout {AMASS_TIMEOUT}min)...")
        run_command(f"amass enum -passive -d {target_domain} -noalts -timeout {AMASS_TIMEOUT} -o {file_amass}", timeout=1800)

        for filename in [file_subfinder, file_amass]:
            if not os.path.exists(filename):
                continue
            with open(filename, 'r') as f:
                for line in f:
                    cl = line.strip().split(' ')[0]
                    # Amass v4 às vezes anexa IP no formato 'host:1.2.3.4' — extrai o domínio.
                    if ':' in cl:
                        cl = cl.split(':')[0]
                    if not cl: continue
                    if '/' in cl: continue
                    if '*' in cl: continue
                    if cl.isdigit(): continue
                    if '.' not in cl: continue
                    # Match estrito evita falso positivo tipo 'evilalvo.com' para 'alvo.com'.
                    if cl != target_domain and not cl.endswith('.' + target_domain):
                        continue
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


def check_alive(subdomains_list, extra_ports=None):
    """Verifica quais subdomínios respondem via httpx.

    extra_ports: lista de portas além de 80/443 (descobertas pelo Naabu).
    Sem isso, hosts respondendo só em :8080/:8443/etc seriam marcados como dead.
    """
    if not subdomains_list:
        return []

    filename = f"temp_subs_{uuid.uuid4().hex}.txt"
    parsed   = []

    try:
        with open(filename, "w") as f:
            f.write("\n".join(subdomains_list))

        ports_arg = ""
        if extra_ports:
            sanitized = sorted({int(p) for p in extra_ports if str(p).isdigit() and 0 < int(p) < 65536})
            if sanitized:
                ports_arg = f"-ports 80,443,{','.join(str(p) for p in sanitized)}"

        print(f"[SCANNER] HTTPX em {len(subdomains_list)} alvos{' (com portas extras)' if ports_arg else ''}...")
        cmd = (
            f"/usr/local/bin/pd-httpx -l {filename} -json -silent "
            f"-sc -td -probe -ip -fr -tls-grab "
            f"-threads {HTTPX_THREADS} -rate-limit {HTTPX_RATE_LIMIT} "
            f"{ports_arg}"
        )
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


def detect_waf(target_url):
    """Detecta WAF via wafw00f. Retorna nome (ex: 'Cloudflare') ou None.

    Cacheado em Redis por 24h — WAF raramente muda. Usado para ajustar
    flags do vuln scan (rate-limit, tamper, delay).
    """
    try:
        target_url = _sanitize_url(target_url)
    except ValueError:
        return None

    from urllib.parse import urlparse
    host = urlparse(target_url).netloc.split(':')[0]
    cache_key = f"waf:{host}"

    try:
        r = _get_redis()
        if r:
            cached = r.get(cache_key)
            if cached is not None:
                return cached if cached != '__null__' else None
    except Exception:
        pass

    waf_name = None
    try:
        result = subprocess.run(
            f"wafw00f -a {target_url}",
            shell=True, capture_output=True, text=True, timeout=60,
        )
        out = (result.stdout or '') + (result.stderr or '')
        # wafw00f imprime "is behind <NOME>" ou "No WAF detected".
        m = re.search(r'is behind\s+([A-Za-z0-9 .\-_/]+)', out)
        if m:
            waf_name = m.group(1).strip()
    except Exception as e:
        print(f"[WAF] Detecção falhou em {host}: {e}")

    try:
        r = _get_redis()
        if r:
            r.setex(cache_key, 60 * 60 * 24, waf_name if waf_name else '__null__')
    except Exception:
        pass

    if waf_name:
        print(f"[WAF] {host}: {waf_name}")
    return waf_name


def scan_nuclei_bulk(targets_file):
    """Roda Nuclei em lote e retorna lista de findings normalizados."""
    print(f"[SCANNER] Nuclei em lote: {targets_file}")
    output = f"nuclei_res_{uuid.uuid4().hex}.json"

    # -dast é exigido pela tag 'fuzzing'; ativado apenas se a tag estiver presente.
    dast_flag = "-dast" if 'fuzzing' in NUCLEI_TAGS else ""

    # -interactsh-url só funciona com servidor próprio — se não setado,
    # o Nuclei usa o público (rate-limitado) ou desabilita templates OAST.
    interactsh_flag = f"-interactsh-url {INTERACTSH_URL}" if INTERACTSH_URL else ""

    cmd = (
        f"nuclei -l {targets_file} "
        f"-tags {NUCLEI_TAGS} "
        f"-s {NUCLEI_SEVERITY} "
        f"-j -silent -timeout {NUCLEI_TIMEOUT} -c {NUCLEI_CONCURRENCY} "
        f"-retries {NUCLEI_RETRIES} -rl {NUCLEI_RATE_LIMIT} "
        f"{dast_flag} {interactsh_flag} "
        f"-o {output}"
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

                        name = info.get('name') or template_id or 'Nuclei Finding'

                        # Findings sem URL e sem extracted são ruído inacionável.
                        if not matched_at and not extracted:
                            print(f"[SCANNER] Nuclei: descartado finding sem URL — template: {template_id}")
                            continue

                        parts = []
                        parts.append(f"Nome: {name}")

                        if matcher:
                            parts.append(f"Matcher: {matcher}")

                        if template_id:
                            parts.append(f"Template: {template_id}")

                        if matched_at:
                            parts.append(f"URL: {matched_at}")

                        if extracted:
                            parts.append(f"Extraído: {', '.join(str(x) for x in extracted[:5])}")

                        template_desc = info.get('description', '')
                        if template_desc and len(parts) < 5:
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


def _strip_scheme_file(src_file, dst_file):
    """Reescreve src_file removendo 'https://'/'http://' de cada linha (para GAU)."""
    try:
        with open(src_file, 'r') as fin, open(dst_file, 'w') as fout:
            for line in fin:
                clean = line.strip().replace('https://', '').replace('http://', '').split('/')[0]
                if clean:
                    fout.write(clean + '\n')
    except Exception as e:
        print(f"[SCANNER] Falha ao preparar arquivo sem scheme: {e}")


def _dedupe_urls_file(path):
    """Deduplica linhas in-place via sort -u (libera retrabalho em Dalfox/SQLMap)."""
    try:
        run_command(f"sort -u -o {path} {path}", timeout=120)
    except Exception as e:
        print(f"[SCANNER] Dedup falhou em {path}: {e}")


def _cap_urls_file(path, max_lines):
    """Trunca o arquivo para no máximo max_lines linhas (head -n).

    Sem cap, pipelines em alvos grandes geram 50k+ URLs e estouram
    timeout antes de produzir resultado.
    """
    if max_lines <= 0:
        return
    try:
        with open(path, 'r') as f:
            total = sum(1 for _ in f)
        if total <= max_lines:
            return
        capped = path + '.capped'
        run_command(f"head -n {max_lines} {path} > {capped} && mv {capped} {path}", timeout=60)
        print(f"[SCANNER] {path} truncado: {total} → {max_lines} URLs")
    except Exception as e:
        print(f"[SCANNER] Cap falhou em {path}: {e}")


def _host_from_url(url):
    """Extrai hostname (sem scheme/path/porta) de uma URL ou string de host."""
    h = (url or '').replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    return h.lower() if h else ''


def detect_waf_bulk(urls, max_checks=20):
    """Detecta WAF para uma lista de URLs/hosts e retorna dict {host: waf_name|None}.

    Usa o cache 24h do detect_waf por host. Limita a max_checks chamadas
    NOVAS (sem cache) para não explodir o tempo de scan.
    """
    hosts = set()
    for u in urls:
        h = _host_from_url(u)
        if h:
            hosts.add(h)

    result = {}
    new_checks = 0
    r = _get_redis()

    for host in hosts:
        cache_key = f"waf:{host}"
        cached = None
        if r:
            try:
                cached = r.get(cache_key)
            except Exception:
                cached = None

        if cached is not None:
            result[host] = cached if cached != '__null__' else None
            continue

        if new_checks >= max_checks:
            # Não checamos novos — assume None (sem WAF) para hosts não cacheados.
            result[host] = None
            continue

        result[host] = detect_waf(f"https://{host}")
        new_checks += 1

    return result


def scan_crawling_xss_bulk(targets_file):
    """Pipeline Katana + GAU → dedup → Dalfox. Retorna lista de XSS encontrados."""
    print(f"[SCANNER] Katana + GAU → Dalfox: {targets_file}")
    temp_urls   = f"crawl_urls_{uuid.uuid4().hex}.txt"
    gau_hosts   = f"gau_hosts_{uuid.uuid4().hex}.txt"
    output_xss  = f"xss_{uuid.uuid4().hex}.json"
    vulns = []

    try:
        iqp_flag = "-iqp" if KATANA_IGNORE_QUERY else ""
        print("[SCANNER] 1/4 Katana...")
        run_command(
            f"katana -list {targets_file} -d {KATANA_DEPTH} -jc -kf all {iqp_flag} -silent -o {temp_urls}",
            timeout=3600,
        )

        # GAU espera só o domínio, sem 'https://'.
        _strip_scheme_file(targets_file, gau_hosts)

        print("[SCANNER] 2/4 GAU...")
        run_command(
            f"cat {gau_hosts} | gau --blacklist {GAU_BLACKLIST} >> {temp_urls}",
            timeout=1800,
        )

        print("[SCANNER] 3/4 Dedup de URLs...")
        _dedupe_urls_file(temp_urls)
        _cap_urls_file(temp_urls, MAX_DALFOX_URLS)

        if not os.path.exists(temp_urls) or os.path.getsize(temp_urls) == 0:
            print("[SCANNER] Katana+GAU: sem URLs.")
            return []

        with open(temp_urls) as f:
            count = sum(1 for _ in f)
        print(f"[SCANNER] 4/4 Dalfox em {count} URLs...")

        blind_flag = f"--blind {DALFOX_BLIND_URL}" if DALFOX_BLIND_URL else ""
        run_command(
            f"dalfox file {temp_urls} --format json --silence --follow-redirects "
            f"--mining-dom --skip-bav "
            f"--timeout {DALFOX_TIMEOUT} {blind_flag} -o {output_xss}",
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
        for fn in [temp_urls, gau_hosts, output_xss]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except Exception:
                    pass

    print(f"[SCANNER] XSS: {len(vulns)} achados.")
    return vulns


def _parse_sqlmap_csv(path):
    """Lê o results-file do SQLMap, ignorando linhas truncadas/malformadas."""
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, 'r') as f:
            for row in csv.reader(f):
                if len(row) < 6 or "Target URL" in str(row[0]):
                    continue
                try:
                    out.append({
                        'host':        row[0],
                        'tool':        'SQLMap',
                        'severity':    'Critical',
                        'name':        f"SQL Injection ({row[4]})",
                        'description': f"Param: {row[2]} | Payload: {row[5]}",
                    })
                except IndexError:
                    continue
    except Exception as e:
        print(f"[SCANNER] SQLMap CSV inválido: {e}")
    return out


def _run_sqlmap(input_file, label, with_waf_evasion=False):
    """Executa SQLMap em um arquivo de URLs e retorna lista de vulns parseadas."""
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        return []

    results_csv = f"sqlmap_res_{uuid.uuid4().hex}.csv"

    tamper = SQLMAP_TAMPER
    delay  = SQLMAP_DELAY
    if with_waf_evasion and not tamper:
        # Tampers genéricos contra os WAFs mais comuns (CF, Akamai, AWS WAF, Imperva).
        tamper = 'between,randomcase,space2comment'
        delay  = max(delay, 1.0)

    tamper_flag = f"--tamper={tamper}" if tamper else ""
    delay_flag  = f"--delay={delay}"   if delay > 0 else ""

    print(f"[SCANNER] SQLMap [{label}]{' (WAF evasion)' if with_waf_evasion else ''}...")
    run_command(
        f"sqlmap -m {input_file} --batch --random-agent "
        f"--risk={SQLMAP_RISK} --level={SQLMAP_LEVEL} --threads={SQLMAP_THREADS} "
        f"--technique={SQLMAP_TECHNIQUE} --time-sec={SQLMAP_TIME_SEC} "
        f"{tamper_flag} {delay_flag} "
        f"--smart --results-file={results_csv}",
        timeout=7200,
    )

    found = _parse_sqlmap_csv(results_csv)
    if os.path.exists(results_csv):
        try:
            os.remove(results_csv)
        except Exception:
            pass
    return found


def scan_sqlmap_bulk(targets_file, waf=None):
    """Pipeline Katana (qurl) → SQLMap. Retorna SQLi confirmados.

    Faz detect_waf por host (com cache) e executa SQLMap em DOIS batches
    separados: hosts com WAF (tamper/delay) e hosts sem WAF (raw, mais rápido).
    O parâmetro `waf` é mantido por compatibilidade — se setado, força evasão
    em todos os hosts (sobrescreve a detecção per-host).
    """
    print(f"[SCANNER] Katana → SQLMap: {targets_file}")
    params_file       = f"sql_params_{uuid.uuid4().hex}.txt"
    params_waf        = f"sql_params_waf_{uuid.uuid4().hex}.txt"
    params_no_waf     = f"sql_params_clean_{uuid.uuid4().hex}.txt"
    vulns = []

    try:
        iqp_flag = "-iqp" if KATANA_IGNORE_QUERY else ""
        print("[SCANNER] 1/3 Katana (qurl)...")
        run_command(
            f"katana -list {targets_file} -d {KATANA_DEPTH} -kf all {iqp_flag} -silent -f qurl -o {params_file}",
            timeout=3600,
        )

        if not os.path.exists(params_file) or os.path.getsize(params_file) == 0:
            print("[SCANNER] SQLMap: sem parâmetros encontrados.")
            return []

        _dedupe_urls_file(params_file)
        _cap_urls_file(params_file, MAX_SQLMAP_URLS)

        # Sem detect per-host se o caller já informou WAF (modo legado/compatibilidade).
        if waf:
            print(f"[SCANNER] 2/3 Forçando evasão para todos ({waf})...")
            return _run_sqlmap(params_file, "all", with_waf_evasion=True)

        print("[SCANNER] 2/3 Detectando WAF por host...")
        with open(params_file) as f:
            urls = [l.strip() for l in f if l.strip()]
        waf_map = detect_waf_bulk(urls)

        # Separa URLs em dois arquivos baseado no WAF do host.
        with open(params_waf, 'w') as fw, open(params_no_waf, 'w') as fn:
            for u in urls:
                host = _host_from_url(u)
                if waf_map.get(host):
                    fw.write(u + '\n')
                else:
                    fn.write(u + '\n')

        waf_count    = os.path.getsize(params_waf) > 0
        no_waf_count = os.path.getsize(params_no_waf) > 0
        print(f"[SCANNER] 3/3 SQLMap em batches: "
              f"{'com-WAF ' if waf_count else ''}"
              f"{'sem-WAF' if no_waf_count else ''}")

        if waf_count:
            vulns.extend(_run_sqlmap(params_waf, "com-WAF", with_waf_evasion=True))
        if no_waf_count:
            vulns.extend(_run_sqlmap(params_no_waf, "sem-WAF", with_waf_evasion=False))

    except Exception as e:
        print(f"[SCANNER] Pipeline SQLMap falhou: {e}")
    finally:
        for fn in [params_file, params_waf, params_no_waf]:
            if os.path.exists(fn):
                try:
                    os.remove(fn)
                except Exception:
                    pass

    print(f"[SCANNER] SQLMap: {len(vulns)} achados.")
    return vulns


def parse_dalfox_json(data):
    """Converte uma entrada JSON do Dalfox para o formato interno de vuln."""
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


def scan_naabu_bulk(targets_file, chunk_size=None, chunk_timeout=None, rate=None):
    """Roda Naabu em lotes para evitar timeout em projetos com 8000+ hosts.

    Configuração via env:
      NAABU_CHUNK_SIZE    (padrão 500)  — hosts por lote
      NAABU_CHUNK_TIMEOUT (padrão 600)  — timeout por lote (segundos)
      NAABU_RATE          (padrão 1000) — pacotes/s
      NAABU_EXCLUDE_CDN   (padrão true) — pula IPs de CDN (CF/Akamai/etc.)
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

    exclude_cdn_flag = "-exclude-cdn" if NAABU_EXCLUDE_CDN else ""

    port_map = {}

    for idx, chunk in enumerate(chunks, 1):
        chunk_file = f"naabu_chunk_{uuid.uuid4().hex}.txt"
        print(f"[SCANNER] Naabu lote {idx}/{total_chunks} ({len(chunk)} hosts)...")

        try:
            with open(chunk_file, 'w') as f:
                f.write("\n".join(chunk))

            cmd = (
                f"naabu -list {chunk_file} "
                f"-top-ports {NAABU_TOP_PORTS} -rate {rate} -retries {NAABU_RETRIES} -timeout {NAABU_PKT_TIMEOUT} "
                f"{exclude_cdn_flag} "
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


def run_dig_info(domain):
    """Coleta info de DNS (CNAME, MX) via dig. Retorna string formatada ou None."""
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


def send_discord_embed(title, description, fields, color_hex):
    """Envia notificação para o webhook do Discord. No-op se DISCORD_WEBHOOK_URL ausente."""
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


def scan_gau(target_domain):
    """Coleta URLs históricas via GAU (Get All URLs). Espera domínio sem scheme."""
    target_domain = _sanitize_domain(target_domain)
    print(f"[SCANNER] GAU em {target_domain}...")
    output = f"gau_{uuid.uuid4().hex}.txt"
    run_command(
        f"gau {target_domain} --blacklist {GAU_BLACKLIST} --o {output}",
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
    """Detecta CMS via CMSeeK. Retorna 'CMS versao' ou None.

    CMSeeK não tem modo batch — para projetos com muitos hosts (>CMSEEK_MAX_HOSTS)
    a decisão de pular fica em tasks.py.
    """
    try:
        target_url = _sanitize_url(target_url)
    except ValueError as e:
        print(str(e))
        return None

    print(f"[SCANNER] CMSeeK em {target_url}...")
    run_command(
        f"python3 /opt/CMSeeK/cmseek.py -u {target_url} --batch --random-agent",
        timeout=300,   # CMSeeK trava facilmente — corte agressivo.
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


def scan_ffuf(target_url):
    """Roda FFuf para descobrir diretórios. Retorna lista de paths achados."""
    try:
        target_url = _sanitize_url(target_url)
    except ValueError as e:
        print(str(e))
        return []

    # Fallback se a wordlist customizada não existir.
    wordlist = FFUF_WORDLIST if os.path.exists(FFUF_WORDLIST) else '/opt/wordlists/common.txt'

    print(f"[SCANNER] FFuf em {target_url} (max {FFUF_MAXTIME}s, wordlist={os.path.basename(wordlist)})...")
    output = f"ffuf_{uuid.uuid4().hex}.json"
    recursion_flag = f"-recursion -recursion-depth {FFUF_RECURSION}" if FFUF_RECURSION > 0 else ""
    run_command(
        f"ffuf -u {target_url}/FUZZ -w {wordlist} "
        f"-mc 200,204,301,302,307,401,403 -o {output} -of json -s "
        f"-t 40 -ac "
        f"{recursion_flag} "
        f"-timeout 8 "
        f"-maxtime {FFUF_MAXTIME} "
        f"-maxtime-job {FFUF_MAXTIME}",
        timeout=FFUF_MAXTIME + 15,
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


_CRTSH_CACHE_TTL = 60 * 60 * 24 * 30


def get_first_seen_crtsh(subdomain: str):
    """Consulta crt.sh para a data do certificado mais antigo do subdomínio.

    Resultado cacheado no Redis por 30 dias (TTL) — crt.sh rate-limita
    pesado. Retorna 'YYYY-MM-DD' ou None.
    """
    cache_key = f"crtsh:{subdomain}"

    try:
        r = _get_redis()
        if r:
            cached = r.get(cache_key)
            if cached is not None:
                print(f"[CACHE] crt.sh hit: {subdomain}")
                return cached if cached != '__null__' else None
    except Exception as e:
        print(f"[CACHE] Redis get falhou: {e}")

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

    # Cacheia também o resultado None como sentinela '__null__'.
    try:
        r = _get_redis()
        if r:
            r.setex(cache_key, _CRTSH_CACHE_TTL, result if result else '__null__')
    except Exception as e:
        print(f"[CACHE] Redis set falhou: {e}")

    return result
