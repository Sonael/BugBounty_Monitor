FROM python:3.9-slim

WORKDIR /app

# Dependências de sistema
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    dnsutils \
    libpq-dev \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Ferramentas de Segurança (binários Go) ────────────────────────────────

# Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -o subfinder_2.6.3_linux_amd64.zip && mv subfinder /usr/local/bin/ && rm subfinder_2.6.3_linux_amd64.zip

# HTTPX (renomeado para pd-httpx para evitar conflito com httpx Python)
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip \
    && unzip -o httpx_1.3.7_linux_amd64.zip \
    && mv httpx /usr/local/bin/pd-httpx \
    && rm httpx_1.3.7_linux_amd64.zip

# Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip -o nuclei_3.1.0_linux_amd64.zip && mv nuclei /usr/local/bin/ && rm nuclei_3.1.0_linux_amd64.zip

# Katana
RUN wget -q https://github.com/projectdiscovery/katana/releases/download/v1.0.4/katana_1.0.4_linux_amd64.zip \
    && unzip -o katana_1.0.4_linux_amd64.zip && mv katana /usr/local/bin/ && rm katana_1.0.4_linux_amd64.zip

# Dalfox (XSS)
RUN wget -q https://github.com/hahwul/dalfox/releases/download/v2.9.1/dalfox_2.9.1_linux_amd64.tar.gz \
    && tar -xvf dalfox_2.9.1_linux_amd64.tar.gz \
    && mv dalfox /usr/local/bin/ \
    && rm dalfox_2.9.1_linux_amd64.tar.gz

# Naabu (Port Scan)
RUN wget -q https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    && unzip -o naabu_2.3.1_linux_amd64.zip \
    && mv naabu /usr/local/bin/ \
    && chmod +x /usr/local/bin/naabu \
    && rm naabu_2.3.1_linux_amd64.zip

# DNSX
RUN wget -q https://github.com/projectdiscovery/dnsx/releases/download/v1.1.6/dnsx_1.1.6_linux_amd64.zip \
    && unzip -o dnsx_1.1.6_linux_amd64.zip && mv dnsx /usr/local/bin/ && rm dnsx_1.1.6_linux_amd64.zip

# SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Amass
RUN curl -L -o amass.zip https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux_amd64.zip \
    && unzip amass.zip \
    && mv amass_Linux_amd64/amass /usr/local/bin/amass \
    && rm -rf amass*

# GAU (Get All Urls)
RUN wget -q https://github.com/lc/gau/releases/download/v2.2.1/gau_2.2.1_linux_amd64.tar.gz \
    && tar -xvf gau_2.2.1_linux_amd64.tar.gz \
    && mv gau /usr/local/bin/gau \
    && rm gau_2.2.1_linux_amd64.tar.gz

# FFUF (Fuzzing)
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xvf ffuf_2.1.0_linux_amd64.tar.gz \
    && mv ffuf /usr/local/bin/ffuf \
    && rm ffuf_2.1.0_linux_amd64.tar.gz

# CMSeeK
RUN git clone https://github.com/Tuhinshubhra/CMSeeK /opt/CMSeeK \
    && cd /opt/CMSeeK \
    && pip install -r requirements.txt

# Wordlist para FFuf
RUN mkdir -p /opt/wordlists \
    && wget -q -O /opt/wordlists/common.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# ── Dependências Python ───────────────────────────────────────────────────

COPY requirements.txt .

# Pacotes originais + novos adicionados nesta versão:
#   gunicorn        — servidor WSGI de produção (substituiu flask run)
#   flask-migrate   — migrações de banco via Alembic (#6 da lista)
#   flask-limiter   — rate limiting para proteção brute-force (#1)
#   flask-wtf       — CSRF protection (#4)
#   redis           — cliente Python para cache crt.sh (#13)
RUN pip install --no-cache-dir -r requirements.txt arjun \
    && pip install --no-cache-dir \
       gunicorn==21.2.0 \
       Flask-Migrate==4.0.5 \
       Flask-Limiter==3.5.0 \
       Flask-WTF==1.2.1 \
       redis==5.0.1

COPY . .

# Atualiza templates do Nuclei no build (evita download em runtime)
RUN nuclei -update-templates || true

ENV FLASK_APP=app/__init__.py
ENV PYTHONUNBUFFERED=1

# Pasta para o schedule persistente do Celery Beat
RUN mkdir -p /var/celerybeat