# BugBounty Monitor

> **Orquestrador de Segurança Ofensiva Automatizado**
>
> Uma plataforma robusta para gestão de reconhecimento (Recon) e análise de vulnerabilidades em escala, construída com arquitetura de microsserviços.

![Python](https://img.shields.io/badge/Python-3.9-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web-lightgrey?style=for-the-badge&logo=flask)
![Celery](https://img.shields.io/badge/Celery-Task_Queue-37814A?style=for-the-badge&logo=celery)
![Redis](https://img.shields.io/badge/Redis-Broker-DC382D?style=for-the-badge&logo=redis)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)
![Postgres](https://img.shields.io/badge/PostgreSQL-Database-336791?style=for-the-badge&logo=postgresql)
![License](https://img.shields.io/badge/License-GPLv3-red?style=for-the-badge)

---

## Arquitetura do Sistema

O projeto utiliza uma arquitetura assíncrona para garantir que scans pesados não travem a interface do usuário.

```mermaid
graph TD
 User([Usuário]) -->|HTTP Request| Web[Flask/Gunicorn]
 Web -->|Leitura/Escrita| DB[(PostgreSQL)]
 Web -->|Enfileira Task| Redis[(Redis Broker)]

 subgraph "Worker Nodes (Escalável)"
 Worker[Celery Worker]
 end

 Redis -->|Consome Task| Worker
 Worker -->|Salva Resultados| DB

 subgraph "Security Tools Engine"
 Worker -->|Executa| Subfinder[Subfinder/Amass]
 Worker -->|Executa| HTTPX[HTTPX — Live Check]
 Worker -->|Executa| Naabu[Naabu — Port Scan]
 Worker -->|Executa| Nuclei[Nuclei]
 Worker -->|Executa| Dalfox[Dalfox — XSS]
 Worker -->|Executa| SQLMap[SQLMap]
 end

 Worker -->|Notificação em Tempo Real| Discord[Discord Webhook]
```

---

## Funcionalidades Principais

### Reconhecimento (Recon) Flexível

- **Modos de Operação:**
 - **`Baseline`** — Coleta subdomínios sem executar scan de vulnerabilidades.
 - **`Recon`** — Subfinder + Amass → HTTPX (live check) → Naabu (port scan nos hosts vivos).
 - **`Scan Vulns`** — Nuclei + Dalfox (XSS) + SQLMap nos alvos pendentes.
 - **`Full`** — Recon + Vuln Scan completo em sequência.
- **Live Check First:** O HTTPX roda **antes** do Naabu, que recebe apenas os hosts confirmados vivos — reduzindo em 10–40× o número de alvos do port scan.
- **Port Scan em Chunks:** O Naabu processa até 500 hosts por lote com timeout independente, evitando falhas em projetos com 8.000+ subdomínios. Configurável via `.env`.
- **Enriquecimento:** DNS (CNAME, MX), IPs e data de certificado SSL via `crt.sh` com **cache Redis de 30 dias**.

### Vulnerability Scanning

- **Engine de Templates:** Nuclei (CVEs, Misconfigurations, Exposures).
- **Pipeline XSS:** `Katana` + `GAU` → `Dalfox`.
- **SQL Injection:** `Katana (qurl)` → `SQLMap`.
- **Smart Fuzzing:** `FFuf` (diretórios) + `CMSeeK` (CMS), configurável por projeto.
- **Apresentação de Resultados:** Cards por vulnerabilidade com parsing inteligente da saída das ferramentas — Nuclei exibe `Matcher` e URL clicável, SQLMap exibe parâmetro e payload, Dalfox exibe o payload XSS. Fallback `<pre>` para qualquer formato desconhecido.

### Controle de Scans

- **Fila Global com Concorrência Limitada:** Ao clicar em "Iniciar Scan Global", no máximo **2 projetos rodam ao mesmo tempo**. Os demais aguardam em fila e são despachados automaticamente conforme os slots abrem.
- **`dispatch_next_pending()`:** Ao finalizar (sucesso, erro ou parada manual), o próximo projeto pendente é despachado automaticamente. Protegido por **mutex Redis** (`SET NX EX`) para evitar que dois workers despachem simultaneamente e ultrapassem o limite de concorrência.
- **Stop Individual e Global:** Para um projeto ou todos de uma vez, limpando a fila do Redis.

### Interface & Gestão

- **Dashboard Interativo:** Aba "Visão Geral" com 5 cards: Superfície de Ataque (distribuição HTTP), Vulnerabilidades (barras de severidade), Projetos em Risco (ranking), Atividade Recente (tabela com status), Cobertura por Projeto (barra de progresso). Polling adaptativo: 4s quando rodando, 120s quando parado.
- **Cards de Projeto:** Barra de cobertura de scan (hosts verificados/vivos), data do último scan com alerta de desatualização (3d amarelo, 7d vermelho), 4 botões de scan rápido (Baseline, Recon, Vulns, Full) diretamente no card, urgência proporcional no alerta de pendentes, distinção visual de estado por borda colorida.
- **Lista de Subdomínios:** Filtros rápidos pill (Todos, 2xx, 3xx, 4xx, Sem Status), ordenação clicável por coluna (nome, status, data), colunas Status e Portas separadas, badge de vulnerabilidades por domínio, badge Verificado/Pendente por linha, contador de resultados.
- **Vulnerabilidades:** Cards por vulnerabilidade com parsing inteligente da saída das ferramentas — Nuclei exibe Matcher e URL clicável, SQLMap exibe parâmetro e payload, Dalfox exibe o payload XSS. Summary bar com contagem por severidade no topo.
- **Exportação:** Download dos dados de cada projeto em **JSON** ou **CSV** diretamente pelo browser.
- **Histórico de Scans:** Aba por projeto com métricas de cada execução: modo, status, duração, novos domínios, hosts vivos e novas vulnerabilidades.
- **Busca Avançada com Paginação:** Filtros no estilo Discord + navegação entre páginas (cap de 500 por request).
- **Marcar como Verificado:** Botão para limpar manualmente o alerta de "alvos pendentes" em um projeto.

### Diferenciais de Engenharia

- **Gunicorn em Produção:** Substitui `flask run --debug` — mais estável, multi-worker.
- **Flask-Migrate:** Schema versionado via Alembic. Migrations aplicadas automaticamente no boot.
- **Rate Limiting no Login:** Máximo de 5 tentativas por minuto por IP (Flask-Limiter + Redis).
- **CSRF Protection:** Flask-WTF instalado e configurado.
- **Race Condition Corrigida:** `celery_uuid()` pré-gerado e salvo no banco **antes** do `apply_async`, garantindo que o worker sempre encontre o `task_id` correto.
- **Mutex Redis no Dispatcher:** `dispatch_next_pending()` usa `SET NX EX` do Redis para serializar o despacho entre workers paralelos — impede que dois `ForkPoolWorker` despachem simultaneamente e ultrapassem o limite de concorrência. TTL de 15s evita deadlock permanente.
- **FFuf com Timeout por Host:** Flags `-timeout`, `-maxtime` e `-maxtime-job` limitam o FFuf a no máximo `FFUF_MAXTIME` segundos por host (padrão: 90s), evitando travamentos em servidores lentos.
- **Worker Init Signal:** O Flask app é inicializado **uma única vez** por processo worker via `@worker_init.connect`, não a cada task.
- **Task Auto-Healing:** Detecta automaticamente scans "zumbis" e corrige o status sem intervenção humana.
- **Reset no Startup:** Projetos com status `Rodando` ou `Na fila` de um boot anterior são resetados para `Parado` automaticamente.
- **Healthchecks Docker:** Todos os serviços (`db`, `redis`, `web`, `worker`) têm healthchecks configurados com `depends_on: condition: service_healthy`.
- **Tabelas Normalizadas:** `scan_history` (histórico de scans) e `port` (portas por domínio com `UniqueConstraint`) com índices compostos para queries rápidas.
- **Sem N+1 Queries:** Todas as rotas que exibem contadores usam `COUNT`/`SUM(CASE...)` SQL em vez de iterar relações SQLAlchemy em Python.

---

## Estrutura do Projeto

```text
BugBounty_Monitor/
├── app/
│ ├── static/ # Arquivos CSS/JS
│ ├── templates/
│ │ ├── partials/ # Fragmentos HTMX (controls, vulns, domains, etc.)
│ │ ├── base.html
│ │ ├── dashboard.html
│ │ ├── login.html
│ │ └── project.html
│ ├── models.py # Schema (User, Project, Domain, Port, Vulnerability, ScanHistory)
│ ├── routes.py # Endpoints Flask + lógica de despacho de tasks
│ ├── scanner.py # Wrappers para ferramentas CLI (subfinder, httpx, naabu, nuclei…)
│ ├── services.py # Camada de serviços — queries SQL centralizadas
│ ├── tasks.py # Workers Celery (run_scan_task, run_daily_scan, dispatch_next_pending)
│ └── __init__.py # Factory da aplicação, Flask-Migrate, Limiter, CSRF
├── migrations/ # Alembic migrations (versionadas no git)
├── docker-compose.yml # web + worker + beat + db + redis
├── Dockerfile # Imagem com todas as ferramentas Go instaladas
├── requirements.txt # Dependências Python
├── .env.example # Template de configuração
```

---

## Instalação e Configuração

### Pré-requisitos

- [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clonar o Repositório

```bash
git clone https://github.com/Sonael/BugBounty_Monitor.git
cd BugBounty_Monitor
```

### 2. Configurar Variáveis de Ambiente

```bash
cp .env.example .env
# Edite o .env com suas credenciais
```

**Referência completa de variáveis (`.env`):**

| Variável | Obrigatória | Descrição | Exemplo |
|---|:---:|---|---|
| `POSTGRES_USER` | | Usuário do banco | `user` |
| `POSTGRES_PASSWORD` | | Senha do banco | `senha_forte` |
| `POSTGRES_DB` | | Nome do banco | `bugbounty` |
| `DATABASE_URL` | | String de conexão SQLAlchemy | `postgresql://user:senha@db:5432/bugbounty` |
| `CELERY_BROKER_URL` | | Redis para fila de tasks (db=0) | `redis://redis:6379/0` |
| `REDIS_HOST` | — | Host Redis para cache Python (db=1) | `redis` |
| `SECRET_KEY` | | Chave de sessão Flask (64 chars hex) | `openssl rand -hex 32` |
| `ADMIN_USER` | — | Username do admin (padrão: `admin`) | `admin` |
| `ADMIN_PASSWORD` | | Senha do admin — **sem fallback hardcoded** | `senha_muito_forte` |
| `DISCORD_WEBHOOK_URL` | — | Webhook para alertas em tempo real | `https://discord.com/api/webhooks/...` |
| `NAABU_CHUNK_SIZE` | — | Hosts por lote no Naabu (padrão: 500) | `500` |
| `NAABU_CHUNK_TIMEOUT` | — | Timeout por lote em segundos (padrão: 600) | `600` |
| `NAABU_RATE` | — | Pacotes/s do Naabu (padrão: 1000) | `1000` |
| `FFUF_MAXTIME` | — | Tempo máximo por host no FFuf em segundos (padrão: 90) | `90` |

> Se `SECRET_KEY` ou `ADMIN_PASSWORD` não estiverem definidas, a aplicação **recusa iniciar**.

### 3. Inicializar o Banco (primeira vez)

```bash
# Sobe apenas o banco
docker compose up -d db
sleep 15

# Cria as tabelas via Flask-Migrate
docker compose run --rm web bash -c "
 flask db init &&
 flask db migrate -m 'initial schema' &&
 flask db upgrade
"

# Commita a pasta de migrations
git add migrations/ && git commit -m "chore: add Flask-Migrate initial schema"
```

### 4. Subir todos os serviços

```bash
docker compose up -d
```

> O build pode demorar alguns minutos na primeira vez — o Docker instala ferramentas Go (Nuclei, Naabu, Subfinder, etc.) e atualiza os templates do Nuclei.

### 5. Acessar

Abra o navegador em: **http://localhost:5000**

Login com as credenciais definidas em `ADMIN_USER` / `ADMIN_PASSWORD`.

---

## Banco de Dados

### Tabelas

| Tabela | Descrição |
|---|---|
| `user` | Usuários da plataforma |
| `project` | Projetos de bug bounty |
| `domain` | Subdomínios descobertos (com índices compostos) |
| `port` | Portas abertas por domínio (normalizada, `UNIQUE domain_id + port_number`) |
| `vulnerability` | Vulnerabilidades encontradas |
| `scan_history` | Registro de cada execução de scan com métricas |
| `system_state` | Estado do agendador (controle do scan diário) |

### Migrations

```bash
# Após alterar models.py
docker compose run --rm web flask db migrate -m "descrição da mudança"
docker compose run --rm web flask db upgrade
git add migrations/ && git commit -m "chore: migration ..."
```

---

## API Endpoints

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/project/<id>/export/json` | Exporta todos os dados do projeto em JSON |
| `GET` | `/project/<id>/export/csv` | Exporta todos os dados do projeto em CSV |
| `GET` | `/api/project/<id>/history` | Retorna histórico de scans (últimos 30) |
| `POST` | `/project/<id>/mark_scanned` | Marca todos os domínios como verificados |
| `GET` | `/api/csrf-token` | Retorna token CSRF para requisições AJAX |
| `POST` | `/project/<id>/scan/<mode>` | Inicia scan (`baseline`, `recon`, `vuln`, `full`) |
| `POST` | `/project/<id>/scan_card/<mode>` | Inicia scan pelo card do dashboard e retorna o card atualizado |
| `POST` | `/scan/global/start` | Inicia scan em todos os projetos (máx 2 simultâneos) |
| `POST` | `/scan/global/stop` | Para todos os scans e limpa a fila |

---

## Guia de Filtros Avançados

A busca de subdomínios usa uma sintaxe no estilo Discord que suporta lógica AND/OR.

### Lógica

| Separador | Comportamento | Exemplo |
|---|---|---|
| **Espaço** entre blocos | **AND** — todos os blocos devem ser satisfeitos | `tech:nginx status:200` |
| **Vírgula** em `status:` e `subdominio:` | **OR** — qualquer valor | `status:200,403` |
| **Vírgula** em `tech:`, `portas:`, `path:` | **AND** — todos os valores obrigatórios | `tech:PHP,Laravel` |

### Filtros Disponíveis

| Chave | Lógica da vírgula | Exemplo |
|---|---|---|
| `status:` | OR | `status:200,403` |
| `subdominio:` | OR | `subdominio:api,dev` |
| `tech:` | AND | `tech:PHP,Laravel` |
| `portas:` | AND | `portas:80,443` |
| `path:` | AND | `path:/.git,/admin` |
| `date:` | intervalo | `date:2024-01-01 to 2024-03-31` |
| `ssl:` | intervalo | `ssl:2023-01-01 to 2023-12-31` |

### Exemplos de Combinação

```text
# Painéis admin vivos com WordPress
subdominio:admin status:200 tech:WordPress

# Servidores Nginx com possível vazamento de Git
tech:nginx path:/.git

# Stack Node + Express em porta alternativa
tech:Node,Express portas:3000

# Subdomínios descobertos em janeiro/2024
date:2024-01-01 to 2024-01-31
```

> Texto sem chave (ex: `login`) faz busca livre no nome do domínio e nas tecnologias.

---

## Notificações Discord

O sistema envia notificações em dois momentos:

1. **Durante o scan** — ao descobrir novos subdomínios vivos (tempo real, não espera o scan terminar).
2. **Ao finalizar o Recon** — resumo com totais por status HTTP e novos domínios.
3. **Ao finalizar o Vuln Scan** — total de vulnerabilidades por ferramenta, ou confirmação de "scan limpo".

Configure `DISCORD_WEBHOOK_URL` no `.env` para ativar.

---

## Serviços Docker

| Serviço | Imagem | Função |
|---|---|---|
| `web` | Custom (Gunicorn) | API Flask + serve o frontend |
| `worker` | Custom (Celery) | Executa os scans (concurrency=2) |
| `beat` | Custom (Celery Beat) | Agenda o scan diário às 03:00 |
| `db` | `postgres:13-alpine` | Banco de dados principal |
| `redis` | `redis:6-alpine` | Broker de tasks + cache |

Todos os serviços têm `restart: unless-stopped` e healthchecks configurados.

---

<div align="center">
Desenvolvido por <a href="https://github.com/Sonael">Sonael</a>
</div>