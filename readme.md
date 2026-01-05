# 🛡️ BugBounty Monitor

> Plataforma automatizada de Reconhecimento (Recon) e Escaneamento de Vulnerabilidades para Bug Bounty e Pentest.

![Python](https://img.shields.io/badge/Python-3.9-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web-lightgrey?style=for-the-badge&logo=flask)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)
![Postgres](https://img.shields.io/badge/PostgreSQL-Database-336791?style=for-the-badge&logo=postgresql)
![License](https://img.shields.io/badge/License-GPLv3-red?style=for-the-badge)

O **BugBounty Monitor** é uma solução completa para orquestrar ferramentas de segurança ofensiva. Ele automatiza o fluxo de descoberta de ativos (subdomínios), verificação de portas, detecção de tecnologias e escaneamento de vulnerabilidades (CVEs, XSS, SQLi), tudo gerenciado através de um dashboard interativo.

---

## 🚀 Funcionalidades Principais

### 🔍 Reconhecimento (Recon) Avançado
- **Coleta de Subdomínios Híbrida:** Combina **Subfinder** e **Amass** (Modo Passivo) para máxima cobertura.
- **Port Scanning:** Utiliza **Naabu** para identificar portas abertas rapidamente.
- **Live Check:** Filtra ativos vivos e coleta Tech Stack usando **HTTPX**.
- **DNS Enrichment:** Coleta automática de registros CNAME e MX.

### 🧠 Lógica Inteligente de Scan
- **Scan Diferencial:** O sistema lembra dos subdomínios antigos. Scans pesados (Fuzzing) são executados **apenas em novos ativos** descobertos no dia, economizando recursos.
- **CMS Detection:** Identifica versão e nome do CMS (WordPress, Joomla, Drupal) via **CMSeeK**.
- **Fuzzing de Diretórios:** Roda **FFuf** automaticamente em ativos com status codes interessantes (200, 403, etc.).

### 💥 Detecção de Vulnerabilidades
- **Nuclei Engine:** Varredura massiva baseada em templates (CVEs, Misconfigs, Exposures).
- **Pipeline XSS:** Integração de **Katana** (Crawler) + **GAU** (URLs históricas) -> **Dalfox** para detectar XSS automaticamente.
- **SQL Injection:** (Opcional) Integração preparada para SQLMap Smart Scan.

### 📊 Gestão e Notificações
- **Dashboard Web:** Interface limpa feita com Flask, Bootstrap 5 e HTMX para atualizações em tempo real.
- **Filas Assíncronas:** Uso de **Redis + Celery** para processar scans em background sem travar a interface.
- **Notificações Discord:** Receba alertas detalhados (Embeds) sobre novos domínios ou vulnerabilidades críticas encontradas.

---

## 🛠️ Stack Tecnológica

O projeto é totalmente containerizado com Docker.

- **Backend:** Python 3 (Flask + SQLAlchemy)
- **Task Queue:** Celery + Redis
- **Banco de Dados:** PostgreSQL
- **Frontend:** HTML5, Bootstrap 5, HTMX
- **Infraestrutura:** Docker & Docker Compose

---

## ⚙️ Instalação e Configuração

### Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/install/) instalados.
- Git.

### 1. Clonar o Repositório
```bash
git clone [https://github.com/SEU_USUARIO/NOME_DO_REPO.git](https://github.com/SEU_USUARIO/NOME_DO_REPO.git)
cd NOME_DO_REPO