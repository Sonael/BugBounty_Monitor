from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, celery
from .models import User, Project, Domain, Vulnerability
from .tasks import run_scan_task, run_daily_scan
import os
from sqlalchemy import or_, and_, func
import fnmatch
from datetime import datetime, timedelta


main = Blueprint('main', __name__)

# --- AUTENTICAÇÃO ---
@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')

@main.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        flash('Login incorreto.', 'error')
        return redirect(url_for('main.index'))
    login_user(user)
    return redirect(url_for('main.dashboard'))

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você foi desconectado com sucesso.', 'info')
    return redirect(url_for('main.index'))

# --- DASHBOARD & PROJETOS ---
@main.route('/dashboard')
@login_required
def dashboard():
    # ==============================================================================
    # LÓGICA DE AUTO-HEALING (CORREÇÃO: TOLERÂNCIA COM FILA)
    # ==============================================================================
    running_projects = Project.query.filter(
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).all()
    
    if running_projects:
        try:
            inspector = celery.control.inspect(timeout=1.0)
            active = inspector.active()    
            reserved = inspector.reserved() 
            scheduled = inspector.scheduled() 
            
            if active is not None:
                real_task_ids = set()
                
                # Coleta IDs de todas as filas visíveis nos workers
                for w_tasks in [active, reserved, scheduled]:
                    if w_tasks:
                        for worker_name, tasks_list in w_tasks.items():
                            for t in tasks_list:
                                real_task_ids.add(t['id'])
                
                changes = 0
                for p in running_projects:
                    # --- ALTERAÇÃO IMPORTANTE AQUI ---
                    # Só aplicamos a verificação rigorosa se o status for 'Rodando'.
                    # Se for 'Na fila', deixamos quieto, pois pode estar no Redis (invisível pro inspector)
                    # ou aguardando geração de ID pelo Scan Global.
                    
                    if p.scan_status == 'Rodando':
                        # Se diz que está rodando, TEM que ter ID
                        if not p.current_task_id:
                            p.scan_status = 'Erro'
                            p.scan_message = '🛑 Erro (Rodando sem ID)'
                            changes += 1
                        
                        # Se tem ID, mas o worker não sabe dele -> Worker reiniciou ou task morreu
                        elif p.current_task_id not in real_task_ids:
                            p.scan_status = 'Erro'
                            p.scan_message = '🛑 Processo perdido (Worker reiniciou?)'
                            p.current_task_id = None
                            changes += 1
                    
                    # Se estiver 'Na fila', NÃO FAZEMOS NADA. 
                    # Assumimos que o Celery vai pegar eventualmente.

                if changes > 0:
                    db.session.commit()
            else:
                print("[AUTO-HEAL SKIP] Celery demorou para responder.")

        except Exception as e:
            print(f"[AUTO-HEAL ERROR] Falha ao inspecionar Celery: {e}")

    # ==============================================================================
    # DADOS DO DASHBOARD (Mantido igual)
    # ==============================================================================
    projects = Project.query.filter_by(user_id=current_user.id).all()
    
    # 1. Estatísticas Globais
    total_subs = Domain.query.join(Project).filter(Project.user_id == current_user.id).count()
    total_vulns = Vulnerability.query.join(Domain).join(Project).filter(Project.user_id == current_user.id).count()
    running_scans = Project.query.filter(
        Project.user_id == current_user.id, 
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).count()

    stats = {
        'projects': len(projects),
        'subdomains': total_subs,
        'vulns': total_vulns,
        'running': running_scans
    }

    # 2. Distribuição de Severidade
    severity_query = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))\
        .join(Domain).join(Project)\
        .filter(Project.user_id == current_user.id)\
        .group_by(Vulnerability.severity).all()
    
    sev_counts_lower = {}
    for s in severity_query:
        if s[0]: 
            key = str(s[0]).lower()
            val = s[1]
            sev_counts_lower[key] = sev_counts_lower.get(key, 0) + val

    crit = sev_counts_lower.get('critical', 0)
    high = sev_counts_lower.get('high', 0)
    med = sev_counts_lower.get('medium', 0)
    low = sev_counts_lower.get('low', 0)
    info = sev_counts_lower.get('info', 0)
    
    total_for_pct = crit + high + med + low + info
    
    def calc_pct(count):
        return (count / total_for_pct * 100) if total_for_pct > 0 else 0

    severity_stats = {
        'critical': crit,
        'high': high,
        'medium': med,
        'low': low,
        'info': info,
        'pct_critical': calc_pct(crit),
        'pct_high': calc_pct(high),
        'pct_medium': calc_pct(med),
        'pct_low': calc_pct(low + info)
    }

    # 3. Feed de Atividade Recente
    recent_activity = Domain.query.join(Project)\
        .filter(Project.user_id == current_user.id)\
        .order_by(Domain.first_seen.desc())\
        .limit(5).all()

    return render_template('dashboard.html', 
                           projects=projects, 
                           stats=stats, 
                           severity=severity_stats, 
                           recent_activity=recent_activity)

@main.route('/add_project', methods=['POST'])
@login_required
def add_project():
    name = request.form.get('name')
    target_url = request.form.get('target_url')
    
    in_scope_raw = request.form.get('in_scope', '')
    out_of_scope_raw = request.form.get('out_of_scope', '')
    
    discovery_enabled = True if request.form.get('auto_discovery') else False
    fuzzing_enabled = True if request.form.get('enable_fuzzing') else False
    vuln_scan_enabled = True if request.form.get('enable_vuln_scan') else False

    if name and target_url:
        new_project = Project(
            name=name, 
            target_url=target_url,
            out_of_scope=out_of_scope_raw,
            in_scope=in_scope_raw,
            discovery_enabled=discovery_enabled,
            fuzzing_enabled=fuzzing_enabled,
            user_id=current_user.id,
            vuln_scan_enabled=vuln_scan_enabled,
        )
        new_project.scan_status = 'Na fila'
        new_project.scan_message = 'Aguardando início...'
        
        db.session.add(new_project)
        db.session.flush()

        if in_scope_raw:
            domains_list = [line.strip() for line in in_scope_raw.splitlines() if line.strip()]
            for domain_name in domains_list:
                clean_name = domain_name.replace('https://', '').replace('http://', '').split('/')[0]
                exists = Domain.query.filter_by(name=clean_name, project_id=new_project.id).first()
                if not exists:
                    new_domain = Domain(name=clean_name, project_id=new_project.id)
                    db.session.add(new_domain)

        target_clean = target_url.replace('https://', '').replace('http://', '').split('/')[0]
        exists_main = Domain.query.filter_by(name=target_clean, project_id=new_project.id).first()
        if not exists_main:
            db.session.add(Domain(name=target_clean, project_id=new_project.id))

        db.session.commit()

        from app.tasks import run_scan_task
        task = run_scan_task.delay(new_project.id, mode='baseline')
        
        new_project.current_task_id = task.id
        db.session.commit()
        
        flash(f'Projeto "{name}" criado! Scan adicionado à fila.', 'success')
        return redirect(url_for('main.dashboard'))
    
    flash('Nome e URL Alvo são obrigatórios!', 'error')
    return redirect(url_for('main.dashboard'))

@main.route('/project/<int:id>')
@login_required
def project_details(id):
    project = Project.query.get_or_404(id)
    
    domains = project.domains
    stats = {
        'total': len(domains),
        'ok': len([d for d in domains if d.status_code and 200 <= d.status_code < 300]),
        'redirect': len([d for d in domains if d.status_code and 300 <= d.status_code < 400]),
        'error': len([d for d in domains if d.status_code and d.status_code >= 400]),
        'dead': len([d for d in domains if not d.status_code or d.status_code == 0])
    }
    
    # Carrega os domínios ordenados
    sorted_domains = Domain.query.filter_by(project_id=id).order_by(Domain.first_seen.desc()).all()
    
    return render_template('project.html', 
                         project=project, 
                         stats=stats,
                         domains=sorted_domains)

@main.route('/project/<int:id>/scan/<mode>', methods=['POST'])
@login_required
def start_scan(id, mode):
    project = Project.query.get_or_404(id)
    
    if mode not in ['recon', 'vuln', 'full', 'baseline']:
        return "Modo inválido", 400

    project.scan_status = 'Na fila'
    project.scan_message = 'Aguardando worker disponível...'
    db.session.commit()
    
    from app.tasks import run_scan_task
    task = run_scan_task.delay(project.id, mode)
    
    project.current_task_id = task.id
    db.session.commit()
    
    return render_template('partials/controls.html', project=project)

@main.route('/project/<int:id>/stop', methods=['POST'])
@login_required
def stop_scan(id):
    project = Project.query.get_or_404(id)
    
    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except: pass
        
        project.scan_status = 'Parado'
        project.scan_message = '🛑 Scan interrompido pelo usuário.'
        project.current_task_id = None
        db.session.commit()
        
        flash('O comando de parada forçada foi enviado.', 'warning') 
        
    return render_template('partials/controls.html', project=project)

@main.route('/project/<int:id>/edit', methods=['POST'])
@login_required
def edit_project(id):
    project = Project.query.get_or_404(id)
    
    name = request.form.get('name')
    target_url = request.form.get('target_url')
    
    in_scope_raw = request.form.get('in_scope', '')
    out_of_scope_raw = request.form.get('out_of_scope', '')
    
    discovery_enabled = True if request.form.get('auto_discovery') else False
    fuzzing_enabled = True if request.form.get('enable_fuzzing') else False
    vuln_scan_enabled = True if request.form.get('enable_vuln_scan') else False
    
    if name and target_url:
        project.name = name
        project.target_url = target_url
        
        # Atualiza configurações no banco
        project.in_scope = in_scope_raw
        project.out_of_scope = out_of_scope_raw
        project.discovery_enabled = discovery_enabled
        project.fuzzing_enabled = fuzzing_enabled
        project.vuln_scan_enabled = vuln_scan_enabled
        
        # 1. PROCESSA NOVOS DO IN_SCOPE
        added_count = 0
        if in_scope_raw:
            domains_list = [line.strip() for line in in_scope_raw.splitlines() if line.strip()]
            for domain_name in domains_list:
                clean_name = domain_name.replace('https://', '').replace('http://', '').split('/')[0]
                exists = Domain.query.filter_by(name=clean_name, project_id=project.id).first()
                if not exists:
                    db.session.add(Domain(name=clean_name, project_id=project.id))
                    added_count += 1
        
        # Garante o domínio principal
        target_clean = target_url.replace('https://', '').replace('http://', '').split('/')[0]
        exists_main = Domain.query.filter_by(name=target_clean, project_id=project.id).first()
        if not exists_main:
            db.session.add(Domain(name=target_clean, project_id=project.id))
            
        # 2. LIMPEZA AUTOMÁTICA DO OUT_OF_SCOPE
        deleted_count = 0
        if out_of_scope_raw:
            # Prepara lista negra
            blacklist = [line.strip() for line in out_of_scope_raw.splitlines() if line.strip()]
            
            # Busca todos os domínios existentes no projeto
            current_domains = Domain.query.filter_by(project_id=project.id).all()
            
            for d in current_domains:
                should_delete = False
                for bl in blacklist:
                    # Verifica Wildcard (ex: *.google.com)
                    if fnmatch.fnmatch(d.name, bl):
                        should_delete = True
                        break
                    # Verifica Sufixo/Exato (ex: google.com)
                    if '*' not in bl:
                        if d.name == bl or d.name.endswith("." + bl):
                            should_delete = True
                            break
                
                if should_delete:
                    db.session.delete(d)
                    deleted_count += 1

        db.session.commit()
        
        msgs = []
        if added_count > 0: msgs.append(f"{added_count} adicionados")
        if deleted_count > 0: msgs.append(f"{deleted_count} removidos (Out of Scope)")
        
        if msgs:
            flash(f'Projeto atualizado: {", ".join(msgs)}.', 'success')
        else:
            flash('Projeto atualizado com sucesso!', 'success')
            
    else:
        flash('Nome e URL Alvo não podem ficar vazios.', 'error')
        
    return redirect(request.referrer or url_for('main.dashboard'))

@main.route('/project/<int:id>/delete', methods=['POST'])
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except: pass
    db.session.delete(project)
    db.session.commit()
    flash(f'Projeto "{project.name}" foi apagado.', 'success')
    return redirect(url_for('main.dashboard'))

# --- PARTIALS & API ---

@main.route('/project/<int:id>/status_part')
@login_required
def project_status_part(id):
    project = Project.query.get_or_404(id)
    return render_template('partials/status_card.html', project=project)

@main.route('/project/<int:id>/controls_part')
@login_required
def project_controls_part(id):
    project = Project.query.get_or_404(id)
    return render_template('partials/controls.html', project=project)

@main.route('/project/<int:id>/vulns_part')
@login_required
def project_vulns_part(id):
    project = Project.query.get_or_404(id)
    return render_template('partials/vulns_list.html', project=project)

@main.route('/project/<int:id>/card_part')
@login_required
def project_card_part(id):
    db.session.expire_all() 
    project = Project.query.get_or_404(id)
    return render_template('partials/dashboard_card.html', project=project)

@main.route('/project/<int:id>/count_domains')
@login_required
def count_domains(id):
    project = Project.query.get_or_404(id)
    return str(len(project.domains))

@main.route('/project/<int:id>/count_vulns')
@login_required
def count_vulns(id):
    # Faz um Join para contar vulns apenas deste projeto
    total = Vulnerability.query.join(Domain).filter(Domain.project_id == id).count()
    return str(total)

def parse_discord_search(query_str):
    # Estrutura de dados alterada para suportar grupos de AND dentro de OR
    filters = {
        'status': [], # Status é sempre OR (lista simples)
        'portas': [], # Lista de listas (Grupos AND)
        'tech': [],   # Lista de listas (Grupos AND)
        'path': [],   # Lista de listas (Grupos AND)
        'sub': [],
        'date': [],   # NOVO: Filtro de Descoberta (First Seen)
        'ssl': [],# OR
        'general': []
    }
    
    if not query_str: return filters
    
    safe_query = query_str.replace(" to ", "__TO__").replace(" até ", "__TO__")
        
    parts = safe_query.split(' ')
    
    for part in parts:
        part = part.strip()
        if not part: continue
        
        part = part.replace("__TO__", " to ")
        
        # Remove vírgula final se sobrar
        if part.endswith(','): part = part[:-1]

        if ':' in part:
            key, value = part.split(':', 1)
            key = key.lower()
            
            # Normalização
            if key in ['ports']: key = 'portas'
            if key in ['tecnologias']: key = 'tech'
            if key in ['paths']: key = 'path'
            if key in ['subdominio', 'domain']: key = 'sub'
            
            if key in ['date', 'data', 'seen']: key = 'date'
            if key in ['ssl', 'cert']: key = 'ssl'
            
            if key in filters:
                # Para status e sub, OR
                if key in ['status', 'sub']:
                    if ',' in value:
                        filters[key].extend([v.strip() for v in value.split(',') if v.strip()])
                    else:
                        filters[key].append(value.strip())
                
                # Para Datas, apenas adicionamos a string crua (ex: "2023-01-01 to 2023-01-05")
                elif key in ['date', 'ssl']:
                     filters[key].append(value.strip())

                # Para Tech, Portas e Path, GRUPOS (AND)
                else:
                    if ',' in value:
                        group = [v.strip() for v in value.split(',') if v.strip()]
                        filters[key].append(group)
                    elif value.strip():
                        filters[key].append([value.strip()])
        else:
            filters['general'].append(part)
            
    return filters

@main.route('/project/<int:id>/domains_part')
@login_required
def project_domains_part(id):
    project = Project.query.get_or_404(id)
    search_query = request.args.get('q', '')
    status_filter = request.args.get('status')
    
    query = Domain.query.filter_by(project_id=project.id)
    
    # 1. Filtros Avançados
    if search_query:
        filters = parse_discord_search(search_query)
        
        # STATUS (Sempre OR -> status IN (...))
        if filters['status']:
            codes = [int(c) for c in filters['status'] if c.isdigit()]
            if codes: query = query.filter(Domain.status_code.in_(codes))

        # PORTAS (Híbrido: Vírgula = AND, Espaço = OR)
        if filters['portas']:
            or_conditions = []
            for group in filters['portas']:
                # Dentro do grupo (vírgula), TEM que ter todas as portas (AND)
                and_conditions = [Domain.open_ports.ilike(f"%{p}%") for p in group]
                or_conditions.append(and_(*and_conditions))
            query = query.filter(or_(*or_conditions))

        # TECH (Híbrido: Vírgula = AND, Espaço = OR)
        if filters['tech']:
            or_conditions = []
            for group in filters['tech']:
                # Ex: tech:Angular,Node -> Busca %Angular% AND %Node%
                and_conditions = [Domain.technologies.ilike(f"%{t}%") for t in group]
                or_conditions.append(and_(*and_conditions))
            
            # Ex: tech:A tech:B -> Busca (Grupo A) OR (Grupo B)
            query = query.filter(or_(*or_conditions))

        # PATH (Híbrido)
        if filters['path']:
            or_conditions = []
            for group in filters['path']:
                and_conditions = [Domain.discovered_paths.ilike(f"%{p}%") for p in group]
                or_conditions.append(and_(*and_conditions))
            query = query.filter(or_(*or_conditions))

        # SUBDOMINIO (OR)
        if filters['sub']:
            conds = [Domain.name.ilike(f"%{s}%") for s in filters['sub']]
            query = query.filter(or_(*conds))
        
        if filters['date']:
            # Pega o último filtro de data adicionado (ignora se user digitou varios)
            date_str = filters['date'][-1] 
            
            try:
                if ' to ' in date_str:
                    # RANGE: YYYY-MM-DD to YYYY-MM-DD
                    start_str, end_str = date_str.split(' to ')
                    start_dt = datetime.strptime(start_str, '%Y-%m-%d')
                    # Ajusta fim para o final do dia (23:59:59)
                    end_dt = datetime.strptime(end_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                    
                    query = query.filter(Domain.first_seen.between(start_dt, end_dt))
                else:
                    start_dt = datetime.strptime(date_str, '%Y-%m-%d')
                    end_dt = start_dt.replace(hour=23, minute=59, second=59)
                    
                    query = query.filter(Domain.first_seen.between(start_dt, end_dt))
            except ValueError:
                pass 

        if filters['ssl']:
            ssl_str = filters['ssl'][-1]
                        
            if ' to ' in ssl_str:
                start_s, end_s = ssl_str.split(' to ')
                query = query.filter(and_(Domain.creation_date >= start_s, Domain.creation_date <= end_s))
            else:
                query = query.filter(Domain.creation_date == ssl_str)

        # GERAL
        for term in filters['general']:
            query = query.filter(or_(
                Domain.name.ilike(f"%{term}%"), 
                Domain.technologies.ilike(f"%{term}%")
            ))

    # 2. Filtros Rápidos
    if status_filter:
        if status_filter == 'ok': 
            query = query.filter(Domain.status_code >= 200, Domain.status_code < 300)
        elif status_filter == 'redirect': 
            query = query.filter(Domain.status_code >= 300, Domain.status_code < 400)
        elif status_filter == 'error': 
            query = query.filter(Domain.status_code >= 400)
        elif status_filter == 'dead': 
            query = query.filter((Domain.status_code == 0) | (Domain.status_code == None))
        elif status_filter.isdigit(): 
            query = query.filter_by(status_code=int(status_filter))

    domains = query.order_by(Domain.first_seen.desc()).all()
    
    return render_template('partials/domains_list.html', 
                           project=project, domains=domains, current_status=status_filter)

@main.route('/api/project/<int:id>/search_options')
@login_required
def project_search_options(id):
    # Status
    status_q = db.session.query(Domain.status_code).filter_by(project_id=id).distinct().all()
    codes = sorted([str(r[0]) for r in status_q if r[0] and r[0] > 0])
    
    # Portas
    ports_q = db.session.query(Domain.open_ports).filter_by(project_id=id).all()
    ports_set = set()
    for row in ports_q:
        if row.open_ports:
            for p in row.open_ports.split(','):
                clean = p.strip()
                if clean.isdigit(): ports_set.add(int(clean))
    unique_ports = [str(p) for p in sorted(list(ports_set))]

    # Techs
    tech_q = db.session.query(Domain.technologies).filter_by(project_id=id).all()
    tech_set = set()
    for row in tech_q:
        if row.technologies:
            for t in row.technologies.split(','):
                c = t.strip()
                if c and c != "Descoberto via Vuln Scan": tech_set.add(c)
    
    # Paths
    path_q = db.session.query(Domain.discovered_paths).filter_by(project_id=id).all()
    path_set = set()
    for row in path_q:
        if row.discovered_paths:
            for p in row.discovered_paths.split(','):
                c = p.strip()
                if c and not c.startswith('['): path_set.add(c)
                
                
    dates_q = db.session.query(func.date(Domain.first_seen)).filter_by(project_id=id).distinct().all()
    valid_dates = [str(r[0]) for r in dates_q if r[0]]
                
    ssl_q = db.session.query(Domain.creation_date).filter_by(project_id=id).distinct().all()
    valid_ssl = [str(r[0]) for r in ssl_q if r[0]]

    return jsonify({
        'status': codes,
        'ports': unique_ports,
        'tech': sorted(list(tech_set))[:50],
        'paths': sorted(list(path_set))[:50],
        'dates': valid_dates,
        'ssl_dates': valid_ssl,
        'keys': ['status:', 'portas:', 'tech:', 'path:', 'subdominio:', 'date:', 'ssl:'],
    })
    
    
@main.route('/scan/global/start', methods=['POST'])
@login_required
def start_global_scan():
    """Dispara o Scan Diário (Sua função existente no tasks.py)"""
    
    # 1. Muda status visualmente para 'Na fila' (feedback imediato)
    # Isso faz o botão mudar de cor antes mesmo do Celery processar
    projects = Project.query.filter_by(user_id=current_user.id).all()
    count = 0
    for p in projects:
        if p.scan_status not in ['Rodando', 'Na fila']:
            p.scan_status = 'Na fila'
            p.scan_message = 'Aguardando Scan Diário...'
            count += 1
    db.session.commit()

    # 2. Chama sua função original do tasks.py
    if count > 0:
        run_daily_scan.delay() 
        flash('Scan Diário iniciado! As tarefas entrarão em execução em breve.', 'success')
    else:
        flash('Todos os projetos já estão em andamento.', 'info')

    return redirect(url_for('main.dashboard'))

@main.route('/scan/global/stop', methods=['POST'])
@login_required
def stop_global_scan():
    """Para todos os scans rodando"""
    projects = Project.query.filter(
        Project.user_id == current_user.id,
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).all()
    
    stopped = 0
    for p in projects:
        # Tenta matar a task pelo ID salvo (graças ao passo 1)
        if p.current_task_id:
            try:
                celery.control.revoke(p.current_task_id, terminate=True)
            except: pass
        
        p.scan_status = 'Parado'
        p.scan_message = '🛑 Parada Manual (Global)'
        p.current_task_id = None
        stopped += 1
        
    db.session.commit()
    
    if stopped > 0:
        flash(f'{stopped} scans foram interrompidos.', 'warning')
    
    return redirect(url_for('main.dashboard'))

@main.route('/htmx/stats')
@login_required
def htmx_stats():
    # Recalcula as estatísticas (Cópia da lógica do dashboard)
    total_projects = Project.query.filter_by(user_id=current_user.id).count()
    total_subs = Domain.query.join(Project).filter(Project.user_id == current_user.id).count()
    total_vulns = Vulnerability.query.join(Domain).join(Project).filter(Project.user_id == current_user.id).count()
    running_scans = Project.query.filter(
        Project.user_id == current_user.id, 
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).count()

    stats = {
        'projects': total_projects,
        'subdomains': total_subs,
        'vulns': total_vulns,
        'running': running_scans
    }
    
    # Retorna APENAS o pedacinho HTML dos cards
    return render_template('partials/dashboard_status.html', stats=stats)