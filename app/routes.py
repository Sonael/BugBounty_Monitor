from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, celery
from .models import User, Project, Domain, Vulnerability
from .tasks import run_scan_task 
import os
from sqlalchemy import or_
import fnmatch

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
    # LÓGICA DE AUTO-HEALING (Limpeza Automática de Scans Travados)
    # ==============================================================================
    # 1. Busca todos os projetos que o banco diz que estão rodando
    running_projects = Project.query.filter(
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).all()
    
    if running_projects:
        try:
            # 2. Pergunta ao Celery quais tarefas estão realmente vivas
            # timeout curto (0.2s) para não deixar o carregamento da página lento
            inspector = celery.control.inspect(timeout=0.2)
            
            active = inspector.active()    # Tarefas executando agora
            reserved = inspector.reserved() # Tarefas na fila do worker
            scheduled = inspector.scheduled() # Tarefas agendadas
            
            # Se active for None, os workers estão offline/inacessíveis
            workers_online = (active is not None)
            
            real_task_ids = set()
            
            # 3. Coleta os IDs reais se os workers estiverem online
            if workers_online:
                for w_tasks in [active, reserved, scheduled]:
                    if w_tasks:
                        for worker_name, tasks_list in w_tasks.items():
                            for t in tasks_list:
                                real_task_ids.add(t['id'])
            
            changes = 0
            for p in running_projects:
                is_dead = False
                
                # Critério A: Não tem worker online -> O processo morreu.
                if not workers_online:
                    is_dead = True
                
                # Critério B: Tem worker, mas o ID da tarefa desse projeto não está lá.
                # Isso acontece quando o container reinicia e perde a memória RAM.
                elif p.current_task_id and p.current_task_id not in real_task_ids:
                    is_dead = True
                
                # Critério C: Projeto diz que roda, mas não tem ID de tarefa salvo.
                elif not p.current_task_id:
                    is_dead = True
                
                # APLICA A CORREÇÃO
                if is_dead:
                    p.scan_status = 'Erro'
                    p.scan_message = '🛑 Interrompido (Reinício do Sistema)'
                    p.current_task_id = None
                    changes += 1
            
            if changes > 0:
                db.session.commit()
                flash(f'{changes} scans interrompidos foram corrigidos automaticamente.', 'warning')
                
        except Exception as e:
            print(f"[AUTO-HEAL ERROR] Falha ao inspecionar Celery: {e}")

    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)


@main.route('/project/new', methods=['POST'])
@login_required
def new_project():
    # Mantido para compatibilidade, mas o ideal é usar add_project
    return add_project()

@main.route('/add_project', methods=['POST'])
@login_required
def add_project():
    name = request.form.get('name')
    target_url = request.form.get('target_url')
    
    in_scope_raw = request.form.get('in_scope', '')
    out_of_scope_raw = request.form.get('out_of_scope', '')
    
    discovery_enabled = True if request.form.get('auto_discovery') else False
    fuzzing_enabled = True if request.form.get('enable_fuzzing') else False

    if name and target_url:
        new_project = Project(
            name=name, 
            target_url=target_url,
            out_of_scope=out_of_scope_raw,
            in_scope=in_scope_raw,
            discovery_enabled=discovery_enabled,
            fuzzing_enabled=fuzzing_enabled,
            user_id=current_user.id
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
    
    if name and target_url:
        project.name = name
        project.target_url = target_url
        
        # Atualiza configurações no banco
        project.in_scope = in_scope_raw
        project.out_of_scope = out_of_scope_raw
        project.discovery_enabled = discovery_enabled
        project.fuzzing_enabled = fuzzing_enabled
        
        # 1. PROCESSA NOVOS DO IN_SCOPE (Adiciona)
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
            
        # 2. LIMPEZA AUTOMÁTICA DO OUT_OF_SCOPE (Remove Proibidos)
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
        
        # Feedback visual detalhado
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

def parse_discord_search(query_str):
    filters = {'general': []}
    if not query_str: return filters
    parts = query_str.split(' ')
    for part in parts:
        if ':' in part:
            key, value = part.split(':', 1)
            filters[key.lower()] = value
        else:
            if part.strip(): filters['general'].append(part)
    return filters

@main.route('/project/<int:id>/domains_part')
@login_required
def project_domains_part(id):
    project = Project.query.get_or_404(id)
    search_query = request.args.get('q', '')
    status_filter = request.args.get('status')
    
    query = Domain.query.filter_by(project_id=project.id)
    
    if search_query:
        filters = parse_discord_search(search_query)
        if 'status' in filters:
            codes = [int(c) for c in filters['status'].split(',') if c.isdigit()]
            if codes: query = query.filter(Domain.status_code.in_(codes))
        if 'portas' in filters or 'ports' in filters:
            p_val = filters.get('portas') or filters.get('ports')
            query = query.filter(Domain.open_ports.ilike(f"%{p_val}%"))
        if 'tech' in filters or 'tecnologias' in filters:
            t_val = filters.get('tech') or filters.get('tecnologias')
            query = query.filter(Domain.technologies.ilike(f"%{t_val}%"))
        if 'path' in filters or 'paths' in filters:
            path_val = filters.get('path') or filters.get('paths')
            query = query.filter(Domain.discovered_paths.ilike(f"%{path_val}%"))
        if 'subdominio' in filters or 'sub' in filters or 'domain' in filters:
            d_val = filters.get('subdominio') or filters.get('sub') or filters.get('domain')
            query = query.filter(Domain.name.ilike(f"%{d_val}%"))
        if filters['general']:
            term = filters['general'][0]
            query = query.filter(or_(Domain.name.ilike(f"%{term}%"), Domain.technologies.ilike(f"%{term}%")))

    if status_filter:
        if status_filter == 'ok': query = query.filter(Domain.status_code >= 200, Domain.status_code < 300)
        elif status_filter == 'redirect': query = query.filter(Domain.status_code >= 300, Domain.status_code < 400)
        elif status_filter == 'error': query = query.filter(Domain.status_code >= 400)
        elif status_filter == 'dead': query = query.filter((Domain.status_code == 0) | (Domain.status_code == None))
        elif status_filter.isdigit(): query = query.filter_by(status_code=int(status_filter))

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

    return jsonify({
        'status': codes,
        'ports': unique_ports,
        'tech': sorted(list(tech_set))[:50],
        'paths': sorted(list(path_set))[:50],
        'keys': ['status:', 'portas:', 'tech:', 'path:', 'subdominio:']
    })