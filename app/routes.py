from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, celery
from .models import User, Project, Domain, Vulnerability
from .tasks import run_scan_task 
import os

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
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)


@main.route('/project/new', methods=['POST'])
@login_required
def new_project():
    name = request.form.get('name')
    target = request.form.get('target')
    
    # Validação
    if not name or not target:
        flash('Nome e Domínio são obrigatórios.', 'error')
        return redirect(url_for('main.dashboard'))

    # 1. Cria o objeto do Projeto
    new_proj = Project(name=name, target_url=target, user_id=current_user.id)
    
    new_proj.scan_status = 'Rodando'
    new_proj.scan_message = '🚀 Iniciando Baseline Automático...'

    db.session.add(new_proj)
    db.session.commit() # Commit necessário para gerar o ID do projeto

    # 2. DISPARA O BASELINE AUTOMATICAMENTE
    # Chama a task do Celery em background
    task = run_scan_task.delay(new_proj.id, mode='baseline')
    
    # 3. Atualiza o ID da tarefa no banco (para poder cancelar se quiser)
    new_proj.current_task_id = task.id
    db.session.commit()
    
    flash(f'Alvo "{name}" criado e Baseline iniciado com sucesso!', 'success')
    
    return redirect(url_for('main.dashboard'))

@main.route('/project/<int:id>')
@login_required
def project_details(id):
    project = Project.query.get_or_404(id)
    
    # --- CÁLCULO DE ESTATÍSTICAS ---
    domains = project.domains
    stats = {
        'total': len(domains),
        # 200 a 299
        'ok': len([d for d in domains if d.status_code and 200 <= d.status_code < 300]),
        # 300 a 399
        'redirect': len([d for d in domains if d.status_code and 300 <= d.status_code < 400]),
        # 400 pra cima (Erros)
        'error': len([d for d in domains if d.status_code and d.status_code >= 400]),
        # Status 0 ou None (Não respondeu / Timeout)
        'dead': len([d for d in domains if not d.status_code or d.status_code == 0])
    }
    
    return render_template('project.html', project=project, stats=stats)

@main.route('/project/<int:id>/scan/<mode>', methods=['POST'])
@login_required
def start_scan(id, mode):
    project = Project.query.get_or_404(id)
    
    if mode not in ['recon', 'vuln', 'full', 'baseline']:
        return "Modo inválido", 400

    project.scan_status = 'Rodando'
    if mode == 'baseline':
        project.scan_message = 'Criando Baseline...'
    elif mode == 'recon':
        project.scan_message = 'Iniciando Recon...'
    elif mode == 'vuln':
        project.scan_message = 'Iniciando Scan de Vulnerabilidades...'
    
    # Inicia a task e PEGA O RETORNO (que contém o ID)
    task = run_scan_task.delay(project.id, mode)
    
    # Salva o ID da tarefa no banco
    project.current_task_id = task.id
    db.session.commit()
    
    return render_template('partials/controls.html', project=project)

@main.route('/project/<int:id>/stop', methods=['POST'])
@login_required
def stop_scan(id):
    project = Project.query.get_or_404(id)
    
    if project.current_task_id:
        celery.control.revoke(project.current_task_id, terminate=True)
        
        project.scan_status = 'Parado'
        project.scan_message = '🛑 Scan interrompido pelo usuário.'
        project.current_task_id = None
        db.session.commit()
        
        flash('O comando de parada forçada foi enviado.', 'warning') 
        
    return render_template('partials/controls.html', project=project)



@main.route('/project/<int:id>/status_part')
@login_required
def project_status_part(id):
    project = Project.query.get_or_404(id)
    # Retorna apenas o HTML do card de status, não a página toda
    return render_template('partials/status_card.html', project=project)


@main.route('/project/<int:id>/controls_part')
@login_required
def project_controls_part(id):
    project = Project.query.get_or_404(id)
    return render_template('partials/controls.html', project=project)

@main.route('/project/<int:id>/delete', methods=['POST'])
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    
    # 1. Verifica se há um scan rodando e mata ele
    if project.current_task_id:
        try:
            # Envia sinal de kill imediato para o worker
            celery.control.revoke(project.current_task_id, terminate=True)
            print(f"Tarefa {project.current_task_id} interrompida para exclusão do projeto.")
        except Exception as e:
            print(f"Erro ao tentar parar scan: {e}")

    # 2. Apaga o projeto do banco
    # (O cascade configurado no model apagará domínios e vulns automaticamente)
    db.session.delete(project)
    db.session.commit()
    
    flash(f'Projeto "{project.name}" foi apagado com sucesso!', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/project/<int:id>/vulns_part')
@login_required
def project_vulns_part(id):
    project = Project.query.get_or_404(id)
    return render_template('partials/vulns_list.html', project=project)

@main.route('/project/<int:id>/domains_part')
@login_required
def project_domains_part(id):
    project = Project.query.get_or_404(id)
    status_filter = request.args.get('status')
    
    query = Domain.query.filter_by(project_id=project.id)
    
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
                           project=project, 
                           domains=domains, 
                           current_status=status_filter)


@main.route('/project/<int:id>/count_domains')
@login_required
def count_domains(id):
    project = Project.query.get_or_404(id)
    # Retorna apenas o número como string
    return str(len(project.domains))

@main.route('/project/<int:id>/card_part')
@login_required
def project_card_part(id):
    # 1. Limpa a sessão para garantir dados frescos do banco
    db.session.expire_all() 
    
    # 2. Busca o projeto novamente
    project = Project.query.get_or_404(id)
    
    return render_template('partials/dashboard_card.html', project=project)

@main.route('/project/<int:id>/stats')
@login_required
def project_stats(id):
    project = Project.query.get_or_404(id)
    domains = project.domains
    stats = {
        'total': len(domains),
        'ok': len([d for d in domains if d.status_code and 200 <= d.status_code < 300]),
        'redirect': len([d for d in domains if d.status_code and 300 <= d.status_code < 400]),
        'error': len([d for d in domains if d.status_code and d.status_code >= 400]),
        'dead': len([d for d in domains if not d.status_code or d.status_code == 0])
    }
    return stats