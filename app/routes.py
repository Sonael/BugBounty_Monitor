from flask import (Blueprint, render_template, redirect, url_for, request,
                   flash, jsonify, make_response, abort)
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, celery, limiter
from .models import User, Project, Domain, Vulnerability, ScanHistory, Port
from .tasks import run_scan_task, run_daily_scan
from celery import uuid as celery_uuid
from .services import (get_user_stats, get_severity_stats,
                        get_project_domain_stats, get_all_projects_card_stats)
import os
import json
import csv
import io
from sqlalchemy import or_, and_, func
import fnmatch
from datetime import datetime, timedelta

main = Blueprint('main', __name__)

# ---------------------------------------------------------------------------
# AUTENTICAÇÃO
# ---------------------------------------------------------------------------

@main.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')


@main.route('/login', methods=['POST'])
@limiter.limit("5 per minute")          # Proteção brute-force: máx 5 tentativas/min por IP
def login_post():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Preencha usuário e senha.', 'error')
        return redirect(url_for('main.index'))

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


# Endpoint para obter o token CSRF via JavaScript/HTMX
@main.route('/api/csrf-token')
@login_required
def get_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return jsonify({'csrf_token': generate_csrf()})


# ---------------------------------------------------------------------------
# DASHBOARD & PROJETOS
# ---------------------------------------------------------------------------

@main.route('/dashboard')
@login_required
def dashboard():
    projects = Project.query.filter_by(user_id=current_user.id).all()

    stats    = get_user_stats(current_user.id)
    severity = get_severity_stats(current_user.id)

    # Contadores de cards calculados em 2 queries (sem carregar domínios na memória)
    project_ids  = [p.id for p in projects]
    cards_stats  = get_all_projects_card_stats(project_ids)

    recent_activity = (
        Domain.query
        .join(Project)
        .filter(Project.user_id == current_user.id)
        .order_by(Domain.first_seen.desc())
        .limit(5)
        .all()
    )

    return render_template('dashboard.html',
                           projects=projects,
                           stats=stats,
                           severity=severity,
                           cards_stats=cards_stats,
                           recent_activity=recent_activity)


@main.route('/add_project', methods=['POST'])
@login_required
def add_project():
    name = request.form.get('name', '').strip()
    target_url = request.form.get('target_url', '').strip()

    in_scope_raw = request.form.get('in_scope', '')[:10000]   # limita tamanho
    out_of_scope_raw = request.form.get('out_of_scope', '')[:10000]

    if not name or not target_url:
        flash('Nome e URL Alvo são obrigatórios!', 'error')
        return redirect(url_for('main.dashboard'))

    discovery_enabled = bool(request.form.get('auto_discovery'))
    fuzzing_enabled = bool(request.form.get('enable_fuzzing'))
    vuln_scan_enabled = bool(request.form.get('enable_vuln_scan'))
    vuln_scan_recon_enabled = bool(request.form.get('enable_vuln_recon'))

    new_project = Project(
        name=name,
        target_url=target_url,
        out_of_scope=out_of_scope_raw,
        in_scope=in_scope_raw,
        discovery_enabled=discovery_enabled,
        fuzzing_enabled=fuzzing_enabled,
        user_id=current_user.id,
        vuln_scan_enabled=vuln_scan_enabled,
        vuln_scan_recon_enabled=vuln_scan_recon_enabled,
        scan_status='Na fila',
        scan_message='Aguardando início...',
    )
    db.session.add(new_project)
    db.session.flush()  # gera o ID antes de criar domínios

    if in_scope_raw:
        for line in in_scope_raw.splitlines():
            clean = line.strip().replace('https://', '').replace('http://', '').split('/')[0]
            if clean and not Domain.query.filter_by(name=clean, project_id=new_project.id).first():
                db.session.add(Domain(name=clean, project_id=new_project.id))

    target_clean = target_url.replace('https://', '').replace('http://', '').split('/')[0]
    if not Domain.query.filter_by(name=target_clean, project_id=new_project.id).first():
        db.session.add(Domain(name=target_clean, project_id=new_project.id))

    # Pré-gera o task ID e salva no banco ANTES de despachar.
    # Sem isso há race condition: o worker pode pegar a task antes do commit
    # do task_id, a verificação de duplicata dispara e a task é descartada.
    task_id = celery_uuid()
    new_project.current_task_id = task_id
    db.session.commit()

    run_scan_task.apply_async(args=[new_project.id, 'baseline'], task_id=task_id)

    flash(f'Projeto "{name}" criado! Scan adicionado à fila.', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/project/<int:id>')
@login_required
def project_details(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    stats = get_project_domain_stats(id)

    sorted_domains = (
        Domain.query
        .filter_by(project_id=id)
        .order_by(Domain.first_seen.desc())
        .limit(200)           # carrega somente os 200 mais recentes na view inicial
        .all()
    )

    return render_template('project.html',
                           project=project,
                           stats=stats,
                           domains=sorted_domains)


@main.route('/project/<int:id>/scan/<mode>', methods=['POST'])
@login_required
def start_scan(id, mode):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    if mode not in ['recon', 'vuln', 'full', 'baseline']:
        return "Modo inválido", 400

    # Pré-gera task ID antes do dispatch para evitar race condition
    task_id = celery_uuid()
    project.scan_status = 'Na fila'
    project.scan_message = 'Aguardando worker disponível...'
    project.current_task_id = task_id
    db.session.commit()

    run_scan_task.apply_async(args=[project.id, mode], task_id=task_id)

    pendentes = Domain.query.filter(
        Domain.project_id == project.id,
        Domain.scanned_vulns == False,
        Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
    ).count()
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/stop', methods=['POST'])
@login_required
def stop_scan(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except Exception:
            pass

        # Marca o histórico em andamento como stopped
        history = ScanHistory.query.filter_by(
            project_id=id, status='running'
        ).order_by(ScanHistory.started_at.desc()).first()
        if history:
            history.status = 'stopped'
            history.finished_at = datetime.utcnow()

        project.scan_status = 'Parado'
        project.scan_message = '🛑 Scan interrompido pelo usuário.'
        project.current_task_id = None
        db.session.commit()

        flash('O comando de parada forçada foi enviado.', 'warning')

    pendentes = Domain.query.filter(
        Domain.project_id == project.id,
        Domain.scanned_vulns == False,
        Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
    ).count()
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/edit', methods=['POST'])
@login_required
def edit_project(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    name = request.form.get('name', '').strip()
    target_url = request.form.get('target_url', '').strip()

    in_scope_raw = request.form.get('in_scope', '')[:10000]
    out_of_scope_raw = request.form.get('out_of_scope', '')[:10000]

    if not name or not target_url:
        flash('Nome e URL Alvo não podem ficar vazios.', 'error')
        return redirect(request.referrer or url_for('main.dashboard'))

    project.name = name
    project.target_url = target_url
    project.in_scope = in_scope_raw
    project.out_of_scope = out_of_scope_raw
    project.discovery_enabled = bool(request.form.get('auto_discovery'))
    project.fuzzing_enabled = bool(request.form.get('enable_fuzzing'))
    project.vuln_scan_enabled = bool(request.form.get('enable_vuln_scan'))
    project.vuln_scan_recon_enabled = bool(request.form.get('enable_vuln_recon'))

    added_count = 0
    if in_scope_raw:
        for line in in_scope_raw.splitlines():
            clean = line.strip().replace('https://', '').replace('http://', '').split('/')[0]
            if clean and not Domain.query.filter_by(name=clean, project_id=id).first():
                db.session.add(Domain(name=clean, project_id=id))
                added_count += 1

    target_clean = target_url.replace('https://', '').replace('http://', '').split('/')[0]
    if not Domain.query.filter_by(name=target_clean, project_id=id).first():
        db.session.add(Domain(name=target_clean, project_id=id))

    deleted_count = 0
    if out_of_scope_raw:
        blacklist = [l.strip() for l in out_of_scope_raw.splitlines() if l.strip()]
        for d in Domain.query.filter_by(project_id=id).all():
            for bl in blacklist:
                if fnmatch.fnmatch(d.name, bl) or ('*' not in bl and (d.name == bl or d.name.endswith('.' + bl))):
                    db.session.delete(d)
                    deleted_count += 1
                    break

    db.session.commit()

    msgs = []
    if added_count:   msgs.append(f"{added_count} adicionados")
    if deleted_count: msgs.append(f"{deleted_count} removidos (Out of Scope)")
    flash(f'Projeto atualizado: {", ".join(msgs)}.' if msgs else 'Projeto atualizado com sucesso!', 'success')

    return redirect(request.referrer or url_for('main.dashboard'))


@main.route('/project/<int:id>/delete', methods=['POST'])
@login_required
def delete_project(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except Exception:
            pass
    db.session.delete(project)
    db.session.commit()
    flash(f'Projeto "{project.name}" foi apagado.', 'success')
    return redirect(url_for('main.dashboard'))


# ---------------------------------------------------------------------------
# EXPORTAÇÃO
# ---------------------------------------------------------------------------

@main.route('/project/<int:id>/export/<fmt>')
@login_required
def export_project(id, fmt):
    """Exporta todos os domínios + vulnerabilidades em JSON ou CSV."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    if fmt not in ('json', 'csv'):
        return "Formato inválido. Use 'json' ou 'csv'.", 400

    domains = Domain.query.filter_by(project_id=id).all()
    safe_name = "".join(c for c in project.name if c.isalnum() or c in (' ', '-', '_')).rstrip()

    if fmt == 'json':
        data = []
        for d in domains:
            data.append({
                'domain': d.name,
                'status_code': d.status_code,
                'ip': d.ip_address,
                'technologies': d.technologies,
                'open_ports': d.open_ports,
                'dns_info': d.dns_info,
                'discovered_paths': d.discovered_paths,
                'ssl_first_seen': d.creation_date,
                'first_seen': d.first_seen.isoformat() if d.first_seen else None,
                'vulnerabilities': [
                    {
                        'tool': v.tool,
                        'severity': v.severity,
                        'description': v.description,
                        'found_at': v.found_at.isoformat() if v.found_at else None,
                    }
                    for v in d.vulnerabilities
                ],
            })
        resp = make_response(json.dumps(data, indent=2, ensure_ascii=False))
        resp.headers['Content-Type'] = 'application/json; charset=utf-8'
        resp.headers['Content-Disposition'] = f'attachment; filename="{safe_name}_export.json"'
        return resp

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Domain', 'Status', 'IP', 'Technologies', 'Open Ports',
        'DNS Info', 'Discovered Paths', 'SSL First Seen', 'First Seen',
        'Vuln Count', 'Highest Severity', 'Vulnerabilities'
    ])
    for d in domains:
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        severities = [v.severity.lower() if v.severity else 'info' for v in d.vulnerabilities]
        highest = min(severities, key=lambda s: sev_order.get(s, 99)) if severities else ''
        vulns_str = ' | '.join(
            f"[{v.severity}] {(v.description or '')[:80]}"
            for v in d.vulnerabilities
        )
        writer.writerow([
            d.name, d.status_code, d.ip_address, d.technologies,
            d.open_ports, d.dns_info, d.discovered_paths,
            d.creation_date, d.first_seen, len(d.vulnerabilities),
            highest, vulns_str
        ])

    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename="{safe_name}_export.csv"'
    return resp


# ---------------------------------------------------------------------------
# HISTÓRICO DE SCANS
# ---------------------------------------------------------------------------

@main.route('/api/project/<int:id>/history')
@login_required
def project_scan_history(id):
    """Retorna o histórico de scans do projeto em JSON (últimos 30 registros)."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    histories = (
        ScanHistory.query
        .filter_by(project_id=id)
        .order_by(ScanHistory.started_at.desc())
        .limit(30)
        .all()
    )

    return jsonify([{
        'id': h.id,
        'mode': h.mode,
        'status': h.status,
        'started_at': h.started_at.isoformat() if h.started_at else None,
        'finished_at': h.finished_at.isoformat() if h.finished_at else None,
        'duration_minutes': h.duration_minutes,
        'new_domains': h.new_domains,
        'total_domains': h.total_domains,
        'alive_hosts': h.alive_hosts,
        'new_vulns': h.new_vulns,
        'total_vulns': h.total_vulns,
        'summary': json.loads(h.summary) if h.summary else None,
    } for h in histories])


# ---------------------------------------------------------------------------
# AUTO-HEALING & HTMX PARTIALS
# ---------------------------------------------------------------------------

@main.route('/api/heal_projects')
@login_required
def heal_projects_api():
    running_projects = Project.query.filter(
        Project.scan_status == 'Rodando',
        Project.user_id == current_user.id   # corrigido: filtro por usuário
    ).all()

    if not running_projects:
        return '''
            <i class="fas fa-server text-success me-2"></i>
            <span>Sistema Online</span>
        '''

    changes = 0
    try:
        inspector = celery.control.inspect(timeout=1.0)
        active = inspector.active()

        if active is None:
            return '''
                <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                <span class="text-danger fw-bold">Worker Offline</span>
            '''

        real_task_ids = set()
        for w_tasks in [active, inspector.reserved()]:
            if w_tasks:
                for _, tasks_list in w_tasks.items():
                    for t in tasks_list:
                        real_task_ids.add(t['id'])

        for p in running_projects:
            if not p.current_task_id or p.current_task_id not in real_task_ids:
                # Marca histórico em andamento como erro
                h = ScanHistory.query.filter_by(
                    project_id=p.id, status='running'
                ).order_by(ScanHistory.started_at.desc()).first()
                if h:
                    h.status = 'error'
                    h.finished_at = datetime.utcnow()

                p.scan_status = 'Erro'
                p.scan_message = '🛑 Processo perdido'
                p.current_task_id = None
                changes += 1

        if changes > 0:
            db.session.commit()
            resp = make_response('''
                <i class="fas fa-band-aid text-warning me-2"></i>
                <span>Auto-Healing Ativo</span>
            ''')
            resp.headers['HX-Trigger'] = 'refreshProjects'
            return resp

    except Exception as e:
        print(f"[AUTO-HEAL ERROR] {e}")
        return '''
            <i class="fas fa-times-circle text-danger me-2"></i>
            <span>Erro Monitor</span>
        '''

    return '''
        <i class="fas fa-cog fa-spin text-primary me-2"></i>
        <span>Processando...</span>
    '''


@main.route('/dashboard')
@login_required
def dashboard_redirect():
    return redirect(url_for('main.dashboard'))


# Quantos projetos podem rodar em paralelo no scan global
GLOBAL_SCAN_CONCURRENCY = 2

@main.route('/scan/global/start', methods=['POST'])
@login_required
def start_global_scan():
    """
    Dispara scans respeitando o limite de GLOBAL_SCAN_CONCURRENCY projetos simultâneos.
    - Marca todos os elegíveis como 'Pendente (fila)' no banco
    - Despacha imediatamente apenas os primeiros N (concurrency)
    - Cada task, ao terminar, acorda o próximo projeto pendente automaticamente
    """
    from .tasks import dispatch_next_pending

    projects = Project.query.filter(
        Project.user_id == current_user.id,
        Project.scan_status.notin_(['Rodando', 'Na fila'])
    ).order_by(Project.id.asc()).all()

    if not projects:
        flash('Nenhum projeto elegível para scan.', 'info')
        return redirect(url_for('main.dashboard'))

    # Marca todos como pendentes (sem despachar ainda)
    for p in projects:
        p.scan_status = 'Na fila'
        p.scan_message = 'Aguardando Worker disponível...'
        p.current_task_id = None

    db.session.commit()

    # Despacha apenas os primeiros N imediatamente
    dispatched = 0
    for p in projects[:GLOBAL_SCAN_CONCURRENCY]:
        task_id = celery_uuid()
        p.current_task_id = task_id
        p.scan_message = 'Aguardando worker disponível...'
        db.session.flush()
        run_scan_task.apply_async(args=[p.id, 'full'], task_id=task_id)
        dispatched += 1

    db.session.commit()

    total = len(projects)
    waiting = total - dispatched
    msg = f'{dispatched} scan(s) iniciado(s)'
    if waiting > 0:
        msg += f', {waiting} aguardando slot.'
    flash(msg, 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/scan/global/stop', methods=['POST'])
@login_required
def stop_global_scan():
    try:
        celery.control.purge()
    except Exception as e:
        print(f"[STOP GLOBAL] Erro ao limpar fila: {e}")

    projects = Project.query.filter(
        Project.user_id == current_user.id,
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).all()

    stopped = 0
    for p in projects:
        if p.current_task_id:
            try:
                celery.control.revoke(p.current_task_id, terminate=True)
            except Exception as e:
                print(f"[STOP GLOBAL] Erro ao revogar task {p.current_task_id}: {e}")

        h = ScanHistory.query.filter_by(
            project_id=p.id, status='running'
        ).order_by(ScanHistory.started_at.desc()).first()
        if h:
            h.status = 'stopped'
            h.finished_at = datetime.utcnow()

        p.scan_status = 'Parado'
        p.scan_message = '🛑 Parada Manual (Global)'
        p.current_task_id = None
        stopped += 1

    db.session.commit()
    flash(f'{stopped} scans interrompidos.' if stopped > 0 else 'Nenhum scan estava rodando.', 'warning' if stopped else 'info')
    return redirect(url_for('main.dashboard'))


# ---------------------------------------------------------------------------
# HTMX PARTIALS
# ---------------------------------------------------------------------------

@main.route('/htmx/stats')
@login_required
def htmx_stats():
    """Atualiza os cards de estatísticas via HTMX (usa serviço centralizado)."""
    stats = get_user_stats(current_user.id)
    return render_template('partials/dashboard_status.html', stats=stats)


@main.route('/project/<int:id>/status_part')
@login_required
def project_status_part(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    return render_template('partials/status_card.html', project=project)


@main.route('/project/<int:id>/controls_part')
@login_required
def project_controls_part(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    # Conta pendentes via SQL — sem carregar project.domains na memória
    pendentes = Domain.query.filter(
        Domain.project_id == id,
        Domain.scanned_vulns == False,
        Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
    ).count()
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/vulns_part')
@login_required
def project_vulns_part(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    # Query direta — sem carregar project.domains nem suas relações (evita N+1)
    vulns = (
        db.session.query(Vulnerability, Domain.name.label('domain_name'))
        .join(Domain, Vulnerability.domain_id == Domain.id)
        .filter(Domain.project_id == id)
        .order_by(
            db.case(
                (Vulnerability.severity == 'critical', 0),
                (Vulnerability.severity == 'high',     1),
                (Vulnerability.severity == 'medium',   2),
                (Vulnerability.severity == 'low',      3),
                else_=4
            ),
            Vulnerability.found_at.desc()
        )
        .all()
    )
    return render_template('partials/vulns_list.html', vulns=vulns, project=project)


@main.route('/project/<int:id>/card_part')
@login_required
def project_card_part(id):
    db.session.expire_all()
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    # Calcula stats via SQL (não carrega todos os domínios)
    card_stats = get_all_projects_card_stats([id]).get(id, {})
    return render_template('partials/dashboard_card.html',
                           project=project, card_stats=card_stats)


@main.route('/project/<int:id>/count_domains')
@login_required
def count_domains(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    count = Domain.query.filter_by(project_id=id).count()
    return str(count)


@main.route('/project/<int:id>/count_vulns')
@login_required
def count_vulns(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    total = Vulnerability.query.join(Domain).filter(Domain.project_id == id).count()
    return str(total)


# ---------------------------------------------------------------------------
# DOMAINS PART (com paginação)
# ---------------------------------------------------------------------------

def parse_discord_search(query_str):
    filters = {
        'status': [],
        'portas': [],
        'tech': [],
        'path': [],
        'sub': [],
        'date': [],
        'ssl': [],
        'general': [],
    }

    if not query_str:
        return filters

    safe_query = query_str.replace(" to ", "__TO__").replace(" até ", "__TO__")
    parts = safe_query.split(' ')

    for part in parts:
        part = part.strip()
        if not part:
            continue
        part = part.replace("__TO__", " to ")
        if part.endswith(','):
            part = part[:-1]

        if ':' in part:
            key, value = part.split(':', 1)
            key = key.lower()

            if key in ['ports']:        key = 'portas'
            if key in ['tecnologias']:  key = 'tech'
            if key in ['paths']:        key = 'path'
            if key in ['subdominio', 'domain']: key = 'sub'
            if key in ['data', 'seen']: key = 'date'
            if key in ['cert']:         key = 'ssl'

            if key in filters:
                if key in ['status', 'sub']:
                    if ',' in value:
                        filters[key].extend([v.strip() for v in value.split(',') if v.strip()])
                    else:
                        filters[key].append(value.strip())
                elif key in ['date', 'ssl']:
                    filters[key].append(value.strip())
                else:
                    if ',' in value:
                        filters[key].append([v.strip() for v in value.split(',') if v.strip()])
                    elif value.strip():
                        filters[key].append([value.strip()])
        else:
            filters['general'].append(part)

    return filters


@main.route('/project/<int:id>/domains_part')
@login_required
def project_domains_part(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    search_query = request.args.get('q', '')
    status_filter = request.args.get('status')
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 200, type=int), 500)  # cap em 500

    query = Domain.query.filter_by(project_id=project.id)

    if search_query:
        filters = parse_discord_search(search_query)

        if filters['status']:
            codes = [int(c) for c in filters['status'] if c.isdigit()]
            if codes:
                query = query.filter(Domain.status_code.in_(codes))

        if filters['portas']:
            or_conds = []
            for group in filters['portas']:
                and_conds = [Domain.open_ports.ilike(f"%{p}%") for p in group]
                or_conds.append(and_(*and_conds))
            query = query.filter(or_(*or_conds))

        if filters['tech']:
            or_conds = []
            for group in filters['tech']:
                and_conds = [Domain.technologies.ilike(f"%{t}%") for t in group]
                or_conds.append(and_(*and_conds))
            query = query.filter(or_(*or_conds))

        if filters['path']:
            or_conds = []
            for group in filters['path']:
                and_conds = [Domain.discovered_paths.ilike(f"%{p}%") for p in group]
                or_conds.append(and_(*and_conds))
            query = query.filter(or_(*or_conds))

        if filters['sub']:
            conds = [Domain.name.ilike(f"%{s}%") for s in filters['sub']]
            query = query.filter(or_(*conds))

        if filters['date']:
            date_str = filters['date'][-1]
            try:
                if ' to ' in date_str:
                    s, e = date_str.split(' to ')
                    start_dt = datetime.strptime(s.strip(), '%Y-%m-%d')
                    end_dt   = datetime.strptime(e.strip(), '%Y-%m-%d').replace(hour=23, minute=59, second=59)
                else:
                    start_dt = datetime.strptime(date_str.strip(), '%Y-%m-%d')
                    end_dt   = start_dt.replace(hour=23, minute=59, second=59)
                query = query.filter(Domain.first_seen.between(start_dt, end_dt))
            except ValueError:
                pass

        if filters['ssl']:
            ssl_str = filters['ssl'][-1]
            if ' to ' in ssl_str:
                s, e = ssl_str.split(' to ')
                query = query.filter(and_(Domain.creation_date >= s.strip(), Domain.creation_date <= e.strip()))
            else:
                query = query.filter(Domain.creation_date == ssl_str.strip())

        for term in filters['general']:
            query = query.filter(or_(
                Domain.name.ilike(f"%{term}%"),
                Domain.technologies.ilike(f"%{term}%"),
            ))

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

    pagination = query.order_by(Domain.first_seen.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    domains = pagination.items

    return render_template('partials/domains_list.html',
                           project=project,
                           domains=domains,
                           pagination=pagination,
                           current_status=status_filter)




@main.route('/project/<int:id>/mark_scanned', methods=['POST'])
@login_required
def mark_all_scanned(id):
    """Marca todos os domínios do projeto como verificados — limpa o alerta de pendentes."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    updated = Domain.query.filter(
        Domain.project_id == id,
        Domain.scanned_vulns == False,
    ).update({Domain.scanned_vulns: True}, synchronize_session=False)

    db.session.commit()
    flash(f'{updated} domínio(s) marcado(s) como verificados.', 'success')
    return redirect(request.referrer or url_for('main.dashboard'))

@main.route('/api/project/<int:id>/search_options')
@login_required
def project_search_options(id):
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    status_q = db.session.query(Domain.status_code).filter_by(project_id=id).distinct().all()
    codes = sorted([str(r[0]) for r in status_q if r[0] and r[0] > 0])

    ports_q = db.session.query(Domain.open_ports).filter_by(project_id=id).all()
    ports_set = set()
    for row in ports_q:
        if row.open_ports:
            for p in row.open_ports.split(','):
                clean = p.strip()
                if clean.isdigit():
                    ports_set.add(int(clean))
    unique_ports = [str(p) for p in sorted(list(ports_set))]

    tech_q = db.session.query(Domain.technologies).filter_by(project_id=id).all()
    tech_set = set()
    for row in tech_q:
        if row.technologies:
            for t in row.technologies.split(','):
                c = t.strip()
                if c and c != "Descoberto via Vuln Scan":
                    tech_set.add(c)

    path_q = db.session.query(Domain.discovered_paths).filter_by(project_id=id).all()
    path_set = set()
    for row in path_q:
        if row.discovered_paths:
            for p in row.discovered_paths.split(','):
                c = p.strip()
                if c and not c.startswith('['):
                    path_set.add(c)

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