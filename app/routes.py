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
import re
import json
import csv
import io
from sqlalchemy import or_, and_, func
import fnmatch
from datetime import datetime, timedelta

# Casa o formato aceito por _sanitize_domain no scanner — bloqueia injeção shell.
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)+$')


def _clean_target_url(value: str) -> str:
    """Extrai hostname puro de uma string. Retorna '' se inválido."""
    cleaned = (value or '').strip().replace('https://', '').replace('http://', '')
    cleaned = cleaned.split('/')[0].split(':')[0].lower()
    return cleaned if _DOMAIN_RE.match(cleaned) else ''


main = Blueprint('main', __name__)


@main.route('/', methods=['GET'])
def index():
    """Página inicial — redireciona para o dashboard se já logado."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('login.html')


@main.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_post():
    """Autentica o usuário. Rate-limited a 5 tentativas/min por IP."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')

    if not username or not password:
        flash('Preencha usuário e senha.', 'error')
        return redirect(url_for('main.index'))

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        flash('Login incorreto.', 'error')
        return redirect(url_for('main.index'))

    login_user(user, remember=True)
    return redirect(url_for('main.dashboard'))


@main.route('/logout')
@login_required
def logout():
    """Encerra a sessão do usuário atual."""
    logout_user()
    flash('Você foi desconectado com sucesso.', 'info')
    return redirect(url_for('main.index'))


@main.route('/dashboard')
@login_required
def dashboard():
    """Renderiza o dashboard com estatísticas agregadas do usuário."""
    projects = Project.query.filter_by(user_id=current_user.id).all()

    stats    = get_user_stats(current_user.id)
    severity = get_severity_stats(current_user.id)

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
                           recent_activity=recent_activity,
                           now=datetime.utcnow())


@main.route('/add_project', methods=['POST'])
@login_required
def add_project():
    """Cria projeto e dispara baseline via fila global."""
    name = request.form.get('name', '').strip()
    target_raw = request.form.get('target_url', '').strip()

    in_scope_raw = request.form.get('in_scope', '')[:10000]
    out_of_scope_raw = request.form.get('out_of_scope', '')[:10000]

    if not name or not target_raw:
        flash('Nome e URL Alvo são obrigatórios!', 'error')
        return redirect(url_for('main.dashboard'))

    target_clean = _clean_target_url(target_raw)
    if not target_clean:
        flash('URL alvo inválida. Use o formato "alvo.com" (sem http:// ou paths).', 'error')
        return redirect(url_for('main.dashboard'))

    discovery_enabled = bool(request.form.get('auto_discovery'))
    fuzzing_enabled = bool(request.form.get('enable_fuzzing'))
    vuln_scan_enabled = bool(request.form.get('enable_vuln_scan'))
    vuln_scan_recon_enabled = bool(request.form.get('enable_vuln_recon'))

    new_project = Project(
        name=name,
        target_url=target_clean,
        out_of_scope=out_of_scope_raw,
        in_scope=in_scope_raw,
        discovery_enabled=discovery_enabled,
        fuzzing_enabled=fuzzing_enabled,
        user_id=current_user.id,
        vuln_scan_enabled=vuln_scan_enabled,
        vuln_scan_recon_enabled=vuln_scan_recon_enabled,
        scan_status='Parado',
        scan_message='Aguardando início...',
    )
    db.session.add(new_project)
    db.session.flush()

    if in_scope_raw:
        for line in in_scope_raw.splitlines():
            clean = _clean_target_url(line)
            if clean and not Domain.query.filter_by(name=clean, project_id=new_project.id).first():
                db.session.add(Domain(name=clean, project_id=new_project.id))

    if not Domain.query.filter_by(name=target_clean, project_id=new_project.id).first():
        db.session.add(Domain(name=target_clean, project_id=new_project.id))

    db.session.commit()

    _dispatch_or_queue(new_project, 'baseline')

    flash(f'Projeto "{name}" criado! Scan adicionado à fila.', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/project/<int:id>')
@login_required
def project_details(id):
    """Página de detalhes de um projeto (lista subdomínios + vulns)."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    stats = get_project_domain_stats(id)

    sorted_domains = (
        Domain.query
        .filter_by(project_id=id)
        .order_by(Domain.first_seen.desc())
        .limit(200)
        .all()
    )

    return render_template('project.html',
                           project=project,
                           stats=stats,
                           domains=sorted_domains)


GLOBAL_SCAN_CONCURRENCY = int(os.environ.get('GLOBAL_SCAN_CONCURRENCY', 2))

# Precisa bater com o filtro de vuln scan em tasks.py.
SCANNABLE_STATUS_CODES = [200, 201, 202, 204, 301, 302, 307, 308, 403]


def _count_pendentes(project_id):
    """Conta domínios vivos ainda não verificados para vuln scan."""
    return Domain.query.filter(
        Domain.project_id == project_id,
        Domain.scanned_vulns == False,
        Domain.status_code.in_(SCANNABLE_STATUS_CODES),
    ).count()


def _count_active_scans():
    """Conta projetos ativos no sistema inteiro (todos usuários)."""
    return Project.query.filter(
        db.or_(
            Project.scan_status == 'Rodando',
            db.and_(
                Project.scan_status == 'Na fila',
                Project.current_task_id.isnot(None)
            )
        )
    ).count()


def _acquire_dispatch_lock(ttl=10, max_wait=5.0):
    """Adquire o mutex Redis de despacho, esperando até max_wait segundos.

    Retorna (acquired, redis_client). Se acquired=False (timeout), o caller
    DEVE abortar a operação — outro processo está despachando.
    """
    try:
        import redis as redis_lib
        import time as _time
        r = redis_lib.Redis(
            host=os.environ.get('REDIS_HOST', 'redis'),
            port=int(os.environ.get('REDIS_PORT', 6379)),
            db=1,
        )
        deadline = _time.monotonic() + max_wait
        while True:
            if r.set('dispatch_lock', '1', nx=True, ex=ttl):
                return True, r
            if _time.monotonic() >= deadline:
                return False, r
            _time.sleep(0.1)
    except Exception as e:
        print(f"[DISPATCH] Redis indisponível ({e}) — sem mutex.")
        return True, None


def _release_dispatch_lock(r):
    """Libera o mutex de despacho. No-op se r for None."""
    if r:
        try:
            r.delete('dispatch_lock')
        except Exception:
            pass


def _dispatch_or_queue(project, mode):
    """Despacha task se houver slot, ou marca como fila passiva.

    Em fila passiva o projeto fica com current_task_id=None e é acordado
    por dispatch_next_pending quando outra task termina.
    """
    acquired, r = _acquire_dispatch_lock()
    if not acquired:
        _release_dispatch_lock(r)
        project.scan_status = 'Na fila'
        project.scan_message = f'mode:{mode}'
        project.current_task_id = None
        db.session.commit()
        print(f"[DISPATCH] {project.name} enfileirado (mutex ocupado)")
        return

    try:
        ativos = _count_active_scans()
        task_id = celery_uuid()

        if ativos < GLOBAL_SCAN_CONCURRENCY:
            project.scan_status = 'Na fila'
            project.scan_message = f'Aguardando worker ({mode})...'
            project.current_task_id = task_id
            db.session.commit()
            run_scan_task.apply_async(args=[project.id, mode], task_id=task_id)
            print(f"[DISPATCH] {project.name} despachado ({ativos+1}/{GLOBAL_SCAN_CONCURRENCY})")
        else:
            project.scan_status = 'Na fila'
            project.scan_message = f'mode:{mode}'
            project.current_task_id = None
            db.session.commit()
            print(f"[DISPATCH] {project.name} enfileirado — slots cheios ({ativos}/{GLOBAL_SCAN_CONCURRENCY})")
    finally:
        _release_dispatch_lock(r)


@main.route('/project/<int:id>/scan_card/<mode>', methods=['POST'])
@login_required
def start_scan_from_card(id, mode):
    """Inicia scan e retorna o card atualizado (botões rápidos do dashboard)."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    if mode not in ['recon', 'vuln', 'full', 'baseline']:
        return "Modo inválido", 400

    if project.scan_status in ['Rodando', 'Na fila']:
        card_stats = get_all_projects_card_stats([id]).get(id, {})
        return render_template('partials/dashboard_card.html',
                               project=project, card_stats=card_stats,
                               now=datetime.utcnow())

    _dispatch_or_queue(project, mode)

    card_stats = get_all_projects_card_stats([id]).get(id, {})
    return render_template('partials/dashboard_card.html',
                           project=project, card_stats=card_stats,
                           now=datetime.utcnow())


@main.route('/project/<int:id>/scan/<mode>', methods=['POST'])
@login_required
def start_scan(id, mode):
    """Inicia scan e retorna o partial de controles."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    if mode not in ['recon', 'vuln', 'full', 'baseline']:
        return "Modo inválido", 400

    if project.scan_status in ['Rodando', 'Na fila']:
        pendentes = _count_pendentes(id)
        return render_template('partials/controls.html', project=project, pendentes=pendentes)

    _dispatch_or_queue(project, mode)

    pendentes = _count_pendentes(project.id)
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/stop', methods=['POST'])
@login_required
def stop_scan(id):
    """Interrompe scan ativo (Rodando ou Na fila) e libera o slot."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    was_active = project.scan_status in ['Rodando', 'Na fila']

    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except Exception:
            pass

    if was_active:
        history = ScanHistory.query.filter_by(
            project_id=id, status='running'
        ).order_by(ScanHistory.started_at.desc()).first()
        if history:
            history.status = 'stopped'
            history.finished_at = datetime.utcnow()

        project.scan_status = 'Parado'
        project.scan_message = ' Scan interrompido pelo usuário.'
        project.current_task_id = None
        db.session.commit()

        try:
            from .tasks import dispatch_next_pending
            dispatch_next_pending()
        except Exception as e:
            print(f"[STOP] dispatch_next_pending falhou: {e}")

        flash('Scan interrompido.', 'warning')

    pendentes = _count_pendentes(project.id)
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/edit', methods=['POST'])
@login_required
def edit_project(id):
    """Atualiza configuração do projeto e ajusta o escopo (in/out)."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    name = request.form.get('name', '').strip()
    target_raw = request.form.get('target_url', '').strip()

    in_scope_raw = request.form.get('in_scope', '')[:10000]
    out_of_scope_raw = request.form.get('out_of_scope', '')[:10000]

    if not name or not target_raw:
        flash('Nome e URL Alvo não podem ficar vazios.', 'error')
        return redirect(request.referrer or url_for('main.dashboard'))

    target_clean = _clean_target_url(target_raw)
    if not target_clean:
        flash('URL alvo inválida. Use o formato "alvo.com".', 'error')
        return redirect(request.referrer or url_for('main.dashboard'))

    project.name = name
    project.target_url = target_clean
    project.in_scope = in_scope_raw
    project.out_of_scope = out_of_scope_raw
    project.discovery_enabled = bool(request.form.get('auto_discovery'))
    project.fuzzing_enabled = bool(request.form.get('enable_fuzzing'))
    project.vuln_scan_enabled = bool(request.form.get('enable_vuln_scan'))
    project.vuln_scan_recon_enabled = bool(request.form.get('enable_vuln_recon'))

    added_count = 0
    if in_scope_raw:
        for line in in_scope_raw.splitlines():
            clean = _clean_target_url(line)
            if clean and not Domain.query.filter_by(name=clean, project_id=id).first():
                db.session.add(Domain(name=clean, project_id=id))
                added_count += 1

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
    """Exclui projeto e libera slot se havia scan ativo."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    was_active = project.scan_status in ['Rodando', 'Na fila']
    if project.current_task_id:
        try:
            celery.control.revoke(project.current_task_id, terminate=True)
        except Exception:
            pass
    db.session.delete(project)
    db.session.commit()

    if was_active:
        try:
            from .tasks import dispatch_next_pending
            dispatch_next_pending()
        except Exception as e:
            print(f"[DELETE] dispatch_next_pending falhou: {e}")

    flash(f'Projeto "{project.name}" foi apagado.', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/project/<int:id>/export/<fmt>')
@login_required
def export_project(id, fmt):
    """Exporta domínios + vulnerabilidades em JSON ou CSV."""
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


@main.route('/api/heal_projects')
@login_required
def heal_projects_api():
    """Detecta scans órfãos (sem worker correspondente) e marca como Erro.

    Retorna um fragmento HTML para o badge de status no header.
    """
    running_projects = Project.query.filter(
        Project.scan_status == 'Rodando',
        Project.user_id == current_user.id
    ).all()

    if not running_projects:
        return '''
            <i class="fas fa-server text-success me-2"></i>
            <span>Sistema Online</span>
        '''

    changes = 0
    try:
        # 1s frequentemente perde a resposta do worker; 3s é estável.
        inspector = celery.control.inspect(timeout=3.0)
        active = inspector.active()

        if active is None:
            return '''
                <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                <span class="text-danger fw-bold">Worker Offline</span>
            '''

        real_task_ids = set()
        for w_tasks in [active, inspector.reserved(), inspector.scheduled()]:
            if w_tasks:
                for _, tasks_list in w_tasks.items():
                    for t in tasks_list:
                        tid = t.get('id') or (t.get('request') or {}).get('id')
                        if tid:
                            real_task_ids.add(tid)

        # Período de graça: evita marcar como perdido enquanto o worker
        # ainda está pegando a task da fila.
        grace_cutoff = datetime.utcnow() - timedelta(seconds=30)

        for p in running_projects:
            if p.current_task_id and p.current_task_id in real_task_ids:
                continue
            if p.last_scan_date and p.last_scan_date > grace_cutoff:
                continue

            h = ScanHistory.query.filter_by(
                project_id=p.id, status='running'
            ).order_by(ScanHistory.started_at.desc()).first()
            if h:
                h.status = 'error'
                h.finished_at = datetime.utcnow()

            p.scan_status = 'Erro'
            p.scan_message = ' Processo perdido'
            p.current_task_id = None
            changes += 1

        if changes > 0:
            db.session.commit()
            return '''
                <i class="fas fa-band-aid text-warning me-2"></i>
                <span>Auto-Healing Ativo</span>
            '''

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


@main.route('/scan/global/start', methods=['POST'])
@login_required
def start_global_scan():
    """Inicia scan 'full' em todos os projetos elegíveis, respeitando o cap global."""
    projects = Project.query.filter(
        Project.user_id == current_user.id,
        Project.scan_status.notin_(['Rodando', 'Na fila'])
    ).order_by(Project.id.asc()).all()

    if not projects:
        flash('Nenhum projeto elegível para scan.', 'info')
        return redirect(url_for('main.dashboard'))

    acquired, r = _acquire_dispatch_lock(ttl=15)
    if not acquired:
        _release_dispatch_lock(r)
        flash('Outro despacho em andamento. Tente novamente em alguns segundos.', 'warning')
        return redirect(url_for('main.dashboard'))

    dispatched = 0
    try:
        ativos = _count_active_scans()
        slots = max(0, GLOBAL_SCAN_CONCURRENCY - ativos)

        for p in projects[:slots]:
            task_id = celery_uuid()
            p.scan_status = 'Na fila'
            p.scan_message = 'Aguardando worker (full)...'
            p.current_task_id = task_id
            run_scan_task.apply_async(args=[p.id, 'full'], task_id=task_id)
            dispatched += 1

        for p in projects[slots:]:
            p.scan_status = 'Na fila'
            p.scan_message = 'mode:full'
            p.current_task_id = None

        db.session.commit()
    finally:
        _release_dispatch_lock(r)

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
    """Interrompe todos os scans do usuário (revoga task a task — não usa purge global)."""
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
        p.scan_message = ' Parada Manual (Global)'
        p.current_task_id = None
        stopped += 1

    db.session.commit()

    if stopped > 0:
        try:
            from .tasks import dispatch_next_pending
            dispatch_next_pending()
        except Exception as e:
            print(f"[STOP GLOBAL] dispatch_next_pending falhou: {e}")

    flash(f'{stopped} scans interrompidos.' if stopped > 0 else 'Nenhum scan estava rodando.', 'warning' if stopped else 'info')
    return redirect(url_for('main.dashboard'))


@main.route('/htmx/stats')
@login_required
def htmx_stats():
    """Atualiza os cards de estatísticas via HTMX."""
    stats = get_user_stats(current_user.id)
    return render_template('partials/dashboard_status.html', stats=stats)


@main.route('/project/<int:id>/status_part')
@login_required
def project_status_part(id):
    """Partial HTMX: card de status do scan."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    return render_template('partials/status_card.html', project=project)


@main.route('/project/<int:id>/controls_part')
@login_required
def project_controls_part(id):
    """Partial HTMX: botões de controle de scan."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    pendentes = _count_pendentes(id)
    return render_template('partials/controls.html', project=project, pendentes=pendentes)


@main.route('/project/<int:id>/vulns_part')
@login_required
def project_vulns_part(id):
    """Partial HTMX: lista de vulnerabilidades ordenadas por severidade."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    # Query direta evita N+1 ao não materializar project.domains.
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
    """Partial HTMX: card do projeto no dashboard."""
    db.session.expire_all()
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    card_stats = get_all_projects_card_stats([id]).get(id, {})
    return render_template('partials/dashboard_card.html',
                           project=project, card_stats=card_stats,
                           now=datetime.utcnow())


@main.route('/project/<int:id>/count_domains')
@login_required
def count_domains(id):
    """Retorna a contagem total de domínios do projeto."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    count = Domain.query.filter_by(project_id=id).count()
    return str(count)


@main.route('/project/<int:id>/count_vulns')
@login_required
def count_vulns(id):
    """Retorna a contagem total de vulnerabilidades do projeto."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)
    total = Vulnerability.query.join(Domain).filter(Domain.project_id == id).count()
    return str(total)


def parse_discord_search(query_str):
    """Faz parse de query estilo Discord ('status:200 tech:nginx,apache').

    Retorna dict com chaves: status, portas, tech, path, sub, date, ssl, general.
    Valores comuns ficam em lista; status/sub são flat; date/ssl pegam o último.
    """
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

    # Preserva 'YYYY-MM-DD to YYYY-MM-DD' antes do split por espaço.
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
    """Partial HTMX: tabela de domínios com filtros, ordenação e paginação."""
    project = Project.query.get_or_404(id)
    if project.user_id != current_user.id:
        abort(403)

    search_query = request.args.get('q', '')
    status_filter = request.args.get('status')
    page     = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 200, type=int), 500)
    sort_by  = request.args.get('sort', 'first_seen')
    sort_dir = request.args.get('dir', 'desc')

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
            query = query.filter(or_(Domain.status_code == 0, Domain.status_code.is_(None)))
        elif status_filter.isdigit():
            query = query.filter_by(status_code=int(status_filter))

    _sort_col = {
        'status':     Domain.status_code,
        'ports':      Domain.open_ports,
        'name':       Domain.name,
        'first_seen': Domain.first_seen,
    }.get(sort_by, Domain.first_seen)

    if sort_dir == 'asc':
        query = query.order_by(_sort_col.asc().nullslast())
    else:
        query = query.order_by(_sort_col.desc().nullslast())

    total_filtered = query.count()

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    domains = pagination.items

    return render_template('partials/domains_list.html',
                           project=project,
                           domains=domains,
                           pagination=pagination,
                           current_status=status_filter,
                           total_filtered=total_filtered,
                           sort_by=sort_by,
                           sort_dir=sort_dir)


@main.route('/project/<int:id>/mark_scanned', methods=['POST'])
@login_required
def mark_all_scanned(id):
    """Marca todos os domínios do projeto como verificados (limpa pendentes)."""
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
    """Retorna valores únicos por categoria para autocomplete da busca."""
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
