"""
services.py — Camada de lógica de negócio.

Extrai cálculos que eram duplicados entre rotas (dashboard vs htmx_stats)
e centraliza queries pesadas para facilitar testes e manutenção.
"""
from . import db
from .models import Project, Domain, Vulnerability
from sqlalchemy import func


def get_user_stats(user_id: int) -> dict:
    """
    Retorna contadores globais para o dashboard de um usuário.
    Usa COUNT no banco (sem carregar objetos na memória).
    """
    total_projects = Project.query.filter_by(user_id=user_id).count()

    total_subs = (
        Domain.query
        .join(Project)
        .filter(Project.user_id == user_id)
        .count()
    )

    total_vulns = (
        Vulnerability.query
        .join(Domain)
        .join(Project)
        .filter(Project.user_id == user_id)
        .count()
    )

    running_scans = Project.query.filter(
        Project.user_id == user_id,
        Project.scan_status.in_(['Rodando', 'Na fila'])
    ).count()

    return {
        'projects': total_projects,
        'subdomains': total_subs,
        'vulns': total_vulns,
        'running': running_scans,
    }


def get_severity_stats(user_id: int) -> dict:
    """
    Retorna distribuição de severidade de vulnerabilidades para um usuário.
    Normaliza para lowercase e calcula percentuais.
    """
    severity_query = (
        db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
        .join(Domain)
        .join(Project)
        .filter(Project.user_id == user_id)
        .group_by(Vulnerability.severity)
        .all()
    )

    counts = {}
    for sev, cnt in severity_query:
        key = str(sev).lower() if sev else 'info'
        counts[key] = counts.get(key, 0) + cnt

    crit = counts.get('critical', 0)
    high = counts.get('high', 0)
    med  = counts.get('medium', 0)
    low  = counts.get('low', 0)
    info = counts.get('info', 0)

    total = crit + high + med + low + info

    def pct(n):
        return round(n / total * 100, 1) if total > 0 else 0

    return {
        'critical': crit,
        'high': high,
        'medium': med,
        'low': low,
        'info': info,
        'pct_critical': pct(crit),
        'pct_high': pct(high),
        'pct_medium': pct(med),
        'pct_low': pct(low + info),
    }


def get_project_domain_stats(project_id: int) -> dict:
    """
    Retorna estatísticas de domínios de um projeto sem carregar todos os objetos.
    Usa GROUP BY no banco.
    """
    from sqlalchemy import case

    result = db.session.query(
        func.count(Domain.id).label('total'),
        func.sum(case((Domain.status_code.between(200, 299), 1), else_=0)).label('ok'),
        func.sum(case((Domain.status_code.between(300, 399), 1), else_=0)).label('redirect'),
        func.sum(case((Domain.status_code >= 400, 1), else_=0)).label('error'),
        func.sum(case(((Domain.status_code == 0) | (Domain.status_code == None), 1), else_=0)).label('dead'),
    ).filter(Domain.project_id == project_id).one()

    return {
        'total':    result.total    or 0,
        'ok':       result.ok       or 0,
        'redirect': result.redirect or 0,
        'error':    result.error    or 0,
        'dead':     result.dead     or 0,
    }


def get_all_projects_card_stats(project_ids: list) -> dict:
    """
    Retorna contadores de status HTTP e vulnerabilidades para uma lista de projetos
    em UMA ÚNICA query cada, sem carregar nenhum objeto Domain na memória.
    Retorna dict: { project_id: { '2xx', '3xx', '4xx', '5xx', 'total', 'vulns', 'pendentes' } }
    """
    if not project_ids:
        return {}

    from sqlalchemy import case, and_

    # --- Contadores de domínios ---
    domain_rows = db.session.query(
        Domain.project_id,
        func.count(Domain.id).label('total'),
        func.sum(case((and_(Domain.status_code >= 200, Domain.status_code < 300), 1), else_=0)).label('c2xx'),
        func.sum(case((and_(Domain.status_code >= 300, Domain.status_code < 400), 1), else_=0)).label('c3xx'),
        func.sum(case((and_(Domain.status_code >= 400, Domain.status_code < 500), 1), else_=0)).label('c4xx'),
        func.sum(case((Domain.status_code >= 500, 1), else_=0)).label('c5xx'),
        func.sum(case((
            and_(
                Domain.scanned_vulns == False,
                Domain.status_code.in_([200, 201, 202, 204, 301, 302, 307, 308])
            ), 1), else_=0
        )).label('pendentes'),
    ).filter(Domain.project_id.in_(project_ids)).group_by(Domain.project_id).all()

    result = {}
    for row in domain_rows:
        result[row.project_id] = {
            'total':    row.total    or 0,
            'c2xx':     row.c2xx     or 0,
            'c3xx':     row.c3xx     or 0,
            'c4xx':     row.c4xx     or 0,
            'c5xx':     row.c5xx     or 0,
            'pendentes': row.pendentes or 0,
            'vulns':    0,
        }

    # --- Contadores de vulnerabilidades ---
    from .models import Vulnerability
    vuln_rows = db.session.query(
        Domain.project_id,
        func.count(Vulnerability.id).label('total_vulns')
    ).join(Vulnerability, Vulnerability.domain_id == Domain.id
    ).filter(Domain.project_id.in_(project_ids)
    ).group_by(Domain.project_id).all()

    for row in vuln_rows:
        if row.project_id in result:
            result[row.project_id]['vulns'] = row.total_vulns or 0

    # Garante entrada para projetos sem nenhum domínio
    for pid in project_ids:
        if pid not in result:
            result[pid] = {'total': 0, 'c2xx': 0, 'c3xx': 0,
                           'c4xx': 0, 'c5xx': 0, 'pendentes': 0, 'vulns': 0}

    return result