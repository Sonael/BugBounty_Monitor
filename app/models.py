from . import db
from flask_login import UserMixin
from datetime import datetime


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class SystemState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    last_daily_scan = db.Column(db.Date, nullable=True)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target_url = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scan_status = db.Column(db.String(50), default="Parado")
    scan_message = db.Column(db.String(200), default="Aguardando inicio")
    last_scan_date = db.Column(db.DateTime, nullable=True)

    current_task_id = db.Column(db.String(50), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domains = db.relationship('Domain', backref='project', lazy=True, cascade="all, delete-orphan")
    scan_histories = db.relationship('ScanHistory', backref='project', lazy=True,
                                     cascade="all, delete-orphan", order_by="ScanHistory.started_at.desc()")

    # Limites de tamanho para evitar payloads malformados quebrarem o fnmatch
    out_of_scope = db.Column(db.Text(), default="")
    in_scope = db.Column(db.Text(), default="")
    discovery_enabled = db.Column(db.Boolean, default=True)

    fuzzing_enabled = db.Column(db.Boolean, default=False)

    vuln_scan_enabled = db.Column(db.Boolean, default=False)
    vuln_scan_recon_enabled = db.Column(db.Boolean, default=False)


class Domain(db.Model):
    __tablename__ = 'domain'

    # Índices compostos para acelerar as queries mais frequentes
    __table_args__ = (
        db.Index('ix_domain_project_status', 'project_id', 'status_code'),
        db.Index('ix_domain_project_first_seen', 'project_id', 'first_seen'),
        db.Index('ix_domain_project_scanned', 'project_id', 'scanned_vulns'),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    scanned_vulns = db.Column(db.Boolean, default=False)
    status_code = db.Column(db.Integer, default=0)

    technologies = db.Column(db.Text, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    vulnerabilities = db.relationship('Vulnerability', backref='domain', lazy=True, cascade="all, delete-orphan")

    # open_ports mantido como campo texto para compatibilidade com templates existentes.
    # Novos dados são gravados também na tabela Port (normalizada) para queries precisas.
    open_ports = db.Column(db.Text, nullable=True)
    ports = db.relationship('Port', backref='domain', lazy=True, cascade="all, delete-orphan")

    dns_info = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    discovered_paths = db.Column(db.Text, nullable=True)
    creation_date = db.Column(db.String(50), nullable=True)


class Port(db.Model):
    """
    Tabela normalizada de portas abertas por domínio.
    Permite queries exatas como: Domain.ports.any(Port.port_number == 443)
    em vez do ILIKE frágil sobre o campo texto open_ports.
    """
    __tablename__ = 'port'
    __table_args__ = (
        db.UniqueConstraint('domain_id', 'port_number', name='uq_domain_port'),
        db.Index('ix_port_number', 'port_number'),
    )

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default='tcp')
    found_at = db.Column(db.DateTime, default=datetime.utcnow)


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tool = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=True)
    description = db.Column(db.Text, nullable=True)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)


class ScanHistory(db.Model):
    """
    Registro imutável de cada execução de scan.
    Permite comparar superfície de ataque entre runs (novos domínios, vulns, etc).
    """
    __tablename__ = 'scan_history'
    __table_args__ = (
        db.Index('ix_scan_history_project_started', 'project_id', 'started_at'),
    )

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    task_id = db.Column(db.String(50), nullable=True)

    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    finished_at = db.Column(db.DateTime, nullable=True)

    mode = db.Column(db.String(20), nullable=False)  # recon, full, vuln, baseline
    # running → completed | error | stopped
    status = db.Column(db.String(20), default='running', nullable=False)

    # Métricas capturadas ao final
    new_domains = db.Column(db.Integer, default=0)
    total_domains = db.Column(db.Integer, default=0)
    alive_hosts = db.Column(db.Integer, default=0)
    new_vulns = db.Column(db.Integer, default=0)
    total_vulns = db.Column(db.Integer, default=0)

    # Resumo livre em JSON (ex: contagens por severidade, ferramentas usadas)
    summary = db.Column(db.Text, nullable=True)

    @property
    def duration_minutes(self):
        if self.finished_at and self.started_at:
            return round((self.finished_at - self.started_at).total_seconds() / 60, 1)
        return None