from . import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


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


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    scanned_vulns = db.Column(db.Boolean, default=False)
    status_code = db.Column(db.Integer, default=0)
    
    technologies = db.Column(db.Text, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    vulnerabilities = db.relationship('Vulnerability', backref='domain', lazy=True, cascade="all, delete-orphan")
    open_ports = db.Column(db.String(200), nullable=True) 
    dns_info = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    discovered_paths = db.Column(db.Text, nullable=True)

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tool = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=True)
    description = db.Column(db.Text, nullable=True)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)