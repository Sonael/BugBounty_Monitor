from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from celery import Celery
from celery.schedules import crontab
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import time
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import OperationalError
from sqlalchemy import text

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

# Redis db 2 para o limiter — db 0 é o broker Celery, db 1 é cache da app.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0').replace('/0', '/2'),
    strategy="fixed-window",
)

celery = Celery(
    __name__,
    broker=os.environ.get('CELERY_BROKER_URL'),
    include=['app.tasks']
)

# Em nível de módulo para ter efeito antes do Celery configurar o logging.
celery.conf.worker_redirect_stdouts       = True
celery.conf.worker_redirect_stdouts_level = 'INFO'

celery.conf.beat_schedule = {
    'scan-all-daily': {
        'task': 'app.tasks.run_daily_scan',
        'schedule': crontab(hour=3, minute=0),
    },
}


def create_app():
    """Constrói e configura a instância Flask da aplicação."""
    app = Flask(__name__)

    # Confia em X-Forwarded-* (1 proxy). Sem isso o rate-limit usa o IP
    # do proxy e bloqueia todos os usuários simultaneamente.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        raise RuntimeError(" [CONFIG] SECRET_KEY não definida!")

    admin_pass = os.environ.get('ADMIN_PASSWORD')
    if not admin_pass:
        raise RuntimeError(
            " [CONFIG] ADMIN_PASSWORD não definida! "
            "Configure no .env antes de iniciar."
        )

    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=int(os.environ.get('SESSION_DAYS', 30)))
    app.config['REMEMBER_COOKIE_SECURE']   = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'

    app.config['WTF_CSRF_CHECK_DEFAULT'] = True
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']

    app.config['REDIS_URL'] = (
        os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0').replace('/0', '/1')
    )

    celery.conf.update(app.config)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.login_view = 'main.index'

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    import sys

    # Pula init pesado quando o processo é worker/beat do Celery —
    # caso contrário o worker bloqueia 30-40s tentando conectar no DB.
    _celery_worker = any(
        arg in sys.argv[0]
        for arg in ['celery', 'worker', 'beat']
    ) or 'celery' in ' '.join(sys.argv)

    _skip_db = (
        _celery_worker
        or (
            len(sys.argv) > 2
            and sys.argv[1] == 'db'
            and sys.argv[2] in {'init', 'migrate', 'upgrade'}
        )
    )

    if not _skip_db:
        with app.app_context():
            wait_for_db()
            init_admin_user()
            reset_orphaned_scans()

    register_commands(app)
    return app


def reset_orphaned_scans():
    """Reseta scans que ficaram 'Rodando'/'Na fila' após reinicialização.

    Sem isso o auto-heal marca todos como 'Erro: Processo perdido' no
    primeiro polling após o boot — confuso para o usuário.
    """
    try:
        from .models import Project, ScanHistory
        from datetime import datetime as _dt

        orphaned = Project.query.filter(
            Project.scan_status.in_(['Rodando', 'Na fila'])
        ).all()

        if not orphaned:
            return

        for p in orphaned:
            h = ScanHistory.query.filter_by(
                project_id=p.id, status='running'
            ).order_by(ScanHistory.started_at.desc()).first()
            if h:
                h.status = 'stopped'
                h.finished_at = _dt.utcnow()

            p.scan_status = 'Parado'
            p.scan_message = 'Interrompido por reinicialização do sistema.'
            p.current_task_id = None

        db.session.commit()
        print(f" [STARTUP] {len(orphaned)} scan(s) órfão(s) resetado(s).")
    except Exception as e:
        db.session.rollback()
        print(f"  [STARTUP] Falha ao resetar scans órfãos: {e}")


def register_commands(app):
    """Registra comandos Flask CLI extras."""

    @app.cli.command("wait-for-db")
    def wait_for_db_cmd():
        """Aguarda o banco de dados ficar disponível (usado pelo entrypoint do Docker)."""
        wait_for_db()
        print(" Banco pronto.")

    @app.cli.command("create-admin")
    def create_admin_cmd():
        """(Re)cria o usuário admin com base nas variáveis de ambiente."""
        init_admin_user(force=True)


def wait_for_db():
    """Aguarda o banco responder e aplica migrations pendentes.

    Resolve o race do docker-compose onde o app sobe antes do Postgres.
    Não cria tabelas diretamente — delega ao Flask-Migrate.
    """
    max_retries = 30
    sleep_seconds = 2

    print(" [SISTEMA] Aguardando Banco de Dados iniciar...")

    for i in range(max_retries):
        try:
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            print(" [SISTEMA] Banco de Dados conectado!")
            _apply_migrations()
            return

        except OperationalError:
            print(f"  [SISTEMA] Banco indisponível... ({i + 1}/{max_retries})")
            time.sleep(sleep_seconds)
        except Exception as e:
            print(f"  [SISTEMA] Erro inesperado: {e}")
            time.sleep(sleep_seconds)

    print(" [SISTEMA] Falha Crítica: banco não respondeu.")
    raise Exception("Database connection failed after multiple retries")


def _apply_migrations():
    """Aplica migrations Flask-Migrate, com fallback para create_all."""
    try:
        from flask_migrate import upgrade as db_upgrade
        db_upgrade()
        print(" [MIGRATE] Schema atualizado via Flask-Migrate.")
    except Exception as e:
        print(f"  [MIGRATE] Flask-Migrate falhou ({e}), usando db.create_all() como fallback.")
        try:
            db.create_all()
            print(" [MIGRATE] Tabelas criadas via db.create_all().")
        except Exception as e2:
            print(f" [MIGRATE] Falha também no create_all: {e2}")
            raise


def init_admin_user(force=False):
    """Cria/atualiza o usuário admin a partir do .env.

    Com force=True, atualiza a senha mesmo se o usuário já existir.
    """
    from .models import User

    admin_user = os.environ.get('ADMIN_USER', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD')

    if not admin_pass:
        print("  [SETUP] ADMIN_PASSWORD não definida — pulando criação do admin.")
        return

    try:
        existing = User.query.filter_by(username=admin_user).first()

        if not existing:
            print(f"  [SETUP] Criando usuário '{admin_user}'...")
            new_user = User(
                username=admin_user,
                password=generate_password_hash(admin_pass, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()
            print(" [SETUP] Admin criado com sucesso!")

        elif force:
            print(f"  [SETUP] Atualizando senha do usuário '{admin_user}'...")
            existing.password = generate_password_hash(admin_pass, method='pbkdf2:sha256')
            db.session.commit()
            print(" [SETUP] Senha atualizada.")

    except Exception as e:
        print(f"  [SETUP] Aviso ao verificar Admin: {e}")
