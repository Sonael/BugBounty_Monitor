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
import os
import time
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import OperationalError
from sqlalchemy import text

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()

# Limiter usa Redis como storage para manter contagens entre reinicializações
# (se Redis não estiver disponível, cai para memória local silenciosamente)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],   # sem limite global — aplicamos por rota
    storage_uri=os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0').replace('/0', '/2'),
    strategy="fixed-window",
)

# Configuração Global do Celery
celery = Celery(
    __name__,
    broker=os.environ.get('CELERY_BROKER_URL'),
    include=['app.tasks']
)

# Redireciona print() dos workers para stdout — deve estar no nivel do modulo
# para ter efeito antes do Celery configurar o logging
celery.conf.worker_redirect_stdouts       = True
celery.conf.worker_redirect_stdouts_level = 'INFO'

# Agendamento do Beat
celery.conf.beat_schedule = {
    'scan-all-daily': {
        'task': 'app.tasks.run_daily_scan',
        'schedule': crontab(hour=3, minute=0),
    },
}


def create_app():
    app = Flask(__name__)

    # --- Validações de segurança no startup ---
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

    # Sessao persistente — nao expira ao fechar o navegador
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=int(os.environ.get('SESSION_DAYS', 30)))
    app.config['REMEMBER_COOKIE_SECURE']   = False
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_HTTPONLY']  = True
    app.config['SESSION_COOKIE_SAMESITE']  = 'Lax'

    # CSRF: check default desativado — ativado explicitamente por rota via @csrf.protect.
    # Para habilitar globalmente, adicione csrf.init_app(app) e atualize os templates
    # com {{ csrf_token() }} nos formulários (ver MIGRATION_GUIDE.md).
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken']  # suporte a AJAX/HTMX

    # Redis db 1 separado do Celery (db 0) para não poluir filas
    app.config['REDIS_URL'] = (
        os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0').replace('/0', '/1')
    )

    # Sincroniza config do Celery com Flask
    celery.conf.update(app.config)

    # Inicializa extensões
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

    # --- Inicialização com retry de conexão ---
    # Pula espera pelo banco em comandos CLI que nao precisam dele
    # (ex: flask db init, flask db migrate)
    import sys
    _skip_db = (
        len(sys.argv) > 2
        and sys.argv[1] == 'db'
        and sys.argv[2] in {'init', 'migrate', 'upgrade'}
    )
    if not _skip_db:
        with app.app_context():
            wait_for_db()
            init_admin_user()

    register_commands(app)
    return app


# --- CLI commands ---

def register_commands(app):
    """Registra comandos Flask CLI extras."""

    @app.cli.command("wait-for-db")
    def wait_for_db_cmd():
        """Aguarda o banco de dados ficar disponível (para uso no entrypoint do Docker)."""
        wait_for_db()
        print(" Banco pronto.")

    @app.cli.command("create-admin")
    def create_admin_cmd():
        """(Re)cria o usuário admin com base nas variáveis de ambiente."""
        init_admin_user(force=True)


def wait_for_db():
    """
    Aguarda o banco responder antes de prosseguir.
    Resolve o race condition do Docker onde o app sobe antes do Postgres.
    Ao invés de criar tabelas aqui (responsabilidade do Flask-Migrate),
    apenas verifica a conexão.
    """
    max_retries = 30
    sleep_seconds = 2

    print(" [SISTEMA] Aguardando Banco de Dados iniciar...")

    for i in range(max_retries):
        try:
            db.session.execute(text('SELECT 1'))
            db.session.commit()
            print(" [SISTEMA] Banco de Dados conectado!")

            # Aplica migrations pendentes (idempotente — seguro rodar sempre)
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
    """
    Tenta aplicar migrations via Flask-Migrate.
    Cai para db.create_all() se a pasta migrations/ ainda não existir
    (primeiro deploy antes de rodar 'flask db init').
    """
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
    """
    Cria o usuário admin automaticamente a partir do .env.
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