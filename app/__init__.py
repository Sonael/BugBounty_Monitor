from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from celery import Celery
from celery.schedules import crontab
import os
import time
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import OperationalError

db = SQLAlchemy()
login_manager = LoginManager()

# Configuração Global do Celery
celery = Celery(__name__, 
                broker=os.environ.get('CELERY_BROKER_URL'),
                include=['app.tasks']) 

# Agendamento do Beat
celery.conf.beat_schedule = {
    'scan-all-daily': {
        'task': 'app.tasks.run_daily_scan',
        'schedule': crontab(hour=3, minute=0), # Roda às 00:00 AM crontab(hour=3, minute=0)
    },
}

def create_app():
    app = Flask(__name__)
    
    # Configurações de Segurança e Banco
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chave-padrao-dev-insegura')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Sincroniza config do Celery
    celery.conf.update(app.config)
    
    # Inicializa Extensões
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # --- INICIALIZAÇÃO INTELIGENTE (Wait-for-DB) ---
    with app.app_context():
        # 1. Espera o banco acordar antes de tentar qualquer coisa
        wait_for_db(app)
        
        # 2. Verifica se precisa criar o Admin padrão
        init_admin_user()

    return app

def wait_for_db(app):
    """
    Tenta conectar ao banco repetidamente.
    Resolve o erro 'Connection Refused' quando o container sobe rápido demais.
    """
    max_retries = 30
    sleep_seconds = 2
    
    print("⏳ [SISTEMA] Aguardando Banco de Dados iniciar...")
    
    for i in range(max_retries):
        try:
            # Tenta criar as tabelas. Se o banco não estiver pronto, isso gera erro.
            db.create_all()
            print("✅ [SISTEMA] Banco de Dados conectado com sucesso!")
            return
        except OperationalError:
            print(f"⚠️  [SISTEMA] Banco indisponível... Tentando novamente em {sleep_seconds}s ({i+1}/{max_retries})")
            time.sleep(sleep_seconds)
        except Exception as e:
            print(f"❌ [SISTEMA] Erro inesperado no banco: {e}")
            time.sleep(sleep_seconds)
            
    # Se falhar 30 vezes, deixa o erro subir para o Docker reiniciar o container
    print("❌ [SISTEMA] Falha Crítica: O Banco de Dados não respondeu.")
    raise Exception("Database connection failed after multiple retries")

def init_admin_user():
    """
    Cria o usuário admin automaticamente baseando-se no .env
    """
    from .models import User
    
    # Pega do .env ou usa padrão
    admin_user = os.environ.get('ADMIN_USER', 'admin')
    admin_pass = os.environ.get('ADMIN_PASSWORD', 'admin123')
    
    try:
        if not User.query.filter_by(username=admin_user).first():
            print(f"⚙️  [SETUP] Criando usuário administrador '{admin_user}'...")
            new_user = User(
                username=admin_user, 
                password=generate_password_hash(admin_pass, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()
            print("✅ [SETUP] Admin criado com sucesso!")
        else:
            pass
    except Exception as e:
        print(f"⚠️  [SETUP] Aviso ao verificar Admin: {e}")