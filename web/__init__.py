from flask import Flask
from flask_login import LoginManager
from database.connection import SessionLocal
from database.models import User

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "aegis_super_secret_key_change_me_in_prod"
    app.config["VERIFICATION_SIMULATION_MODE"] = True
    app.config["VERIFICATION_TOKEN_EXPIRY_HOURS"] = 48

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        db = SessionLocal()
        try:
            return db.query(User).filter(User.id == int(user_id)).first()
        finally:
            db.close()

    # Register blueprints
    from .auth import auth_bp
    from .dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    return app
