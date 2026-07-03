from flask import Flask
from flask_login import LoginManager
from database.connection import SessionLocal
from database.models import User

def create_app():
    import os
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "aegis_super_secret_key_change_me_in_prod")
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

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    return app
