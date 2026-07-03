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
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'self'; frame-src 'self';"
        response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Run startup database self-healing maintenance check
    try:
        from database.models import Assessment, ScanExecution, ReconExecution, AuditLog
        import datetime
        db_start = SessionLocal()
        
        running_scans = db_start.query(ScanExecution).filter(ScanExecution.status == "RUNNING").all()
        for scan in running_scans:
            scan.status = "FAILED"
            scan.completed_at = datetime.datetime.now()
            db_start.add(AuditLog(
                assessment_id=scan.assessment_id,
                event_type="SYSTEM_INTERRUPTED",
                event_details="Scan execution was interrupted due to a system restart/crash."
            ))

        running_recons = db_start.query(ReconExecution).filter(ReconExecution.status == "RUNNING").all()
        for recon in running_recons:
            recon.status = "FAILED"
            recon.completed_at = datetime.datetime.now()
            db_start.add(AuditLog(
                assessment_id=recon.assessment_id,
                event_type="SYSTEM_INTERRUPTED",
                event_details="Reconnaissance was interrupted due to a system restart/crash."
            ))

        running_assessments = db_start.query(Assessment).filter(Assessment.status == "RUNNING").all()
        for ass in running_assessments:
            ass.status = "FAILED"
            ass.completed_at = datetime.datetime.now()
            db_start.add(AuditLog(
                assessment_id=ass.id,
                event_type="SYSTEM_INTERRUPTED",
                event_details="Assessment execution was interrupted due to a system restart/crash."
            ))
        db_start.commit()
    except Exception as e:
        print(f"Startup maintenance failed: {e}")
    finally:
        db_start.close()

    return app
