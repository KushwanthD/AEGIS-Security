import os
import sys

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import engine, SessionLocal, Base
from database.models import User, ThreatIntel
from werkzeug.security import generate_password_hash
from sqlalchemy import text

def run_migrations():
    """Apply schema migrations not handled by create_all.
    Each migration runs in its own session so a failure never blocks the others.
    """
    migrations = [
        ("ALTER TABLE Reports ADD COLUMN pdf_data BLOB", "pdf_data on Reports"),
        ("ALTER TABLE Assets ADD COLUMN ssh_credentials TEXT", "ssh_credentials on Assets"),
        ("ALTER TABLE ScanResults ADD COLUMN epss_score FLOAT", "epss_score on ScanResults"),
        ("ALTER TABLE ScanResults ADD COLUMN epss_percentile FLOAT", "epss_percentile on ScanResults"),
        ("ALTER TABLE CorrelatedFindings ADD COLUMN epss_score FLOAT", "epss_score on CorrelatedFindings"),
        ("ALTER TABLE CorrelatedFindings ADD COLUMN epss_percentile FLOAT", "epss_percentile on CorrelatedFindings")
    ]
    
    for sql, name in migrations:
        db = SessionLocal()
        try:
            db.execute(text(sql))
            db.commit()
            print(f"Migration successful: {name}")
        except Exception:
            db.rollback()  # Column/table likely already exists
        finally:
            db.close()


def seed_threat_intel():
    db = SessionLocal()
    try:
        if db.query(ThreatIntel).count() == 0:
            print("Seeding ThreatIntel table...")
            db.add_all([
                ThreatIntel(
                    technology="SSH", risk_level="HIGH",
                    threat_title="Exposed Administrative Service (SSH)",
                    threat_description="SSH service is exposed to the internet. Attacker can perform brute force or vulnerability exploit.",
                    recommended_action="Restrict SSH access to trusted networks, use strong key-based authentication, or enforce VPN requirements.",
                    source="AEGIS Internal Threat Feed"
                ),
                ThreatIntel(
                    technology="HTTP", risk_level="MEDIUM",
                    threat_title="Unencrypted HTTP Web Service",
                    threat_description="The site allows HTTP connections, exposing user credentials and data to man-in-the-middle attacks.",
                    recommended_action="Enforce HTTPS with automatic redirection and configure HSTS headers.",
                    source="AEGIS Internal Threat Feed"
                ),
                ThreatIntel(
                    technology="HTTPS", risk_level="LOW",
                    threat_title="Public HTTPS Web Interface",
                    threat_description="HTTPS is correctly configured, but public exposure of web interfaces increases the attack surface.",
                    recommended_action="Keep web services updated and verify secure cookie flag policies.",
                    source="AEGIS Internal Threat Feed"
                ),
            ])
            db.commit()
            print("ThreatIntel seeded successfully.")
    except Exception as e:
        print(f"Error seeding ThreatIntel: {e}")
        db.rollback()
    finally:
        db.close()

def seed_demo_admin():
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            print("Seeding default demo admin user...")
            db.add(User(
                username="admin",
                email="admin@aegis.local",
                password_hash="admin",  # Auto-upgraded to pbkdf2 on first login
                role="Admin",
                is_active=True
            ))
            db.commit()
            print("Demo admin user seeded successfully.")
    except Exception as e:
        print(f"Error seeding demo admin: {e}")
        db.rollback()
    finally:
        db.close()

def seed_superadmin():
    """Always ensure the Kushwanth superadmin account exists with the correct credentials."""
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "Kushwanth").first()
        correct_hash = generate_password_hash("Kushwanth@123", method="pbkdf2:sha256")
        if not existing:
            print("Seeding Kushwanth superadmin account...")
            db.add(User(
                username="Kushwanth",
                email="kushwanth@aegis.local",
                password_hash=correct_hash,
                role="Superadmin",
                is_active=True
            ))
            db.commit()
            print("Kushwanth superadmin account created successfully.")
        else:
            # Always correct role, active status, and reset password to known-good hash
            existing.role = "Superadmin"
            existing.is_active = True
            existing.password_hash = correct_hash
            db.commit()
            print("Kushwanth superadmin account verified and credentials reset.")
    except Exception as e:
        print(f"Error seeding Kushwanth account: {e}")
        db.rollback()
    finally:
        db.close()

def purge_stale_threat_intel_logs():
    """Purges old THREAT_FEED_REFRESH logs on startup to keep the database size down."""
    db = SessionLocal()
    try:
        from database.models import AuditLog
        # Keep only the single latest log entry so that age tracking works, delete the rest
        last_log = db.query(AuditLog).filter(AuditLog.event_type == "THREAT_FEED_REFRESH").order_by(AuditLog.id.desc()).first()
        if last_log:
            db.query(AuditLog).filter(
                AuditLog.event_type == "THREAT_FEED_REFRESH",
                AuditLog.id != last_log.id
            ).delete(synchronize_session=False)
            db.commit()
            print("Purged duplicate/repetitive threat intelligence sync logs.")
    except Exception as e:
        print(f"Error purging threat intel logs: {e}")
        db.rollback()
    finally:
        db.close()

def init_db():
    print("Creating tables...")
    Base.metadata.create_all(engine)

    # Each step is isolated — one failure never blocks the next
    run_migrations()
    seed_threat_intel()
    seed_demo_admin()
    seed_superadmin()
    purge_stale_threat_intel_logs()

    print("Database initialization complete.")

if __name__ == "__main__":
    init_db()
