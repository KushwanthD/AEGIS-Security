import os
import sys

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import engine, SessionLocal, Base
from database.models import User, ThreatIntel
from werkzeug.security import generate_password_hash
from sqlalchemy import text

def run_migrations(db):
    """Apply schema migrations not handled by create_all (e.g. new columns on existing tables)."""
    try:
        db.execute(text("ALTER TABLE Reports ADD COLUMN pdf_data BLOB"))
        db.commit()
        print("Migration: added pdf_data column to Reports.")
    except Exception:
        db.rollback()  # Column already exists — that's fine

def init_db():
    print("Creating tables in database/aegis.db...")
    Base.metadata.create_all(engine)

    db = SessionLocal()
    try:
        # Run schema migrations for new columns on existing tables
        run_migrations(db)

        # Seed ThreatIntel if empty
        if db.query(ThreatIntel).count() == 0:
            print("Seeding ThreatIntel table...")
            seeds = [
                ThreatIntel(
                    technology="SSH",
                    risk_level="HIGH",
                    threat_title="Exposed Administrative Service (SSH)",
                    threat_description="SSH service is exposed to the internet. Attacker can perform brute force or vulnerability exploit.",
                    recommended_action="Restrict SSH access to trusted networks, use strong key-based authentication, or enforce VPN requirements.",
                    source="AEGIS Internal Threat Feed"
                ),
                ThreatIntel(
                    technology="HTTP",
                    risk_level="MEDIUM",
                    threat_title="Unencrypted HTTP Web Service",
                    threat_description="The site allows HTTP connections, exposing user credentials and data to man-in-the-middle attacks.",
                    recommended_action="Enforce HTTPS with automatic redirection and configure HSTS headers.",
                    source="AEGIS Internal Threat Feed"
                ),
                ThreatIntel(
                    technology="HTTPS",
                    risk_level="LOW",
                    threat_title="Public HTTPS Web Interface",
                    threat_description="HTTPS is correctly configured, but public exposure of web interfaces increases the attack surface.",
                    recommended_action="Keep web services updated and verify secure cookie flag policies.",
                    source="AEGIS Internal Threat Feed"
                )
            ]
            db.add_all(seeds)
            db.commit()
            print("ThreatIntel seeded successfully.")

        # Seed demo admin account if no users exist at all
        if db.query(User).count() == 0:
            print("Seeding default demo admin user...")
            admin = User(
                username="admin",
                email="admin@aegis.local",
                password_hash="admin",  # Auto-upgraded to pbkdf2 on first login
                role="Admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
            print("Demo admin user seeded successfully.")

        # Seed Kushwanth superadmin account if it doesn't exist
        existing_kush = db.query(User).filter(User.username == "Kushwanth").first()
        if not existing_kush:
            print("Seeding Kushwanth superadmin account...")
            kush = User(
                username="Kushwanth",
                email="kushwanth@aegis.local",
                password_hash=generate_password_hash("Kushwanth@123"),
                role="Superadmin",
                is_active=True
            )
            db.add(kush)
            db.commit()
            print("Kushwanth superadmin account created.")

        print("Database initialized and verified successfully.")
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
