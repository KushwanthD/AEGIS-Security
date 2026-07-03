import os
import sys

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.connection import engine, SessionLocal, Base
from database.models import User, ThreatIntel

def init_db():
    print("Creating tables in database/aegis.db...")
    Base.metadata.create_all(engine)
    
    db = SessionLocal()
    try:
        # Check if threat intel needs seeding
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
            
        # Check if default admin needs seeding
        if db.query(User).count() == 0:
            print("Seeding default admin user...")
            # Using simple text password_hash since password hashing function will be added in auth.py
            admin = User(
                username="admin",
                email="admin@aegis.local",
                password_hash="admin", # Plain text placeholder, auth module will auto-upgrade to pbkdf2 hash on first login
                role="Admin",
                is_active=True
            )
            db.add(admin)
            db.commit()
            print("Admin user seeded successfully.")
            
        print("Database initialized and verified successfully.")
    except Exception as e:
        print(f"Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
