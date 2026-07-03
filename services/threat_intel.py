import requests
from database.connection import SessionLocal
from database.models import ThreatIntel, AuditLog

def fetch_latest_cisa_threats(db):
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            
            # Fetch the latest 30 vulnerability alerts from CISA KEV
            latest_vulns = vulns[-30:]
            
            added_count = 0
            for v in latest_vulns:
                cve_id = v.get("cveID", "Unknown CVE")
                tech = v.get("product", "General")
                title = f"{cve_id}: {v.get('vulnerabilityName', 'Active Exploitation Alert')}"
                desc = v.get("shortDescription", "No description provided.")
                action = v.get("requiredAction", "Apply vendor updates immediately.")
                
                # Check for duplicate entry by title
                exists = db.query(ThreatIntel).filter(ThreatIntel.threat_title == title).first()
                if not exists:
                    db.add(ThreatIntel(
                        technology=tech,
                        risk_level="CRITICAL",
                        threat_title=title,
                        threat_description=desc,
                        recommended_action=action,
                        source="CISA Known Exploited Vulnerabilities Catalog"
                    ))
                    added_count += 1
            
            db.add(AuditLog(
                event_type="THREAT_FEED_REFRESH",
                event_details=f"Threat intelligence sync completed. Fetched from CISA KEV. Added {added_count} new threat alerts."
            ))
            db.commit()
            print(f"CISA Threat Sync Complete. Added {added_count} records.")
    except Exception as e:
        print(f"Failed to sync CISA threat feed: {e}")
    finally:
        db.close()
