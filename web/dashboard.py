import os
import secrets
import hashlib
import datetime
import queue
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, current_app, Response, jsonify
from flask_login import login_required, current_user
import requests
import dns.resolver
import socket
from urllib.parse import urlparse

from database.connection import SessionLocal
from database.models import (
    Asset, Assessment, CorrelatedFinding, ReconExecution, ScanExecution,
    CorrelationExecution, AuditLog, ThreatIntel, Report, AuthorizationToken, Approval,
    User, Notification
)
from services.recon import run_dns_recon
from services.scan import execute_security_scans
from services.correlation import run_correlation_engine
from services.reports import generate_pdf
from services.threat_intel import fetch_latest_cisa_threats
from .auth import role_required

class PubSub:
    def __init__(self):
        self.listeners = []

    def listen(self):
        q = queue.Queue(maxsize=10)
        self.listeners.append(q)
        return q

    def publish(self, data):
        for q in list(self.listeners):
            try:
                q.put_nowait(data)
            except queue.Full:
                self.listeners.remove(q)
            except Exception:
                pass

pubsub = PubSub()

def create_system_notification(db, recipient, title, message, link=None):
    user_ids = []
    if isinstance(recipient, str):
        users = db.query(User).filter(User.role == recipient).all()
        user_ids = [u.id for u in users]
    elif isinstance(recipient, list):
        for r in recipient:
            if hasattr(r, 'id'):
                user_ids.append(r.id)
            else:
                user_ids.append(int(r))
    else:
        if hasattr(recipient, 'id'):
            user_ids.append(recipient.id)
        else:
            user_ids.append(int(recipient))

    import json
    for uid in user_ids:
        db.add(Notification(
            user_id=uid,
            title=title,
            message=message,
            link=link
        ))
    db.commit()

    pubsub.publish(json.dumps({
        "event": "new_notification",
        "title": title,
        "message": message,
        "link": link,
        "recipients": user_ids
    }))

dashboard_bp = Blueprint("dashboard", __name__)

# Asynchronous Task Executor
executor = ThreadPoolExecutor(max_workers=4)

import time
last_threat_sync_time = 0

@dashboard_bp.before_app_request
def trigger_threat_sync_on_click():
    global last_threat_sync_time
    if current_user and current_user.is_authenticated:
        current_time = time.time()
        # Throttled at most once every 30 seconds to prevent overloading CISA's servers
        if current_time - last_threat_sync_time > 30:
            last_threat_sync_time = current_time
            executor.submit(fetch_latest_cisa_threats, SessionLocal())

def db_session(f):
    """Decorator to inject database session cleanly and handle rollback/close."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        db = SessionLocal()
        try:
            return f(db, *args, **kwargs)
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close()
    return decorated_function

from functools import wraps

def check_and_trigger_threat_sync():
    db = SessionLocal()
    try:
        last_log = db.query(AuditLog).filter(AuditLog.event_type == "THREAT_FEED_REFRESH").order_by(AuditLog.id.desc()).first()
        trigger_sync = False
        if not last_log:
            trigger_sync = True
        else:
            age = datetime.datetime.now() - last_log.created_at
            # If threat data is older than 12 hours, trigger a background update
            if age.total_seconds() > 43200:
                trigger_sync = True
        
        if trigger_sync:
            print("Threat feed is outdated. Triggering background refresh...")
            # Submit to background executor thread pool to avoid blocking the HTTP response
            executor.submit(fetch_latest_cisa_threats, SessionLocal())
    except Exception as e:
        print(f"Error checking threat feed age: {e}")
    finally:
        db.close()

@dashboard_bp.route("/")
@login_required
def home():
    # Trigger background threat intelligence update check
    check_and_trigger_threat_sync()

    db = SessionLocal()
    try:
        # Metrics queries
        if current_user.role == "Owner":
            asset_count = db.query(Asset).filter(Asset.user_id == current_user.id).count()
            assessment_count = db.query(Assessment).join(Asset).filter(Asset.user_id == current_user.id).count()
            approved_count = db.query(Assessment).join(Asset).filter(Asset.user_id == current_user.id, Assessment.status == "APPROVED").count()
            high_risk_count = db.query(CorrelatedFinding).join(Assessment).join(Asset).filter(Asset.user_id == current_user.id, CorrelatedFinding.risk_level.in_(["HIGH", "CRITICAL"])).count()
            assets = db.query(Asset).filter(Asset.user_id == current_user.id).all()
        else:
            asset_count = db.query(Asset).count()
            assessment_count = db.query(Assessment).count()
            approved_count = db.query(Assessment).filter(Assessment.status == "APPROVED").count()
            high_risk_count = db.query(CorrelatedFinding).filter(CorrelatedFinding.risk_level.in_(["HIGH", "CRITICAL"])).count()
            assets = db.query(Asset).all()

        return render_template(
            "index.html",
            assets=assets,
            asset_count=asset_count,
            assessment_count=assessment_count,
            approved_count=approved_count,
            high_risk_count=high_risk_count
        )
    finally:
        db.close()

@dashboard_bp.route("/register-asset", methods=["GET", "POST"])
@login_required
def register_asset():
    if current_user.role == "Analyst":
        flash("Access Denied: Security Analysts are restricted from registering new assets.", "error")
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        asset_value = request.form.get("asset_value").strip().lower()

        # Helper to identify IP addresses
        def is_valid_ip(val):
            import socket
            try:
                socket.inet_aton(val)
                return True
            except socket.error:
                pass
            try:
                socket.inet_pton(socket.AF_INET6, val)
                return True
            except socket.error:
                pass
            return False

        # 1. Auto-detect Asset Type and Verification Method
        if "@" in asset_value:
            asset_type = "email"
            verification_method = "DNS"
            try:
                temp_val = asset_value.split("@")[-1]
            except Exception:
                temp_val = asset_value
        elif asset_value.startswith(("http://", "https://")):
            asset_type = "website"
            verification_method = "FILE"
            # Extract host for DNS validation rule
            try:
                parsed = urlparse(asset_value)
                temp_val = parsed.netloc.split(":")[0]
            except Exception:
                temp_val = asset_value
        elif is_valid_ip(asset_value):
            asset_type = "ip"
            verification_method = "FILE"
            temp_val = asset_value
        else:
            asset_type = "domain"
            verification_method = "DNS"
            temp_val = asset_value

        # Validate input target structure to prevent shell injections
        dangerous_chars = [";", "&", "|", "`", "$", "<", ">", "\n", "\r", "'", '"', "\\"]
        if not asset_value or any(c in asset_value for c in dangerous_chars):
            flash("Invalid characters detected in target value.", "error")
            return redirect(url_for("dashboard.register_asset"))

        if not temp_val or not all(c.isalnum() or c in ".-" for c in temp_val):
            flash("Invalid domain or IP target structure.", "error")
            return redirect(url_for("dashboard.register_asset"))

        db = SessionLocal()
        try:
            if verification_method == "EMAIL":
                import random
                token = f"{random.randint(100000, 999999)}"
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                
                # Log simulated email contents to root file
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                mock_email_path = os.path.join(project_root, "mock_emails.txt")
                email_content = (
                    f"==================================================\n"
                    f"TO: {asset_value}\n"
                    f"FROM: verification@aegis.local\n"
                    f"DATE: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"SUBJECT: AEGIS Asset Ownership Verification Code\n"
                    f"--------------------------------------------------\n"
                    f"Hello,\n\n"
                    f"You have registered this email address as a target asset in AEGIS.\n"
                    f"To verify your ownership, please enter the following 6-digit verification code:\n\n"
                    f"    👉  {token}  👈\n\n"
                    f"This code will expire in 24 hours.\n"
                    f"==================================================\n\n"
                )
                with open(mock_email_path, "a", encoding="utf-8") as f:
                    f.write(email_content)
            else:
                token = secrets.token_hex(16)
                token_hash = hashlib.sha256(token.encode()).hexdigest()

            ssh_creds_raw = request.form.get("ssh_credentials", "").strip()
            ssh_creds_json = None
            if ssh_creds_raw:
                try:
                    # Validate JSON structure
                    json.loads(ssh_creds_raw)
                    ssh_creds_json = ssh_creds_raw
                except Exception:
                    flash("Warning: Provided SSH credentials are not valid JSON. Asset registered without credentials.", "error")

            new_asset = Asset(
                user_id=current_user.id,
                asset_type=asset_type,
                asset_value=asset_value,
                verification_status="TOKEN_GENERATED",
                verification_token_hash=token_hash,
                verification_method=verification_method,
                ssh_credentials=ssh_creds_json
            )
            db.add(new_asset)
            db.commit()

            db.add(AuditLog(
                user_id=current_user.id,
                asset_id=new_asset.id,
                event_type="ASSET_REGISTERED",
                event_details=f"Asset {asset_value} ({asset_type}) registered. Verification challenge: {verification_method}."
            ))
            db.commit()

            # Create persistent notifications
            create_system_notification(
                db, 
                "Admin", 
                "New Target Registered", 
                f"A new target asset {asset_value} ({asset_type}) has been registered by {current_user.username}."
            )
            create_system_notification(
                db, 
                current_user.id, 
                "Target Registered", 
                f"You registered target asset {asset_value}. Ownership verification challenge initiated."
            )

            # Instructions rendering
            if verification_method == 'DNS':
                if asset_type == "email":
                    email_domain = asset_value.split("@")[-1]
                    instructions = f"Add a DNS TXT record with host name <b>_aegis-verification.{email_domain}</b> and paste this token as the TXT value."
                else:
                    instructions = f"Add a DNS TXT record with host name <b>_aegis-verification.{asset_value}</b> and paste this token as the TXT value."
            else:
                if asset_value.startswith(("http://", "https://")):
                    challenge_url = f"{asset_value.rstrip('/')}/.well-known/aegis-verification.txt"
                else:
                    challenge_url = f"http://{asset_value}/.well-known/aegis-verification.txt"
                instructions = f"Create a plain text file at <b>{challenge_url}</b> and paste this token as the content."

            return f"""
            <html>
            <head>
                <link rel="stylesheet" href="/static/style.css">
                <style>
                    body {{
                        background-color: var(--bg-main);
                        color: var(--text-primary);
                        font-family: 'Inter', sans-serif;
                    }}
                </style>
            </head>
            <body class="container" style="padding-top: 100px;">
                <div class="card" style="max-width: 620px; margin: 0 auto;">
                    <h2 style="font-family: 'Outfit', sans-serif; margin-bottom: 1.5rem; background: linear-gradient(to right, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Asset Registered: Token Generated</h2>
                    <p style="margin: 0.5rem 0;"><b>Detected Asset Type:</b> <span class="user-tag" style="background-color: var(--bg-hover); text-transform: uppercase;">{asset_type}</span></p>
                    <p style="margin: 0.5rem 0;"><b>Selected Authentication:</b> <span class="user-tag" style="background-color: var(--bg-hover);">{verification_method} Challenge</span></p>
                    <p style="margin: 0.5rem 0;"><b>Target Value:</b> <code>{asset_value}</code></p>
                    
                    <div style="background: rgba(255, 255, 255, 0.02); padding: 1.5rem; border-radius: 8px; margin: 1.5rem 0; border: 1px dashed var(--border-color); text-align: center; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);">
                        <p style="font-family: monospace; word-break: break-all; color: var(--primary); font-size: 1.25rem; font-weight: bold; letter-spacing: 1px;">{token}</p>
                    </div>

                    <p style="color: var(--text-secondary); margin-bottom: 2rem; line-height: 1.6;">
                        <b>Authentication Instructions:</b><br>
                        {instructions}
                    </p>
                    
                    <a href="/" class="btn" style="background-color: var(--accent); color: white;">Confirm & Go to Dashboard</a>
                </div>
            </body>
            </html>
            """
        except Exception as e:
            # Simplify error message to display only necessary user-facing context
            err_msg = "An error occurred during asset registration."
            if "UNIQUE constraint failed" in str(e) or "IntegrityError" in type(e).__name__:
                err_msg = "This asset is already registered in the system."
            flash(err_msg, "error")
            return redirect(url_for("dashboard.register_asset"))
        finally:
            db.close()

    return render_template("register_asset.html")

def is_private_ip(hostname: str) -> bool:
    try:
        # Extract host out of URL if protocol is present
        if hostname.startswith(("http://", "https://")):
            from urllib.parse import urlparse
            hostname = urlparse(hostname).netloc.split(":")[0]
        ip = socket.gethostbyname(hostname)
    except Exception:
        return True  # Fail-safe: block if unresolvable
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    try:
        p1, p2 = int(parts[0]), int(parts[1])
        if p1 == 127: return True
        if p1 == 10: return True
        if p1 == 172 and 16 <= p2 <= 31: return True
        if p1 == 192 and p2 == 168: return True
        if p1 == 169 and p2 == 254: return True
    except ValueError:
        return True
    return False

@dashboard_bp.route("/verify-asset/<int:asset_id>", methods=["GET", "POST"])
@login_required
def verify_asset(asset_id):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            flash("Asset not found.", "error")
            return redirect(url_for("dashboard.home"))

        # Enforce that only the registered owner can trigger automated verification
        if asset.user_id != current_user.id:
            flash("Access Denied: You can only verify assets that you registered.", "error")
            return redirect(url_for("dashboard.home"))

        # If it's an email asset, redirect to the OTP input page instead
        if asset.asset_type == "email":
            return redirect(url_for("dashboard.verify_email_asset", asset_id=asset_id))

        simulation_active = current_app.config.get("VERIFICATION_SIMULATION_MODE", False)

        # If it's a POST request with bypass=true in simulation mode, verify immediately
        if request.method == "POST" and request.form.get("bypass") == "true" and simulation_active:
            asset.verification_status = "VERIFIED"
            asset.verification_date = datetime.datetime.now()
            
            db.add(AuditLog(
                user_id=current_user.id,
                asset_id=asset.id,
                event_type="ASSET_VERIFIED",
                event_details=f"Asset {asset.asset_value} verified successfully via simulation bypass."
            ))
            db.commit()

            # Create persistent notifications
            create_system_notification(
                db, 
                "Admin", 
                "Target Verified", 
                f"Target asset {asset.asset_value} has been verified successfully via simulation bypass."
            )
            create_system_notification(
                db, 
                asset.user_id, 
                "Target Verified", 
                f"Your target asset {asset.asset_value} has been verified successfully."
            )
            
            flash("Asset verified successfully via simulation bypass!", "success")
            return redirect(url_for("dashboard.home"))

        # 1. Token Expiry Check (48 Hours)
        token_age = datetime.datetime.now() - asset.created_at
        expiry_limit = current_app.config.get("VERIFICATION_TOKEN_EXPIRY_HOURS", 48)
        if token_age.total_seconds() > (expiry_limit * 3600):
            flash("Ownership verification failed: Token has expired. Please register this asset again.", "error")
            return redirect(url_for("dashboard.home"))

        # Real verification check
        success = False
        token_hash = asset.verification_token_hash

        if asset.verification_method == "DNS":
            # Lookup DNS TXT record for _aegis-verification.domain
            if asset.asset_type == "email":
                email_domain = asset.asset_value.split("@")[-1]
                txt_host = f"_aegis-verification.{email_domain}"
            else:
                txt_host = f"_aegis-verification.{asset.asset_value}"
            try:
                answers = dns.resolver.resolve(txt_host, "TXT")
                for r in answers:
                    val = b"".join(r.strings).decode(errors="replace").strip()
                    val_hash = hashlib.sha256(val.encode()).hexdigest()
                    if val_hash == token_hash:
                        success = True
                        break
            except Exception:
                pass
        else:
            # File check: query /.well-known/aegis-verification.txt
            # SSRF Protection: Block private IPs in production
            if not simulation_active and is_private_ip(asset.asset_value):
                flash("Verification blocked: Private IP target detected (SSRF Protection).", "error")
                return redirect(url_for("dashboard.home"))

            # If target has protocol, query directly. Else check HTTPS followed by HTTP
            if asset.asset_value.startswith(("http://", "https://")):
                file_urls = [
                    f"{asset.asset_value.rstrip('/')}/.well-known/aegis-verification.txt"
                ]
            else:
                file_urls = [
                    f"https://{asset.asset_value}/.well-known/aegis-verification.txt",
                    f"http://{asset.asset_value}/.well-known/aegis-verification.txt"
                ]
            for url in file_urls:
                try:
                    resp = requests.get(url, timeout=6, verify=False if simulation_active else True)
                    if resp.status_code == 200:
                        val = resp.text.strip()
                        val_hash = hashlib.sha256(val.encode()).hexdigest()
                        if val_hash == token_hash:
                            success = True
                            break
                except Exception:
                    pass

        if success:
            asset.verification_status = "VERIFIED"
            asset.verification_date = datetime.datetime.now()
            
            db.add(AuditLog(
                user_id=current_user.id,
                asset_id=asset.id,
                event_type="ASSET_VERIFIED",
                event_details=f"Asset {asset.asset_value} successfully verified."
            ))
            db.commit()

            # Create persistent notifications
            create_system_notification(
                db, 
                "Admin", 
                "Target Verified", 
                f"Target asset {asset.asset_value} has been verified successfully."
            )
            create_system_notification(
                db, 
                asset.user_id, 
                "Target Verified", 
                f"Your target asset {asset.asset_value} has been verified successfully."
            )
            flash("Asset ownership verified successfully via real-time proof!", "success")
            return redirect(url_for("dashboard.home"))
        else:
            # Render the failed check page with retry and bypass controls
            if asset.verification_method == "DNS":
                error_msg = f"DNS TXT lookup on host name <code>_aegis-verification.{asset.asset_value}</code> returned no matching record containing the generated token."
            else:
                error_msg = f"HTTP request to /.well-known/aegis-verification.txt failed or returned an incorrect token value."
                
            return render_template("verification_failed.html", asset=asset, error_msg=error_msg, simulation_active=simulation_active)
            
    finally:
        db.close()

@dashboard_bp.route("/verify-email-asset/<int:asset_id>", methods=["GET", "POST"])
@login_required
def verify_email_asset(asset_id):
    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset or asset.asset_type != "email":
            flash("Invalid asset selected.", "error")
            return redirect(url_for("dashboard.home"))

        if asset.user_id != current_user.id:
            flash("Access Denied: You do not own this asset.", "error")
            return redirect(url_for("dashboard.home"))

        simulation_active = current_app.config.get("VERIFICATION_SIMULATION_MODE", False)

        if request.method == "POST":
            # If bypass parameter is sent, verify immediately
            if request.form.get("bypass") == "true" and simulation_active:
                asset.verification_status = "VERIFIED"
                asset.verification_date = datetime.datetime.now()
                
                db.add(AuditLog(
                    user_id=current_user.id,
                    asset_id=asset.id,
                    event_type="ASSET_VERIFIED",
                    event_details=f"Email asset {asset.asset_value} verified successfully via simulation bypass."
                ))
                db.commit()

                # Create persistent notifications
                create_system_notification(
                    db, 
                    "Admin", 
                    "Target Verified", 
                    f"Email target {asset.asset_value} has been verified successfully via simulation bypass."
                )
                create_system_notification(
                    db, 
                    asset.user_id, 
                    "Target Verified", 
                    f"Your email target {asset.asset_value} has been verified successfully."
                )
                flash("Email verified successfully via simulation bypass.", "success")
                return redirect(url_for("dashboard.home"))

            supplied_code = request.form.get("code").strip()
            supplied_hash = hashlib.sha256(supplied_code.encode()).hexdigest()

            if supplied_hash == asset.verification_token_hash:
                asset.verification_status = "VERIFIED"
                asset.verification_date = datetime.datetime.now()
                
                db.add(AuditLog(
                    user_id=current_user.id,
                    asset_id=asset.id,
                    event_type="ASSET_VERIFIED",
                    event_details=f"Email asset {asset.asset_value} verified successfully via OTP validation."
                ))
                db.commit()

                # Create persistent notifications
                create_system_notification(
                    db, 
                    "Admin", 
                    "Target Verified", 
                    f"Email target {asset.asset_value} has been verified successfully via OTP."
                )
                create_system_notification(
                    db, 
                    asset.user_id, 
                    "Target Verified", 
                    f"Your email target {asset.asset_value} has been verified successfully."
                )
                flash("Email asset verified successfully!", "success")
                return redirect(url_for("dashboard.home"))
            else:
                flash("Invalid verification code submitted.", "error")
                return redirect(url_for("dashboard.verify_email_asset", asset_id=asset_id))
                
        return render_template("verify_email.html", asset=asset, simulation_active=simulation_active)
    finally:
        db.close()

@dashboard_bp.route("/request-assessment/<int:asset_id>")
@login_required
def request_assessment(asset_id):
    if current_user.role == "Owner":
        flash("Access Denied: Only Security Analysts and Admins can request security assessments.", "error")
        return redirect(url_for("dashboard.home"))

    db = SessionLocal()
    try:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset or asset.verification_status != "VERIFIED":
            flash("Asset must be verified before requesting assessments.", "error")
            return redirect(url_for("dashboard.home"))

        # Rate limit validation check: 30-second cooldown
        latest = db.query(Assessment).filter(Assessment.asset_id == asset_id).order_by(Assessment.id.desc()).first()
        if latest:
            elapsed = datetime.datetime.now() - latest.created_at
            cooldown_seconds = 30
            if elapsed.total_seconds() < cooldown_seconds:
                remaining = int(cooldown_seconds - elapsed.total_seconds())
                flash(f"Rate Limit Exceeded: Please wait {remaining} seconds before requesting another assessment for this target.", "error")
                return redirect(url_for("dashboard.assessments"))

        # Generate a unique reference id
        count = db.query(Assessment).count()
        reference = f"AEGIS-2026-{count+1:04d}"

        new_assessment = Assessment(
            asset_id=asset_id,
            assessment_reference=reference,
            status="PENDING",
            scope_status="IN_SCOPE"
        )
        db.add(new_assessment)
        db.commit()

        db.add(AuditLog(
            user_id=current_user.id,
            asset_id=asset_id,
            assessment_id=new_assessment.id,
            event_type="ASSESSMENT_REQUESTED",
            event_details=f"Assessment requested with reference: {reference}"
        ))
        db.commit()

        # Create persistent notifications
        create_system_notification(
            db, 
            "Admin", 
            "Audit Request Received", 
            f"Analyst {current_user.username} requested a security audit scan on target {asset.asset_value}.", 
            "/requested-assessments"
        )
        create_system_notification(
            db, 
            asset.user_id, 
            "Audit Requested on Your Asset", 
            f"Analyst {current_user.username} requested a security audit scan on your target {asset.asset_value}.",
            "/assessments"
        )
        create_system_notification(
            db, 
            current_user.id, 
            "Audit Request Submitted", 
            f"You requested a security audit scan on target {asset.asset_value}. Awaiting Admin approval.", 
            "/assessments"
        )

        # Publish real-time notification
        import json
        pubsub.publish(json.dumps({
            "event": "assessment_requested",
            "assessment_id": new_assessment.id,
            "reference": reference,
            "target": asset.asset_value,
            "requested_by": current_user.username
        }))

        flash(f"Assessment requested successfully. Reference: {reference}", "success")
        return redirect(url_for("dashboard.assessments"))
    finally:
        db.close()

@dashboard_bp.route("/assessments")
@login_required
def assessments():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            assessments_list = db.query(Assessment).join(Asset).filter(Asset.user_id == current_user.id).order_by(Assessment.id.desc()).all()
        elif current_user.role == "Analyst":
            requested_ids = db.query(AuditLog.assessment_id).filter(
                AuditLog.user_id == current_user.id,
                AuditLog.event_type == "ASSESSMENT_REQUESTED"
            ).all()
            requested_ids = [r[0] for r in requested_ids if r[0]]
            assessments_list = db.query(Assessment).filter(Assessment.id.in_(requested_ids)).order_by(Assessment.id.desc()).all()
        else:
            assessments_list = db.query(Assessment).order_by(Assessment.id.desc()).all()
        return render_template("assessments.html", assessments=assessments_list)
    finally:
        db.close()

@dashboard_bp.route("/analyst/assess-target", methods=["POST"])
@role_required(["Analyst"])
def analyst_assess_target():
    target_val = request.form.get("target", "").strip()
    if not target_val:
        flash("Please enter a target value.", "error")
        return redirect(url_for("dashboard.home"))

    db = SessionLocal()
    try:
        # Check if verified asset exists in database
        asset = db.query(Asset).filter(
            Asset.asset_value == target_val,
            Asset.verification_status == "VERIFIED"
        ).first()

        if not asset:
            # Audit log attempt
            db.add(AuditLog(
                user_id=current_user.id,
                event_type="UNAUTHORIZED_ACCESS_ATTEMPT",
                event_details=f"Analyst tried to assess unverified/unregistered target: {target_val}"
            ))
            db.commit()
            
            # Notify Admin
            create_system_notification(
                db, 
                "Admin", 
                "Unauthorized Lookup Attempt", 
                f"Analyst {current_user.username} tried to assess target {target_val} (not registered/verified)."
            )
            
            flash("Target is not registered or not verified by the asset owner.", "error")
            return redirect(url_for("dashboard.home"))

        # Notify Owner and Admin about Analyst activity
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        create_system_notification(
            db, 
            "Admin", 
            "Target Accessed by Analyst", 
            f"Analyst {current_user.username} accessed target {target_val} to initiate scan at {timestamp}.",
            "/assessments"
        )
        create_system_notification(
            db, 
            asset.user_id, 
            "Your Target Accessed by Analyst", 
            f"Analyst {current_user.username} accessed your target {target_val} to initiate scan at {timestamp}.",
            "/assessments"
        )
        
        # Check if there is an active assessment for this asset
        assessment = db.query(Assessment).filter(Assessment.asset_id == asset.id).order_by(Assessment.id.desc()).first()
        if not assessment:
            # Auto-initiate new request
            return redirect(url_for("dashboard.request_assessment", asset_id=asset.id))
        else:
            return redirect(url_for("dashboard.assessments"))
    finally:
        db.close()

@dashboard_bp.context_processor
def inject_global_data():
    db = SessionLocal()
    try:
        pending_count = db.query(Assessment).filter(Assessment.status == "PENDING").count()
        unread_notifications_count = 0
        recent_notifications = []
        if current_user and current_user.is_authenticated:
            unread_notifications_count = db.query(Notification).filter(
                Notification.user_id == current_user.id,
                Notification.read == False
            ).count()
            recent_notifications = db.query(Notification).filter(
                Notification.user_id == current_user.id
            ).order_by(Notification.id.desc()).limit(5).all()
        return dict(
            pending_count=pending_count,
            unread_notifications_count=unread_notifications_count,
            recent_notifications=recent_notifications
        )
    except Exception:
        return dict(
            pending_count=0,
            unread_notifications_count=0,
            recent_notifications=[]
        )
    finally:
        db.close()

@dashboard_bp.route("/requested-assessments")
@role_required(["Admin", "Analyst"])
def requested_assessments():
    db = SessionLocal()
    try:
        pending_list = db.query(Assessment).filter(Assessment.status == "PENDING").order_by(Assessment.id.desc()).all()
        return render_template("requested_assessments.html", assessments=pending_list)
    finally:
        db.close()

@dashboard_bp.route("/approve-assessment/<int:assessment_id>")
@role_required(["Admin"])
def approve_assessment(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment or assessment.status != "PENDING":
            flash("Assessment is not pending approval.", "error")
            return redirect(url_for("dashboard.assessments"))

        assessment.status = "APPROVED"
        assessment.approved_at = datetime.datetime.now()

        # Add approval entry
        db.add(Approval(
            assessment_id=assessment_id,
            requested_by="Security Analyst",
            approved_by=current_user.username,
            decision="APPROVED",
            comments="Approved security scan request."
        ))

        # Generate compliance token automatically on approval
        token = secrets.token_hex(16)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        db.add(AuthorizationToken(
            assessment_id=assessment_id,
            token_hash=token_hash,
            expires_at=datetime.datetime.now() + datetime.timedelta(hours=24)
        ))

        db.add(AuditLog(
            user_id=current_user.id,
            assessment_id=assessment.id,
            event_type="ASSESSMENT_APPROVED",
            event_details=f"Assessment approved and authorization token generated by {current_user.username}"
        ))
        db.commit()

        # Create persistent notifications
        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        target_name = asset.asset_value if asset else "Target"
        
        # Find who requested the assessment
        req_log = db.query(AuditLog).filter(
            AuditLog.assessment_id == assessment_id,
            AuditLog.event_type == "ASSESSMENT_REQUESTED"
        ).first()
        analyst_id = req_log.user_id if req_log else None

        create_system_notification(
            db, 
            "Admin", 
            "Assessment Approved", 
            f"Assessment for target {target_name} approved and compliance token generated.", 
            "/assessments"
        )
        if analyst_id:
            create_system_notification(
                db, 
                analyst_id, 
                "Assessment Approved", 
                f"Admin approved scan request on target {target_name}. Use token to start scan.", 
                "/assessments"
            )
        if asset and asset.user_id != analyst_id:
            create_system_notification(
                db, 
                asset.user_id, 
                "Assessment Approved", 
                f"Security audit request approved on your target {target_name}.", 
                "/assessments"
            )

        # Publish SSE approval notification
        import json
        pubsub.publish(json.dumps({
            "event": "assessment_approved",
            "assessment_id": assessment_id,
            "target": target_name
        }))

        # Render warning token screen directly
        return f"""
        <html>
        <head><link rel="stylesheet" href="/static/style.css"></head>
        <body class="container" style="padding-top: 100px;">
            <div class="card" style="max-width: 600px; margin: 0 auto;">
                <h2>Legal Authorization Token Generated</h2>
                <p>This token is needed by the security analyst to execute scanning tools against the target.</p>
                
                <div style="background: #0f172a; padding: 1.5rem; border-radius: 6px; margin: 1.5rem 0; border: 1px dashed var(--border-color);">
                    <p style="font-family: monospace; word-break: break-all; color: var(--accent-yellow); font-size: 1.1rem; font-weight: bold;">{token}</p>
                </div>

                <p style="color: var(--accent); font-weight: bold; margin-bottom: 1.5rem;">⚠️ Copy this token now. It will not be shown again.</p>
                
                <a href="/assessments" class="btn">Return to Assessments</a>
            </div>
        </body>
        </html>
        """
    finally:
        db.close()

@dashboard_bp.route("/regenerate-token/<int:assessment_id>")
@role_required(["Admin"])
def regenerate_token(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment or assessment.status != "APPROVED":
            flash("Token can only be regenerated for approved assessments pending verification.", "error")
            return redirect(url_for("dashboard.assessments"))

        token = secrets.token_hex(16)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Mark all previous tokens for this run as used/invalidated
        db.query(AuthorizationToken).filter(
            AuthorizationToken.assessment_id == assessment_id
        ).update({"used": True})

        # Save new token
        db.add(AuthorizationToken(
            assessment_id=assessment_id,
            token_hash=token_hash,
            expires_at=datetime.datetime.now() + datetime.timedelta(hours=24)
        ))

        db.add(AuditLog(
            user_id=current_user.id,
            assessment_id=assessment.id,
            event_type="TOKEN_GENERATED",
            event_details=f"Compliance token regenerated by Admin: {current_user.username}"
        ))
        db.commit()

        # Render warning token screen
        return f"""
        <html>
        <head><link rel="stylesheet" href="/static/style.css"></head>
        <body class="container" style="padding-top: 100px;">
            <div class="card" style="max-width: 600px; margin: 0 auto;">
                <h2>Legal Authorization Token Regenerated</h2>
                <p>A new token has been generated. The previous token has been invalidated.</p>
                
                <div style="background: #0f172a; padding: 1.5rem; border-radius: 6px; margin: 1.5rem 0; border: 1px dashed var(--border-color);">
                    <p style="font-family: monospace; word-break: break-all; color: var(--accent-yellow); font-size: 1.1rem; font-weight: bold;">{token}</p>
                </div>

                <p style="color: var(--accent); font-weight: bold; margin-bottom: 1.5rem;">⚠️ Copy this token now. It will not be shown again.</p>
                
                <a href="/assessments" class="btn">Return to Assessments</a>
            </div>
        </body>
        </html>
        """
    finally:
        db.close()

@dashboard_bp.route("/verify-token/<int:assessment_id>", methods=["GET", "POST"])
@role_required(["Analyst"])
def verify_token(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))
            
        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))

        if request.method == "POST":
            supplied_token = request.form.get("token").strip()
            record = db.query(AuthorizationToken).filter(
                AuthorizationToken.assessment_id == assessment_id
            ).order_by(AuthorizationToken.id.desc()).first()

            if not record or record.used:
                flash("Token has already been consumed or does not exist.", "error")
                return redirect(url_for("dashboard.assessments"))

            supplied_hash = hashlib.sha256(supplied_token.encode()).hexdigest()
            if supplied_hash != record.token_hash:
                flash("Invalid token submitted.", "error")
                return redirect(url_for("dashboard.assessments"))

            record.used = True
            record.used_at = datetime.datetime.now()
            
            # Start scan immediately
            assessment.status = "RUNNING"
            assessment.scan_usage += 1
            assessment.started_at = datetime.datetime.now()

            db.add(AuditLog(
                user_id=current_user.id,
                assessment_id=assessment_id,
                event_type="TOKEN_VERIFIED",
                event_details="Authorization token verified successfully. Scan triggered automatically."
            ))
            db.commit()

            # Launch background scan execution task
            executor.submit(
                run_unified_assessment_pipeline, 
                SessionLocal(), 
                assessment_id, 
                asset.asset_value, 
                asset.asset_type.lower()
            )

            # Publish event
            import json
            pubsub.publish(json.dumps({
                "event": "scan_started",
                "assessment_id": assessment_id,
                "target": asset.asset_value
            }))

            flash("Token verified successfully! Background scan started automatically.", "success")
            return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

    return render_template("verify_token.html", assessment_id=assessment_id)

@dashboard_bp.route("/assessment-summary/<int:assessment_id>")
@login_required
def assessment_summary(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))

        # Get latest run statuses
        recon_run = db.query(ReconExecution).filter(ReconExecution.assessment_id == assessment_id).order_by(ReconExecution.id.desc()).first()
        recon_status = recon_run.status if recon_run else "NOT RUN"

        scan_run = db.query(ScanExecution).filter(ScanExecution.assessment_id == assessment_id).order_by(ScanExecution.id.desc()).first()
        scan_status = scan_run.status if scan_run else "NOT RUN"

        corr_run = db.query(CorrelationExecution).filter(CorrelationExecution.assessment_id == assessment_id).order_by(CorrelationExecution.id.desc()).first()
        correlation_status = corr_run.status if corr_run else "NOT RUN"

        # Calculate risks
        corr_findings = db.query(CorrelatedFinding).filter(CorrelatedFinding.assessment_id == assessment_id).all()
        findings_list = [(f.correlation_title, f.risk_level) for f in corr_findings]

        risk_score = sum(10 if f.risk_level=="CRITICAL" else 7 if f.risk_level=="HIGH" else 4 if f.risk_level=="MEDIUM" else 1 for f in corr_findings)
        overall_risk = "INFO"
        if risk_score >= 15: overall_risk = "CRITICAL"
        elif risk_score >= 10: overall_risk = "HIGH"
        elif risk_score >= 5: overall_risk = "MEDIUM"
        elif risk_score >= 1: overall_risk = "LOW"

        # Fetch attack path mapping edges
        from database.models import NetworkEdge
        edges = db.query(NetworkEdge).filter(NetworkEdge.assessment_id == assessment_id).all()
        edges_list = [{"source": e.source, "target": e.target, "port": e.port, "protocol": e.protocol, "weight": e.risk_weight} for e in edges]

        return render_template(
            "assessment_summary.html",
            assessment_id=assessment_id,
            assessment_reference=assessment.assessment_reference,
            asset_value=asset.asset_value,
            overall_risk=overall_risk,
            risk_score=risk_score,
            recon_status=recon_status,
            scan_status=scan_status,
            correlation_status=correlation_status,
            findings=findings_list,
            assessment_status=assessment.status,
            network_edges=edges_list
        )
    finally:
        db.close()

# Unified background pipeline orchestrator
def run_unified_assessment_pipeline(db, assessment_id, target, asset_type):
    def set_progress(details):
        db.add(AuditLog(
            assessment_id=assessment_id,
            event_type="SCAN_PROGRESS",
            event_details=details
        ))
        db.commit()

    try:
        print(f"Starting unified assessment for target: {target} (Type: {asset_type})")
        set_progress("Initializing background unified security scan pipeline...")
        
        # Extract host domain/IP if target is an email address
        scan_target = target
        if asset_type == "email" and "@" in target:
            scan_target = target.split("@")[-1]

        # 1. Run DNS Recon (for domains/websites/emails)
        if asset_type in ("domain", "website", "email"):
            set_progress("DNS reconnaissance phase: Resolving zone files, SPF policies, and DMARC settings...")
            run_dns_recon(db, assessment_id, scan_target)
            
        # 2. Run Port Scanning
        set_progress("Nmap scanner phase: Probing active host ports and mapping network services...")
        exec_entry = ScanExecution(assessment_id=assessment_id, status="RUNNING")
        db.add(exec_entry)
        db.commit()
        
        from services.scan import run_nmap_scan, run_ssl_audit, run_headers_audit, run_pixel_audit, run_robots_audit, run_nikto_scan
        run_nmap_scan(db, assessment_id, exec_entry.id, scan_target)
        
        # 3. Run SSL check (always try, falls back safely)
        set_progress("SSL audit phase: Validating certificate chain trust, signatures, and cipher suites...")
        run_ssl_audit(db, assessment_id, exec_entry.id, scan_target)
        
        # 4. Run HTTP Headers check (for domain/web/email targets)
        if asset_type in ("domain", "website", "email"):
            set_progress("Security headers phase: Checking HTTP response controls (HSTS, CSP, X-Frame-Options)...")
            run_headers_audit(db, assessment_id, exec_entry.id, scan_target)
            
        # 5. Run Robots.txt Audit
        if asset_type in ("domain", "website", "email"):
            set_progress("Robots audit phase: Parsing robots.txt for hidden directory and system exclusions...")
            run_robots_audit(db, assessment_id, exec_entry.id, scan_target)
            
        # 6. Run Nikto Web Application Audit
        if asset_type in ("domain", "website"):
            set_progress("Nikto vulnerability scanner phase: Probing for server files, admin dashboards, and common OSVDB hazards...")
            run_nikto_scan(db, assessment_id, exec_entry.id, scan_target)
            
        # 7. Run Playwright Pixel Auditing (for domain/web/email targets)
        if asset_type in ("domain", "website", "email"):
            set_progress("Pixel tracking audit phase: Invoking Playwright browser engine for PII and pixel leakage analysis...")
            run_pixel_audit(db, assessment_id, exec_entry.id, scan_target)
            
        exec_entry.status = "COMPLETED"
        exec_entry.completed_at = datetime.datetime.now()
        db.commit()
        
        # 8. Run Correlation Engine
        set_progress("Correlation phase: Running rule engines to map threats and vulnerability signatures...")
        run_correlation_engine(db, assessment_id)
        
        # 9. Generate PDF Reports
        set_progress("Report compiler phase: Packaging executive summaries and compiling technical reports...")
        generate_pdf(db, assessment_id, "TECHNICAL")
        generate_pdf(db, assessment_id, "EXECUTIVE")
        
        # 10. Update Assessment Status
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if assessment:
            assessment.status = "COMPLETED"
            assessment.completed_at = datetime.datetime.now()
            
        db.add(AuditLog(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_COMPLETED",
            event_details="Unified compliance assessment successfully finished. Reports compiled."
        ))
        
        # Create persistent notifications for completion
        asset = assessment.asset if assessment else None
        owner_id = asset.user_id if asset else None
        
        req_log = db.query(AuditLog).filter(
            AuditLog.assessment_id == assessment_id,
            AuditLog.event_type == "ASSESSMENT_REQUESTED"
        ).first()
        analyst_id = req_log.user_id if req_log else None
        
        title = "Security Scan Completed"
        msg = f"Security scan on target {target} has finished successfully. PDF reports are now available."
        link = f"/assessment-summary/{assessment_id}"
        
        create_system_notification(db, "Admin", title, msg, link)
        if owner_id:
            create_system_notification(db, owner_id, title, f"Security scan on your target {target} has completed. Reports are available.", link)
        if analyst_id and analyst_id != owner_id:
            create_system_notification(db, analyst_id, title, msg, link)

        db.commit()
        print(f"Unified assessment completed successfully for target: {target}")
        
    except Exception as e:
        print(f"Error in unified assessment pipeline: {e}")
        db.rollback()
        db.add(AuditLog(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_FAILED",
            event_details=f"Unified assessment failed: {str(e)}"
        ))
        
        # Create persistent notifications for failure
        title = "Security Scan Failed"
        msg = f"Security scan on target {target} failed: {str(e)}"
        link = f"/assessment-summary/{assessment_id}"
        
        # Find analyst who requested this scan
        req_log = db.query(AuditLog).filter(
            AuditLog.assessment_id == assessment_id,
            AuditLog.event_type == "ASSESSMENT_REQUESTED"
        ).first()
        analyst_id = req_log.user_id if req_log else None
        
        create_system_notification(db, "Admin", title, msg, link)
        if analyst_id:
            create_system_notification(db, analyst_id, title, msg, link)
            
        db.commit()
    finally:
        db.close()

@dashboard_bp.route("/assessment-status/<int:assessment_id>")
@login_required
def assessment_status_api(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            return jsonify({"error": "Assessment not found"}), 404
            
        # Get latest event log for this assessment
        latest_log = db.query(AuditLog).filter(
            AuditLog.assessment_id == assessment_id
        ).order_by(AuditLog.id.desc()).first()
        
        status_text = "Initializing scan pipeline..."
        if latest_log:
            status_text = latest_log.event_details or latest_log.event_type

        # Compute percentage based on latest log type or event details
        progress_percent = 5
        if "completed" in status_text.lower() or assessment.status == "COMPLETED":
            progress_percent = 100
        elif "failed" in status_text.lower() or assessment.status == "FAILED":
            progress_percent = 100
        elif "report" in status_text.lower():
            progress_percent = 90
        elif "correlation" in status_text.lower():
            progress_percent = 80
        elif "pixel" in status_text.lower():
            progress_percent = 70
        elif "nikto" in status_text.lower():
            progress_percent = 55
        elif "robots" in status_text.lower():
            progress_percent = 45
        elif "header" in status_text.lower():
            progress_percent = 35
        elif "ssl" in status_text.lower():
            progress_percent = 25
        elif "nmap" in status_text.lower():
            progress_percent = 15
        elif "dns" in status_text.lower() or "recon" in status_text.lower():
            progress_percent = 10

        return jsonify({
            "status": assessment.status,
            "status_text": status_text,
            "progress_percent": progress_percent
        })
    finally:
        db.close()

@dashboard_bp.route("/stream")
@login_required
def stream():
    def event_stream():
        q = pubsub.listen()
        yield "data: {\"event\": \"ping\"}\n\n"
        while True:
            try:
                data = q.get(timeout=20)
                yield f"data: {data}\n\n"
            except queue.Empty:
                yield "data: {\"event\": \"ping\"}\n\n"
            except GeneratorExit:
                if q in pubsub.listeners:
                    pubsub.listeners.remove(q)
                break
    res = Response(event_stream(), mimetype="text/event-stream")
    res.headers["Cache-Control"] = "no-cache"
    res.headers["X-Accel-Buffering"] = "no"
    res.headers["Connection"] = "keep-alive"
    return res

@dashboard_bp.route("/execute-assessment/<int:assessment_id>")
@login_required
def execute_assessment(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment or assessment.status not in ("TOKEN_VERIFIED", "COMPLETED", "APPROVED"):
            flash("Assessment token must be verified first.", "error")
            return redirect(url_for("dashboard.assessments"))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))

        # Verify scan quotas limits
        if assessment.scan_usage >= assessment.scan_limit:
            flash("Scan quota limit exceeded. Contact administrator to extend quota.", "error")
            return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        
        # Increment scan usage
        assessment.scan_usage += 1
        assessment.status = "RUNNING"
        assessment.started_at = datetime.datetime.now()
        db.commit()

        # Create persistent notifications
        create_system_notification(
            db, 
            "Admin", 
            "Security Scan Started", 
            f"Background security scan started on target {asset.asset_value} by {current_user.username}.", 
            f"/assessment-summary/{assessment.id}"
        )
        create_system_notification(
            db, 
            current_user.id, 
            "Security Scan Started", 
            f"You started a background security scan on target {asset.asset_value}.", 
            f"/assessment-summary/{assessment.id}"
        )
        if asset.user_id != current_user.id:
            create_system_notification(
                db, 
                asset.user_id, 
                "Security Scan Running", 
                f"A security scan is now running on your target {asset.asset_value}.", 
                f"/assessment-summary/{assessment.id}"
            )

        # Submit background task
        executor.submit(
            run_unified_assessment_pipeline, 
            SessionLocal(), 
            assessment_id, 
            asset.asset_value, 
            asset.asset_type.lower()
        )
        
        flash("Unified compliance assessment pipeline triggered in the background. Generating reports...", "success")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()


# --- Pipelines Execution endpoints (Asynchronous) ---

@dashboard_bp.route("/run-recon/<int:assessment_id>")
@login_required
def run_recon_route(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment or assessment.status not in ("TOKEN_VERIFIED", "COMPLETED", "APPROVED"):
            # Check compliance authorization token status
            flash("Assessment token must be verified first.", "error")
            return redirect(url_for("dashboard.assessments"))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))
        
        # Submit scanner task to background executor thread pool
        executor.submit(run_dns_recon, SessionLocal(), assessment_id, asset.asset_value)
        
        flash("DNS & DMARC reconnaissance pipeline triggered in the background.", "success")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

@dashboard_bp.route("/run-scan/<int:assessment_id>")
@login_required
def run_scan_route(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment or assessment.status not in ("TOKEN_VERIFIED", "COMPLETED", "APPROVED"):
            flash("Assessment token must be verified first.", "error")
            return redirect(url_for("dashboard.assessments"))

        # Verify quotas limits
        if assessment.scan_usage >= assessment.scan_limit:
            flash("Scan quota limit exceeded. Contact administrator to extend quota.", "error")
            return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))
        
        # Increment scan usage
        assessment.scan_usage += 1
        db.commit()

        # Submit background task
        executor.submit(execute_security_scans, SessionLocal(), assessment_id, asset.asset_value)
        
        flash("Nmap and Playwright Pixel Auditing triggered in the background.", "success")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

@dashboard_bp.route("/run-correlation/<int:assessment_id>")
@login_required
def run_correlation_route(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))

        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this assessment.", "error")
            return redirect(url_for("dashboard.assessments"))

        run_correlation_engine(db, assessment_id)
        flash("Correlation engine completed execution successfully.", "success")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

@dashboard_bp.route("/generate-technical-report/<int:assessment_id>")
@login_required
def technical_report(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))
            
        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this report.", "error")
            return redirect(url_for("dashboard.assessments"))

        file_name = generate_pdf(db, assessment_id, "TECHNICAL")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf_path = os.path.join(project_root, file_name)
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        flash(f"Failed to generate technical report: {str(e)}", "error")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

@dashboard_bp.route("/generate-executive-report/<int:assessment_id>")
@login_required
def executive_report(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))
            
        asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
        if current_user.role == "Owner" and asset.user_id != current_user.id:
            flash("Access Denied: You do not own the asset associated with this report.", "error")
            return redirect(url_for("dashboard.assessments"))

        file_name = generate_pdf(db, assessment_id, "EXECUTIVE")
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf_path = os.path.join(project_root, file_name)
        return send_file(pdf_path, as_attachment=True)
    except Exception as e:
        flash(f"Failed to generate executive report: {str(e)}", "error")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

# --- Log History Views ---

@dashboard_bp.route("/threat-intelligence")
@login_required
def threat_intelligence():
    db = SessionLocal()
    try:
        threats = db.query(ThreatIntel).all()
        threats_list = [(t.technology, t.risk_level, t.threat_title, t.source, t.threat_description) for t in threats]
        return render_template("threat_intelligence.html", threats=threats_list)
    finally:
        db.close()

@dashboard_bp.route("/report-history")
@login_required
def report_history():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            reports = db.query(Report).join(Assessment).join(Asset).filter(Asset.user_id == current_user.id).order_by(Report.id.desc()).all()
        else:
            reports = db.query(Report).order_by(Report.id.desc()).all()
        reports_list = [(r.id, r.assessment_id, r.report_type, r.created_at.strftime("%Y-%m-%d %H:%M"), r.file_name, r.assessment.assessment_reference) for r in reports]
        return render_template("report_history.html", reports=reports_list)
    finally:
        db.close()

@dashboard_bp.route("/audit-logs")
@role_required(["Admin", "Analyst"])
def audit_logs():
    db = SessionLocal()
    try:
        logs = db.query(AuditLog).filter(AuditLog.event_type != "THREAT_FEED_REFRESH").order_by(AuditLog.id.desc()).all()
        logs_list = [(l.id, l.assessment_id, l.event_type, l.event_details, l.created_at.strftime("%Y-%m-%d %H:%M")) for l in logs]
        return render_template("audit_logs.html", logs=logs_list)
    finally:
        db.close()
@dashboard_bp.route("/recon-history")
@login_required
def recon_history():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            executions = db.query(ReconExecution).join(Assessment).join(Asset).filter(Asset.user_id == current_user.id).order_by(ReconExecution.id.desc()).all()
        else:
            executions = db.query(ReconExecution).order_by(ReconExecution.id.desc()).all()
        executions_list = [
            (
                ex.id,
                ex.assessment_id,
                ex.status,
                ex.started_at.strftime("%Y-%m-%d %H:%M") if ex.started_at else "N/A",
                ex.completed_at.strftime("%Y-%m-%d %H:%M") if ex.completed_at else "N/A"
            ) for ex in executions
        ]
        return render_template("recon_history.html", executions=executions_list)
    finally:
        db.close()

@dashboard_bp.route("/recon-results/<int:execution_id>")
@login_required
def recon_results(execution_id):
    db = SessionLocal()
    try:
        results = db.query(ReconResult).filter(ReconResult.recon_execution_id == execution_id).all()
        results_list = [(r.recon_type, r.result_data) for r in results]
        return render_template("recon_results.html", results=results_list)
    finally:
        db.close()

@dashboard_bp.route("/scan-history")
@login_required
def scan_history():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            executions = db.query(ScanExecution).join(Assessment).join(Asset).filter(Asset.user_id == current_user.id).order_by(ScanExecution.id.desc()).all()
        else:
            executions = db.query(ScanExecution).order_by(ScanExecution.id.desc()).all()
        executions_list = [
            (
                ex.id,
                ex.assessment_id,
                ex.status,
                ex.started_at.strftime("%Y-%m-%d %H:%M") if ex.started_at else "N/A",
                ex.completed_at.strftime("%Y-%m-%d %H:%M") if ex.completed_at else "N/A"
            ) for ex in executions
        ]
        return render_template("scan_history.html", executions=executions_list)
    finally:
        db.close()

@dashboard_bp.route("/scan-results/<int:execution_id>")
@login_required
def scan_results(execution_id):
    db = SessionLocal()
    try:
        findings = db.query(ScanResult).filter(ScanResult.scan_execution_id == execution_id).all()
        findings_list = [(f.finding_title, f.finding_category or "N/A", f.severity or "INFO", f.description or "N/A", f.evidence or "N/A") for f in findings]
        return render_template("scan_results.html", findings=findings_list)
    finally:
        db.close()

@dashboard_bp.route("/correlation-history")
@login_required
def correlation_history():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            executions = db.query(CorrelationExecution).join(Assessment).join(Asset).filter(Asset.user_id == current_user.id).order_by(CorrelationExecution.id.desc()).all()
        else:
            executions = db.query(CorrelationExecution).order_by(CorrelationExecution.id.desc()).all()
        executions_list = [
            (
                ex.id,
                ex.assessment_id,
                ex.status,
                ex.started_at.strftime("%Y-%m-%d %H:%M") if ex.started_at else "N/A",
                ex.completed_at.strftime("%Y-%m-%d %H:%M") if ex.completed_at else "N/A"
            ) for ex in executions
        ]
        return render_template("correlation_history.html", executions=executions_list)
    finally:
        db.close()

@dashboard_bp.route("/correlation-results/<int:execution_id>")
@login_required
def correlation_results(execution_id):
    db = SessionLocal()
    try:
        findings = db.query(CorrelatedFinding).filter(CorrelatedFinding.correlation_execution_id == execution_id).all()
        findings_list = [(f.correlation_title, f.risk_level, f.correlation_reason, f.recommended_action) for f in findings]
        return render_template("correlation_results.html", findings=findings_list)
    finally:
        db.close()

@dashboard_bp.route("/extend-quota/<int:assessment_id>")
@role_required(["Admin"])
def extend_quota(assessment_id):
    db = SessionLocal()
    try:
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            flash("Assessment not found.", "error")
            return redirect(url_for("dashboard.assessments"))
            
        amount = request.args.get("amount", default=10, type=int)
        if amount <= 0:
            flash("Invalid quota extension amount.", "error")
            return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))

        assessment.scan_limit += amount
        db.add(AuditLog(
            user_id=current_user.id,
            assessment_id=assessment_id,
            event_type="QUOTA_EXTENDED",
            event_details=f"Admin extended scan limit by {amount}. New limit: {assessment.scan_limit}"
        ))
        db.commit()
        flash(f"Scan limit extended successfully by {amount}! New limit: {assessment.scan_limit}", "success")
        return redirect(url_for("dashboard.assessment_summary", assessment_id=assessment_id))
    finally:
        db.close()

@dashboard_bp.route("/refresh-threats")
@role_required(["Admin", "Analyst"])
def refresh_threats():
    db = SessionLocal()
    try:
        fetch_latest_cisa_threats(db)
        flash("Threat Intelligence repository successfully synced with live CISA KEV Feed!", "success")
        return redirect(url_for("dashboard.threat_intelligence"))
    except Exception as e:
        flash(f"Manual sync failed: {str(e)}", "error")
        return redirect(url_for("dashboard.threat_intelligence"))

@dashboard_bp.route("/notifications")
@login_required
def notifications_page():
    db = SessionLocal()
    try:
        notifs = db.query(Notification).filter(
            Notification.user_id == current_user.id
        ).order_by(Notification.id.desc()).all()
        
        # Mark as read
        db.query(Notification).filter(
            Notification.user_id == current_user.id,
            Notification.read == False
        ).update({"read": True})
        db.commit()
        
        return render_template("notifications.html", notifications=notifs)
    finally:
        db.close()

@dashboard_bp.route("/notifications/clear", methods=["POST"])
@login_required
def clear_notifications():
    db = SessionLocal()
    try:
        db.query(Notification).filter(Notification.user_id == current_user.id).delete()
        db.commit()
        flash("All notifications cleared successfully.", "success")
        return redirect(url_for("dashboard.notifications_page"))
    finally:
        db.close()

@dashboard_bp.route("/notifications/read/<int:notification_id>", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    db = SessionLocal()
    try:
        notif = db.query(Notification).filter(
            Notification.id == notification_id,
            Notification.user_id == current_user.id
        ).first()
        if notif:
            notif.read = True
            db.commit()
        return jsonify({"status": "success"})
    finally:
        db.close()

@dashboard_bp.route("/serve-pdf/<path:filename>")
@login_required
def serve_pdf(filename):
    if not filename.endswith(".pdf") or ".." in filename:
        return "Access Denied", 403

    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.file_name == filename).order_by(Report.id.desc()).first()
        if report and report.pdf_data:
            return Response(
                report.pdf_data,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'inline; filename="{filename}"'}
            )
    finally:
        db.close()

    # Fallback: try disk
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf_path = os.path.join(project_root, filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, mimetype='application/pdf')
    return "Report not found. Please regenerate the report.", 404

@dashboard_bp.route("/download-pdf/<path:filename>")
@login_required
def download_pdf(filename):
    if not filename.endswith(".pdf") or ".." in filename:
        return "Access Denied", 403

    db = SessionLocal()
    try:
        report = db.query(Report).filter(Report.file_name == filename).order_by(Report.id.desc()).first()
        if report and report.pdf_data:
            return Response(
                report.pdf_data,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename="{filename}"'}
            )
    finally:
        db.close()

    # Fallback: try disk
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf_path = os.path.join(project_root, filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    return "Report not found. Please regenerate the report.", 404

@dashboard_bp.route("/high-risks-assessments")
@login_required
def high_risks_assessments():
    db = SessionLocal()
    try:
        if current_user.role == "Owner":
            assessments = db.query(Assessment).join(Asset).join(CorrelatedFinding).filter(
                Asset.user_id == current_user.id,
                CorrelatedFinding.risk_level.in_(["CRITICAL", "HIGH"])
            ).distinct().order_by(Assessment.id.desc()).all()
        else:
            assessments = db.query(Assessment).join(CorrelatedFinding).filter(
                CorrelatedFinding.risk_level.in_(["CRITICAL", "HIGH"])
            ).distinct().order_by(Assessment.id.desc()).all()
            
        return render_template("high_risks_assessments.html", assessments=assessments)
    finally:
        db.close()


# ─── Superadmin: User Management (Kushwanth only) ───────────────────────────

@dashboard_bp.route("/user-management")
@login_required
def user_management():
    if current_user.role != "Superadmin":
        flash("Access Denied: Superadmin privileges required.", "error")
        return redirect(url_for("dashboard.home"))
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id).all()
        return render_template("user_management.html", users=users)
    finally:
        db.close()

@dashboard_bp.route("/delete-user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "Superadmin":
        flash("Access Denied: Superadmin privileges required.", "error")
        return redirect(url_for("dashboard.home"))
    if user_id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("dashboard.user_management"))
    db = SessionLocal()
    try:
        target_user = db.query(User).filter(User.id == user_id).first()
        if not target_user:
            flash("User not found.", "error")
            return redirect(url_for("dashboard.user_management"))
        username = target_user.username
        db.delete(target_user)
        db.add(AuditLog(
            user_id=current_user.id,
            event_type="USER_DELETED",
            event_details=f"Superadmin {current_user.username} deleted user: {username} (ID {user_id})."
        ))
        db.commit()
        flash(f"User '{username}' has been deleted.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error deleting user: {str(e)}", "error")
    finally:
        db.close()
    return redirect(url_for("dashboard.user_management"))


# ─── Emergency: Force-reset Kushwanth superadmin (one-time URL call) ─────────

@dashboard_bp.route("/reset-superadmin")
def reset_superadmin():
    """
    Protected setup route: creates or resets the Kushwanth superadmin account.
    Requires secret token: /reset-superadmin?token=aegis-kush-2026
    """
    if request.args.get("token") != "aegis-kush-2026":
        return "<h2 style='color:red;font-family:sans-serif'>403 - Access Denied</h2>", 403

    from werkzeug.security import generate_password_hash as gph
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "Kushwanth").first()
        import hashlib
        client_hash = hashlib.sha256(b"Kushwanth@123").hexdigest()
        new_hash = gph(client_hash, method="pbkdf2:sha256")
        if existing:
            existing.password_hash = new_hash
            existing.role = "Superadmin"
            existing.is_active = True
            db.commit()
            return "<h2 style='font-family:sans-serif;color:green'>✅ Kushwanth superadmin password RESET.<br><br><a href='/login'>Go to Login</a></h2>", 200
        else:
            db.add(User(
                username="Kushwanth",
                email="kushwanth@aegis.local",
                password_hash=new_hash,
                role="Superadmin",
                is_active=True
            ))
            db.commit()
            return "<h2 style='font-family:sans-serif;color:green'>✅ Kushwanth superadmin CREATED.<br><br><a href='/login'>Go to Login</a></h2>", 200
    except Exception as e:
        db.rollback()
        return f"<h2 style='color:red'>Error: {str(e)}</h2>", 500
    finally:
        db.close()

@dashboard_bp.route("/debug-login")
def debug_login():
    if request.args.get("token") != "aegis-kush-2026":
        return "403", 403
    from werkzeug.security import check_password_hash as cph
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == "Kushwanth").first()
        if not u:
            return "<pre>USER NOT FOUND IN DB</pre>"
        test_result = cph(u.password_hash, "Kushwanth@123")
        return f"""<pre>
username    : {u.username}
role        : {u.role}
is_active   : {u.is_active}
hash_method : {u.password_hash[:40]}...
check_result: {test_result}
</pre>"""
    finally:
        db.close()


