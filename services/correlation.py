import sqlite3
import datetime
import json
from sqlalchemy.orm import Session
from database.models import (
    CorrelationExecution, CorrelatedFinding, ReconResult,
    ScanResult, ThreatIntel, AuditLog
)

def run_correlation_engine(db: Session, assessment_id: int):
    """
    Correlates Recon and Scan findings with Threat Intelligence rules.
    Automatically identifies risks for DNS, DMARC, SPF, open ports, exposed directories, and Pixel leaks.
    """
    exec_entry = CorrelationExecution(
        assessment_id=assessment_id,
        status="RUNNING"
    )
    db.add(exec_entry)
    db.commit()

    # Get latest results
    recon_results = db.query(ReconResult).filter(ReconResult.assessment_id == assessment_id).all()
    scan_results = db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).all()

    mx_found = False
    spf_grade = None
    spf_note = ""
    dmarc_grade = None
    dmarc_note = ""

    ssh_found = False
    ssh_details = ""
    http_found = False
    http_details = ""
    https_found = False
    https_details = ""

    pixel_audit_finding = None
    robots_finding = None
    headers_finding = None
    ssl_finding = None

    # Analyze recon records
    for r in recon_results:
        if r.recon_type == "DNS_MX_RECORDS" and r.result_data and "Lookup failed" not in r.result_data:
            mx_found = True
        elif r.recon_type == "DNS_DMARC_RECORD":
            for line in r.result_data.splitlines():
                if line.startswith("Grade:"):
                    dmarc_grade = line.split(":", 1)[1].strip()
                if line.startswith("Note:"):
                    dmarc_note = line.split(":", 1)[1].strip()
        elif r.recon_type == "DNS_SPF_RECORD":
            for line in r.result_data.splitlines():
                if line.startswith("Grade:"):
                    spf_grade = line.split(":", 1)[1].strip()
                if line.startswith("Note:"):
                    spf_note = line.split(":", 1)[1].strip()

    # Analyze scan results
    for s in scan_results:
        if s.tool_name == "Nmap":
            if "SSH" in s.finding_title:
                ssh_found = True
                ssh_details = s.description
            elif "HTTP" in s.finding_title and "HTTPS" not in s.finding_title:
                http_found = True
                http_details = s.description
            elif "HTTPS" in s.finding_title:
                https_found = True
                https_details = s.description
        elif s.tool_name == "Pixel Auditor":
            if "Privacy Audit" in s.finding_category:
                pixel_audit_finding = s
        elif s.tool_name == "Robots.txt Auditor":
            robots_finding = s
        elif s.tool_name == "Headers Auditor":
            headers_finding = s
        elif s.tool_name == "SSL Auditor":
            ssl_finding = s

    findings_created = 0

    # Rule 1: Email Infrastructure
    if mx_found:
        db.add(CorrelatedFinding(
            assessment_id=assessment_id,
            correlation_execution_id=exec_entry.id,
            correlation_title="External Email Infrastructure Detected",
            risk_level="INFO",
            correlation_reason="MX records indicate that the domain receives external email, expanding spoofing vector.",
            recommended_action="Ensure SPF, DKIM, and DMARC enforcement parameters are tightly maintained."
        ))
        findings_created += 1

    # Rule 2: SPF Policy Spoofing Risk
    if spf_grade:
        risk_level = "INFO"
        if spf_grade in ("EXPOSED", "WEAK"):
            risk_level = "HIGH"
        elif spf_grade == "PARTIAL":
            risk_level = "MEDIUM"
            
        if spf_grade != "PROTECTED":
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Spoofing Vulnerability: Weak Email Security (SPF)",
                risk_level=risk_level,
                correlation_reason=f"SPF status is {spf_grade}. {spf_note}",
                recommended_action="Update the domain's SPF DNS TXT record to end with '-all' (HardFail) instead of '~all' (SoftFail) or '+all' (AllowAll) to enforce strict sender authentication checks."
            ))
            findings_created += 1

    # Rule 3: DMARC Spoofing Risk
    if dmarc_grade:
        risk_level = "INFO"
        if dmarc_grade in ("EXPOSED", "WEAK"):
            risk_level = "HIGH"
        elif dmarc_grade == "PARTIAL":
            risk_level = "MEDIUM"
        
        if dmarc_grade != "PROTECTED" and dmarc_grade != "MANAGED":
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Spoofing Vulnerability: Weak Email Security (DMARC)",
                risk_level=risk_level,
                correlation_reason=f"DMARC status is {dmarc_grade}. {dmarc_note}",
                recommended_action="Set DMARC policy to 'quarantine' or 'reject' (p=quarantine or p=reject) to enforce recipient email filtering and prevent spoofing."
            ))
            findings_created += 1

    # Rule 4: Administrative Service Exposure (SSH)
    if ssh_found:
        intel = db.query(ThreatIntel).filter(ThreatIntel.technology == "SSH").first()
        risk = intel.risk_level if intel else "HIGH"
        reason = ssh_details if ssh_details else (intel.threat_description if intel else "Exposed SSH port detected.")
        action = intel.recommended_action if intel else "Restrict SSH access."
        db.add(CorrelatedFinding(
            assessment_id=assessment_id,
            correlation_execution_id=exec_entry.id,
            correlation_title="Exposed Administrative Service (SSH)",
            risk_level=risk,
            correlation_reason=reason,
            recommended_action=action
        ))
        findings_created += 1

    # Rule 5: Web Server Exposure
    if http_found or https_found:
        tech = "HTTPS" if https_found else "HTTP"
        intel = db.query(ThreatIntel).filter(ThreatIntel.technology == tech).first()
        risk = intel.risk_level if intel else "MEDIUM"
        reason = ""
        if https_found and https_details:
            reason += https_details
        if http_found and http_details:
            if reason: reason += "\n"
            reason += http_details
        if not reason:
            reason = intel.threat_description if intel else f"Public web server running on {tech} exposed."
        action = intel.recommended_action if intel else "Enforce SSL configuration."
        db.add(CorrelatedFinding(
            assessment_id=assessment_id,
            correlation_execution_id=exec_entry.id,
            correlation_title=f"Public Web Server Detected ({tech})",
            risk_level=risk,
            correlation_reason=reason,
            recommended_action=action
        ))
        findings_created += 1

    # Rule 6: Pixel Tracker Leakage
    if pixel_audit_finding and pixel_audit_finding.evidence:
        try:
            pages = json.loads(pixel_audit_finding.evidence)
            leaked_vendors = set()
            total_leaks = 0
            highest_page_score = 0
            
            for p in pages:
                highest_page_score = max(highest_page_score, p.get("risk_score", 0))
                for l in p.get("pii_leaks", []):
                    leaked_vendors.add(l.get("vendor", "Unknown Tracker"))
                    total_leaks += 1

            if leaked_vendors:
                risk_level = "LOW"
                if highest_page_score >= 9: risk_level = "CRITICAL"
                elif highest_page_score >= 7: risk_level = "HIGH"
                elif highest_page_score >= 5: risk_level = "MEDIUM"

                vendors_str = ", ".join(leaked_vendors)
                db.add(CorrelatedFinding(
                    assessment_id=assessment_id,
                    correlation_execution_id=exec_entry.id,
                    correlation_title="Ad-Tech Tracker & Privacy Data Leakage",
                    risk_level=risk_level,
                    correlation_reason=f"Third-party tracking trackers ({vendors_str}) were identified transmitting cookies, health-context parameters, or potential user inputs across sensitive portal and intake pages.",
                    recommended_action="Implement a consent management banner, configure Google Tag Manager to restrict triggers before consent, use proxy endpoints to strip PII from analytics payloads, or remove tracking pixels from patient scheduling pages."
                ))
                findings_created += 1
        except Exception as e:
            print(f"Failed to parse pixel auditor findings: {e}")

    # Rule 7: Web Security Headers Compliance
    if headers_finding and "missing" in headers_finding.description.lower():
        db.add(CorrelatedFinding(
            assessment_id=assessment_id,
            correlation_execution_id=exec_entry.id,
            correlation_title="Missing HTTP Security Headers",
            risk_level=headers_finding.severity,
            correlation_reason=headers_finding.description,
            recommended_action="Configure the web server to return HSTS, CSP, X-Frame-Options, and X-Content-Type-Options headers in all HTTP responses."
        ))
        findings_created += 1

    # Rule 8: SSL/TLS Cryptographic Security
    if ssl_finding:
        if "expired" in ssl_finding.description.lower() or ssl_finding.severity == "HIGH":
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Insecure Cryptography: Expired SSL Certificate",
                risk_level="CRITICAL",
                correlation_reason=ssl_finding.description,
                recommended_action="Renew the SSL/TLS certificate immediately with a trusted Certificate Authority to prevent browser security warnings and connection dropouts."
            ))
            findings_created += 1
        elif "expiring" in ssl_finding.description.lower() or ssl_finding.severity == "MEDIUM":
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Insecure Cryptography: SSL Certificate Expiring Soon",
                risk_level="MEDIUM",
                correlation_reason=ssl_finding.description,
                recommended_action="Renew the SSL/TLS certificate within the next 30 days to avoid disruption."
            ))
            findings_created += 1
        elif "deprecated" in ssl_finding.description.lower():
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Insecure Cryptography: Deprecated TLS Version Enabled",
                risk_level="MEDIUM",
                correlation_reason=ssl_finding.description,
                recommended_action="Disable support for TLS 1.0 and TLS 1.1 protocol versions on your web server and load balancer, and enforce TLS 1.2 or TLS 1.3 only."
            ))
            findings_created += 1
        elif "failed" in ssl_finding.description.lower() or "handshake failed" in ssl_finding.description.lower():
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Insecure Web Server: SSL/TLS Disabled",
                risk_level="HIGH",
                correlation_reason="Port 443 is unreachable or SSL/TLS handshake failed. Data is transmitted unencrypted.",
                recommended_action="Install an SSL/TLS certificate, open port 443, and configure automated HTTP-to-HTTPS redirection."
            ))
            findings_created += 1

    # Rule 9: Robots.txt Directory Exposure
    if robots_finding and robots_finding.severity == "MEDIUM":
        db.add(CorrelatedFinding(
            assessment_id=assessment_id,
            correlation_execution_id=exec_entry.id,
            correlation_title="Information Exposure: Administrative Paths Revealed in robots.txt",
            risk_level="MEDIUM",
            correlation_reason=robots_finding.description,
            recommended_action="Remove sensitive directory listings (such as /admin or backup folders) from robots.txt. Instead, block these directories using active web server authentication blocks (like HTTP Basic Auth) or IP access restriction lists."
        ))
        findings_created += 1

    # Rule 10: Nikto Web Server Vulnerabilities
    nikto_findings = [s for s in scan_results if s.tool_name == "Nikto"]
    for nf in nikto_findings:
        if nf.severity in ("HIGH", "MEDIUM") or "osvdb" in nf.description.lower() or "vulnerability" in nf.description.lower():
            db.add(CorrelatedFinding(
                assessment_id=assessment_id,
                correlation_execution_id=exec_entry.id,
                correlation_title="Web Exposure: Nikto Flags Server Vulnerabilities",
                risk_level="MEDIUM",
                correlation_reason=nf.description,
                recommended_action="Inspect the flagged web paths or OSVDB alerts. Configure web server rules to deny access to administrative panels, restrict directory index listing, and patch server components to the latest secure version."
            ))
            findings_created += 1

    # Rule 11: Dynamic CISA KEV Threat Intelligence Match
    threat_intel_pool = db.query(ThreatIntel).all()
    if threat_intel_pool:
        added_titles = set()
        for s in scan_results:
            if s.tool_name == "Nmap" and s.finding_category == "Open Port":
                # Split service name (e.g. "HTTP", "SSH", "MYSQL", "FTP")
                service_prefix = s.finding_title.split(" ")[0].upper()
                for intel in threat_intel_pool:
                    intel_tech = intel.technology.upper()
                    # Check if finding title or service matches CISA technology keyword
                    if service_prefix in intel_tech or intel_tech in service_prefix or (s.description and intel_tech in s.description.upper()):
                        title_key = f"CISA KEV Active Exploitation Match: {intel.threat_title}"
                        if title_key not in added_titles:
                            added_titles.add(title_key)
                            db.add(CorrelatedFinding(
                                assessment_id=assessment_id,
                                correlation_execution_id=exec_entry.id,
                                correlation_title=title_key,
                                risk_level=intel.risk_level,
                                correlation_reason=f"Exposed service matches technology in CISA's catalog of actively exploited vulnerabilities. Detail: {intel.threat_description}",
                                recommended_action=intel.recommended_action
                            ))
                            findings_created += 1

    # Complete correlation execution
    exec_entry.status = "COMPLETED"
    exec_entry.completed_at = datetime.datetime.now()

    db.add(AuditLog(
        assessment_id=assessment_id,
        event_type="CORRELATION_COMPLETED",
        event_details=f"Correlation engine completed. Created {findings_created} correlated findings."
    ))
    db.commit()

    print(f"Correlation completed. Findings generated: {findings_created}")
