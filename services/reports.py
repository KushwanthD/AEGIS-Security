import os
import io
import json
import datetime
from sqlalchemy.orm import Session
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from database.models import (
    Assessment, Asset, ReconResult, ScanResult, CorrelatedFinding, AuditLog, Report
)

def generate_pdf(db: Session, assessment_id: int, report_type: str) -> str:
    """
    Generates a technical or executive PDF report for the given assessment.
    Returns the file name path of the generated PDF.
    """
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise ValueError("Assessment not found.")

    asset = db.query(Asset).filter(Asset.id == assessment.asset_id).first()
    target = asset.asset_value if asset else "Unknown Target"

    # Define report file names
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    if report_type.upper() == "EXECUTIVE":
        file_name = f"aegis_executive_report_{assessment_id}.pdf"
    else:
        file_name = f"aegis_report_{assessment_id}.pdf"
        
    # Generate into an in-memory buffer so bytes are stored in DB (survives ephemeral FS)
    pdf_buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        pdf_buffer,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styled paragraph wrappers
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#4c1d95'),
        spaceAfter=15
    )
    h1_style = ParagraphStyle(
        'DocH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        textColor=colors.HexColor('#7c3aed'),
        spaceBefore=15,
        spaceAfter=10
    )
    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#4c1d95'),
        spaceBefore=10,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        spaceAfter=8
    )
    code_style = ParagraphStyle(
        'DocCode',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#333333'),
        backColor=colors.HexColor('#f5f5f5'),
        borderPadding=5
    )

    content = []

    # Get dynamic database findings
    recon_results = db.query(ReconResult).filter(ReconResult.assessment_id == assessment_id).all()
    scan_results = db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).all()
    findings = db.query(CorrelatedFinding).filter(CorrelatedFinding.assessment_id == assessment_id).all()
    audit_logs = db.query(AuditLog).filter(AuditLog.assessment_id == assessment_id).all()

    # Calculate overall risk score
    risk_score = 0
    for f in findings:
        if f.risk_level == "CRITICAL": risk_score += 10
        elif f.risk_level == "HIGH": risk_score += 7
        elif f.risk_level == "MEDIUM": risk_score += 4
        elif f.risk_level == "LOW": risk_score += 1
    
    overall_risk = "INFO"
    risk_color = '#92D050'
    if risk_score >= 15:
        overall_risk = "CRITICAL"
        risk_color = '#8B0000'
    elif risk_score >= 10:
        overall_risk = "HIGH"
        risk_color = '#FF4444'
    elif risk_score >= 5:
        overall_risk = "MEDIUM"
        risk_color = '#FFD966'
    elif risk_score >= 1:
        overall_risk = "LOW"
        risk_color = '#92D050'

    # --- Title Page ---
    report_title = f"AEGIS Technical Security Report (ID: {assessment_id})" if report_type.upper() == "TECHNICAL" else f"AEGIS Executive Security Report (ID: {assessment_id})"
    content.append(Paragraph(report_title, title_style))
    content.append(Spacer(1, 10))

    meta_data = [
        [Paragraph("<b>Target Domain / IP:</b>", body_style), Paragraph(target, body_style)],
        [Paragraph("<b>Assessment ID:</b>", body_style), Paragraph(str(assessment_id), body_style)],
        [Paragraph("<b>Reference Number:</b>", body_style), Paragraph(assessment.assessment_reference, body_style)],
        [Paragraph("<b>Date of Report:</b>", body_style), Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), body_style)],
        [Paragraph("<b>Overall Risk Status:</b>", body_style), Paragraph(f"<font color='{risk_color}'><b>{overall_risk}</b></font> (Score: {risk_score})", body_style)]
    ]
    meta_table = Table(meta_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    content.append(meta_table)
    content.append(Spacer(1, 15))

    # --- Report Content Division ---
    if report_type.upper() == "EXECUTIVE":
        # Executive Summary Page
        content.append(Paragraph("Executive Summary", h1_style))
        summary_text = (
            f"An authorized external security assessment was conducted for target resource <b>{target}</b>. "
            f"The assessment analyzed public DNS records, mail infrastructure parameters, open network services (Nmap), "
            f"and web privacy tracking compliance (Pixel Auditor). Based on the correlation of findings and threat "
            f"intelligence models, the target's security posture is rated as <b>{overall_risk}</b>.<br/><br/>"
            f"Exposed web elements and lack of enforced validation can increase administrative visibility. Immediate remediation "
            f"for vulnerabilities (like insecure mail setups or pixel data leakage) is advised to lock down exposure boundaries."
        )
        content.append(Paragraph(summary_text, body_style))
        content.append(Spacer(1, 10))

        content.append(Paragraph("Key Findings Summary", h1_style))
        for f in findings:
            item_text = f"<b>{f.correlation_title}</b> ({f.risk_level})<br/><i>Impact:</i> {f.correlation_reason}"
            content.append(Paragraph(item_text, body_style))
            content.append(Spacer(1, 5))

        content.append(PageBreak())

        # Recommendations Page
        content.append(Paragraph("Remediation Roadmap", h1_style))
        for idx, f in enumerate(findings, 1):
            rec_text = f"<b>{idx}. {f.correlation_title} ({f.risk_level})</b><br/><i>Recommended Action:</i> {f.recommended_action}"
            content.append(Paragraph(rec_text, body_style))
            content.append(Spacer(1, 10))

        content.append(Spacer(1, 15))
        content.append(Paragraph("Assessment Log Timeline", h1_style))
        for log in audit_logs:
            if log.event_type in ("ASSESSMENT_REQUESTED", "ASSESSMENT_APPROVED", "RECON_COMPLETED", "SCAN_COMPLETED", "CORRELATION_COMPLETED"):
                log_text = f"• <b>{log.created_at.strftime('%Y-%m-%d %H:%M')}</b> - {log.event_details or log.event_type}"
                content.append(Paragraph(log_text, body_style))

    else:
        # --- TECHNICAL REPORT (Structured by Tool Categories) ---
        
        # 1. Correlated Vulnerabilities
        content.append(Paragraph("1. Correlated Findings & Risks", h1_style))
        content.append(Paragraph(
            "<b>Assessment Overview:</b> The correlation engine matches vulnerability indicators across active scanning plugins "
            "to trace exploit combinations and risk chains.", body_style))
        content.append(Spacer(1, 4))
        
        if not findings:
            content.append(Paragraph("No severe vulnerabilities or correlated risks identified during this assessment cycle.", body_style))
        for f in findings:
            finding_block = (
                f"<b>Title:</b> {f.correlation_title} (<font color='red'><b>{f.risk_level}</b></font>)<br/>"
                f"<b>Threat Analysis:</b> {f.correlation_reason}<br/>"
                f"<b>Remediation:</b> {f.recommended_action}"
            )
            content.append(Paragraph(finding_block, body_style))
            content.append(Spacer(1, 8))

        content.append(Spacer(1, 10))

        # 2. Network & Port Infrastructure (Nmap / OpenVAS / Nessus)
        content.append(Paragraph("2. Network Infrastructure & Port Discovery (Nmap)", h1_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Active host scanning, open port audits, and service identification.<br/>"
            "<b>What We Looked For:</b> Unnecessary open ports, outdated daemon versions (SSH, HTTP, FTP), and service banner exposures.<br/>"
            "<b>Audit Result:</b> Active findings are detailed below.", body_style
        ))
        content.append(Spacer(1, 4))
        
        nmap_results = [s for s in scan_results if s.tool_name == "Nmap" or s.tool_name == "Nmap NSE Script"]
        if not nmap_results:
            content.append(Paragraph("No network infrastructure vulnerability findings recorded.", body_style))
        for s in nmap_results:
            content.append(Paragraph(f"<b>{s.finding_title}</b> - Category: {s.finding_category} ({s.severity})", h2_style))
            content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
            content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
            content.append(Spacer(1, 4))

        content.append(Spacer(1, 10))

        # 3. Web Application & Privacy Audit (Nikto / Playwright / SQLmap)
        content.append(Paragraph("3. Web Application Security & Privacy Assessment", h1_style))
        
        # SQL Injection (SQLmap)
        content.append(Paragraph("A. SQL Injection Auditor (SQLmap Fuzzer)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Active query parameter fuzzing and authentication form payload injection.<br/>"
            "<b>What We Looked For:</b> SQL syntax errors, database driver exceptions, or authentication bypass indicators on form parameters (GET, POST Form, and POST JSON).", body_style
        ))
        sqlmap_results = [s for s in scan_results if s.tool_name == "SQLmap Form Auditor"]
        if sqlmap_results:
            for s in sqlmap_results:
                content.append(Paragraph(f"<b>Result:</b> <font color='red'><b>{s.severity}</b></font> - {s.finding_title}", body_style))
                content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
                content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
                content.append(Spacer(1, 4))
        else:
            content.append(Paragraph("<b>Result:</b> <font color='green'><b>PASS</b></font> - No SQL Injection indicators detected on the login or form parameters.", body_style))
        content.append(Spacer(1, 8))

        # Web app vuln findings (Nikto)
        content.append(Paragraph("B. Web Server Vulnerability Scan (Nikto)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Server misconfiguration probes and administrative directory exposure checking.<br/>"
            "<b>What We Looked For:</b> Excluded config file paths, default files, and active administrative endpoints (e.g. /admin, /wp-admin).", body_style
        ))
        nikto_results = [s for s in scan_results if s.tool_name == "Nikto"]
        if nikto_results:
            for s in nikto_results:
                content.append(Paragraph(f"<b>Result:</b> {s.finding_title} - Severity: <b>{s.severity}</b>", body_style))
                content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
                content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
                content.append(Spacer(1, 4))
        else:
            content.append(Paragraph("<b>Result:</b> <font color='green'><b>PASS</b></font> - Web server configurations conform to standard directory exposure rules.", body_style))
        content.append(Spacer(1, 8))

        # Web Privacy / Tracker audit (Playwright)
        content.append(Paragraph("C. Privacy & Tracker Tracker Audit (Playwright Pixel Auditor)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Headless browser instrumentation and HTTP network request interception.<br/>"
            "<b>What We Looked For:</b> Unauthorized transmission of data to third-party advertising trackers (such as Meta Pixel, GTM, GA4, TikTok, or LinkedIn Insight) on sensitive page scopes.", body_style
        ))
        pixel_result = next((s for s in scan_results if s.tool_name == "Pixel Auditor" and s.finding_category == "Privacy Audit"), None)
        if pixel_result and pixel_result.evidence:
            try:
                pages_data = json.loads(pixel_result.evidence)
                for page in pages_data:
                    url_p = page.get("url", "Unknown Link")
                    p_type = page.get("page_type", "General Page")
                    trackers = ", ".join(page.get("trackers", [])) or "None Detected"
                    score = page.get("risk_score", 0)
                    
                    page_summary = (
                        f"<b>Page URL:</b> {url_p}<br/>"
                        f"<b>Page Classification:</b> {p_type.capitalize()} | <b>Risk Score:</b> {score}/10<br/>"
                        f"<b>Detected Trackers:</b> {trackers}"
                    )
                    content.append(Paragraph(page_summary, body_style))
                    
                    leaks = page.get("pii_leaks", [])
                    if leaks:
                        content.append(Paragraph("<i>Detected Payload Disclosures:</i>", body_style))
                        for leak in leaks:
                            leak_line = f"<font color='red'>• [{leak['severity'].upper()}]</font> {leak['finding']} ({leak['vendor']})"
                            content.append(Paragraph(leak_line, body_style))
                    content.append(Spacer(1, 8))
            except Exception as ex:
                content.append(Paragraph(f"Failed to parse pixel auditor payload data: {ex}", body_style))
        else:
            content.append(Paragraph("<b>Result:</b> <font color='green'><b>PASS</b></font> - No data leakage or third-party pixel tracking detected on checked portals.", body_style))

        content.append(Spacer(1, 10))

        # 4. Compliance & Header Audits (SSL / Security Headers / Robots.txt / Dirb Crawler)
        content.append(Paragraph("4. Configuration Compliance & Exposures", h1_style))
        
        # SSL TLS Cert
        content.append(Paragraph("A. Cryptographic Cipher Strength & Certificate Validity (SSL Auditor)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> SSL/TLS handshake port 443 audits.<br/>"
            "<b>What We Looked For:</b> Deprecated TLS versions (TLS 1.0/1.1), expired SSL certificates, and weak encryption cipher suites.", body_style
        ))
        ssl_results = [s for s in scan_results if s.tool_name == "SSL Auditor"]
        for s in ssl_results:
            content.append(Paragraph(f"<b>Result:</b> {s.finding_title} - Severity: <b>{s.severity}</b>", body_style))
            content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
            content.append(Spacer(1, 4))
        content.append(Spacer(1, 8))

        # HTTP Headers
        content.append(Paragraph("B. Web Security Headers Compliance (Headers Auditor)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Target HTTP response header configuration verification.<br/>"
            "<b>What We Looked For:</b> Missing security flags: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options (XFO), and X-Content-Type-Options.", body_style
        ))
        header_results = [s for s in scan_results if s.tool_name == "Headers Auditor"]
        for s in header_results:
            content.append(Paragraph(f"<b>Result:</b> {s.finding_title} - Severity: <b>{s.severity}</b>", body_style))
            content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
            content.append(Spacer(1, 4))
        content.append(Spacer(1, 8))

        # Dirb Web Crawler
        content.append(Paragraph("C. Directory Crawler & Sensitive File Scanner (Dirb Crawler)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Crawling local links and directory brute-forcing.<br/>"
            "<b>What We Looked For:</b> Exposed repositories (/.git/config, /.git/HEAD), configuration variables (/.env, /secrets.json), and backup files.", body_style
        ))
        dirb_results = [s for s in scan_results if s.tool_name == "Dirb Web Crawler"]
        if dirb_results:
            for s in dirb_results:
                content.append(Paragraph(f"<b>Result:</b> <font color='red'><b>{s.severity}</b></font> - {s.finding_title}", body_style))
                content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
                content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
                content.append(Spacer(1, 4))
        else:
            content.append(Paragraph("<b>Result:</b> <font color='green'><b>PASS</b></font> - Crawled directories did not expose any system configurations, backup scripts, or code repositories.", body_style))
        content.append(Spacer(1, 8))

        # Robots.txt
        content.append(Paragraph("D. Crawler Indexing Configurations (Robots Auditor)", h2_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Retrieval and parse audits of /robots.txt files.<br/>"
            "<b>What We Looked For:</b> Crawl rules exposing sensitive directories, administrative consoles, or developer directory routes.", body_style
        ))
        robots_results = [s for s in scan_results if s.tool_name == "Robots Auditor"]
        for s in robots_results:
            content.append(Paragraph(f"<b>Result:</b> {s.finding_title} - Severity: <b>{s.severity}</b>", body_style))
            content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
            content.append(Spacer(1, 4))
        content.append(Spacer(1, 8))

        content.append(Spacer(1, 10))

        # 5. Code & Dependencies Audit (Snyk / OWASP Dependency Check)
        content.append(Paragraph("5. Code & Dependency Audit (Snyk)", h1_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> Software composition analysis (SCA) of active dependencies.<br/>"
            "<b>What We Looked For:</b> Libraries matching open vulnerability reports (CVE entries) in the National Vulnerability Database (NVD) or Snyk vulnerability catalog.", body_style
        ))
        snyk_results = [s for s in scan_results if s.tool_name == "Snyk"]
        if snyk_results:
            for s in snyk_results:
                content.append(Paragraph(f"<b>Result:</b> <font color='orange'><b>{s.severity}</b></font> - {s.finding_title}", body_style))
                content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
                content.append(Spacer(1, 4))
        else:
            content.append(Paragraph("<b>Result:</b> <font color='green'><b>PASS</b></font> - Scanned requirements list contains no vulnerabilities matching known CVE database listings.", body_style))
        
        content.append(Spacer(1, 10))

        # 6. DNS Reconnaissance (DNSRecon / Amass / Sublist3r)
        content.append(Paragraph("6. Domain Intelligence & DNS Recon (DNSRecon)", h1_style))
        content.append(Paragraph(
            "<b>What We Tested:</b> DNS resolver zone queries.<br/>"
            "<b>What We Looked For:</b> Unsecured zones, active MX server routing parameters, and valid email security configurations (DMARC / SPF records).", body_style
        ))
        for r in recon_results:
            content.append(Paragraph(f"<b>{r.recon_type}</b>", h2_style))
            content.append(Paragraph(r.result_data.replace("\n", "<br/>"), code_style))
            content.append(Spacer(1, 6))

        content.append(PageBreak())

        # 7. Technical Audit Log
        content.append(Paragraph("7. Assessment Technical Audit Trail", h1_style))
        audit_rows = [["Timestamp", "System Log Event Type", "Details"]]
        for log in audit_logs:
            audit_rows.append([
                log.created_at.strftime("%Y-%m-%d %H:%M"),
                log.event_type,
                log.event_details or "No details"
            ])
        
        audit_table = Table(audit_rows, colWidths=[110, 150, 240])
        audit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dddddd')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))
        content.append(audit_table)

    # Document generation
    doc.build(content)
    pdf_bytes = pdf_buffer.getvalue()

    # Also write to disk as a fallback (for local dev)
    try:
        pdf_path = os.path.join(project_root, file_name)
        with open(pdf_path, 'wb') as f:
            f.write(pdf_bytes)
    except Exception:
        pass

    # Save Report record in DB with PDF bytes
    report_entry = Report(
        assessment_id=assessment_id,
        report_type=report_type.upper(),
        file_name=file_name,
        pdf_data=pdf_bytes
    )
    db.add(report_entry)
    db.commit()

    return file_name
