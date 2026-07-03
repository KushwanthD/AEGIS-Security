import os
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
        
    pdf_path = os.path.join(project_root, file_name)

    doc = SimpleDocTemplate(
        pdf_path,
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
    report_title = "AEGIS Technical Security Report" if report_type.upper() == "TECHNICAL" else "AEGIS Executive Security Report"
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
        # --- TECHNICAL REPORT ---
        
        # 1. Correlated Vulnerabilities
        content.append(Paragraph("1. Correlated Findings & Risks", h1_style))
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

        # 2. DNS Recon & DMARC Results
        content.append(Paragraph("2. DNS Reconnaissance & DMARC Inspection", h1_style))
        for r in recon_results:
            content.append(Paragraph(f"<b>{r.recon_type}</b>", h2_style))
            content.append(Paragraph(r.result_data.replace("\n", "<br/>"), code_style))
            content.append(Spacer(1, 6))

        content.append(Spacer(1, 10))

        # 3. Scanning Results
        content.append(Paragraph("3. Network Services (Nmap Scan)", h1_style))
        nmap_results = [s for s in scan_results if s.tool_name == "Nmap"]
        if not nmap_results:
            content.append(Paragraph("No open network ports discovered during fast scan.", body_style))
        for s in nmap_results:
            content.append(Paragraph(f"<b>{s.finding_title}</b> - Severity: <b>{s.severity}</b>", h2_style))
            content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
            content.append(Spacer(1, 4))

        content.append(Spacer(1, 10))

        # 4. Pixel Tracking Leakage Auditor
        content.append(Paragraph("4. Web Privacy & Pixel Tracker Auditor", h1_style))
        pixel_result = next((s for s in scan_results if s.tool_name == "Pixel Auditor" and s.finding_category == "Privacy Audit"), None)
        
        if not pixel_result or not pixel_result.evidence:
            content.append(Paragraph("No pixel auditing data discovered or scan was not executed.", body_style))
        else:
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
                    
                    # Log leaks
                    leaks = page.get("pii_leaks", [])
                    if leaks:
                        content.append(Paragraph("<i>Detected Payload Disclosures:</i>", h2_style))
                        for leak in leaks:
                            leak_line = f"<font color='red'>• [{leak['severity'].upper()}]</font> {leak['finding']} ({leak['vendor']})"
                            content.append(Paragraph(leak_line, body_style))
                    content.append(Spacer(1, 8))
            except Exception as ex:
                content.append(Paragraph(f"Failed to parse pixel auditor payload data: {ex}", body_style))

        content.append(Spacer(1, 10))

        # 5. Nikto Web Vulnerabilities
        content.append(Paragraph("5. Web Application Vulnerabilities (Nikto Scan)", h1_style))
        nikto_results = [s for s in scan_results if s.tool_name == "Nikto"]
        if not nikto_results:
            content.append(Paragraph("No web application scanning executed or target is not web-enabled.", body_style))
        for s in nikto_results:
            content.append(Paragraph(f"<b>{s.finding_title}</b>", h2_style))
            content.append(Paragraph(s.description.replace("\n", "<br/>"), body_style))
            content.append(Paragraph(f"Evidence: {s.evidence}", code_style))
            content.append(Spacer(1, 4))
            
        content.append(PageBreak())

        # 6. Technical Audit Log
        content.append(Paragraph("6. Assessment Technical Audit Trail", h1_style))
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
    
    # Save Report record in DB
    report_entry = Report(
        assessment_id=assessment_id,
        report_type=report_type.upper(),
        file_name=file_name
    )
    db.add(report_entry)
    db.commit()

    return file_name
