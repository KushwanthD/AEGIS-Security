import sqlite3
import argparse

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle


)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


parser = argparse.ArgumentParser()

parser.add_argument(
    "--assessment-id",
    type=int,
    required=True
)

args = parser.parse_args()

ASSESSMENT_ID = args.assessment_id

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

pdf_file = f"aegis_report_{ASSESSMENT_ID}.pdf"

document = SimpleDocTemplate(pdf_file)

styles = getSampleStyleSheet()

content = []

# Title

content.append(
    Paragraph(
        "AEGIS Assessment Report",
        styles["Title"]
    )
)

content.append(Spacer(1, 12))

# Assessment Information

cursor.execute("""
SELECT
    assessment_reference,
    status,
    asset_id
FROM Assessments
WHERE id = ?
""", (ASSESSMENT_ID,))

assessment = cursor.fetchone()

if assessment is None:

    print("Assessment not found.")
    connection.close()
    exit()

assessment_reference = assessment[0]
assessment_status = assessment[1]
asset_id = assessment[2]

cursor.execute("""
SELECT asset_value
FROM Assets
WHERE id = ?
""", (asset_id,))

asset = cursor.fetchone()

asset_value = asset[0]

content.append(
    Paragraph(
        f"<b>Assessment:</b> {assessment_reference}",
        styles["BodyText"]
    )
)

content.append(
    Paragraph(
        f"<b>Asset:</b> {asset_value}",
        styles["BodyText"]
    )
)

content.append(
    Paragraph(
        f"<b>Status:</b> {assessment_status}",
        styles["BodyText"]
    )
)

content.append(Spacer(1, 12))

# ==========================
# RECON RESULTS
# ==========================

content.append(
    Paragraph(
        "Recon Results",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT MAX(id)
FROM ReconExecutions
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

latest_recon_execution = cursor.fetchone()[0]

cursor.execute("""
SELECT
    recon_type,
    result_data
FROM ReconResults
WHERE recon_execution_id = ?
""", (latest_recon_execution,))

for recon_type, result_data in cursor.fetchall():

    content.append(
        Paragraph(
            f"<b>{recon_type}</b>",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            result_data.replace("\n", "<br/>"),
            styles["BodyText"]
        )
    )

content.append(Spacer(1, 12))

# ==========================
# SCAN RESULTS
# ==========================

content.append(
    Paragraph(
        "Scan Results",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT MAX(id)
FROM ScanExecutions
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

latest_scan_execution = cursor.fetchone()[0]

cursor.execute("""
SELECT
    finding_title,
    severity,
    evidence
FROM ScanResults
WHERE scan_execution_id = ?
""", (latest_scan_execution,))

for title, severity, evidence in cursor.fetchall():

    content.append(
        Paragraph(
            f"<b>{title}</b>",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Severity: {severity}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Evidence: {evidence}",
            styles["BodyText"]
        )
    )

content.append(Spacer(1, 12))

# ==========================
# CORRELATED FINDINGS
# ==========================

content.append(
    Paragraph(
        "Correlated Findings",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT MAX(id)
FROM CorrelationExecutions
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

latest_correlation_execution = cursor.fetchone()[0]

cursor.execute("""
SELECT
    correlation_title,
    risk_level,
    correlation_reason,
    recommended_action
FROM CorrelatedFindings
WHERE correlation_execution_id = ?
""", (latest_correlation_execution,))

for title, risk, reason, action in cursor.fetchall():

    content.append(
        Paragraph(
            f"<b>{title}</b>",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            f"Risk: {risk}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Threat Intelligence: {reason}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Recommended Action: {action}",
            styles["BodyText"]
        )
    )

    content.append(
        Spacer(1, 6)
    )

content.append(PageBreak())

# ==========================
# AUDIT TRAIL
# ==========================

content.append(
    Paragraph(
        "Audit Trail",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT
    created_at,
    event_type
FROM AuditLogs
WHERE assessment_id = ?
ORDER BY id
""", (ASSESSMENT_ID,))

audit_rows = [
    ["Timestamp", "Event"]
]

for created_at, event_type in cursor.fetchall():

    audit_rows.append([
        created_at,
        event_type
    ])

audit_table = Table(
    audit_rows,
    colWidths=[180, 250]
)

audit_table.setStyle(
    TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ])
)

content.append(audit_table)

document.build(content)

connection.close()

print(f"PDF report generated: {pdf_file}")
