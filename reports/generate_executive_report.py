import sqlite3
import argparse

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

parser = argparse.ArgumentParser()

parser.add_argument(
    "--assessment-id",
    type=int,
    required=True
)

args = parser.parse_args()

ASSESSMENT_ID = args.assessment_id

connection = sqlite3.connect(
    "database/aegis.db"
)

cursor = connection.cursor()

pdf_file = (
    f"aegis_executive_report_"
    f"{ASSESSMENT_ID}.pdf"
)

document = SimpleDocTemplate(
    pdf_file
)

styles = getSampleStyleSheet()

content = []

# =====================
# TITLE
# =====================

content.append(
    Paragraph(
        "AEGIS Executive Security Report",
        styles["Title"]
    )
)

content.append(
    Spacer(1, 12)
)

# =====================
# ASSESSMENT INFO
# =====================

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

content.append(
    Spacer(1, 12)
)

# =====================
# OVERALL RISK
# =====================

cursor.execute("""
SELECT risk_level
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

risks = [
    row[0]
    for row in cursor.fetchall()
]

overall_risk = "INFO"

if "CRITICAL" in risks:
    overall_risk = "CRITICAL"

elif "HIGH" in risks:
    overall_risk = "HIGH"

elif "MEDIUM" in risks:
    overall_risk = "MEDIUM"

elif "LOW" in risks:
    overall_risk = "LOW"

content.append(
    Paragraph(
        f"<b>Overall Risk:</b> {overall_risk}",
        styles["Heading1"]
    )
)

content.append(
    Spacer(1, 12)
)

# =====================
# EXECUTIVE SUMMARY
# =====================

content.append(
    Paragraph(
        "Executive Summary",
        styles["Heading1"]
    )
)

summary = (
    f"The authorized assessment of "
    f"{asset_value} identified "
    f"internet-facing services and "
    f"security-relevant infrastructure. "
    f"The overall risk level for this "
    f"assessment is classified as "
    f"{overall_risk} based on "
    f"correlated findings and threat "
    f"intelligence analysis."
)

content.append(
    Paragraph(
        summary,
        styles["BodyText"]
    )
)

content.append(
    Spacer(1, 12)
)

# =====================
# KEY FINDINGS
# =====================

content.append(
    Paragraph(
        "Key Findings",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT
    correlation_title,
    risk_level
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for title, risk in cursor.fetchall():

    content.append(
        Paragraph(
            f"• {title} ({risk})",
            styles["BodyText"]
        )
    )

content.append(
    Spacer(1, 12)
)

# =====================
# THREAT INTELLIGENCE
# =====================

content.append(
    Paragraph(
        "Threat Intelligence Summary",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT DISTINCT
    correlation_reason
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for row in cursor.fetchall():

    content.append(
        Paragraph(
            f"• {row[0]}",
            styles["BodyText"]
        )
    )

content.append(
    Spacer(1, 12)
)

# =====================
# BUSINESS IMPACT
# =====================

content.append(
    Paragraph(
        "Business Impact",
        styles["Heading1"]
    )
)

content.append(
    Paragraph(
        "Exposed administrative and web "
        "services may increase attack "
        "surface visibility and create "
        "opportunities for unauthorized "
        "access attempts. Continuous "
        "monitoring and security control "
        "validation are recommended.",
        styles["BodyText"]
    )
)

content.append(
    Spacer(1, 12)
)

# =====================
# RECOMMENDATIONS
# =====================

content.append(
    Paragraph(
        "Recommendations",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT DISTINCT
    recommended_action
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for row in cursor.fetchall():

    content.append(
        Paragraph(
            f"• {row[0]}",
            styles["BodyText"]
        )
    )

content.append(
    Spacer(1, 12)
)

# =====================
# ASSESSMENT TIMELINE
# =====================

content.append(
    Paragraph(
        "Assessment Timeline",
        styles["Heading1"]
    )
)

cursor.execute("""
SELECT
    event_type,
    created_at
FROM AuditLogs
WHERE assessment_id = ?
AND event_type IN (
    'ASSESSMENT_APPROVED',
    'TOKEN_VERIFIED',
    'RECON_COMPLETED',
    'SCAN_COMPLETED',
    'CORRELATION_COMPLETED'
)
ORDER BY id
""", (ASSESSMENT_ID,))

for event_type, created_at in cursor.fetchall():

    content.append(
        Paragraph(
            f"• {created_at} - {event_type}",
            styles["BodyText"]
        )
    )

document.build(content)

connection.close()

print(
    f"Executive report generated: "
    f"{pdf_file}"
)
