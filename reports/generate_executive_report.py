import sqlite3
import argparse

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
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
        f"<b>Assessment:</b> "
        f"{assessment_reference}",
        styles["BodyText"]
    )
)

content.append(
    Paragraph(
        f"<b>Asset:</b> "
        f"{asset_value}",
        styles["BodyText"]
    )
)

content.append(
    Paragraph(
        f"<b>Status:</b> "
        f"{assessment_status}",
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
        f"<b>Overall Risk:</b> "
        f"{overall_risk}",
        styles["Heading2"]
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

content.append(
    Paragraph(
        "This assessment identified "
        "security-relevant services and "
        "internet-facing infrastructure "
        "associated with the authorized "
        "asset. Findings were correlated "
        "from reconnaissance and scanning "
        "activities performed through "
        "the AEGIS assessment workflow.",
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
    correlation_reason
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

findings = cursor.fetchall()

for title, reason in findings:

    content.append(
        Paragraph(
            f"• {title}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            reason,
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
SELECT
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

document.build(content)

connection.close()

print(
    f"Executive report generated: "
    f"{pdf_file}"
)
