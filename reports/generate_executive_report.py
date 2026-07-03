import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
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

risk_score = 0

for risk in risks:

    if risk == "CRITICAL":
        risk_score += 10

    elif risk == "HIGH":
        risk_score += 7

    elif risk == "MEDIUM":
        risk_score += 4

    elif risk == "LOW":
        risk_score += 1

overall_risk = "INFO"

if risk_score >= 15:
    overall_risk = "CRITICAL"

elif risk_score >= 10:
    overall_risk = "HIGH"

elif risk_score >= 5:
    overall_risk = "MEDIUM"

elif risk_score >= 1:
    overall_risk = "LOW"
content.append(
    Paragraph(
        f"<b>Risk Score:</b> {overall_risk}",
        styles["Heading1"]
    )
)

content.append(
    Spacer(1, 12)
)

# =====================
# AI-POWERED NARRATIVE GENERATION
# =====================
import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load API key from workspace root .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

# Fetch all correlated findings to provide context to Gemini
cursor.execute("""
SELECT correlation_title, risk_level, correlation_reason, recommended_action
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))
correlated_findings = cursor.fetchall()

ai_summary = (
    f"The authorized assessment of {asset_value} identified "
    f"internet-facing services and security-relevant infrastructure. "
    f"The overall risk level for this assessment is classified as "
    f"{overall_risk} based on correlated findings and threat intelligence analysis."
)
ai_impact = (
    "Exposed administrative and web services may increase attack "
    "surface visibility and create opportunities for unauthorized "
    "access attempts. Continuous monitoring and security control "
    "validation are recommended."
)
ai_recommendations = []

# Fetch default static recommendations as fallbacks
cursor.execute("""
SELECT DISTINCT recommended_action
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))
for row in cursor.fetchall():
    ai_recommendations.append(row[0])

if api_key and len(correlated_findings) > 0:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        findings_text = "\n".join([f"- {row[0]} ({row[1]} risk) - Detail: {row[2]}" for row in correlated_findings])
        
        prompt = f"""
You are Aegis AI, a security assessment expert writing an Executive Security Assessment Report for target {asset_value}.
Overall Risk Rating: {overall_risk}

Findings detected during scan:
{findings_text}

Write three sections for the report:
1. Executive Summary (2-3 sentences summarizing the critical exposure).
2. Business Impact (2-3 sentences outlining the corporate risk and operational threat).
3. Recommendations (3-4 concise, high-level remediation steps).

Respond strictly in this template:
[EXECUTIVE_SUMMARY]
<summary here>
[BUSINESS_IMPACT]
<impact here>
[RECOMMENDATIONS]
• <rec 1>
• <rec 2>
• <rec 3>
"""
        response = model.generate_content(prompt)
        text = response.text
        
        if "[EXECUTIVE_SUMMARY]" in text and "[BUSINESS_IMPACT]" in text and "[RECOMMENDATIONS]" in text:
            ai_summary = text.split("[EXECUTIVE_SUMMARY]")[1].split("[BUSINESS_IMPACT]")[0].strip()
            ai_impact = text.split("[BUSINESS_IMPACT]")[1].split("[RECOMMENDATIONS]")[0].strip()
            recs_raw = text.split("[RECOMMENDATIONS]")[1].strip().split("\n")
            parsed_recs = [r.replace("•", "").replace("-", "").strip() for r in recs_raw if r.strip()]
            if len(parsed_recs) > 0:
                ai_recommendations = parsed_recs
    except Exception as e:
        print(f"Gemini API error, falling back to static templates: {e}")

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
        ai_summary,
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
for title, risk in [(row[0], row[1]) for row in correlated_findings]:
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
unique_reasons = list(set([row[2] for row in correlated_findings if row[2]]))
for reason in unique_reasons:
    content.append(
        Paragraph(
            f"• {reason}",
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
        ai_impact,
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
for rec in ai_recommendations:
    content.append(
        Paragraph(
            f"• {rec}",
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
