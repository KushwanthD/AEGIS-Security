import sqlite3
import argparse

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



# Get recon results
cursor.execute("""
SELECT
    recon_type,
    result_data
FROM ReconResults
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

recon_results = cursor.fetchall()

# Get scan results
cursor.execute("""
SELECT
    finding_title,
    severity,
    evidence
FROM ScanResults
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

scan_results = cursor.fetchall()

findings_created = 0

# Rule 1: MX Records Detected
for recon_type, result_data in recon_results:

    if recon_type == "DNS_MX_RECORDS":

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            ASSESSMENT_ID,
            "External Email Infrastructure Detected",
            "INFO",
            "MX records indicate that the domain receives email.",
            "Review SPF, DKIM and DMARC configurations."
        ))

        findings_created += 1

# Rule 2: SPF Record Detected
for recon_type, result_data in recon_results:

    if recon_type == "DNS_TXT_RECORDS" and "v=spf1" in result_data:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            ASSESSMENT_ID,
            "SPF Record Detected",
            "INFO",
            "Domain publishes an SPF policy.",
            "Verify SPF policy is maintained and monitored."
        ))

        findings_created += 1

# Rule 3: SSH Exposed
for finding_title, severity, evidence in scan_results:

    if "SSH Service Exposed" in finding_title:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?)
        """, (
            ASSESSMENT_ID,
            "Administrative Service Exposed",
            "LOW",
            "SSH service is reachable.",
            "Restrict SSH access to trusted networks or VPN users."
        ))

        findings_created += 1

# Audit log
cursor.execute("""
INSERT INTO AuditLogs (
    assessment_id,
    event_type,
    event_details
)
VALUES (?, ?, ?)
""", (
    ASSESSMENT_ID,
    "CORRELATION_COMPLETED",
    f"{findings_created} correlated findings generated"
))

connection.commit()

print(
    f"Correlation completed successfully. "
    f"Generated {findings_created} findings."
)

connection.close()
