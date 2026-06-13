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

# Create Correlation Execution
cursor.execute("""
INSERT INTO CorrelationExecutions (
    assessment_id,
    status
)
VALUES (?, ?)
""", (
    ASSESSMENT_ID,
    "RUNNING"
))

correlation_execution_id = cursor.lastrowid

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

# Detection flags
mx_found = False
spf_found = False
ssh_found = False
http_found = False
https_found = False

# Analyze recon results
for recon_type, result_data in recon_results:

    if recon_type == "DNS_MX_RECORDS":
        mx_found = True

    if (
        recon_type == "DNS_TXT_RECORDS"
        and "v=spf1" in result_data
    ):
        spf_found = True

# Analyze scan results
for finding_title, severity, evidence in scan_results:

    if "SSH Service Exposed" in finding_title:
        ssh_found = True

    if "HTTP Service Exposed" in finding_title:
        http_found = True

    if "HTTPS Service Exposed" in finding_title:
        https_found = True

findings_created = 0

# Rule 1: MX Records
if mx_found:

    cursor.execute("""
    INSERT INTO CorrelatedFindings (
        assessment_id,
        correlation_execution_id,
        correlation_title,
        risk_level,
        correlation_reason,
        recommended_action
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        ASSESSMENT_ID,
        correlation_execution_id,
        "External Email Infrastructure Detected",
        "INFO",
        "MX records indicate that the domain receives email.",
        "Review SPF, DKIM and DMARC configurations."
    ))

    findings_created += 1

# Rule 2: SPF Record
if spf_found:

    cursor.execute("""
    INSERT INTO CorrelatedFindings (
        assessment_id,
        correlation_execution_id,
        correlation_title,
        risk_level,
        correlation_reason,
        recommended_action
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        ASSESSMENT_ID,
        correlation_execution_id,
        "SPF Record Detected",
        "INFO",
        "Domain publishes an SPF policy.",
        "Verify SPF policy is maintained and monitored."
    ))

    findings_created += 1

# Rule 3: SSH Exposure + Threat Intelligence
if ssh_found:

    cursor.execute("""
    SELECT
        risk_level,
        threat_title,
        recommended_action
    FROM ThreatIntel
    WHERE technology = 'SSH'
    LIMIT 1
    """)

    intel = cursor.fetchone()

    risk = "LOW"
    threat = "SSH service is reachable."
    recommendation = (
        "Restrict SSH access to trusted networks or VPN users."
    )

    if intel:

        risk = intel[0]
        threat = intel[1]
        recommendation = intel[2]

    cursor.execute("""
    INSERT INTO CorrelatedFindings (
        assessment_id,
        correlation_execution_id,
        correlation_title,
        risk_level,
        correlation_reason,
        recommended_action
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        ASSESSMENT_ID,
        correlation_execution_id,
        "Administrative Service Exposed",
        risk,
        threat,
        recommendation
    ))

    findings_created += 1

# Rule 4: Web Service Exposure + Threat Intelligence
if http_found or https_found:

    technology = "HTTP"

    if https_found:
        technology = "HTTPS"

    cursor.execute("""
    SELECT
        risk_level,
        threat_title,
        recommended_action
    FROM ThreatIntel
    WHERE technology = ?
    LIMIT 1
    """, (technology,))

    intel = cursor.fetchone()

    risk = "LOW"
    threat = "Public web services were detected during scanning."
    recommendation = (
        "Review exposed web services and ensure security controls are configured."
    )

    if intel:

        risk = intel[0]
        threat = intel[1]
        recommendation = intel[2]

    cursor.execute("""
    INSERT INTO CorrelatedFindings (
        assessment_id,
        correlation_execution_id,
        correlation_title,
        risk_level,
        correlation_reason,
        recommended_action
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        ASSESSMENT_ID,
        correlation_execution_id,
        "Web Service Exposure Detected",
        risk,
        threat,
        recommendation
    ))

    findings_created += 1

# Mark execution completed
cursor.execute("""
UPDATE CorrelationExecutions
SET
    status = ?,
    completed_at = CURRENT_TIMESTAMP
WHERE id = ?
""", (
    "COMPLETED",
    correlation_execution_id
))

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
