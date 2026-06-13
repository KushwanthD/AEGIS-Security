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

print("=" * 50)
print("AEGIS ASSESSMENT REPORT")
print("=" * 50)

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

print(f"\nAssessment: {assessment_reference}")
print(f"Asset: {asset_value}")
print(f"Status: {assessment_status}")

# Recon Results
print("\n" + "-" * 50)
print("RECON RESULTS")
print("-" * 50)

cursor.execute("""
SELECT
    recon_type,
    result_data
FROM ReconResults
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for recon_type, result_data in cursor.fetchall():

    print(f"\n[{recon_type}]")
    print(result_data)

# Scan Results
print("\n" + "-" * 50)
print("SCAN RESULTS")
print("-" * 50)

cursor.execute("""
SELECT
    finding_title,
    severity,
    evidence
FROM ScanResults
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for title, severity, evidence in cursor.fetchall():

    print(f"\nTitle: {title}")
    print(f"Severity: {severity}")
    print(f"Evidence: {evidence}")

# Correlated Findings
print("\n" + "-" * 50)
print("CORRELATED FINDINGS")
print("-" * 50)

cursor.execute("""
SELECT
    correlation_title,
    risk_level,
    correlation_reason,
    recommended_action
FROM CorrelatedFindings
WHERE assessment_id = ?
""", (ASSESSMENT_ID,))

for title, risk, reason, action in cursor.fetchall():

    print(f"\nTitle: {title}")
    print(f"Risk: {risk}")
    print(f"Reason: {reason}")
    print(f"Recommendation: {action}")

# Audit Trail
print("\n" + "-" * 50)
print("AUDIT TRAIL")
print("-" * 50)

cursor.execute("""
SELECT
    event_type,
    created_at
FROM AuditLogs
ORDER BY id
""")

for event_type, created_at in cursor.fetchall():

    print(
        f"{created_at} | {event_type}"
    )

print("\n" + "=" * 50)
print("END OF REPORT")
print("=" * 50)

connection.close()
