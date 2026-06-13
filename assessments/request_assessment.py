import sqlite3
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    "--asset-id",
    type=int,
    required=True
)

parser.add_argument(
    "--reference",
    required=True
)

args = parser.parse_args()

ASSET_ID = args.asset_id
ASSESSMENT_REFERENCE = args.reference

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

cursor.execute("""
SELECT verification_status
FROM Assets
WHERE id = ?
""", (ASSET_ID,))

asset = cursor.fetchone()

if asset is None:
    print("Asset not found.")

elif asset[0] != "VERIFIED":
    print("Asset must be verified before assessment.")

else:

    cursor.execute("""
    INSERT INTO Assessments (
        asset_id,
        assessment_reference,
        status
    )
    VALUES (?, ?, ?)
    """, (
        ASSET_ID,
        ASSESSMENT_REFERENCE,
        "PENDING"
    ))

    assessment_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO AuditLogs (
        asset_id,
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?, ?)
    """, (
        ASSET_ID,
        assessment_id,
        "ASSESSMENT_REQUESTED",
        f"Assessment requested: {ASSESSMENT_REFERENCE}"
    ))

    connection.commit()

    print("Assessment created successfully.")
    print(f"Reference: {ASSESSMENT_REFERENCE}")

connection.close()
