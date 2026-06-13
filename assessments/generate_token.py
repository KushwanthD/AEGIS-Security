import sqlite3
import secrets
import hashlib
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

cursor.execute("""
SELECT status
FROM Assessments
WHERE id = ?
""", (ASSESSMENT_ID,))

assessment = cursor.fetchone()

if assessment is None:
    print("Assessment not found.")

elif assessment[0] != "APPROVED":
    print("Assessment must be approved first.")

else:

    token = secrets.token_hex(16)

    token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    cursor.execute("""
    INSERT INTO AuthorizationTokens (
        assessment_id,
        token_hash,
        expires_at
    )
    VALUES (
        ?, ?, datetime('now', '+24 hours')
    )
    """, (
        ASSESSMENT_ID,
        token_hash
    ))

    cursor.execute("""
    INSERT INTO AuditLogs (
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?)
    """, (
        ASSESSMENT_ID,
        "TOKEN_GENERATED",
        "Authorization token generated"
    ))

    connection.commit()

    print("Authorization token generated.")
    print(f"Token: {token}")

connection.close()
