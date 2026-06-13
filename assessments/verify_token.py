import sqlite3
import hashlib
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    "--assessment-id",
    type=int,
    required=True
)

parser.add_argument(
    "--token",
    required=True
)

args = parser.parse_args()

ASSESSMENT_ID = args.assessment_id
token = args.token

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    id,
    token_hash,
    expires_at,
    used
FROM AuthorizationTokens
WHERE assessment_id = ?
ORDER BY id DESC
LIMIT 1
""", (ASSESSMENT_ID,))

record = cursor.fetchone()

if record is None:
    print("No authorization token found.")

else:

    token_id = record[0]
    stored_hash = record[1]
    expires_at = record[2]
    used = record[3]

    if used:
        print("Token already used.")

    else:

        supplied_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        if supplied_hash != stored_hash:
            print("Invalid token.")

        else:

            cursor.execute("""
            UPDATE AuthorizationTokens
            SET
                used = 1,
                used_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """, (token_id,))

            cursor.execute("""
            INSERT INTO AuditLogs (
                assessment_id,
                event_type,
                event_details
            )
            VALUES (?, ?, ?)
            """, (
                ASSESSMENT_ID,
                "TOKEN_VERIFIED",
                "Authorization token verified successfully"
            ))

            connection.commit()

            print("Token verified successfully.")

connection.close()
