import sqlite3
import hashlib
import requests
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    "--asset-id",
    type=int,
    required=True
)

args = parser.parse_args()

ASSET_ID = args.asset_id

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    asset_value,
    verification_token_hash,
    verification_status
FROM Assets
WHERE id = ?
""", (ASSET_ID,))

asset = cursor.fetchone()

if asset is None:

    print("Asset not found.")

else:

    asset_value = asset[0]
    stored_hash = asset[1]

    verification_url = (
        f"http://{asset_value}"
        "/.well-known/aegis-verification.txt"
    )

    try:

        response = requests.get(
            verification_url,
            timeout=10
        )

        token = response.text.strip()

        supplied_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        if supplied_hash == stored_hash:

            cursor.execute("""
            UPDATE Assets
            SET
                verification_status = ?,
                verification_date = CURRENT_TIMESTAMP
            WHERE id = ?
            """, (
                "VERIFIED",
                ASSET_ID
            ))

            cursor.execute("""
            INSERT INTO AuditLogs (
                asset_id,
                event_type,
                event_details
            )
            VALUES (?, ?, ?)
            """, (
                ASSET_ID,
                "ASSET_VERIFIED",
                f"File verification successful for {asset_value}"
            ))

            connection.commit()

            print("Asset verified successfully.")

        else:

            print("Verification token mismatch.")

    except Exception as error:

        print(
            f"Verification failed: {error}"
        )

connection.close()
