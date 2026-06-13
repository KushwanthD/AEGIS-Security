import sqlite3
import hashlib

# Simulated DNS TXT value
dns_token = "60df47fe62912d5e850a09922e654e9d"

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

cursor.execute("""
SELECT
    id,
    user_id,
    asset_value,
    verification_token_hash
FROM Assets
WHERE asset_value = 'aegis-approval-test.com'
""")

asset = cursor.fetchone()

if asset is None:
    print("Asset not found.")

else:
    asset_id = asset[0]
    user_id = asset[1]
    asset_value = asset[2]
    stored_hash = asset[3]

    dns_token_hash = hashlib.sha256(
        dns_token.encode()
    ).hexdigest()

    if dns_token_hash == stored_hash:

        cursor.execute("""
        UPDATE Assets
        SET
            verification_status = 'VERIFIED',
            verification_date = CURRENT_TIMESTAMP
        WHERE id = ?
        """, (asset_id,))

        cursor.execute("""
        INSERT INTO AuditLogs (
            user_id,
            asset_id,
            event_type,
            event_details
        )
        VALUES (?, ?, ?, ?)
        """, (
            user_id,
            asset_id,
            "ASSET_VERIFIED",
            f"Ownership verification successful for {asset_value}"
        ))

        connection.commit()

        print("Verification successful.")
        print(f"Asset: {asset_value}")

    else:

        print("Verification failed.")
        print("Token does not match.")

connection.close()
