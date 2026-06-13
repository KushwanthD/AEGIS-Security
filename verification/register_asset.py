import sqlite3
import secrets
import hashlib
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
    "--asset-type",
    required=True
)

parser.add_argument(
    "--asset-value",
    required=True
)

parser.add_argument(
    "--verification-method",
    choices=["DNS", "FILE"],
    required=True
)

args = parser.parse_args()

USER_ID = 1

ASSET_TYPE = args.asset_type
ASSET_VALUE = args.asset_value
VERIFICATION_METHOD = args.verification_method

verification_token = secrets.token_hex(16)

verification_token_hash = hashlib.sha256(
    verification_token.encode()
).hexdigest()

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

try:

    cursor.execute("""
    INSERT INTO Assets (
        user_id,
        asset_type,
        asset_value,
        verification_status,
        verification_token_hash,
        verification_method
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        USER_ID,
        ASSET_TYPE,
        ASSET_VALUE,
        "TOKEN_GENERATED",
        verification_token_hash,
        VERIFICATION_METHOD
    ))

    asset_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO AuditLogs (
        user_id,
        asset_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?, ?)
    """, (
        USER_ID,
        asset_id,
        "ASSET_REGISTERED",
        f"Asset registered: {ASSET_VALUE}"
    ))

    connection.commit()

    print("Asset registered successfully.")
    print(f"Asset: {ASSET_VALUE}")
    print(f"Verification Method: {VERIFICATION_METHOD}")
    print(f"Verification Token: {verification_token}")

except sqlite3.IntegrityError:
    print("Asset already registered.")

finally:
    connection.close()
