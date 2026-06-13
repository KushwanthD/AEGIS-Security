import sqlite3
import dns.resolver
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



# Verify assessment is approved
cursor.execute("""
SELECT status
FROM Assessments
WHERE id = ?
""", (ASSESSMENT_ID,))

assessment = cursor.fetchone()

if assessment is None:
    print("Assessment not found.")

elif assessment[0] != "APPROVED":
    print("Assessment must be approved.")

else:

    # Verify authorization token has been used
    cursor.execute("""
    SELECT used
    FROM AuthorizationTokens
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (ASSESSMENT_ID,))

    token = cursor.fetchone()

    if token is None:
        print("Authorization token not found.")

    elif token[0] != 1:
        print("Authorization token not verified.")

    else:

        # Create Recon Execution
        cursor.execute("""
        INSERT INTO ReconExecutions (
            assessment_id,
            status
        )
        VALUES (?, ?)
        """, (
            ASSESSMENT_ID,
            "RUNNING"
        ))

        recon_execution_id = cursor.lastrowid

        # Audit: Recon Started
        cursor.execute("""
        INSERT INTO AuditLogs (
            assessment_id,
            event_type,
            event_details
        )
        VALUES (?, ?, ?)
        """, (
            ASSESSMENT_ID,
            "RECON_STARTED",
            "DNS reconnaissance started"
        ))

        # Get authorized asset
        cursor.execute("""
        SELECT A.asset_value
        FROM Assessments S
        JOIN Assets A
        ON S.asset_id = A.id
        WHERE S.id = ?
        """, (ASSESSMENT_ID,))

        asset = cursor.fetchone()

        if asset is None:
            print("No asset found.")
            connection.close()
            exit()

        target = asset[0]

        print(f"Recon target: {target}")

        # A Records
        try:

            answers = dns.resolver.resolve(
                target,
                "A"
            )

            result_data = "\n".join(
                str(record)
                for record in answers
            )

            cursor.execute("""
            INSERT INTO ReconResults (
                assessment_id,
                recon_execution_id,
                recon_type,
                result_data
            )
            VALUES (?, ?, ?, ?)
            """, (
                ASSESSMENT_ID,
                recon_execution_id,
                "DNS_A_RECORDS",
                result_data
            ))

        except Exception as e:
            print(f"A record lookup failed: {e}")

        # MX Records
        try:

            answers = dns.resolver.resolve(
                target,
                "MX"
            )

            result_data = "\n".join(
                str(record)
                for record in answers
            )

            cursor.execute("""
            INSERT INTO ReconResults (
                assessment_id,
                recon_execution_id,
                recon_type,
                result_data
            )
            VALUES (?, ?, ?, ?)
            """, (
                ASSESSMENT_ID,
                recon_execution_id,
                "DNS_MX_RECORDS",
                result_data
            ))

        except Exception as e:
            print(f"MX lookup failed: {e}")

        # TXT Records
        try:

            answers = dns.resolver.resolve(
                target,
                "TXT"
            )

            result_data = "\n".join(
                str(record)
                for record in answers
            )

            cursor.execute("""
            INSERT INTO ReconResults (
                assessment_id,
                recon_execution_id,
                recon_type,
                result_data
            )
            VALUES (?, ?, ?, ?)
            """, (
                ASSESSMENT_ID,
                recon_execution_id,
                "DNS_TXT_RECORDS",
                result_data
            ))

        except Exception as e:
            print(f"TXT lookup failed: {e}")

        # Mark execution completed
        cursor.execute("""
        UPDATE ReconExecutions
        SET
            status = ?,
            completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """, (
            "COMPLETED",
            recon_execution_id
        ))

        # Audit: Recon Completed
        cursor.execute("""
        INSERT INTO AuditLogs (
            assessment_id,
            event_type,
            event_details
        )
        VALUES (?, ?, ?)
        """, (
            ASSESSMENT_ID,
            "RECON_COMPLETED",
            "DNS reconnaissance completed"
        ))

        connection.commit()

        print("Recon completed successfully.")

connection.close()
