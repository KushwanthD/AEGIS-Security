import sqlite3
import subprocess
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

    # Verify authorization token was used
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

        # Get target asset
        cursor.execute("""
        SELECT a.asset_value
        FROM Assets a
        JOIN Assessments s
            ON a.id = s.asset_id
        WHERE s.id = ?
        """, (ASSESSMENT_ID,))

        asset = cursor.fetchone()

        if asset is None:
            print("Target asset not found.")

        else:

            target = asset[0]

            print(f"Scanning authorized asset: {target}")

            # Create Scan Execution
            cursor.execute("""
            INSERT INTO ScanExecutions (
                assessment_id,
                status
            )
            VALUES (?, ?)
            """, (
                ASSESSMENT_ID,
                "RUNNING"
            ))

            scan_execution_id = cursor.lastrowid

            # Audit: Scan Started
            cursor.execute("""
            INSERT INTO AuditLogs (
                assessment_id,
                event_type,
                event_details
            )
            VALUES (?, ?, ?)
            """, (
                ASSESSMENT_ID,
                "SCAN_STARTED",
                "Security scan started"
            ))

            # Run Nmap
            result = subprocess.run(
                ["nmap", "-F", target],
                capture_output=True,
                text=True
            )

            output = result.stdout

            print("\n===== NMAP OUTPUT =====")
            print(output)
            print("=======================\n")

            findings_created = 0

            # Parse open ports
            for line in output.splitlines():

                if "/tcp" in line and "open" in line:

                    parts = line.split()

                    if len(parts) < 3:
                        continue

                    port = parts[0]
                    service = parts[2]

                    finding_title = (
                        f"{service.upper()} Service Exposed"
                    )

                    cursor.execute("""
                    INSERT INTO ScanResults (
                        assessment_id,
                        scan_execution_id,
                        tool_name,
                        finding_title,
                        finding_category,
                        severity,
                        description,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ASSESSMENT_ID,
                        scan_execution_id,
                        "Nmap",
                        finding_title,
                        "Open Port",
                        "LOW",
                        f"{service} service detected",
                        line
                    ))

                    findings_created += 1

                    print(
                        f"OPEN PORT FOUND: "
                        f"{port} ({service})"
                    )

            print(
                f"Total findings inserted: "
                f"{findings_created}"
            )

            # Mark execution completed
            cursor.execute("""
            UPDATE ScanExecutions
            SET
                status = ?,
                completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """, (
                "COMPLETED",
                scan_execution_id
            ))

            # Audit: Scan Completed
            cursor.execute("""
            INSERT INTO AuditLogs (
                assessment_id,
                event_type,
                event_details
            )
            VALUES (?, ?, ?)
            """, (
                ASSESSMENT_ID,
                "SCAN_COMPLETED",
                "Security scan completed"
            ))

            connection.commit()

            print("Scan completed successfully.")

connection.close()
