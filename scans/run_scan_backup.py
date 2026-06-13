import sqlite3

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

ASSESSMENT_ID = 1

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

        # Finding 1
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
            "SSH Service Exposed",
            "Service Exposure",
            "LOW",
            "SSH service detected on port 22",
            "22/tcp open ssh"
        ))

        # Finding 2
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
            "HTTP Service Detected",
            "Web Service",
            "INFO",
            "HTTP service detected on port 80",
            "80/tcp open http"
        ))

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
