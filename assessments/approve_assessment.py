import sqlite3

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

ASSESSMENT_ID = 1

REQUESTED_BY = "SecurityFirmA"
APPROVED_BY = "AssetOwnerA"

DECISION = "APPROVED"

COMMENTS = "Quarterly security review approved."

cursor.execute("""
SELECT id, status
FROM Assessments
WHERE id = ?
""", (ASSESSMENT_ID,))

assessment = cursor.fetchone()

if assessment is None:
    print("Assessment not found.")

elif assessment[1] != "PENDING":
    print("Assessment is not pending.")

else:

    cursor.execute("""
    INSERT INTO Approvals (
        assessment_id,
        requested_by,
        approved_by,
        decision,
        comments
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        ASSESSMENT_ID,
        REQUESTED_BY,
        APPROVED_BY,
        DECISION,
        COMMENTS
    ))

    cursor.execute("""
    UPDATE Assessments
    SET
        status = ?,
        approved_at = CURRENT_TIMESTAMP
    WHERE id = ?
    """, (
        DECISION,
        ASSESSMENT_ID
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
        "ASSESSMENT_APPROVED",
        f"Assessment approved by {APPROVED_BY}"
    ))

    connection.commit()

    print("Assessment approved successfully.")

connection.close()
