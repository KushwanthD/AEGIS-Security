from flask import (
    Flask,
    render_template,
    request
)

import sqlite3
import secrets
import hashlib

app = Flask(__name__)


@app.route("/")
def home():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        asset_value,
        verification_status
    FROM Assets
    """)

    assets = cursor.fetchall()

    connection.close()

    return render_template(
        "index.html",
        assets=assets
    )


@app.route(
    "/register-asset",
    methods=["GET", "POST"]
)
def register_asset():

    if request.method == "POST":

        asset_type = request.form["asset_type"]
        asset_value = request.form["asset_value"]
        verification_method = request.form[
            "verification_method"
        ]

        token = secrets.token_hex(16)

        token_hash = hashlib.sha256(
            token.encode()
        ).hexdigest()

        connection = sqlite3.connect(
            "database/aegis.db"
        )

        cursor = connection.cursor()

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
            1,
            asset_type,
            asset_value,
            "TOKEN_GENERATED",
            token_hash,
            verification_method
        ))

        connection.commit()

        connection.close()

        return f"""
        <h1>Asset Registered</h1>

        <p><b>Asset:</b> {asset_value}</p>

        <p><b>Verification Method:</b>
        {verification_method}</p>

        <p><b>Verification Token:</b>
        {token}</p>

        <a href="/">Back to Dashboard</a>
        """

    return render_template(
        "register_asset.html"
    )


@app.route("/verify-asset/<int:asset_id>")
def verify_asset(asset_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    UPDATE Assets
    SET
        verification_status = 'VERIFIED',
        verification_date = CURRENT_TIMESTAMP
    WHERE id = ?
    """, (asset_id,))

    connection.commit()

    connection.close()

    return """
    <h1>Asset Verified</h1>

    <a href="/">
        Back to Dashboard
    </a>
    """


@app.route("/request-assessment/<int:asset_id>")
def request_assessment(asset_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT COUNT(*)
    FROM Assessments
    """)

    count = cursor.fetchone()[0]

    assessment_reference = (
        f"AEGIS-2026-{count + 1:04d}"
    )

    cursor.execute("""
    INSERT INTO Assessments (
        asset_id,
        assessment_reference,
        status
    )
    VALUES (?, ?, ?)
    """, (
        asset_id,
        assessment_reference,
        "PENDING"
    ))

    connection.commit()

    connection.close()

    return f"""
    <h1>Assessment Created</h1>

    <p>{assessment_reference}</p>

    <a href="/">Back to Dashboard</a>
    """


@app.route("/assessments")
def assessments():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_reference,
        status
    FROM Assessments
    ORDER BY id DESC
    """)

    assessments = cursor.fetchall()

    connection.close()

    return render_template(
        "assessments.html",
        assessments=assessments
    )


@app.route("/approve-assessment/<int:assessment_id>")
def approve_assessment(assessment_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    UPDATE Assessments
    SET
        status = 'APPROVED',
        approved_at = CURRENT_TIMESTAMP
    WHERE id = ?
    """, (assessment_id,))

    connection.commit()

    connection.close()

    return """
    <h1>Assessment Approved</h1>

    <a href="/assessments">
        Back to Assessments
    </a>
    """

@app.route("/generate-token/<int:assessment_id>")
def generate_token(assessment_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT status
    FROM Assessments
    WHERE id = ?
    """, (assessment_id,))

    assessment = cursor.fetchone()

    if (
        assessment is None
        or assessment[0] != "APPROVED"
    ):

        connection.close()

        return """
        <h1>Assessment must be approved first</h1>

        <a href="/assessments">
            Back
        </a>
        """

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
        assessment_id,
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
        assessment_id,
        "TOKEN_GENERATED",
        "Authorization token generated"
    ))

    connection.commit()

    connection.close()

    return f"""
    <h1>Authorization Token Generated</h1>

    <p><b>Assessment:</b> {assessment_id}</p>

    <p><b>Token:</b> {token}</p>

    <p>
    Save this token now.
    It will not be shown again.
    </p>

    <a href="/assessments">
        Back to Assessments
    </a>
    """


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
