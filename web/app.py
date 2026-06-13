from flask import (
    Flask,
    render_template,
    request,
    send_file
)

import sqlite3
import secrets
import hashlib
import dns.resolver
import subprocess
import os


app = Flask(__name__)



@app.route("/")
def home():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    # Metrics
    cursor.execute("""
    SELECT COUNT(*)
    FROM Assets
    """)

    asset_count = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM Assessments
    """)

    assessment_count = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM Assessments
    WHERE status = 'APPROVED'
    """)

    approved_count = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM CorrelatedFindings
    WHERE risk_level IN (
        'HIGH',
        'CRITICAL'
    )
    """)

    high_risk_count = cursor.fetchone()[0]

    # Existing asset query
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
        assets=assets,
        asset_count=asset_count,
        assessment_count=assessment_count,
        approved_count=approved_count,
        high_risk_count=high_risk_count
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

    <a href="/verify-token/{assessment_id}">
        Go To Token Verification
    </a>
    """


@app.route(
    "/verify-token/<int:assessment_id>",
    methods=["GET", "POST"]
)
def verify_token(assessment_id):

    if request.method == "POST":

        supplied_token = request.form["token"]

        connection = sqlite3.connect(
            "database/aegis.db"
        )

        cursor = connection.cursor()

        cursor.execute("""
        SELECT
            id,
            token_hash,
            used
        FROM AuthorizationTokens
        WHERE assessment_id = ?
        ORDER BY id DESC
        LIMIT 1
        """, (assessment_id,))

        record = cursor.fetchone()

        if record is None:

            connection.close()

            return "<h1>No token found</h1>"

        token_id = record[0]
        stored_hash = record[1]
        used = record[2]

        if used:

            connection.close()

            return "<h1>Token already used</h1>"

        supplied_hash = hashlib.sha256(
            supplied_token.encode()
        ).hexdigest()

        if supplied_hash != stored_hash:

            connection.close()

            return "<h1>Invalid Token</h1>"

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
            assessment_id,
            "TOKEN_VERIFIED",
            "Authorization token verified"
        ))

        connection.commit()

        connection.close()

        return f"""
        <h1>Token Verified Successfully</h1>

        <p>Assessment: {assessment_id}</p>

        <a href="/assessments">
            Back to Assessments
        </a>
        """

    return render_template(
        "verify_token.html",
        assessment_id=assessment_id
    )


@app.route("/run-recon/<int:assessment_id>")
def run_recon(assessment_id):

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

    if assessment is None:

        connection.close()

        return "<h1>Assessment not found</h1>"

    if assessment[0] != "APPROVED":

        connection.close()

        return "<h1>Assessment must be approved</h1>"

    cursor.execute("""
    SELECT used
    FROM AuthorizationTokens
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    token = cursor.fetchone()

    if token is None:

        connection.close()

        return "<h1>No authorization token found</h1>"

    if token[0] != 1:

        connection.close()

        return "<h1>Authorization token not verified</h1>"

    cursor.execute("""
    INSERT INTO ReconExecutions (
        assessment_id,
        status
    )
    VALUES (?, ?)
    """, (
        assessment_id,
        "RUNNING"
    ))

    recon_execution_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO AuditLogs (
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "RECON_STARTED",
        "DNS reconnaissance started"
    ))

    cursor.execute("""
    SELECT A.asset_value
    FROM Assessments S
    JOIN Assets A
    ON S.asset_id = A.id
    WHERE S.id = ?
    """, (assessment_id,))

    asset = cursor.fetchone()

    if asset is None:

        connection.close()

        return "<h1>No asset found</h1>"

    target = asset[0]

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
            assessment_id,
            recon_execution_id,
            "DNS_A_RECORDS",
            result_data
        ))

    except Exception:
        pass

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
            assessment_id,
            recon_execution_id,
            "DNS_MX_RECORDS",
            result_data
        ))

    except Exception:
        pass

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
            assessment_id,
            recon_execution_id,
            "DNS_TXT_RECORDS",
            result_data
        ))

    except Exception:
        pass

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

    cursor.execute("""
    INSERT INTO AuditLogs (
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "RECON_COMPLETED",
        "DNS reconnaissance completed"
    ))

    connection.commit()

    connection.close()

    return """
    <h1>Recon Completed</h1>

    <a href="/recon-history">
        View Recon History
    </a>
    """





@app.route("/recon-history")
def recon_history():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_id,
        status,
        started_at,
        completed_at
    FROM ReconExecutions
    ORDER BY id DESC
    """)

    executions = cursor.fetchall()

    connection.close()

    return render_template(
        "recon_history.html",
        executions=executions
    )




@app.route("/recon-results/<int:execution_id>")
def recon_results(execution_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        assessment_id
    FROM ReconExecutions
    WHERE id = ?
    """, (execution_id,))

    execution = cursor.fetchone()

    if execution is None:

        connection.close()

        return "<h1>Recon execution not found</h1>"

    assessment_id = execution[0]

    cursor.execute("""
    SELECT
        recon_type,
        result_data
    FROM ReconResults
    WHERE recon_execution_id = ?
    """, (assessment_id,))

    results = cursor.fetchall()

    connection.close()

    return render_template(
        "recon_results.html",
        results=results
    )


@app.route("/scan-history")
def scan_history():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_id,
        status,
        started_at,
        completed_at
    FROM ScanExecutions
    ORDER BY id DESC
    """)

    executions = cursor.fetchall()

    connection.close()

    return render_template(
        "scan_history.html",
        executions=executions
    )



@app.route("/scan-results/<int:execution_id>")
def scan_results(execution_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        assessment_id
    FROM ScanExecutions
    WHERE id = ?
    """, (execution_id,))

    execution = cursor.fetchone()

    if execution is None:

        connection.close()

        return "<h1>Scan execution not found</h1>"

    assessment_id = execution[0]

    cursor.execute("""
    SELECT
        finding_title,
        finding_category,
        severity,
        description,
        evidence
    FROM ScanResults
    WHERE scan_execution_id = ?
    """, (assessment_id,))

    findings = cursor.fetchall()

    connection.close()

    return render_template(
        "scan_results.html",
        findings=findings
    )


@app.route("/run-scan/<int:assessment_id>")
def run_scan(assessment_id):

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

    if assessment is None:

        connection.close()

        return "<h1>Assessment not found</h1>"

    if assessment[0] != "APPROVED":

        connection.close()

        return "<h1>Assessment must be approved</h1>"

    cursor.execute("""
    SELECT used
    FROM AuthorizationTokens
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    token = cursor.fetchone()

    if token is None:

        connection.close()

        return "<h1>No authorization token found</h1>"

    if token[0] != 1:

        connection.close()

        return "<h1>Authorization token not verified</h1>"

    cursor.execute("""
    SELECT a.asset_value
    FROM Assets a
    JOIN Assessments s
        ON a.id = s.asset_id
    WHERE s.id = ?
    """, (assessment_id,))

    asset = cursor.fetchone()

    if asset is None:

        connection.close()

        return "<h1>Target asset not found</h1>"

    target = asset[0]

    cursor.execute("""
    INSERT INTO ScanExecutions (
        assessment_id,
        status
    )
    VALUES (?, ?)
    """, (
        assessment_id,
        "RUNNING"
    ))

    scan_execution_id = cursor.lastrowid

    cursor.execute("""
    INSERT INTO AuditLogs (
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "SCAN_STARTED",
        "Security scan started"
    ))

    result = subprocess.run(
        ["nmap", "-F", target],
        capture_output=True,
        text=True
    )

    output = result.stdout

    for line in output.splitlines():

        if "/tcp" in line and "open" in line:

            parts = line.split()

            if len(parts) < 3:
                continue

            service = parts[2]

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
                assessment_id,
                scan_execution_id,
                "Nmap",
                f"{service.upper()} Service Exposed",
                "Open Port",
                "LOW",
                f"{service} service detected",
                line
            ))

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

    cursor.execute("""
    INSERT INTO AuditLogs (
        assessment_id,
        event_type,
        event_details
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "SCAN_COMPLETED",
        "Security scan completed"
    ))

    connection.commit()

    connection.close()

    return """
    <h1>Scan Completed</h1>

    <a href="/scan-history">
        View Scan History
    </a>
    """

@app.route("/audit-logs")
def audit_logs():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_id,
        event_type,
        event_details,
        created_at
    FROM AuditLogs
    ORDER BY id DESC
    """)

    logs = cursor.fetchall()

    connection.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


@app.route("/correlation-history")
def correlation_history():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_id,
        status,
        started_at,
        completed_at
    FROM CorrelationExecutions
    ORDER BY id DESC
    """)

    executions = cursor.fetchall()

    connection.close()

    return render_template(
        "correlation_history.html",
        executions=executions
    )

@app.route("/correlation-results/<int:execution_id>")
def correlation_results(execution_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        assessment_id
    FROM CorrelationExecutions
    WHERE id = ?
    """, (execution_id,))

    execution = cursor.fetchone()

    if execution is None:

        connection.close()

        return "<h1>Correlation execution not found</h1>"

    assessment_id = execution[0]

    cursor.execute("""
    SELECT
        correlation_title,
        risk_level,
        correlation_reason,
        recommended_action
    FROM CorrelatedFindings
    WHERE assessment_id = ?
    """, (assessment_id,))

    findings = cursor.fetchall()

    connection.close()

    return render_template(
        "correlation_results.html",
        findings=findings
    )

@app.route("/run-correlation/<int:assessment_id>")
def run_correlation(assessment_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO CorrelationExecutions (
        assessment_id,
        status
    )
    VALUES (?, ?)
    """, (
        assessment_id,
        "RUNNING"
    ))

    correlation_execution_id = cursor.lastrowid

    cursor.execute("""
    SELECT id
    FROM ReconExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT  1
    """, (assessment_id,))

    latest_recon = cursor.fetchone()

    cursor.execute("""
    SELECT id
    FROM ScanExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    latest_scan = cursor.fetchone()

    if latest_recon is None or latest_scan is None:

        print(
            "Recon or scan execution not found."
    )

    connection.close()

    exit()

    latest_recon_id = latest_recon[0]
    latest_scan_id = latest_scan[0]


    cursor.execute("""
    SELECT
        recon_type,
        result_data
    FROM ReconResults
    WHERE recon_execution_id = ?
    """, (assessment_id,))

    recon_results = cursor.fetchall()

    cursor.execute("""
    SELECT
        finding_title,
        severity,
        evidence
    FROM ScanResults
    WHERE scan_execution_id = ?
    """, (assessment_id,))

    scan_results = cursor.fetchall()

    mx_found = False
    spf_found = False
    ssh_found = False
    http_found = False
    https_found = False

    for recon_type, result_data in recon_results:

        if recon_type == "DNS_MX_RECORDS":
            mx_found = True

        if (
            recon_type == "DNS_TXT_RECORDS"
            and "v=spf1" in result_data
        ):
            spf_found = True

    for finding_title, severity, evidence in scan_results:

        if "SSH Service Exposed" in finding_title:
            ssh_found = True

        if "HTTP Service Exposed" in finding_title:
            http_found = True

        if "HTTPS Service Exposed" in finding_title:
            https_found = True

    if mx_found:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_execution_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            assessment_id,
            correlation_execution_id,
            "External Email Infrastructure Detected",
            "INFO",
            "MX records indicate email services.",
            "Review SPF, DKIM and DMARC."
        ))

    if spf_found:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_execution_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            assessment_id,
            correlation_execution_id,
            "SPF Record Detected",
            "INFO",
            "SPF policy identified.",
            "Review and maintain SPF records."
        ))

    if ssh_found:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_execution_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            assessment_id,
            correlation_execution_id,
            "Administrative Service Exposed",
            "LOW",
            "SSH service reachable.",
            "Restrict SSH access."
        ))

    if http_found or https_found:

        cursor.execute("""
        INSERT INTO CorrelatedFindings (
            assessment_id,
            correlation_execution_id,
            correlation_title,
            risk_level,
            correlation_reason,
            recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            assessment_id,
            correlation_execution_id,
            "Web Service Exposure Detected",
            "LOW",
            "Public web services detected.",
            "Review exposed web services."
        ))

    cursor.execute("""
    UPDATE CorrelationExecutions
    SET
        status = ?,
        completed_at = CURRENT_TIMESTAMP
    WHERE id = ?
    """, (
        "COMPLETED",
        correlation_execution_id
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
        "CORRELATION_COMPLETED",
        "Correlation completed"
    ))

    connection.commit()

    connection.close()

    return """
    <h1>Correlation Completed</h1>

    <a href="/correlation-history">
        View Correlation History
    </a>
    """

@app.route(
    "/generate-executive-report/<int:assessment_id>"
)
def generate_executive_report(
    assessment_id
):

    pdf_file = (
        f"aegis_executive_report_"
        f"{assessment_id}.pdf"
    )

    subprocess.run([
        "python",
        "reports/generate_executive_report.py",
        "--assessment-id",
        str(assessment_id)
    ])

    if not os.path.exists(pdf_file):

        return """
        <h1>
        Executive report generation failed
        </h1>
        """

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO Reports (
        assessment_id,
        report_type,
        file_name
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "EXECUTIVE",
        pdf_file
    ))

    connection.commit()
    connection.close()

    return send_file(
        os.path.abspath(pdf_file),
        as_attachment=True
    )


@app.route(
    "/generate-technical-report/<int:assessment_id>"
)
def generate_technical_report(
    assessment_id
):

    pdf_file = (
        f"aegis_report_"
        f"{assessment_id}.pdf"
    )

    subprocess.run([
        "python",
        "reports/generate_pdf_report.py",
        "--assessment-id",
        str(assessment_id)
    ])

    if not os.path.exists(pdf_file):

        return """
        <h1>
        Technical report generation failed
        </h1>
        """

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO Reports (
        assessment_id,
        report_type,
        file_name
    )
    VALUES (?, ?, ?)
    """, (
        assessment_id,
        "TECHNICAL",
        pdf_file
    ))

    connection.commit()
    connection.close()

    return send_file(
        os.path.abspath(pdf_file),
        as_attachment=True
    )





@app.route("/threat-intelligence")
def threat_intelligence():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        technology,
        risk_level,
        threat_title,
        source
    FROM ThreatIntel
    ORDER BY technology
    """)

    threats = cursor.fetchall()

    connection.close()

    return render_template(
        "threat_intelligence.html",
        threats=threats
    )


@app.route(
    "/assessment-summary/<int:assessment_id>"
)
def assessment_summary(assessment_id):

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        assessment_reference,
        status,
        asset_id
    FROM Assessments
    WHERE id = ?
    """, (assessment_id,))

    assessment = cursor.fetchone()

    if assessment is None:

        connection.close()

        return "<h1>Assessment not found</h1>"

    assessment_reference = assessment[0]
    assessment_status = assessment[1]
    asset_id = assessment[2]

    cursor.execute("""
    SELECT asset_value
    FROM Assets
    WHERE id = ?
    """, (asset_id,))

    asset_value = cursor.fetchone()[0]

    cursor.execute("""
    SELECT id
    FROM CorrelationExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    latest_correlation = cursor.fetchone()

    latest_correlation_id = None

    if latest_correlation:

        latest_correlation_id = latest_correlation[0]

        cursor.execute("""
        SELECT risk_level
        FROM CorrelatedFindings
        WHERE correlation_execution_id = ?
        """, (latest_correlation_id,))

        risks = [
            row[0]
            for row in cursor.fetchall()
        ]

    else:

        risks = []
    risk_score = 0

    for risk in risks:

        if risk == "CRITICAL":
            risk_score += 10

        elif risk == "HIGH":
            risk_score += 7

        elif risk == "MEDIUM":
            risk_score += 4

        elif risk == "LOW":
            risk_score += 1

    overall_risk = "INFO"

    if risk_score >= 15:
        overall_risk = "CRITICAL"

    elif risk_score >= 10:
        overall_risk = "HIGH"

    elif risk_score >= 5:
        overall_risk = "MEDIUM"

    elif risk_score >= 1:
        overall_risk = "LOW"


    cursor.execute("""
    SELECT status
    FROM ReconExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    row = cursor.fetchone()
    recon_status = (
        row[0] if row else "NOT RUN"
    )

    cursor.execute("""
    SELECT status
    FROM ScanExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    row = cursor.fetchone()
    scan_status = (
        row[0] if row else "NOT RUN"
    )

    cursor.execute("""
    SELECT status
    FROM CorrelationExecutions
    WHERE assessment_id = ?
    ORDER BY id DESC
    LIMIT 1
    """, (assessment_id,))

    row = cursor.fetchone()
    correlation_status = (
        row[0] if row else "NOT RUN"
    )

    if latest_correlation_id:

        cursor.execute("""
        SELECT
            correlation_title,
            risk_level
        FROM CorrelatedFindings
        WHERE correlation_execution_id = ?
        ORDER BY id DESC
        """, (latest_correlation_id,))

        findings = cursor.fetchall()

    else:

        findings = []







    connection.close()

    return render_template(
        "assessment_summary.html",
        assessment_id=assessment_id,
        assessment_reference=assessment_reference,
        assessment_status=assessment_status,
        asset_value=asset_value,
        overall_risk=overall_risk,
        risk_score=risk_score,
        recon_status=recon_status,
        scan_status=scan_status,
        correlation_status=correlation_status,
        findings=findings
    )

@app.route("/report-history")
def report_history():

    connection = sqlite3.connect(
        "database/aegis.db"
    )

    cursor = connection.cursor()

    cursor.execute("""
    SELECT
        id,
        assessment_id,
        report_type,
        created_at,
        file_name
    FROM Reports
    ORDER BY id DESC
    """)

    reports = cursor.fetchall()

    connection.close()

    return render_template(
        "report_history.html",
        reports=reports
    )







if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
