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

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
