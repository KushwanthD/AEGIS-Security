from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():

    connection = sqlite3.connect("database/aegis.db")
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

    html = """
    <h1>AEGIS Dashboard</h1>

    <h2>Assets</h2>

    <table border="1">
        <tr>
            <th>ID</th>
            <th>Asset</th>
            <th>Status</th>
        </tr>
    """

    for asset in assets:

        html += f"""
        <tr>
            <td>{asset[0]}</td>
            <td>{asset[1]}</td>
            <td>{asset[2]}</td>
        </tr>
        """

    html += "</table>"

    return html

if __name__ == "__main__":
    app.run(debug=True)
