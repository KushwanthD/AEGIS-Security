import os
from web import create_app
from database.create_database import init_db

# Automatically initialize database schema and seeds on startup
DATABASE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "aegis.db")
if not os.path.exists(DATABASE_FILE):
    print("Database file not found. Initializing...")
    init_db()
else:
    # Always run to ensure any new columns/tables in SQLAlchemy are created
    init_db()

app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        threaded=True
    )
