import sqlite3

DATABASE_PATH = "database/aegis.db"

def get_connection():
    return sqlite3.connect(DATABASE_PATH)
