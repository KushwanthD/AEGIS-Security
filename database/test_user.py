import sqlite3

connection = sqlite3.connect("database/aegis.db")
cursor = connection.cursor()

cursor.execute("""
INSERT INTO Users (
    username,
    email,
    password_hash
)
VALUES (?, ?, ?)
""", (
    "admin",
    "admin@aegis.local",
    "test_hash"
))

connection.commit()

print("User inserted successfully.")

connection.close()
