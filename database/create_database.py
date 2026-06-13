import sqlite3

connection = sqlite3.connect("database/aegis.db")

cursor = connection.cursor()

# Users Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# Assets Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    asset_type TEXT NOT NULL,
    asset_value TEXT NOT NULL UNIQUE,
    verification_status TEXT NOT NULL DEFAULT 'PENDING',
    verification_token_hash TEXT,
    verification_date TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES Users(id)
)
""")

# CorrelatedFindings Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS CorrelatedFindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    correlation_title TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    correlation_reason TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# AuditLogs Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS AuditLogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    asset_id INTEGER,
    assessment_id INTEGER,
    event_type TEXT NOT NULL,
    event_details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES Users(id),
    FOREIGN KEY(asset_id) REFERENCES Assets(id)
)
""")

# Assessments Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    assessment_reference TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'PENDING',
    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY(asset_id) REFERENCES Assets(id)
)
""")

# Approvals Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS Approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    requested_by TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    decision TEXT NOT NULL,
    comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# AuthorizationTokens Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS AuthorizationTokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# ReconResults Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS ReconResults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    recon_type TEXT NOT NULL,
    result_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# ReconExecutions Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS ReconExecutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT NOT NULL,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# ScanExecutions Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS ScanExecutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT NOT NULL,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

# ScanResults Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS ScanResults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    finding_title TEXT NOT NULL,
    finding_category TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES Assessments(id)
)
""")

connection.commit()

print("Users, Assets, Assessments,  AuditLogsa, ReconResults, Approvals,  AuthorizationTokens, ReconExecutions, ScanExecutions, CorrelatedFindings  and ScanResults tables created successfully.")

connection.close()
