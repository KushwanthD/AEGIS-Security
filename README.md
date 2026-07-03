# AEGIS Shield: Advanced Compliance & Security Scan Orchestrator

AEGIS Shield is a modern web application designed for compliance validation and security scanner orchestration. Built with Flask, SQLite, and vanilla CSS, it offers a secure, glassmorphic dashboard for managing assets, requesting and approving scans, running live network scans (like Nmap and Nikto), and compiling PDF reports.

## Key Features
*   **Decoupled Multi-Role Governance:**
    *   **Admin:** Reviews target registration, approves scans, generates/regenerates compliance authorization tokens, and accesses system audit logs.
    *   **Analyst:** Operates as an outside auditor. Has zero visibility into assets or other assessments by default. Initiates scan requests manually via a target lookup form.
    *   **Asset Owner:** Registers target assets, validates ownership, and tracks active scans and risk ratings on their assets.
*   **Real-Time SSE Sync:** Instant Server-Sent Events updates. If a scan is requested, approved, or completed, live glassmorphic toasts and badge counters update instantly across portals without page refreshes.
*   **Automated Scan Engine:** Orchestrates DNS reconnaissance, Nmap port scans, SSL cipher suites audit, HTTP security headers review, and Nikto web vulnerability scanner.
*   **PDF Report Compiler:** Auto-generates high-fidelity Technical and Executive PDF reports on scan completion.
*   **Persistent Notification Center:** Real-time bell dropdown and notification history panel for users to clear and manage system updates.

## Technical Stack
*   **Backend:** Python 3 (Flask, SQLAlchemy ORM)
*   **Database:** SQLite (`aegis.db`, automatically created and seeded on startup)
*   **Frontend:** HTML5, CSS3, JavaScript (SSE, AJAX polling)
*   **Production WSGI:** Gunicorn (production gateway)

## Local Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/KushwanthD/AEGIS-Security.git
    cd AEGIS-Security
    ```
2.  Set up a virtual environment:
    ```bash
    python -m venv venv
    venv\Scripts\activate  # On Windows
    source venv/bin/activate  # On Linux/macOS
    ```
3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Run the application locally:
    ```bash
    python app.py
    ```
    Access the application at `http://localhost:5000`.

## Production Deployment
The live production instance is deployed on **Render** at:
👉 **[https://aegis-shield.onrender.com](https://aegis-shield.onrender.com)**

### Build Config (on Render)
*   **Runtime:** `Python`
*   **Build Command:** `pip install -r requirements.txt`
*   **Start Command:** `gunicorn app:app`
*   **Environment Variable:** `FLASK_SECRET_KEY` (configured for session encryption)
