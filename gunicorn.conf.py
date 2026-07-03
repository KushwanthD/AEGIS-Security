# Gunicorn production configuration file
import os

# Render sets the port dynamically via PORT environment variable
port = os.environ.get("PORT", "10000")
bind = f"0.0.0.0:{port}"

# Concurrency configurations
workers = 1    # Keep 1 worker process to prevent SQLite database write contention
threads = 10   # Use multiple threads to handle multiple concurrent SSE client streams
timeout = 1000 # Set high timeout to prevent worker kills during persistent SSE connections
keepalive = 2  # Keep connections open for fast subsequent request responses
