import os

# All sensitive files (database, encryption key, logs, backups) are kept
# in a single data/ directory under the project root.
# The encryption key (secret.key) is the most critical file — whoever has
# it can decrypt everything in the database and logs.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(PROJECT_ROOT, "src/data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
LOG_PATH = os.path.join(DATA_DIR, "logs.enc")    # encrypted log entries
KEY_PATH = os.path.join(DATA_DIR, "secret.key")   # Fernet master key
BACKUP_DIR = os.path.join(DATA_DIR, "backups")


def ensure_data_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
