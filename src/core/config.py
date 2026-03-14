import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
LOG_PATH = os.path.join(DATA_DIR, "logs.enc")
KEY_PATH = os.path.join(DATA_DIR, "secret.key")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")


def ensure_data_dirs() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
