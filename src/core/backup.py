import datetime
import os
import shutil
import tempfile
import zipfile

from core.config import BACKUP_DIR, DB_PATH, LOG_PATH


def create_backup() -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"backup_{timestamp}.zip"
    backup_path = os.path.join(BACKUP_DIR, name)
    with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(DB_PATH):
            zf.write(DB_PATH, arcname="app.db")
        if os.path.exists(LOG_PATH):
            zf.write(LOG_PATH, arcname="logs.enc")
    return name


def list_backups() -> list:
    if not os.path.exists(BACKUP_DIR):
        return []
    return sorted([f for f in os.listdir(BACKUP_DIR) if f.endswith(".zip")])


def restore_backup(name: str) -> bool:
    backup_path = os.path.join(BACKUP_DIR, name)
    if os.path.exists(backup_path):
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(backup_path, "r") as zf:
                zf.extractall(temp_dir)
            db_source = os.path.join(temp_dir, "app.db")
            if os.path.exists(db_source):
                shutil.copy2(db_source, DB_PATH)
        return True
    return False
