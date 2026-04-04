import datetime
import os
import shutil
import tempfile
import zipfile

from core.config import BACKUP_DIR, DB_PATH, LOG_PATH

# --- Backup system ---
# Backups include the database and the encrypted log file.
# Since the DB already stores everything encrypted (Fernet) and passwords
# are hashed (PBKDF2), no extra encryption is needed for the zip —
# the data inside is already unreadable without the encryption key.


def create_backup() -> str:
    # Timestamped name ensures multiple backups can coexist without overwriting.
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
    # Extracts to a temp directory first, then copies the DB file over.
    # Using a temp dir avoids partial restores if extraction fails halfway.
    # After restore, users are forced to re-login (handled in app.py)
    # because session data and passwords may have changed.
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
