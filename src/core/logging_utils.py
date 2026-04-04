import datetime
import json
import os
from typing import Dict, Iterable, List

from core.config import DATA_DIR, LOG_PATH
from core.crypto import decrypt_text, encrypt_text

# --- Encrypted audit logging ---
# Log entries are individually encrypted before writing to the log file.
# Each line in logs.enc is a separate Fernet-encrypted JSON object.
# This means the log file is unreadable with a text editor — you can only
# view logs through the application interface (as required by the spec).
# Even if someone copies the file, they can't see usernames, actions, etc.


def _read_raw_lines() -> List[bytes]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "rb") as handle:
        return [line.strip() for line in handle.readlines() if line.strip()]


def get_next_log_id() -> int:
    # Auto-increment by reading the last entry's ID.
    lines = _read_raw_lines()
    if not lines:
        return 1
    try:
        last = json.loads(decrypt_text(lines[-1]))
        return int(last.get("id", 0)) + 1
    except Exception:
        return len(lines) + 1


def append_log(username: str, description: str, info: str, suspicious: bool) -> None:
    # Every action in the system gets logged here — logins, CRUD operations,
    # failed attempts, etc. The "suspicious" flag marks entries that need
    # attention (e.g. multiple failed logins, unauthorized access attempts).
    log_id = get_next_log_id()
    now = datetime.datetime.now()
    entry = {
        "id": log_id,
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "username": username,
        "description": description,
        "info": info,
        "suspicious": "Yes" if suspicious else "No",
    }
    # Encrypt the entire JSON entry before writing — each line is independently
    # encrypted so we can append without re-encrypting the whole file.
    payload = encrypt_text(json.dumps(entry))
    with open(LOG_PATH, "ab") as handle:
        handle.write(payload + b"\n")


def read_logs() -> List[Dict[str, str]]:
    entries = []
    for line in _read_raw_lines():
        try:
            entries.append(json.loads(decrypt_text(line)))
        except Exception:
            continue
    return entries


def count_unread_suspicious(last_read: str) -> int:
    # Counts suspicious entries that appeared after the user's last log view.
    # This powers the alert notification shown to managers/super admin on login —
    # so they immediately know if something shady happened while they were away.
    if not last_read:
        last_read = "0000-00-00 00:00:00"
    count = 0
    for entry in read_logs():
        timestamp = f"{entry.get('date', '')} {entry.get('time', '')}"
        if entry.get("suspicious") == "Yes" and timestamp > last_read:
            count += 1
    return count


def get_super_last_read() -> str:
    path = os.path.join(DATA_DIR, "super_last_read.enc")
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as handle:
        return decrypt_text(handle.read())


def set_super_last_read(timestamp: str) -> None:
    # Stored encrypted on disk — even the "last read" timestamp is sensitive
    # because it reveals when the admin was last active.
    path = os.path.join(DATA_DIR, "super_last_read.enc")
    with open(path, "wb") as handle:
        handle.write(encrypt_text(timestamp))
