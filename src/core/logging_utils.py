import datetime
import json
import os
from typing import Dict, Iterable, List

from core.config import DATA_DIR, LOG_PATH
from core.crypto import decrypt_text, encrypt_text


def _read_raw_lines() -> List[bytes]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "rb") as handle:
        return [line.strip() for line in handle.readlines() if line.strip()]


def get_next_log_id() -> int:
    lines = _read_raw_lines()
    if not lines:
        return 1
    try:
        last = json.loads(decrypt_text(lines[-1]))
        return int(last.get("id", 0)) + 1
    except Exception:
        return len(lines) + 1


def append_log(username: str, description: str, info: str, suspicious: bool) -> None:
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
    path = os.path.join(DATA_DIR, "super_last_read.enc")
    with open(path, "wb") as handle:
        handle.write(encrypt_text(timestamp))
