import datetime
import secrets
from typing import Optional

from core.crypto import deterministic_hash, encrypt_text, decrypt_text
from core.db import execute, fetch_one


def generate_restore_code(manager_user_id: int, backup_name: str) -> str:
    code = secrets.token_urlsafe(8)
    code_hash = deterministic_hash(code)
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    execute(
        """
        INSERT INTO restore_codes (code_hash, manager_user_id, backup_name_enc, used, created_at_enc)
        VALUES (?, ?, ?, 0, ?)
        """,
        (code_hash, manager_user_id, encrypt_text(backup_name), encrypt_text(created_at)),
    )
    return code


def verify_and_use_code(manager_user_id: int, code: str) -> Optional[str]:
    code_hash = deterministic_hash(code)
    row = fetch_one(
        """
        SELECT id, backup_name_enc, used FROM restore_codes
        WHERE code_hash = ? AND manager_user_id = ?
        """,
        (code_hash, manager_user_id),
    )
    if not row:
        return None
    if int(row[2]) == 1:
        return None
    execute("UPDATE restore_codes SET used = 1 WHERE id = ?", (row[0],))
    return decrypt_text(row[1])


def revoke_code(code: str) -> bool:
    code_hash = deterministic_hash(code)
    row = fetch_one("SELECT id FROM restore_codes WHERE code_hash = ?", (code_hash,))
    if row:
        execute("DELETE FROM restore_codes WHERE id = ?", (row[0],))
        return True
    return False
