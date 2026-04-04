import datetime
import secrets
from typing import Optional

from core.crypto import deterministic_hash, encrypt_text, decrypt_text
from core.db import execute, fetch_one

# --- One-time restore codes ---
# Super admin generates a code tied to a specific manager + backup.
# The code itself is never stored — only its HMAC hash goes in the DB.
# This is the same principle as password storage: if someone reads the DB
# they can't recover the original code from the hash.


def generate_restore_code(manager_user_id: int, backup_name: str) -> str:
    # secrets.token_urlsafe generates a cryptographically secure random token.
    # This is much better than random.randint or similar — it uses the OS
    # entropy source so the output is unpredictable.
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
    # Three security checks happen here:
    # 1. Code hash must match (proves the user has the correct code)
    # 2. manager_user_id must match (code is scoped to one specific manager)
    # 3. used flag must be 0 (one-time use — prevents replay attacks)
    # After successful use, we immediately mark it as used.
    code_hash = deterministic_hash(code)
    row = fetch_one(
        """
        SELECT id, backup_name_enc, used FROM restore_codes
        WHERE code_hash = ? AND manager_user_id = ?
        """,
        (code_hash, manager_user_id),
    )
    result = None
    if row and int(row[2]) != 1:
        execute("UPDATE restore_codes SET used = 1 WHERE id = ?", (row[0],))
        result = decrypt_text(row[1])
    return result


def revoke_code(code: str) -> bool:
    # Super admin can revoke a code before the manager uses it.
    # Deletes the record entirely so the code becomes permanently invalid.
    code_hash = deterministic_hash(code)
    row = fetch_one("SELECT id FROM restore_codes WHERE code_hash = ?", (code_hash,))
    result = False
    if row:
        execute("DELETE FROM restore_codes WHERE id = ?", (row[0],))
        result = True
    return result
