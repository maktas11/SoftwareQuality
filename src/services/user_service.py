import datetime
import sqlite3
from typing import Dict, Optional

from core.crypto import decrypt_text, deterministic_hash, encrypt_text, hash_password, verify_password
from core.db import DatabaseOperationError, execute, execute_insert, execute_many, fetch_all, fetch_one


def create_user(username: str, password: str, role: str) -> int:
    # Store username both encrypted (for later display) and as a keyed hash
    # (for efficient lookups). The password is stored as a PBKDF2 hash — we
    # never store the actual password, not even in encrypted form.
    # The UNIQUE constraint on username_hash prevents duplicate usernames
    # at the database level (defense in depth — we also check in the UI).
    # Usernames are case-insensitive: lowercased before hashing and storing.
    username = username.lower()
    username_hash = deterministic_hash(username)
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        user_id = execute_insert(
            """
            INSERT INTO users (username_enc, username_hash, password_hash, role_hash, role_enc, created_at_enc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                encrypt_text(username),
                username_hash,
                hash_password(password),       # one-way hash, not encryption
                deterministic_hash(role),
                encrypt_text(role),
                encrypt_text(created_at),
            ),
        )
        return user_id
    except DatabaseOperationError as exc:
        # IntegrityError means username_hash already exists (duplicate username).
        # We convert it to a ValueError with a safe message — no DB internals leaked.
        if isinstance(exc.original, sqlite3.IntegrityError):
            raise ValueError("Username already exists.") from exc
        raise


def username_exists(username: str) -> bool:
    # Lookup by HMAC hash — we never put the plaintext username in a SQL query.
    row = fetch_one("SELECT id FROM users WHERE username_hash = ?", (deterministic_hash(username.lower()),))
    result = row is not None
    return result


def get_user_by_username(username: str) -> Optional[Dict[str, str]]:
    row = fetch_one(
        """
        SELECT id, username_enc, password_hash, role_enc, last_log_read_at_enc, session_version
        FROM users WHERE username_hash = ?
        """,
        (deterministic_hash(username.lower()),),
    )
    result = None
    if row:
        result = {
            "id": row[0],
            "username": decrypt_text(row[1]),
            "password_hash": row[2],
            "role": decrypt_text(row[3]),
            "last_log_read_at": decrypt_text(row[4]),
            "session_version": row[5],
        }
    return result


def get_user_by_id(user_id: int) -> Optional[Dict[str, str]]:
    row = fetch_one(
        """
        SELECT id, username_enc, password_hash, role_enc, last_log_read_at_enc, session_version
        FROM users WHERE id = ?
        """,
        (user_id,),
    )
    result = None
    if row:
        result = {
            "id": row[0],
            "username": decrypt_text(row[1]),
            "password_hash": row[2],
            "role": decrypt_text(row[3]),
            "last_log_read_at": decrypt_text(row[4]),
            "session_version": row[5],
        }
    return result


def verify_user_password(username: str, password: str) -> Optional[Dict[str, str]]:
    # Returns user dict only if password matches. We don't tell the caller
    # whether the username was wrong or the password was wrong — returning None
    # for both cases prevents username enumeration (attacker can't figure out
    # which usernames exist based on different error messages).
    user = get_user_by_username(username)
    result = None
    if user and verify_password(user["password_hash"], password):
        result = user
    return result


def update_password(user_id: int, new_password: str) -> None:
    # Incrementing session_version forces all existing sessions for this user
    # to become invalid — so if someone stole the old password and is logged in,
    # they get kicked out as soon as the real user changes their password.
    execute(
        "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
        (hash_password(new_password), user_id),
    )


def update_role(user_id: int, role: str) -> None:
    execute(
        "UPDATE users SET role_hash = ?, role_enc = ?, session_version = session_version + 1 WHERE id = ?",
        (deterministic_hash(role), encrypt_text(role), user_id),
    )


def update_last_log_read(user_id: int, timestamp: str) -> None:
    execute(
        "UPDATE users SET last_log_read_at_enc = ? WHERE id = ?",
        (encrypt_text(timestamp), user_id),
    )


def delete_user(user_id: int) -> None:
    # Cascading delete across all related tables in a single transaction.
    # If any step fails, everything rolls back — we won't end up with orphaned
    # claims or profiles pointing to a non-existent user.
    # Order matters: delete child records before the parent (users) row.
    execute_many(
        [
            ("DELETE FROM claims WHERE employee_user_id = ?", (user_id,)),
            ("DELETE FROM restore_codes WHERE manager_user_id = ?", (user_id,)),
            ("DELETE FROM profiles WHERE user_id = ?", (user_id,)),
            ("DELETE FROM employees WHERE user_id = ?", (user_id,)),
            ("DELETE FROM users WHERE id = ?", (user_id,)),
        ]
    )


def list_users_by_role(role: str) -> list:
    rows = fetch_all(
        """
        SELECT id, username_enc FROM users WHERE role_hash = ?
        """,
        (deterministic_hash(role),),
    )
    results = [{"id": r[0], "username": decrypt_text(r[1])} for r in rows]
    return results
