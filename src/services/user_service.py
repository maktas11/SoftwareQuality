import datetime
import sqlite3
from typing import Dict, Optional

from core.crypto import decrypt_text, deterministic_hash, encrypt_text, hash_password, verify_password
from core.db import DatabaseOperationError, execute, execute_insert, execute_many, fetch_all, fetch_one
from core.validation import normalize_username


def create_user(username: str, password: str, role: str) -> int:
    normalized = normalize_username(username)
    username_hash = deterministic_hash(normalized)
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        return execute_insert(
            """
            INSERT INTO users (username_enc, username_hash, password_hash, role_name, role_enc, created_at_enc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                encrypt_text(username),
                username_hash,
                hash_password(password),
                role,
                encrypt_text(role),
                encrypt_text(created_at),
            ),
        )
    except DatabaseOperationError as exc:
        if isinstance(exc.original, sqlite3.IntegrityError):
            raise ValueError("Username already exists.") from exc
        raise


def username_exists(username: str) -> bool:
    normalized = normalize_username(username)
    row = fetch_one("SELECT id FROM users WHERE username_hash = ?", (deterministic_hash(normalized),))
    return row is not None


def get_user_by_username(username: str) -> Optional[Dict[str, str]]:
    normalized = normalize_username(username)
    row = fetch_one(
        """
        SELECT id, username_enc, password_hash, role_enc, last_log_read_at_enc, session_version
        FROM users WHERE username_hash = ?
        """,
        (deterministic_hash(normalized),),
    )
    if row:
        return {
            "id": row[0],
            "username": decrypt_text(row[1]),
            "password_hash": row[2],
            "role": decrypt_text(row[3]),
            "last_log_read_at": decrypt_text(row[4]),
            "session_version": row[5],
        }
    return None


def get_user_by_id(user_id: int) -> Optional[Dict[str, str]]:
    row = fetch_one(
        """
        SELECT id, username_enc, password_hash, role_enc, last_log_read_at_enc, session_version
        FROM users WHERE id = ?
        """,
        (user_id,),
    )
    if row:
        return {
            "id": row[0],
            "username": decrypt_text(row[1]),
            "password_hash": row[2],
            "role": decrypt_text(row[3]),
            "last_log_read_at": decrypt_text(row[4]),
            "session_version": row[5],
        }
    return None


def verify_user_password(username: str, password: str) -> Optional[Dict[str, str]]:
    user = get_user_by_username(username)
    if user and verify_password(user["password_hash"], password):
        return user
    return None


def update_password(user_id: int, new_password: str) -> None:
    execute(
        "UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ?",
        (hash_password(new_password), user_id),
    )


def update_role(user_id: int, role: str) -> None:
    execute(
        "UPDATE users SET role_name = ?, role_enc = ?, session_version = session_version + 1 WHERE id = ?",
        (role, encrypt_text(role), user_id),
    )


def update_last_log_read(user_id: int, timestamp: str) -> None:
    execute(
        "UPDATE users SET last_log_read_at_enc = ? WHERE id = ?",
        (encrypt_text(timestamp), user_id),
    )


def delete_user(user_id: int) -> None:
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
        SELECT id, username_enc FROM users WHERE role_name = ?
        """,
        (role,),
    )
    return [{"id": r[0], "username": decrypt_text(r[1])} for r in rows]
