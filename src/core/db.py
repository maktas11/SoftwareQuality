import sqlite3
from typing import Any, List, Optional, Sequence, Tuple

from core.config import DB_PATH
from core.crypto import deterministic_hash


class DatabaseOperationError(Exception):
    def __init__(self, operation: str, original: Exception):
        self.operation = operation
        self.original = original
        super().__init__(f"Database error during {operation}: {original}")


def get_connection() -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except sqlite3.Error as exc:
        raise DatabaseOperationError("get_connection", exc) from exc


def _migrate_role_name_to_hash(cursor) -> None:
    rows = cursor.execute("SELECT id, role_hash FROM users").fetchall()
    for row in rows:
        user_id, plaintext_role = row[0], row[1]
        cursor.execute(
            "UPDATE users SET role_hash = ? WHERE id = ?",
            (deterministic_hash(plaintext_role), user_id),
        )


def init_db() -> None:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username_enc BLOB NOT NULL,
                    username_hash TEXT NOT NULL UNIQUE,
                    password_hash BLOB NOT NULL,
                    role_hash TEXT NOT NULL,
                    role_enc BLOB NOT NULL,
                    created_at_enc BLOB NOT NULL,
                    last_log_read_at_enc BLOB
                )
                """
            )
            columns = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
            if "session_version" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
            if "role_name" in columns:
                cursor.execute("ALTER TABLE users RENAME COLUMN role_name TO role_hash")
                _migrate_role_name_to_hash(cursor)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    first_name_enc BLOB NOT NULL,
                    last_name_enc BLOB NOT NULL,
                    registration_date_enc BLOB NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL UNIQUE,
                    employee_id_enc BLOB NOT NULL,
                    birthday_enc BLOB,
                    gender_enc BLOB,
                    street_enc BLOB,
                    house_number_enc BLOB,
                    zip_enc BLOB,
                    city_enc BLOB,
                    email_enc BLOB,
                    mobile_enc BLOB,
                    id_doc_type_enc BLOB,
                    id_doc_number_enc BLOB,
                    bsn_enc BLOB,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS claims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_user_id INTEGER NOT NULL,
                    claim_date_enc BLOB NOT NULL,
                    project_number_enc BLOB NOT NULL,
                    claim_type_enc BLOB NOT NULL,
                    travel_distance_enc BLOB,
                    from_zip_enc BLOB,
                    from_house_enc BLOB,
                    to_zip_enc BLOB,
                    to_house_enc BLOB,
                    approval_status_enc BLOB NOT NULL,
                    approved_by_enc BLOB,
                    salary_batch_enc BLOB,
                    FOREIGN KEY(employee_user_id) REFERENCES users(id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS restore_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    manager_user_id INTEGER NOT NULL,
                    backup_name_enc BLOB NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at_enc BLOB NOT NULL,
                    FOREIGN KEY(manager_user_id) REFERENCES users(id)
                )
                """
            )
    except sqlite3.Error as exc:
        raise DatabaseOperationError("init_db", exc) from exc


def execute(query: str, params: Tuple = ()) -> None:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
    except sqlite3.Error as exc:
        raise DatabaseOperationError("execute", exc) from exc


def execute_insert(query: str, params: Tuple = ()) -> int:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return int(cur.lastrowid)
    except sqlite3.Error as exc:
        raise DatabaseOperationError("execute_insert", exc) from exc


def execute_many(statements: Sequence[Tuple[str, Tuple]]) -> None:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            for query, params in statements:
                cur.execute(query, params)
    except sqlite3.Error as exc:
        raise DatabaseOperationError("execute_many", exc) from exc


def fetch_one(query: str, params: Tuple = ()) -> Optional[Tuple[Any, ...]]:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            row = cur.fetchone()
            return row
    except sqlite3.Error as exc:
        raise DatabaseOperationError("fetch_one", exc) from exc


def fetch_all(query: str, params: Tuple = ()) -> List[Tuple[Any, ...]]:
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()
            return rows
    except sqlite3.Error as exc:
        raise DatabaseOperationError("fetch_all", exc) from exc
