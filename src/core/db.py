import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.config import DB_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_enc BLOB NOT NULL,
            username_hash TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            role_name TEXT NOT NULL,
            role_enc BLOB NOT NULL,
            created_at_enc BLOB NOT NULL,
            last_log_read_at_enc BLOB
        )
        """
    )
    columns = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
    if "session_version" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
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
    conn.commit()
    conn.close()


def execute(query: str, params: Tuple = ()) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    conn.close()


def fetch_one(query: str, params: Tuple = ()) -> Optional[Tuple[Any, ...]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    row = cur.fetchone()
    conn.close()
    return row


def fetch_all(query: str, params: Tuple = ()) -> List[Tuple[Any, ...]]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows
