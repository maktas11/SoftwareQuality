from typing import Dict, List, Optional

from core.crypto import decrypt_text, encrypt_text
from core.db import execute, fetch_all, fetch_one


def create_profile(user_id: int, first_name: str, last_name: str, registration_date: str) -> None:
    execute(
        """
        INSERT INTO profiles (user_id, first_name_enc, last_name_enc, registration_date_enc)
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            encrypt_text(first_name),
            encrypt_text(last_name),
            encrypt_text(registration_date),
        ),
    )


def update_profile(user_id: int, first_name: str, last_name: str) -> None:
    execute(
        """
        UPDATE profiles SET first_name_enc = ?, last_name_enc = ? WHERE user_id = ?
        """,
        (encrypt_text(first_name), encrypt_text(last_name), user_id),
    )


def generate_employee_id(user_id: int) -> str:
    result = str(1000 + user_id)
    return result


def create_employee(user_id: int, data: Dict[str, str]) -> str:
    employee_id = generate_employee_id(user_id)
    execute(
        """
        INSERT INTO employees (
            user_id, employee_id_enc, birthday_enc, gender_enc, street_enc, house_number_enc,
            zip_enc, city_enc, email_enc, mobile_enc, id_doc_type_enc, id_doc_number_enc, bsn_enc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            encrypt_text(employee_id),
            encrypt_text(data.get("birthday", "")),
            encrypt_text(data.get("gender", "")),
            encrypt_text(data.get("street", "")),
            encrypt_text(data.get("house_number", "")),
            encrypt_text(data.get("zip", "")),
            encrypt_text(data.get("city", "")),
            encrypt_text(data.get("email", "")),
            encrypt_text(data.get("mobile", "")),
            encrypt_text(data.get("id_doc_type", "")),
            encrypt_text(data.get("id_doc_number", "")),
            encrypt_text(data.get("bsn", "")),
        ),
    )
    return employee_id


def update_employee(user_id: int, data: Dict[str, str]) -> None:
    execute(
        """
        UPDATE employees SET
            birthday_enc = ?, gender_enc = ?, street_enc = ?, house_number_enc = ?,
            zip_enc = ?, city_enc = ?, email_enc = ?, mobile_enc = ?,
            id_doc_type_enc = ?, id_doc_number_enc = ?, bsn_enc = ?
        WHERE user_id = ?
        """,
        (
            encrypt_text(data.get("birthday", "")),
            encrypt_text(data.get("gender", "")),
            encrypt_text(data.get("street", "")),
            encrypt_text(data.get("house_number", "")),
            encrypt_text(data.get("zip", "")),
            encrypt_text(data.get("city", "")),
            encrypt_text(data.get("email", "")),
            encrypt_text(data.get("mobile", "")),
            encrypt_text(data.get("id_doc_type", "")),
            encrypt_text(data.get("id_doc_number", "")),
            encrypt_text(data.get("bsn", "")),
            user_id,
        ),
    )


def get_employee_by_user_id(user_id: int) -> Optional[Dict[str, str]]:
    row = fetch_one(
        """
        SELECT employee_id_enc, birthday_enc, gender_enc, street_enc, house_number_enc,
               zip_enc, city_enc, email_enc, mobile_enc, id_doc_type_enc, id_doc_number_enc, bsn_enc
        FROM employees WHERE user_id = ?
        """,
        (user_id,),
    )
    result = None
    if row:
        result = {
            "employee_id": decrypt_text(row[0]),
            "birthday": decrypt_text(row[1]),
            "gender": decrypt_text(row[2]),
            "street": decrypt_text(row[3]),
            "house_number": decrypt_text(row[4]),
            "zip": decrypt_text(row[5]),
            "city": decrypt_text(row[6]),
            "email": decrypt_text(row[7]),
            "mobile": decrypt_text(row[8]),
            "id_doc_type": decrypt_text(row[9]),
            "id_doc_number": decrypt_text(row[10]),
            "bsn": decrypt_text(row[11]),
        }
    return result


def list_employee_records() -> List[Dict[str, str]]:
    rows = fetch_all(
        """
        SELECT users.id, users.username_enc, profiles.first_name_enc, profiles.last_name_enc,
               profiles.registration_date_enc, employees.employee_id_enc, employees.city_enc
        FROM users
        JOIN profiles ON profiles.user_id = users.id
        JOIN employees ON employees.user_id = users.id
        """
    )
    results = []
    for row in rows:
        results.append(
            {
                "user_id": row[0],
                "username": decrypt_text(row[1]),
                "first_name": decrypt_text(row[2]),
                "last_name": decrypt_text(row[3]),
                "registration_date": decrypt_text(row[4]),
                "employee_id": decrypt_text(row[5]),
                "city": decrypt_text(row[6]),
            }
        )
    return results


def search_employees(term: str) -> List[Dict[str, str]]:
    term_lower = term.lower()
    results = []
    for row in list_employee_records():
        haystack = " ".join(str(v) for v in row.values()).lower()
        if term_lower in haystack:
            results.append(row)
    return results
