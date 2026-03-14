import datetime
import re
from typing import Iterable, List, Tuple


CITY_OPTIONS = [
    "Amsterdam",
    "Rotterdam",
    "Utrecht",
    "Eindhoven",
    "Groningen",
    "Tilburg",
    "Nijmegen",
    "Haarlem",
    "Leiden",
    "Breda",
]


def normalize_username(username: str) -> str:
    return username.strip().lower()


def validate_username(username: str) -> Tuple[bool, str]:
    if not username:
        return False, "Username is required."
    pattern = r"^(?=.{8,10}$)[A-Za-z_][A-Za-z0-9_'.]*$"
    if re.match(pattern, username):
        return True, ""
    return False, "Username format is invalid."


def validate_password(password: str) -> Tuple[bool, str]:
    if not password:
        return False, "Password is required."
    if len(password) < 12 or len(password) > 50:
        return False, "Password length is invalid."
    checks = [
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"\d", password),
        re.search(r"[~!@#$%&_\-+=`|\\(){}\[\]:;'<>,.?/]", password),
    ]
    if all(checks):
        return True, ""
    return False, "Password must include lower, upper, digit, and special."


def validate_name(value: str) -> Tuple[bool, str]:
    if not value or len(value.strip()) < 1:
        return False, "Value is required."
    if re.match(r"^[A-Za-z\-\s']{1,50}$", value):
        return True, ""
    return False, "Only letters, spaces, hyphens, and apostrophes allowed."


def validate_street(value: str) -> Tuple[bool, str]:
    if not value or len(value.strip()) < 2:
        return False, "Street is required."
    if re.match(r"^[A-Za-z0-9\-\s']{2,80}$", value):
        return True, ""
    return False, "Street contains invalid characters."


def validate_date(value: str) -> Tuple[bool, str]:
    try:
        datetime.datetime.strptime(value, "%Y-%m-%d")
        return True, ""
    except ValueError:
        return False, "Date must be YYYY-MM-DD."


def validate_claim_date(value: str) -> Tuple[bool, str]:
    ok, msg = validate_date(value)
    if not ok:
        return False, msg
    date_value = datetime.datetime.strptime(value, "%Y-%m-%d").date()
    today = datetime.date.today()
    past_limit = today - datetime.timedelta(days=62)
    future_limit = today + datetime.timedelta(days=14)
    if past_limit <= date_value <= future_limit:
        return True, ""
    return False, "Claim date must be within 2 months past or 14 days future."


def validate_gender(value: str) -> Tuple[bool, str]:
    if value.lower() in {"male", "female"}:
        return True, ""
    return False, "Gender must be male or female."


def validate_house_number(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{1,6}$", value):
        return True, ""
    return False, "House number must be digits only."


def validate_zip(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{4}[A-Z]{2}$", value.upper()):
        return True, ""
    return False, "ZIP code must be DDDDXX."


def validate_city(value: str) -> Tuple[bool, str]:
    if value in CITY_OPTIONS:
        return True, ""
    return False, "City must be one of predefined options."


def validate_email(value: str) -> Tuple[bool, str]:
    if re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", value):
        return True, ""
    return False, "Email format invalid."


def validate_mobile(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{8}$", value):
        return True, ""
    return False, "Mobile number must be 8 digits."


def format_mobile(value: str) -> str:
    return f"+31-6-{value}"


def validate_id_doc_number(value: str) -> Tuple[bool, str]:
    if re.match(r"^(?:[A-Z]{2}\d{6}|[A-Z]{1}\d{7})$", value.upper()):
        return True, ""
    return False, "Identity number format invalid."


def validate_bsn(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{9}$", value):
        return True, ""
    return False, "BSN must be 9 digits."


def validate_project_number(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{2,10}$", value):
        return True, ""
    return False, "Project number must be 2-10 digits."


def validate_travel_distance(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{1,6}$", value):
        return True, ""
    return False, "Travel distance must be digits only."


def validate_claim_type(value: str) -> Tuple[bool, str]:
    if value.strip().lower() in {"travel", "home office"}:
        return True, ""
    return False, "Claim type must be Travel or Home Office."


def validate_salary_batch(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{4}-\d{2}$", value):
        return True, ""
    return False, "Salary batch must be YYYY-MM."


def validate_identity_doc_type(value: str) -> Tuple[bool, str]:
    if value.strip().lower() in {"passport", "id-card"}:
        return True, ""
    return False, "Document type must be Passport or ID-Card."
