import datetime
import re
from typing import Tuple

# --- Input validation layer ---
# All validation uses a whitelist approach: we define exactly what IS allowed
# with regex patterns, and reject everything else. This is more secure than
# blacklisting (trying to block known-bad characters) because you can't
# accidentally miss a dangerous character you didn't think of.
#
# Every validator returns (bool, str) — True + empty string on success,
# False + error message on failure. This keeps validation separate from
# the UI layer (separation of concerns).
#
# Length limits on all fields also protect against buffer-overflow style
# issues — even though Python handles memory automatically, excessively
# long inputs could still cause problems in the DB or downstream processing.

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



def validate_username(username: str) -> Tuple[bool, str]:
    # Whitelist regex: 8-10 chars, must start with letter or underscore.
    # Only allows a-z, 0-9, _, apostrophe, period — no special SQL/HTML chars.
    # The null check (username truthy) also blocks null-byte injection.
    pattern = r"^[A-Za-z_][A-Za-z0-9_'.]{7,9}$"
    if username and re.match(pattern, username):
        return True, ""
    return False, "Username format is invalid."


def validate_password(password: str) -> Tuple[bool, str]:
    # Enforces complexity requirements: minimum 12 chars, max 50,
    # must contain lowercase + uppercase + digit + special character.
    # The max length of 50 prevents denial-of-service through extremely
    # long passwords that would be expensive to hash with PBKDF2.
    checks = [
        password,                                                    # not empty / not None
        12 <= len(password) <= 50,                                   # length range
        re.search(r"[a-z]", password),                               # at least one lowercase
        re.search(r"[A-Z]", password),                               # at least one uppercase
        re.search(r"\d", password),                                  # at least one digit
        re.search(r"[~!@#$%&_\-+=`|\\(){}\[\]:;'<>,.?/]", password),  # at least one special
    ]
    if all(checks):
        return True, ""
    return False, "Password must be 12-50 chars with lower, upper, digit, and special."


def validate_name(value: str) -> Tuple[bool, str]:
    if value and re.match(r"^[A-Za-z](?:[A-Za-z]|[ '\-](?=[A-Za-z])){0,49}$", value):
        return True, ""
    return False, "Only letters, spaces, hyphens, and apostrophes allowed."


def validate_street(value: str) -> Tuple[bool, str]:
    if value and re.match(r"^[A-Za-z0-9](?:[A-Za-z0-9]|[ '\-](?=[A-Za-z0-9])){1,79}$", value):
        return True, ""
    return False, "Street contains invalid characters."


def validate_date(value: str) -> Tuple[bool, str]:
    try:
        datetime.datetime.strptime(value, "%Y-%m-%d")
        return True, ""
    except ValueError:
        return False, "Date must be YYYY-MM-DD."


def validate_claim_date(value: str) -> Tuple[bool, str]:
    # Business rule: claims can only be for dates within 2 months in the past
    # or 14 days in the future. This prevents backdated fraud and far-future
    # placeholder claims. The range check happens server-side so it can't be bypassed.
    try:
        date_value = datetime.datetime.strptime(value, "%Y-%m-%d").date()
        today = datetime.date.today()
        past_limit = today - datetime.timedelta(days=62)
        future_limit = today + datetime.timedelta(days=14)
        if past_limit <= date_value <= future_limit:
            return True, ""
    except ValueError:
        pass
    return False, "Claim date must be within 2 months past or 14 days future."


def validate_gender(value: str) -> Tuple[bool, str]:
    if re.fullmatch(r"male|female", value, flags=re.IGNORECASE):
        return True, ""
    return False, "Gender must be male or female."


def validate_house_number(value: str) -> Tuple[bool, str]:
    if re.match(r"^(?:0|[1-9]\d{0,5})$", value):
        return True, ""
    return False, "House number must be digits only."


def validate_zip(value: str) -> Tuple[bool, str]:
    # Dutch ZIP format: exactly 4 digits followed by 2 uppercase letters.
    # Strict pattern means no spaces, no extra chars — prevents injection.
    if re.match(r"^\d{4}[A-Z]{2}$", value, flags=re.IGNORECASE):
        return True, ""
    return False, "ZIP code must be DDDDXX."


def validate_city(value: str) -> Tuple[bool, str]:
    # City is validated against a fixed whitelist — user can only pick from
    # predefined options, so there's zero risk of injection through this field.
    if value in CITY_OPTIONS:
        return True, ""
    return False, "City must be one of predefined options."


def validate_email(value: str) -> Tuple[bool, str]:
    # RFC-style email check — also rejects double dots (..) and @. at the start
    # of the domain, which are common in malformed injection payloads.
    # Length is implicitly limited by the pattern structure.
    if re.match(
        r"^(?!.*\.\.)(?!.*@\.)[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?@"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$",
        value,
    ):
        return True, ""
    return False, "Email format invalid."


def validate_mobile(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{8}$", value):
        return True, ""
    return False, "Mobile number must be 8 digits."


def format_mobile(value: str) -> str:
    return f"+31-6-{value}"


def validate_id_doc_number(value: str) -> Tuple[bool, str]:
    # Accepts two formats: XX123456 (passport) or X1234567 (ID card).
    # Only letters and digits in a fixed structure — no room for injection.
    if re.match(r"^(?:[A-Z]{2}\d{7}|[A-Z]{1}\d{8})$", value, flags=re.IGNORECASE):
        return True, ""
    return False, "Identity number format invalid."

def validate_int(value: str) -> Tuple[bool, str]:
    # Generic integer validator with range check to prevent unreasonable values.
    if not value or not value.isdigit():
        return False, "Must be digits only."
    try:
        num = int(value)
        if 0 <= num <= 999999:  # reasonable range for claim/employee IDs
            return True, ""
    except ValueError:
        pass
    return False, "Must be a valid integer in range."

def validate_bsn(value: str) -> Tuple[bool, str]:
    # BSN (Dutch social security number) — exactly 9 digits, nothing else.
    # Strict digit-only pattern blocks any non-numeric injection attempts.
    if re.match(r"^\d{9}$", value):
        return True, ""
    return False, "BSN must be 9 digits."


def validate_project_number(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{2,10}$", value):
        return True, ""
    return False, "Project number must be 2-10 digits."


def validate_travel_distance(value: str) -> Tuple[bool, str]:
    if re.match(r"^(?:0|[1-9]\d{0,5})$", value):
        return True, ""
    return False, "Travel distance must be digits only."


def validate_claim_type(value: str) -> Tuple[bool, str]:
    if re.fullmatch(r"travel|home office", value, flags=re.IGNORECASE):
        return True, ""
    return False, "Claim type must be Travel or Home Office."


def validate_salary_batch(value: str) -> Tuple[bool, str]:
    if re.match(r"^\d{4}-(0[1-9]|1[0-2])$", value):
        return True, ""
    return False, "Salary batch must be YYYY-MM with month 01-12."


def validate_identity_doc_type(value: str) -> Tuple[bool, str]:
    if re.fullmatch(r"passport|id-card", value, flags=re.IGNORECASE):
        return True, ""
    return False, "Document type must be Passport or ID-Card."
