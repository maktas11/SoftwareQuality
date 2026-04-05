import datetime
import os
import secrets
import string
from typing import Dict, List, Optional

from core import backup
from core.auth import ROLE_EMPLOYEE, ROLE_MANAGER, ROLE_SUPER, has_permission
from core.config import DATA_DIR, ensure_data_dirs
from core.crypto import encrypt_text, decrypt_text
from core.db import DatabaseOperationError, init_db
from core.logging_utils import (
    append_log,
    count_unread_suspicious,
    get_super_last_read,
    read_logs,
    set_super_last_read,
)
from core.validation import (
    CITY_OPTIONS,
    format_mobile,
    validate_bsn,
    validate_claim_date,
    validate_claim_type,
    validate_date,
    validate_email,
    validate_gender,
    validate_house_number,
    validate_id_doc_number,
    validate_identity_doc_type,
    validate_int,
    validate_mobile,
    validate_name,
    validate_password,
    validate_project_number,
    validate_salary_batch,
    validate_travel_distance,
    validate_username,
    validate_zip,
    validate_street,
)
from services import claim_service, employee_service, restore_code_service, user_service
from ui.prompts import (
    prompt_choice,
    prompt_password,
    prompt_password_until_valid,
    prompt_text,
    prompt_until_valid,
)

# Hard-coded super admin credentials (required by the assignment spec).
# In a real system this would be stored securely or set during first-run setup.
SUPER_USERNAME = "super_admin"
SUPER_PASSWORD = "Admin_123?"

USERNAME_HINT = "8-10 chars. First char: letter or _. Allowed: letters, digits, _, apostrophe ('), dot (.)."
PASSWORD_HINT = "12-50 chars; lower, upper, digit, special"
NAME_HINT = "letters, spaces, hyphens, apostrophes; up to 50"
DOC_TYPE_HINT = "Passport or ID-Card"
DATE_HINT = "YYYY-MM-DD"
CLAIM_DATE_HINT = "YYYY-MM-DD; past 2 months or next 14 days"
GENDER_HINT = "male or female"
STREET_HINT = "2-80 chars; letters, digits, spaces, hyphen, apostrophe"
HOUSE_HINT = "1-6 digits"
ZIP_HINT = "DDDDXX"
EMAIL_HINT = "name@domain.tld"
MOBILE_HINT = "8 digits"
ID_DOC_HINT = "AA1234567 or A12345678"
BSN_HINT = "9 digits"
PROJECT_HINT = "2-10 digits"
CLAIM_TYPE_HINT = "Travel or Home Office"
TRAVEL_HINT = "1-6 digits"
SALARY_HINT = "YYYY-MM"

# --- Brute-force protection ---
# Track failed login attempts per username. After 5 failures within 5 minutes
# the account gets temporarily locked. This stops automated password guessing.
FAILED_LOGIN_ATTEMPTS: Dict[str, List[datetime.datetime]] = {}
LOCKED_UNTIL: Dict[str, datetime.datetime] = {}
FORCE_LOGOUT_AFTER_RESTORE = False
RESTORE_NOTICE_PATH = os.path.join(DATA_DIR, "last_restore_notice.enc")


def generate_temp_password() -> str:
    special = "~!@#$%&_-+="
    parts = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(special),
    ]
    alphabet = string.ascii_letters + string.digits + special
    parts += [secrets.choice(alphabet) for _ in range(8)]
    secrets.SystemRandom().shuffle(parts)
    return ''.join(parts)


def log_action(user: Dict[str, str], description: str, info: str = "", suspicious: bool = False) -> None:
    # Wrapper that's called from every action in the app — login, CRUD, errors, etc.
    # The suspicious flag triggers alerts for managers/admins on their next login.
    append_log(user.get("username", ""), description, info, suspicious)


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    prompt_text("Press Enter to continue...")


def ensure_permission(user: Dict[str, str], permission: str) -> bool:
    # Central authorization gate — every menu action calls this first.
    # If the user doesn't have the required permission, the attempt is
    # logged as suspicious and the action is blocked.
    if has_permission(user["role"], permission):
        return True
    log_action(user, "Unauthorized access", f"permission: {permission}", True)
    print("Unauthorized action.")
    pause()
    return False


def is_session_active(user: Dict[str, str]) -> bool:
    # Session validation runs before every menu iteration.
    # Checks two things:
    # 1. Does the user still exist? (could have been deleted by admin)
    # 2. Has session_version changed? (means password was reset or role changed —
    #    the old session should no longer be valid)
    # This prevents "ghost sessions" where a deleted or modified user keeps access.
    if user.get("id") is None:
        return True
    current = user_service.get_user_by_id(user["id"])
    if not current:
        print("Your account no longer exists. Please log in again.")
        return False
    if current.get("session_version") != user.get("session_version"):
        print("Your session is no longer valid. Please log in again.")
        return False
    return True


def track_failed_login(username: str) -> bool:
    # Sliding window: only count failures from the last 5 minutes.
    # After 5 failures -> lock the account for 5 minutes.
    # Returns True (suspicious) after 3+ failures so we can flag it in the log.
    # This makes brute-force attacks impractical — attacker can only try
    # 5 passwords every 5 minutes per username.
    now = datetime.datetime.now()
    key = username
    FAILED_LOGIN_ATTEMPTS.setdefault(key, [])
    FAILED_LOGIN_ATTEMPTS[key] = [t for t in FAILED_LOGIN_ATTEMPTS[key] if (now - t).seconds < 300]
    FAILED_LOGIN_ATTEMPTS[key].append(now)
    if len(FAILED_LOGIN_ATTEMPTS[key]) >= 5:
        LOCKED_UNTIL[key] = now + datetime.timedelta(minutes=5)
    return len(FAILED_LOGIN_ATTEMPTS[key]) >= 3


def clear_failed_login(username: str) -> None:
    key = username
    FAILED_LOGIN_ATTEMPTS.pop(key, None)
    LOCKED_UNTIL.pop(key, None)


def is_locked_out(username: str) -> bool:
    key = username
    until = LOCKED_UNTIL.get(key)
    if until and datetime.datetime.now() < until:
        return True
    LOCKED_UNTIL.pop(key, None)
    return False


def confirm_restore_risk() -> bool:
    # Requires the user to type "RESTORE" exactly — prevents accidental restores.
    # This is a destructive action that can't be undone, so we want explicit consent.
    print("WARNING: Restoring a backup overwrites current database data.")
    print("Changes made after that backup will be lost.")
    print("Passwords and account data may revert to older values.")
    confirm = prompt_text("Type RESTORE to continue: ")
    return confirm == "RESTORE"


def set_restore_notice(timestamp: str) -> None:
    with open(RESTORE_NOTICE_PATH, "wb") as handle:
        handle.write(encrypt_text(timestamp))


def get_restore_notice() -> str:
    if not os.path.exists(RESTORE_NOTICE_PATH):
        return ""
    try:
        with open(RESTORE_NOTICE_PATH, "rb") as handle:
            return decrypt_text(handle.read())
    except (OSError, Exception):
        return ""


def handle_restore_success(user: Dict[str, str], backup_name: str) -> None:
    # After a restore, force everyone (including the current user) to re-login.
    # The restored DB might have different passwords, roles, or users —
    # continuing with the old session would be a security risk.
    # Also clear lockout state since the old failed-attempt data is stale.
    global FORCE_LOGOUT_AFTER_RESTORE
    FORCE_LOGOUT_AFTER_RESTORE = True
    FAILED_LOGIN_ATTEMPTS.clear()
    LOCKED_UNTIL.clear()
    set_restore_notice(datetime.datetime.now().strftime("%d-%m-%Y %H:%M"))
    log_action(user, "Backup restored", f"backup: {backup_name}")
    print("Backup restored.")
    print("All users are logged out. Please log in again.")


def login() -> Optional[Dict[str, str]]:
    clear_screen()
    print("=== Login ===")
    restore_notice = get_restore_notice()
    if restore_notice:
        print(f"SYSTEM NOTICE: A backup was restored on {restore_notice}. Your password may have reverted.")
    print("Type exit to quit.")
    username = prompt_text("Username: ")
    if username == "exit":
        return "EXIT"
    username = username.lower()
    # Password input is masked using getpass — characters are not echoed to screen.
    password = prompt_password("Password: ")

    # Check lockout BEFORE attempting authentication — don't even try to verify
    # the password if the account is locked, to prevent timing-based info leaks.
    if is_locked_out(username):
        log_action({"username": username}, "Login locked", "Too many attempts", True)
        print("Account temporarily locked. Try again later.")
        return None

    # Super admin uses hardcoded credentials (assignment requirement).
    if username == SUPER_USERNAME:
        if password == SUPER_PASSWORD:
            clear_failed_login(username)
            user = {"id": None, "username": SUPER_USERNAME, "role": ROLE_SUPER}
            log_action(user, "Logged in", "")
            return user
        suspicious = track_failed_login(username)
        log_action({"username": username}, "Unsuccessful login", f"username: {username}", suspicious)
        # Generic error message — we don't say "wrong password" vs "wrong username"
        # because that would let attackers confirm valid usernames.
        print("Invalid credentials.")
        return None

    user = user_service.verify_user_password(username, password)
    if user:
        clear_failed_login(username)
        log_action(user, "Logged in", "")
        return user

    # Failed login — track it and check if it's becoming suspicious (3+ attempts).
    suspicious = track_failed_login(username)
    log_action({"username": username}, "Unsuccessful login", f"username: {username}", suspicious)
    print("Invalid credentials.")
    return None


def notify_unread_suspicious(user: Dict[str, str]) -> None:
    # Alert for managers and super admin right after login —
    # shows how many suspicious events happened since they last checked the logs.
    # This way security incidents don't go unnoticed.
    if user["role"] == ROLE_SUPER:
        last_read = get_super_last_read()
    else:
        last_read = user.get("last_log_read_at", "")
    count = count_unread_suspicious(last_read)
    if count > 0:
        print(f"WARNING: {count} unread suspicious log entries.")
        pause()


def handle_view_logs(user: Dict[str, str]) -> None:
    log_action(user, "View logs", "")
    logs = read_logs()
    if not logs:
        print("No logs available.")
    else:
        print("No | Date | Time | Username | Description | Info | Suspicious")
        for entry in logs:
            print(
                f"{entry.get('id')} | {entry.get('date')} | {entry.get('time')} | "
                f"{entry.get('username')} | {entry.get('description')} | {entry.get('info')} | {entry.get('suspicious')}"
            )
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if user["role"] == ROLE_SUPER:
        set_super_last_read(timestamp)
    else:
        user_service.update_last_log_read(user["id"], timestamp)


def prompt_employee_data() -> Dict[str, str]:
    doc_type = prompt_until_valid(
        "Document Type (Passport/ID-Card): ", validate_identity_doc_type, hint=DOC_TYPE_HINT
    )
    data = {
        "birthday": prompt_until_valid("Birthday (YYYY-MM-DD): ", validate_date, hint=DATE_HINT),
        "gender": prompt_until_valid("Gender (male/female): ", validate_gender, hint=GENDER_HINT),
        "street": prompt_until_valid("Street name: ", validate_street, hint=STREET_HINT),
        "house_number": prompt_until_valid("House number: ", validate_house_number, hint=HOUSE_HINT),
        "zip": prompt_until_valid("ZIP code (DDDDXX): ", validate_zip, hint=ZIP_HINT),
        "city": prompt_choice(
            "City (choose number): "
            + " ".join([f"{idx + 1}:{name}" for idx, name in enumerate(CITY_OPTIONS)])
            + "\n",
            {str(idx + 1): name for idx, name in enumerate(CITY_OPTIONS)},
        ),
        "email": prompt_until_valid("Email: ", validate_email, hint=EMAIL_HINT),
        "mobile": format_mobile(prompt_until_valid("Mobile (8 digits): ", validate_mobile, hint=MOBILE_HINT)),
        "id_doc_type": doc_type,
        "id_doc_number": prompt_until_valid("Document Number: ", validate_id_doc_number, hint=ID_DOC_HINT),
        "bsn": prompt_until_valid("BSN (9 digits): ", validate_bsn, hint=BSN_HINT),
    }
    return data


def prompt_claim_data() -> Dict[str, str]:
    data = {
        "claim_date": prompt_until_valid("Claim date (YYYY-MM-DD): ", validate_claim_date, hint=CLAIM_DATE_HINT),
        "project_number": prompt_until_valid("Project number (2-10 digits): ", validate_project_number, hint=PROJECT_HINT),
        "claim_type": prompt_until_valid("Claim type (Travel/Home Office): ", validate_claim_type, hint=CLAIM_TYPE_HINT),
    }
    if data["claim_type"] == "Travel":
        data.update(
            {
                "travel_distance": prompt_until_valid(
                    "Travel distance (km): ", validate_travel_distance, hint=TRAVEL_HINT
                ),
                "from_zip": prompt_until_valid("From ZIP (DDDDXX): ", validate_zip, hint=ZIP_HINT),
                "from_house": prompt_until_valid("From house number: ", validate_house_number, hint=HOUSE_HINT),
                "to_zip": prompt_until_valid("To ZIP (DDDDXX): ", validate_zip, hint=ZIP_HINT),
                "to_house": prompt_until_valid("To house number: ", validate_house_number, hint=HOUSE_HINT),
            }
        )
    return data


def display_claims(claims: List[Dict[str, str]]) -> None:
    if not claims:
        print("No claims found.")
        return
    for claim in claims:
        print(
            f"ID {claim['id']} | Date {claim['claim_date']} | Project {claim['project_number']} | "
            f"Type {claim['claim_type']} | Status {claim['approval_status']} | Salary {claim['salary_batch']}"
        )


def display_employees(records: List[Dict[str, str]]) -> None:
    if not records:
        print("No employees found.")
        return
    for rec in records:
        print(
            f"User {rec['username']} | Name {rec['first_name']} {rec['last_name']} | "
            f"Employee ID {rec['employee_id']} | City {rec['city']}"
        )


def prompt_int(label: str) -> Optional[int]:
    result = prompt_until_valid(label, validate_int)
    if result:
        value = int(result)
    else:
        value = None
    return value

def employee_menu(user: Dict[str, str]) -> None:
    # Every loop iteration re-checks session validity (is_session_active)
    # and every action re-checks permissions (ensure_permission).
    # Double-checking like this is "defense in depth" — even if the menu
    # is somehow reached by the wrong role, the permission check blocks it.
    while True:
        if not is_session_active(user):
            break
        clear_screen()
        print("\nEmployee Menu")
        print("1. Add claim")
        print("2. Update claim")
        print("3. Delete claim")
        print("4. Search my claims")
        print("5. Update my password")
        print("0. Logout")
        choice = prompt_text("Choose: ")
        clear_screen()
        if choice == "1":
            if not ensure_permission(user, "claim.add"):
                continue
            data = prompt_claim_data()
            claim_id = claim_service.create_claim(user["id"], data)
            log_action(user, "New claim", f"claim_id: {claim_id}")
            print("Claim created.")
            pause()
        elif choice == "2":
            if not ensure_permission(user, "claim.update_own"):
                continue
            claim_id = prompt_int("Claim ID: ")
            if claim_id is None:
                print("Invalid claim ID.")
                pause()
                continue
            data = prompt_claim_data()
            # The service layer verifies ownership (user["id"] must match the claim's
            # employee_user_id) — so an employee can't update someone else's claim.
            if claim_service.update_claim_employee(claim_id, user["id"], data):
                log_action(user, "Claim updated", f"claim_id: {claim_id}")
                print("Claim updated.")
            else:
                log_action(user, "Unauthorized claim update", f"claim_id: {claim_id}", True)
                print("Cannot update claim.")
            pause()
        elif choice == "3":
            if not ensure_permission(user, "claim.delete_own"):
                continue
            claim_id = prompt_int("Claim ID: ")
            if claim_id is None:
                print("Invalid claim ID.")
                pause()
                continue
            if claim_service.delete_claim_employee(claim_id, user["id"]):
                log_action(user, "Claim deleted", f"claim_id: {claim_id}")
                print("Claim deleted.")
            else:
                log_action(user, "Unauthorized claim delete", f"claim_id: {claim_id}", True)
                print("Cannot delete claim.")
            pause()
        elif choice == "4":
            if not ensure_permission(user, "claim.search_own"):
                continue
            term = prompt_text("Search term (or Enter to list all): ")
            claims = claim_service.list_claims_by_employee(user["id"])
            if term:
                claims = [
                    c for c in claims
                    if term.lower() in " ".join(str(v) for v in c.values()).lower()
                ]
            log_action(user, "Search claims", f"term: {term}" if term else "scope: own")
            display_claims(claims)
            pause()
        elif choice == "5":
            if not ensure_permission(user, "self.update_password"):
                continue
            password = prompt_password_until_valid("New password: ", validate_password, hint=PASSWORD_HINT)
            user_service.update_password(user["id"], password)
            log_action(user, "Password updated", "")
            print("Password updated. Please log in again.")
            pause()
            break
        elif choice == "0":
            log_action(user, "Logged out", "")
            break
        else:
            print("Invalid choice.")
            pause()


def manager_menu(user: Dict[str, str]) -> None:
    while True:
        if not is_session_active(user):
            break
        clear_screen()
        print("\nManager Menu")
        print("1. Add employee")
        print("2. Update employee")
        print("3. Delete employee")
        print("4. Reset employee password")
        print("5. Search employees")
        print("6. Modify claim")
        print("7. Approve or reject claim")
        print("8. Search claims")
        print("9. Backup system")
        print("10. Restore backup (with code)")
        print("11. View logs")
        print("12. Update my account")
        print("13. Delete my account")
        print("0. Logout")
        choice = prompt_text("Choose: ")
        clear_screen()

        if choice == "1":
            if not ensure_permission(user, "user.add_employee"):
                continue
            username = prompt_until_valid("Username: ", validate_username, hint=USERNAME_HINT)
            if user_service.username_exists(username):
                print("Username already exists.")
                pause()
                continue
            password = prompt_password_until_valid("Password: ", validate_password, hint=PASSWORD_HINT)
            first_name = prompt_until_valid("First name: ", validate_name, hint=NAME_HINT)
            last_name = prompt_until_valid("Last name: ", validate_name, hint=NAME_HINT)
            try:
                user_id = user_service.create_user(username, password, ROLE_EMPLOYEE)
            except ValueError as exc:
                print(str(exc))
                pause()
                continue
            registration_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            employee_service.create_profile(user_id, first_name, last_name, registration_date)
            employee_id = employee_service.create_employee(user_id, prompt_employee_data())
            log_action(user, "New employee created", f"username: {username}, employee_id: {employee_id}")
            print("Employee created.")
            pause()
        elif choice == "2":
            if not ensure_permission(user, "user.update_employee"):
                continue
            username = prompt_text("Employee username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_EMPLOYEE:
                print("User is not an employee.")
                pause()
                continue
            data = prompt_employee_data()
            employee_service.update_employee(target["id"], data)
            log_action(user, "Employee updated", f"username: {username}")
            print("Employee updated.")
            pause()
        elif choice == "3":
            if not ensure_permission(user, "user.delete_employee"):
                continue
            username = prompt_text("Employee username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_EMPLOYEE:
                print("User is not an employee.")
                pause()
                continue
            user_service.delete_user(target["id"])
            log_action(user, "Employee deleted", f"username: {username}")
            print("Employee deleted.")
            pause()
        elif choice == "4":
            if not ensure_permission(user, "user.reset_employee_pw"):
                continue
            username = prompt_text("Employee username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_EMPLOYEE:
                print("User is not an employee.")
                pause()
                continue
            # Temporary password for reset — shown once and must be changed by the user.
            # update_password also bumps session_version, kicking the employee out
            # of any active session immediately.
            temp_pw = generate_temp_password()
            user_service.update_password(target["id"], temp_pw)
            log_action(user, "Employee password reset", f"username: {username}")
            print(f"Temporary password: {temp_pw}")
            pause()
        elif choice == "5":
            if not ensure_permission(user, "employee.search"):
                continue
            term = prompt_text("Search term: ")
            results = employee_service.search_employees(term)
            log_action(user, "Search employees", f"term: {term}")
            display_employees(results)
            pause()
        elif choice == "6":
            if not ensure_permission(user, "claim.modify"):
                continue
            claim_id = prompt_int("Claim ID: ")
            if claim_id is None:
                print("Invalid claim ID.")
                pause()
                continue
            project = prompt_until_valid("New project number: ", validate_project_number, hint=PROJECT_HINT)
            distance = prompt_until_valid("New travel distance: ", validate_travel_distance, hint=TRAVEL_HINT)
            if claim_service.manager_modify_claim(claim_id, {"project_number": project, "travel_distance": distance}):
                log_action(user, "Claim modified", f"claim_id: {claim_id}")
                print("Claim modified.")
            else:
                log_action(user, "Claim modify failed", f"claim_id: {claim_id}", True)
                print("Claim not found.")
            pause()
        elif choice == "7":
            if not ensure_permission(user, "claim.approve"):
                continue
            claim_id = prompt_int("Claim ID: ")
            if claim_id is None:
                print("Invalid claim ID.")
                pause()
                continue
            status = prompt_choice("Approve (A) or Reject (R): ", {"A": "Approved", "R": "Rejected"})
            salary_batch = ""
            if status == "Approved":
                salary_batch = prompt_until_valid("Salary batch (YYYY-MM): ", validate_salary_batch, hint=SALARY_HINT)
            if claim_service.set_approval(claim_id, status, user["username"], salary_batch):
                log_action(user, f"Claim {status}", f"claim_id: {claim_id}")
                print("Claim status updated.")
            else:
                log_action(user, "Claim approval failed", f"claim_id: {claim_id}", True)
                print("Claim not found.")
            pause()
        elif choice == "8":
            if not ensure_permission(user, "claim.search_all"):
                continue
            term = prompt_text("Search term: ")
            claims = [
                c
                for c in claim_service.list_all_claims()
                if term.lower() in " ".join(str(v) for v in c.values()).lower()
            ]
            log_action(user, "Search claims", f"term: {term}")
            display_claims(claims)
            pause()
        elif choice == "9":
            if not ensure_permission(user, "backup.create"):
                continue
            name = backup.create_backup()
            log_action(user, "Backup created", f"backup: {name}")
            print(f"Backup created: {name}")
            pause()
        elif choice == "10":
            if not ensure_permission(user, "backup.restore_with_code"):
                continue
            if not confirm_restore_risk():
                print("Restore cancelled.")
                pause()
                continue
            code = prompt_text("Restore code: ")
            backup_name = restore_code_service.verify_and_use_code(user["id"], code)
            if not backup_name:
                log_action(user, "Restore denied", "invalid code", True)
                print("Invalid or used code.")
            else:
                if backup.restore_backup(backup_name):
                    handle_restore_success(user, backup_name)
                    pause()
                    break
                else:
                    print("Backup not found.")
            pause()
        elif choice == "11":
            if not ensure_permission(user, "log.view"):
                continue
            handle_view_logs(user)
            pause()
        elif choice == "12":
            if not ensure_permission(user, "self.update"):
                continue
            sub = prompt_choice("Update (P)assword or (N)ame: ", {"P": "password", "N": "name"})
            if sub == "password":
                password = prompt_password_until_valid("New password: ", validate_password, hint=PASSWORD_HINT)
                user_service.update_password(user["id"], password)
                log_action(user, "Password updated", "")
                print("Password updated. Please log in again.")
                pause()
                break
            else:
                first_name = prompt_until_valid("First name: ", validate_name, hint=NAME_HINT)
                last_name = prompt_until_valid("Last name: ", validate_name, hint=NAME_HINT)
                employee_service.update_profile(user["id"], first_name, last_name)
                log_action(user, "Profile updated", "")
                print("Profile updated.")
                pause()
        elif choice == "13":
            if not ensure_permission(user, "self.delete"):
                continue
            confirm = prompt_text("Type DELETE to confirm: ")
            if confirm == "DELETE":
                user_service.delete_user(user["id"])
                log_action(user, "Account deleted", "")
                print("Account deleted.")
                pause()
                break
            print("Cancelled.")
            pause()
        elif choice == "0":
            log_action(user, "Logged out", "")
            break
        else:
            print("Invalid choice.")
            pause()


def super_menu(user: Dict[str, str]) -> None:
    while True:
        if not is_session_active(user):
            break
        clear_screen()
        print("\nSuper Admin Menu")
        print("1. Add manager")
        print("2. Update manager")
        print("3. Delete manager")
        print("4. Reset manager password")
        print("5. Generate restore code")
        print("6. Revoke restore code")
        print("7. Restore backup")
        print("8. View logs")
        print("9. Backup system")
        print("10. Manager functions")
        print("0. Logout")
        choice = prompt_text("Choose: ")
        clear_screen()

        if choice == "1":
            if not ensure_permission(user, "user.add_manager"):
                continue
            username = prompt_until_valid("Username: ", validate_username, hint=USERNAME_HINT)
            if user_service.username_exists(username):
                print("Username already exists.")
                pause()
                continue
            password = prompt_password_until_valid("Password: ", validate_password, hint=PASSWORD_HINT)
            first_name = prompt_until_valid("First name: ", validate_name, hint=NAME_HINT)
            last_name = prompt_until_valid("Last name: ", validate_name, hint=NAME_HINT)
            try:
                user_id = user_service.create_user(username, password, ROLE_MANAGER)
            except ValueError as exc:
                print(str(exc))
                pause()
                continue
            registration_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            employee_service.create_profile(user_id, first_name, last_name, registration_date)
            log_action(user, "Manager created", f"username: {username}")
            print("Manager created.")
            pause()
        elif choice == "2":
            if not ensure_permission(user, "user.update_manager"):
                continue
            username = prompt_text("Manager username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_MANAGER:
                print("User is not a manager.")
                pause()
                continue
            first_name = prompt_until_valid("First name: ", validate_name, hint=NAME_HINT)
            last_name = prompt_until_valid("Last name: ", validate_name, hint=NAME_HINT)
            employee_service.update_profile(target["id"], first_name, last_name)
            log_action(user, "Manager updated", f"username: {username}")
            print("Manager updated.")
            pause()
        elif choice == "3":
            if not ensure_permission(user, "user.delete_manager"):
                continue
            username = prompt_text("Manager username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_MANAGER:
                print("User is not a manager.")
                pause()
                continue
            user_service.delete_user(target["id"])
            log_action(user, "Manager deleted", f"username: {username}")
            print("Manager deleted.")
            pause()
        elif choice == "4":
            if not ensure_permission(user, "user.reset_manager_pw"):
                continue
            username = prompt_text("Manager username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_MANAGER:
                print("User is not a manager.")
                pause()
                continue
            temp_pw = generate_temp_password()
            user_service.update_password(target["id"], temp_pw)
            log_action(user, "Manager password reset", f"username: {username}")
            print(f"Temporary password: {temp_pw}")
            pause()
        elif choice == "5":
            if not ensure_permission(user, "backup.generate_restore_code"):
                continue
            username = prompt_text("Manager username: ")
            target = user_service.get_user_by_username(username)
            if not target:
                print("User not found.")
                pause()
                continue
            if target["role"] != ROLE_MANAGER:
                print("User is not a manager.")
                pause()
                continue
            backups = backup.list_backups()
            if not backups:
                print("No backups available.")
                pause()
                continue
            print("Backups: " + ", ".join(backups))
            backup_name = prompt_text("Backup name: ")
            if backup_name not in backups:
                print("Backup not found.")
                pause()
                continue
            code = restore_code_service.generate_restore_code(target["id"], backup_name)
            log_action(user, "Restore code generated", f"manager: {username}, backup: {backup_name}")
            print(f"Restore code: {code}")
            pause()
        elif choice == "6":
            if not ensure_permission(user, "backup.revoke_restore_code"):
                continue
            code = prompt_text("Restore code to revoke: ")
            if restore_code_service.revoke_code(code):
                log_action(user, "Restore code revoked", "")
                print("Code revoked.")
            else:
                print("Code not found.")
            pause()
        elif choice == "7":
            if not ensure_permission(user, "backup.restore_any"):
                continue
            if not confirm_restore_risk():
                print("Restore cancelled.")
                pause()
                continue
            backups = backup.list_backups()
            if not backups:
                print("No backups available.")
                pause()
                continue
            print("Backups: " + ", ".join(backups))
            name = prompt_text("Backup name: ")
            if backup.restore_backup(name):
                handle_restore_success(user, name)
                pause()
                break
            else:
                print("Backup not found.")
            pause()
        elif choice == "8":
            if not ensure_permission(user, "log.view"):
                continue
            handle_view_logs(user)
            pause()
        elif choice == "9":
            if not ensure_permission(user, "backup.create"):
                continue
            name = backup.create_backup()
            log_action(user, "Backup created", f"backup: {name}")
            print(f"Backup created: {name}")
            pause()
        elif choice == "10":
            manager_menu(user)
            if FORCE_LOGOUT_AFTER_RESTORE:
                break
        elif choice == "0":
            log_action(user, "Logged out", "")
            break
        else:
            print("Invalid choice.")
            pause()


def run_app() -> None:
    global FORCE_LOGOUT_AFTER_RESTORE
    ensure_data_dirs()
    try:
        init_db()
    except DatabaseOperationError as exc:
        # Show a generic message — don't expose the actual DB error to the user.
        # The real error is logged for admin review.
        print("Database initialization failed. Please contact an administrator.")
        append_log("system", "DB initialization failed", str(exc), True)
        return

    while True:
        try:
            user = login()
            if user == "EXIT":
                break
            if not user:
                continue
            FORCE_LOGOUT_AFTER_RESTORE = False
            # Check for suspicious activity right after login so admins see it immediately.
            notify_unread_suspicious(user)
            # Route to the correct menu based on role — each menu only shows
            # options relevant to that role, and every option still re-checks
            # permissions through ensure_permission() as a safety net.
            if user["role"] == ROLE_EMPLOYEE:
                employee_menu(user)
            elif user["role"] == ROLE_MANAGER:
                manager_menu(user)
            elif user["role"] == ROLE_SUPER:
                super_menu(user)
            else:
                print("Unknown role.")
                break
        except DatabaseOperationError as exc:
            # Catch-all for unexpected DB errors — log them as suspicious
            # (could indicate tampering or corruption) and show a safe message.
            append_log("system", "Database error", str(exc), True)
            print("A database error occurred. Please try again.")
            pause()


if __name__ == "__main__":
    run_app()
