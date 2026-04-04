from typing import Dict, List, Optional

from core.crypto import decrypt_text, encrypt_text
from core.db import execute, execute_insert, fetch_all, fetch_one

# Approval statuses — using constants instead of string literals throughout
# the code to avoid typos that could bypass status checks.
APPROVAL_PENDING = "Pending"
APPROVAL_APPROVED = "Approved"
APPROVAL_REJECTED = "Rejected"


def create_claim(employee_user_id: int, data: Dict[str, str]) -> int:
    # All claim data is encrypted before insertion — dates, amounts, zip codes, etc.
    # New claims always start as "Pending" — employees can't set their own approval.
    claim_id = execute_insert(
        """
        INSERT INTO claims (
            employee_user_id, claim_date_enc, project_number_enc, claim_type_enc,
            travel_distance_enc, from_zip_enc, from_house_enc, to_zip_enc, to_house_enc,
            approval_status_enc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            employee_user_id,
            encrypt_text(data.get("claim_date", "")),
            encrypt_text(data.get("project_number", "")),
            encrypt_text(data.get("claim_type", "")),
            encrypt_text(data.get("travel_distance", "")),
            encrypt_text(data.get("from_zip", "")),
            encrypt_text(data.get("from_house", "")),
            encrypt_text(data.get("to_zip", "")),
            encrypt_text(data.get("to_house", "")),
            encrypt_text(APPROVAL_PENDING),
        ),
    )
    return claim_id


def _decrypt_claim_row(row) -> Dict[str, str]:
    result = {
        "id": row[0],
        "employee_user_id": row[1],
        "claim_date": decrypt_text(row[2]),
        "project_number": decrypt_text(row[3]),
        "claim_type": decrypt_text(row[4]),
        "travel_distance": decrypt_text(row[5]),
        "from_zip": decrypt_text(row[6]),
        "from_house": decrypt_text(row[7]),
        "to_zip": decrypt_text(row[8]),
        "to_house": decrypt_text(row[9]),
        "approval_status": decrypt_text(row[10]),
        "approved_by": decrypt_text(row[11]),
        "salary_batch": decrypt_text(row[12]),
    }
    return result


def get_claim_by_id(claim_id: int) -> Optional[Dict[str, str]]:
    row = fetch_one(
        """
        SELECT id, employee_user_id, claim_date_enc, project_number_enc, claim_type_enc,
               travel_distance_enc, from_zip_enc, from_house_enc, to_zip_enc, to_house_enc,
               approval_status_enc, approved_by_enc, salary_batch_enc
        FROM claims WHERE id = ?
        """,
        (claim_id,),
    )
    result = None
    if row:
        result = _decrypt_claim_row(row)
    return result


def list_claims_by_employee(employee_user_id: int) -> List[Dict[str, str]]:
    rows = fetch_all(
        """
        SELECT id, employee_user_id, claim_date_enc, project_number_enc, claim_type_enc,
               travel_distance_enc, from_zip_enc, from_house_enc, to_zip_enc, to_house_enc,
               approval_status_enc, approved_by_enc, salary_batch_enc
        FROM claims WHERE employee_user_id = ?
        """,
        (employee_user_id,),
    )
    results = [_decrypt_claim_row(row) for row in rows]
    return results


def list_all_claims() -> List[Dict[str, str]]:
    rows = fetch_all(
        """
        SELECT id, employee_user_id, claim_date_enc, project_number_enc, claim_type_enc,
               travel_distance_enc, from_zip_enc, from_house_enc, to_zip_enc, to_house_enc,
               approval_status_enc, approved_by_enc, salary_batch_enc
        FROM claims
        """,
    )
    results = [_decrypt_claim_row(row) for row in rows]
    return results


def update_claim_employee(claim_id: int, employee_user_id: int, data: Dict[str, str]) -> bool:
    # Authorization check: employee can only update their OWN claims.
    # We verify employee_user_id matches the claim's owner at the service level.
    # Also blocked if the claim already has a salary_batch (processed/paid out)
    # or if the approval status is not "Pending" — once a manager has approved
    # or rejected a claim, the employee shouldn't be able to silently change it.
    claim = get_claim_by_id(claim_id)
    success = False
    if (
        claim
        and claim["employee_user_id"] == employee_user_id
        and not claim.get("salary_batch")
        and claim.get("approval_status") == APPROVAL_PENDING
    ):
        new_type = data.get("claim_type", claim.get("claim_type", ""))
        clear_travel = new_type == "Home Office"
        execute(
            """
            UPDATE claims SET claim_date_enc = ?, project_number_enc = ?, claim_type_enc = ?,
                travel_distance_enc = ?, from_zip_enc = ?, from_house_enc = ?, to_zip_enc = ?, to_house_enc = ?
            WHERE id = ?
            """,
            (
                encrypt_text(data.get("claim_date", claim.get("claim_date", ""))),
                encrypt_text(data.get("project_number", claim.get("project_number", ""))),
                encrypt_text(new_type),
                encrypt_text("" if clear_travel else data.get("travel_distance", claim.get("travel_distance", ""))),
                encrypt_text("" if clear_travel else data.get("from_zip", claim.get("from_zip", ""))),
                encrypt_text("" if clear_travel else data.get("from_house", claim.get("from_house", ""))),
                encrypt_text("" if clear_travel else data.get("to_zip", claim.get("to_zip", ""))),
                encrypt_text("" if clear_travel else data.get("to_house", claim.get("to_house", ""))),
                claim_id,
            ),
        )
        success = True
    return success


def delete_claim_employee(claim_id: int, employee_user_id: int) -> bool:
    # Same checks as update — ownership, no salary_batch, and must still be "Pending".
    # Can't delete a claim that a manager already reviewed.
    claim = get_claim_by_id(claim_id)
    success = False
    if (
        claim
        and claim["employee_user_id"] == employee_user_id
        and not claim.get("salary_batch")
        and claim.get("approval_status") == APPROVAL_PENDING
    ):
        execute("DELETE FROM claims WHERE id = ?", (claim_id,))
        success = True
    return success


def manager_modify_claim(claim_id: int, data: Dict[str, str]) -> bool:
    # Managers can only change project_number and travel_distance (as per spec).
    # They can't touch claim_date, claim_type, or other employee-entered fields.
    claim = get_claim_by_id(claim_id)
    success = False
    if claim:
        execute(
            """
            UPDATE claims SET project_number_enc = ?, travel_distance_enc = ? WHERE id = ?
            """,
            (
                encrypt_text(data.get("project_number", claim.get("project_number", ""))),
                encrypt_text(data.get("travel_distance", claim.get("travel_distance", ""))),
                claim_id,
            ),
        )
        success = True
    return success


def set_approval(claim_id: int, status: str, approved_by: str, salary_batch: str) -> bool:
    # Records who approved/rejected the claim (approved_by is set automatically
    # from the logged-in manager's username — the user can't spoof this).
    claim = get_claim_by_id(claim_id)
    success = False
    if claim:
        execute(
            """
            UPDATE claims SET approval_status_enc = ?, approved_by_enc = ?, salary_batch_enc = ?
            WHERE id = ?
            """,
            (
                encrypt_text(status),
                encrypt_text(approved_by),
                encrypt_text(salary_batch),
                claim_id,
            ),
        )
        success = True
    return success
