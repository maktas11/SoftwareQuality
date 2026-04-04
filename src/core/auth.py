# --- Role-Based Access Control (RBAC) ---
# Authorization is centralized here instead of scattered through the codebase.
# Every action in the app goes through has_permission() or require_permission()
# before executing — this way we have a single source of truth for who can do what.

ROLE_SUPER = "SuperAdmin"
ROLE_MANAGER = "Manager"
ROLE_EMPLOYEE = "Employee"

# Permission matrix: each role maps to a set of allowed actions.
# Using a whitelist approach — if a permission isn't in the set, it's denied.
# This is safer than a blacklist because forgetting to add a restriction
# means the action is blocked by default.
PERMISSIONS = {
    ROLE_SUPER: {
        "user.add_manager",
        "user.update_manager",
        "user.delete_manager",
        "user.reset_manager_pw",
        "user.add_employee",
        "user.update_employee",
        "user.delete_employee",
        "user.reset_employee_pw",
        "claim.approve",
        "claim.modify",
        "claim.search_all",
        "employee.search",
        "backup.create",
        "backup.restore_any",        # super admin can restore any backup directly
        "backup.generate_restore_code",
        "backup.revoke_restore_code",
        "log.view",
        "self.update",
        "self.delete",
    },
    ROLE_MANAGER: {
        "user.add_employee",
        "user.update_employee",
        "user.delete_employee",
        "user.reset_employee_pw",
        "claim.approve",
        "claim.modify",
        "claim.search_all",
        "employee.search",
        "backup.create",
        "backup.restore_with_code",   # managers need a one-time code from super admin
        "log.view",
        "self.update",
        "self.delete",
    },
    ROLE_EMPLOYEE: {
        # employees can only manage their own claims and password
        "claim.add",
        "claim.update_own",
        "claim.delete_own",
        "claim.search_own",
        "self.update_password",
    },
}


def has_permission(role: str, permission: str) -> bool:
    # Lookup in the permission set — returns False for unknown roles too,
    # so even if someone tampers with their role string they get nothing.
    return permission in PERMISSIONS.get(role, set())


def require_permission(role: str, permission: str) -> None:
    # Raises PermissionError so the caller can catch it and log the attempt.
    if not has_permission(role, permission):
        raise PermissionError("Unauthorized action")
