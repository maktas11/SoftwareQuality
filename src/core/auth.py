ROLE_SUPER = "SuperAdmin"
ROLE_MANAGER = "Manager"
ROLE_EMPLOYEE = "Employee"

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
        "backup.restore_any",
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
        "backup.restore_with_code",
        "log.view",
        "self.update",
        "self.delete",
    },
    ROLE_EMPLOYEE: {
        "claim.add",
        "claim.update_own",
        "claim.delete_own",
        "claim.search_own",
        "self.update_password",
    },
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())


def require_permission(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise PermissionError("Unauthorized action")
