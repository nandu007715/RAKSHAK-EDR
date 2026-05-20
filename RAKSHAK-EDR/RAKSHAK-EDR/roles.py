"""
roles.py
Role-Based Access Control for RAKSHAK-EDR
"""

ROLES = {
    "admin": {
        "label": "SOC ADMIN",
        "permissions": [
            "inject_threat",
            "clear_logs",
            "export_csv",
            "manage_users",
            "change_status",
            "monitor_network",
            "view_dashboard"
        ]
    },

    "analyst": {
        "label": "ANALYST",
        "permissions": [
            "change_status",
            "export_csv",
            "view_dashboard"
        ]
    },

    "cisco": {
        "label": "CISCO ENGINEER",
        "permissions": [
            "monitor_network",
            "export_csv",
            "view_dashboard"
        ]
    },

    "viewer": {
        "label": "VIEWER",
        "permissions": [
            "view_dashboard"
        ]
    }
}


def has_permission(role, permission):
    role = (role or "").lower()

    if role not in ROLES:
        return False

    return permission in ROLES[role]["permissions"]


def get_role_label(role):
    role = (role or "").lower()

    if role in ROLES:
        return ROLES[role]["label"]

    return "UNKNOWN"