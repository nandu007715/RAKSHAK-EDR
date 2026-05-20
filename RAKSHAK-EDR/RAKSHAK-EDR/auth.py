"""
auth.py
Authentication helpers for RAKSHAK-EDR
"""

from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return check_password_hash(hashed, password)
    except Exception:
        return False


def seed_default_users(User, db):
    """
    Create default demo users if DB empty
    """

    defaults = [
        ("admin", "admin123", "admin"),
        ("analyst", "analyst123", "analyst"),
        ("cisco", "cisco123", "cisco"),
        ("viewer", "viewer123", "viewer"),
    ]

    for username, password, role in defaults:
        exists = User.query.filter_by(username=username).first()

        if not exists:
            user = User(
                username=username,
                password=hash_password(password),
                role=role,
                active=True
            )
            db.session.add(user)

    db.session.commit()