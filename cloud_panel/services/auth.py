"""Authentication services for administrator and agent accounts."""

from datetime import datetime
from typing import Dict, Optional

from werkzeug.security import check_password_hash

from cloud_panel.database import db


def _row_to_dict(row) -> Optional[Dict]:
    """Convert a SQLite row to a normal dictionary."""
    return dict(row) if row else None


def get_admin_by_username(username: str) -> Optional[Dict]:
    """Load an administrator account by username."""
    username = str(username or "").strip()

    if not username:
        return None

    con = db()

    try:
        row = con.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            LIMIT 1
            """,
            (username,),
        ).fetchone()
    finally:
        con.close()

    return _row_to_dict(row)


def authenticate_admin(
    username: str,
    password: str,
) -> Optional[Dict]:
    """Validate administrator credentials."""
    user = get_admin_by_username(username)

    if not user:
        return None

    password_hash = str(
        user.get("password_hash") or ""
    )

    if not password_hash:
        return None

    try:
        valid = check_password_hash(
            password_hash,
            str(password or ""),
        )
    except (TypeError, ValueError):
        valid = False

    return user if valid else None


def get_agent_by_username(username: str) -> Optional[Dict]:
    """Load an agent account by username."""
    username = str(username or "").strip()

    if not username:
        return None

    con = db()

    try:
        row = con.execute(
            """
            SELECT *
            FROM agent_accounts
            WHERE username=?
            LIMIT 1
            """,
            (username,),
        ).fetchone()
    finally:
        con.close()

    return _row_to_dict(row)


def authenticate_agent(
    username: str,
    password: str,
) -> Optional[Dict]:
    """Validate an enabled agent account."""
    account = get_agent_by_username(username)

    if not account:
        return None

    if not account.get("enabled"):
        return None

    password_hash = str(
        account.get("password_hash") or ""
    )

    if not password_hash:
        return None

    try:
        valid = check_password_hash(
            password_hash,
            str(password or ""),
        )
    except (TypeError, ValueError):
        valid = False

    return account if valid else None


def record_agent_login(
    account_id: int,
    login_time: Optional[datetime] = None,
) -> str:
    """Update and return the agent's last-login timestamp."""
    timestamp = (
        login_time or datetime.now()
    ).isoformat(timespec="seconds")

    con = db()

    try:
        cursor = con.execute(
            """
            UPDATE agent_accounts
            SET last_login_at=?
            WHERE id=?
            """,
            (
                timestamp,
                int(account_id),
            ),
        )

        if cursor.rowcount == 0:
            raise LookupError(
                "حساب الوكيل غير موجود"
            )

        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

    return timestamp
