"""Agent authentication routes."""

from datetime import datetime

from flask import flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from cloud_panel.database import db


def register_agent_auth_routes(app) -> None:
    """Register the backward-compatible agent login and logout endpoints."""

    def agent_login():
        if request.method == "GET":
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        account = con.execute(
            "SELECT * FROM agent_accounts WHERE username=?",
            (username,),
        ).fetchone()
        con.close()

        if (
            account
            and account["enabled"]
            and check_password_hash(account["password_hash"], password)
        ):
            session.clear()
            session["agent_account_id"] = int(account["id"])
            session["agent_username"] = account["username"]
            session["agent_display_name"] = (
                account["display_name"] or account["username"]
            )
            con = db()
            con.execute(
                "UPDATE agent_accounts SET last_login_at=? WHERE id=?",
                (
                    datetime.now().isoformat(timespec="seconds"),
                    int(account["id"]),
                ),
            )
            con.commit()
            con.close()
            return redirect(url_for("agent_dashboard"))

        flash("اسم المستخدم أو كلمة المرور غير صحيحة", "danger")
        return redirect(url_for("login"))

    def agent_logout():
        session.pop("agent_account_id", None)
        session.pop("agent_username", None)
        session.pop("agent_display_name", None)
        return redirect(url_for("login"))

    app.add_url_rule(
        "/agent/login",
        endpoint="agent_login",
        view_func=agent_login,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/agent/logout",
        endpoint="agent_logout",
        view_func=agent_logout,
        methods=["GET"],
    )
