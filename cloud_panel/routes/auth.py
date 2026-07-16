"""Login and logout routes for Cloud WG Panel."""

from typing import Callable

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from cloud_panel.services.auth import (
    authenticate_admin,
    authenticate_agent,
    record_agent_login,
)
from cloud_panel.services.settings import get_settings


def register_auth_routes(
    app,
    current_agent_account: Callable,
    create_notification: Callable,
) -> None:
    """Register login/logout while preserving legacy endpoint names."""

    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if current_agent_account():
            return redirect(
                url_for("agent_dashboard")
            )

        if request.method == "POST":
            username = request.form.get(
                "username",
                "",
            ).strip()

            password = request.form.get(
                "password",
                "",
            )

            user = authenticate_admin(
                username,
                password,
            )

            if user:
                session.clear()

                session["user_id"] = int(
                    user["id"]
                )
                session["username"] = user[
                    "username"
                ]
                session["display_name"] = (
                    user.get("display_name")
                    or user["username"]
                )

                create_notification(
                    "تسجيل دخول الإدارة",
                    "تم تسجيل الدخول بواسطة %s"
                    % user["username"],
                    kind="success",
                    audience="admin",
                )

                return redirect(
                    url_for("dashboard")
                )

            account = authenticate_agent(
                username,
                password,
            )

            if account:
                session.clear()

                session["agent_account_id"] = int(
                    account["id"]
                )
                session["agent_username"] = account[
                    "username"
                ]
                session["agent_display_name"] = (
                    account.get("display_name")
                    or account["username"]
                )

                create_notification(
                    "دخول وكيل",
                    "سجل الوكيل %s الدخول"
                    % (
                        account.get("display_name")
                        or account["username"]
                    ),
                    kind="info",
                    audience="admin",
                )

                create_notification(
                    "تم تسجيل الدخول",
                    "مرحباً بك في بوابة الوكيل",
                    kind="success",
                    audience="agent",
                    agent_account_id=account["id"],
                )

                record_agent_login(
                    account["id"]
                )

                return redirect(
                    url_for("agent_dashboard")
                )

            flash(
                "اسم المستخدم أو كلمة المرور غير صحيحة",
                "danger",
            )

        return render_template(
            "login.html",
            settings=get_settings(),
        )

    def logout():
        session.clear()
        return redirect(url_for("login"))

    app.add_url_rule(
        "/login",
        endpoint="login",
        view_func=login,
        methods=["GET", "POST"],
    )

    app.add_url_rule(
        "/logout",
        endpoint="logout",
        view_func=logout,
        methods=["GET"],
    )
