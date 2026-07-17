"""Agent-managed subagent accounts and permission pages."""

import sqlite3
from datetime import datetime
from typing import Callable, Iterable

from flask import abort, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_agent_subagent_routes(
    app,
    agent_login_required: Callable,
    current_agent_account: Callable,
    assigned_peers_for_agent: Callable,
    permission_fields: Iterable[str],
    permission_groups,
) -> None:
    """Register subagent CRUD routes scoped to their parent account."""

    fields = tuple(permission_fields)

    def cap_child_permissions(parent, data):
        result = {
            field: 1 if parent.get(field) and data.get(field) else 0
            for field in fields
        }
        if parent.get("read_only"):
            result["read_only"] = 1
        return result

    @agent_login_required
    def agent_profile_page():
        account = current_agent_account()
        con = db()
        rows = con.execute(
            """
            SELECT aa.*, COUNT(DISTINCT ap.peer_id) AS peer_count,
                   GROUP_CONCAT(DISTINCT p.name) AS peer_names
            FROM agent_accounts aa
            LEFT JOIN agent_account_peers ap ON ap.account_id=aa.id
            LEFT JOIN peers p ON p.id=ap.peer_id
            WHERE aa.parent_agent_id=?
            GROUP BY aa.id ORDER BY aa.id DESC
            """,
            (int(account["id"]),),
        ).fetchall()
        con.close()
        accounts = []
        for row in rows:
            item = dict(row)
            item["permission_count"] = sum(
                1 for field in fields if field != "read_only" and item.get(field)
            )
            accounts.append(item)
        return render_template(
            "agent_subagents.html", accounts=accounts, settings=get_settings()
        )

    @agent_login_required
    def agent_subagent_add():
        parent = current_agent_account()
        allowed_peers = assigned_peers_for_agent(parent["id"])
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            display_name = request.form.get("display_name", "").strip()
            password = request.form.get("password", "")
            selected = {
                int(value)
                for value in request.form.getlist("peer_ids")
                if str(value).isdigit()
            }
            allowed = {int(peer["id"]) for peer in allowed_peers}
            selected &= allowed
            permissions = cap_child_permissions(
                parent, {field: bool(request.form.get(field)) for field in fields}
            )
            if not username or not password:
                flash("اسم المستخدم وكلمة المرور مطلوبان", "danger")
            else:
                con = db()
                stamp = datetime.now().isoformat(timespec="seconds")
                try:
                    columns = [
                        "username", "password_hash", "display_name", "enabled",
                        "parent_agent_id", "created_by_agent_id",
                    ] + list(fields) + ["created_at", "updated_at"]
                    values = [
                        username, generate_password_hash(password),
                        display_name or username, 1, int(parent["id"]), int(parent["id"]),
                    ] + [permissions[field] for field in fields] + [stamp, stamp]
                    con.execute(
                        "INSERT INTO agent_accounts(%s) VALUES(%s)"
                        % (",".join(columns), ",".join("?" for _ in columns)),
                        tuple(values),
                    )
                    account_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
                    for peer_id in selected:
                        con.execute(
                            "INSERT OR IGNORE INTO agent_account_peers(account_id,peer_id) VALUES(?,?)",
                            (account_id, peer_id),
                        )
                    con.commit()
                    flash("تم إنشاء الوكيل الفرعي", "success")
                    return redirect(url_for("agent_profile_page"))
                except sqlite3.IntegrityError:
                    con.rollback()
                    flash("اسم المستخدم مستخدم مسبقاً", "danger")
                finally:
                    con.close()
        return render_template(
            "agent_subagent_form.html", item=None, peers=allowed_peers, selected=[],
            parent=parent, permission_groups=permission_groups, settings=get_settings(),
        )

    @agent_login_required
    def agent_subagent_edit(account_id):
        parent = current_agent_account()
        con = db()
        row = con.execute(
            "SELECT * FROM agent_accounts WHERE id=? AND parent_agent_id=?",
            (account_id, int(parent["id"])),
        ).fetchone()
        con.close()
        if not row:
            abort(404)
        item = dict(row)
        allowed_peers = assigned_peers_for_agent(parent["id"])
        allowed = {int(peer["id"]) for peer in allowed_peers}
        if request.method == "POST":
            display_name = request.form.get("display_name", "").strip()
            password = request.form.get("password", "")
            enabled = 1 if request.form.get("enabled") else 0
            selected = {
                int(value) for value in request.form.getlist("peer_ids")
                if str(value).isdigit()
            } & allowed
            permissions = cap_child_permissions(
                parent, {field: bool(request.form.get(field)) for field in fields}
            )
            assignments = ["display_name=?", "enabled=?", "updated_at=?"]
            assignments += ["%s=?" % field for field in fields]
            values = [
                display_name or item["username"], enabled,
                datetime.now().isoformat(timespec="seconds"),
            ] + [permissions[field] for field in fields]
            if password:
                assignments.append("password_hash=?")
                values.append(generate_password_hash(password))
            values.append(account_id)
            con = db()
            con.execute(
                "UPDATE agent_accounts SET %s WHERE id=?" % ",".join(assignments),
                tuple(values),
            )
            con.execute("DELETE FROM agent_account_peers WHERE account_id=?", (account_id,))
            for peer_id in selected:
                con.execute(
                    "INSERT OR IGNORE INTO agent_account_peers(account_id,peer_id) VALUES(?,?)",
                    (account_id, peer_id),
                )
            con.commit()
            con.close()
            flash("تم حفظ الوكيل الفرعي", "success")
            return redirect(url_for("agent_profile_page"))
        con = db()
        selected = [
            row[0] for row in con.execute(
                "SELECT peer_id FROM agent_account_peers WHERE account_id=?", (account_id,)
            ).fetchall()
        ]
        con.close()
        return render_template(
            "agent_subagent_form.html", item=item, peers=allowed_peers, selected=selected,
            parent=parent, permission_groups=permission_groups, settings=get_settings(),
        )

    @agent_login_required
    def agent_subagent_delete(account_id):
        parent = current_agent_account()
        con = db()
        con.execute(
            "DELETE FROM agent_accounts WHERE id=? AND parent_agent_id=?",
            (account_id, int(parent["id"])),
        )
        con.commit()
        con.close()
        flash("تم حذف الوكيل الفرعي", "success")
        return redirect(url_for("agent_profile_page"))

    @agent_login_required
    def agent_permissions_overview():
        return redirect(url_for("agent_profile_page"))

    @agent_login_required
    def agent_permissions_detail():
        return redirect(url_for("agent_profile_page"))

    app.add_url_rule("/agent/account", endpoint="agent_profile_page", view_func=agent_profile_page)
    app.add_url_rule("/agent/account/add", endpoint="agent_subagent_add", view_func=agent_subagent_add, methods=["GET", "POST"])
    app.add_url_rule("/agent/account/<int:account_id>/edit", endpoint="agent_subagent_edit", view_func=agent_subagent_edit, methods=["GET", "POST"])
    app.add_url_rule("/agent/account/<int:account_id>/delete", endpoint="agent_subagent_delete", view_func=agent_subagent_delete, methods=["POST"])
    app.add_url_rule("/agent/permissions", endpoint="agent_permissions_overview", view_func=agent_permissions_overview)
    app.add_url_rule("/agent/permissions/details", endpoint="agent_permissions_detail", view_func=agent_permissions_detail)
