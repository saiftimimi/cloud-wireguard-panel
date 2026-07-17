"""Administrator-facing agent account routes."""

import sqlite3
import threading
from datetime import datetime
from typing import Callable, Iterable, Mapping

from flask import flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_agent_account_routes(
    app,
    login_required: Callable,
    permission_fields: Iterable[str],
    permission_labels: Mapping[str, str],
    account_form_data: Callable,
    account_form_context: Callable,
    get_agent_account: Callable,
    db_write_lock,
    run_automatic_wireguard_sync: Callable,
) -> None:
    """Register the agent account list with its existing endpoint."""

    fields = tuple(permission_fields)

    @login_required
    def agent_accounts_page():
        con = db()
        rows = con.execute(
            """
            SELECT aa.*,
                   COUNT(DISTINCT ap.peer_id) AS peer_count,
                   GROUP_CONCAT(p.name, '، ') AS peer_names
            FROM agent_accounts aa
            LEFT JOIN agent_account_peers ap ON ap.account_id=aa.id
            LEFT JOIN peers p ON p.id=ap.peer_id
            GROUP BY aa.id
            ORDER BY aa.id DESC
            """
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
            "agent_accounts.html",
            accounts=accounts,
            permission_labels=permission_labels,
            settings=get_settings(),
        )

    @login_required
    def agent_account_add():
        if request.method == "POST":
            try:
                username, display_name, password, enabled, peer_ids, permissions = (
                    account_form_data()
                )
                if len(password) < 8:
                    raise RuntimeError("كلمة المرور يجب أن تكون 8 أحرف على الأقل")
                stamp = datetime.now().isoformat(timespec="seconds")
                columns = ["username", "password_hash", "display_name", "enabled"]
                columns += list(fields)
                columns += ["can_download_vpn", "created_at", "updated_at"]
                values = [
                    username,
                    generate_password_hash(password),
                    display_name,
                    enabled,
                ]
                values += [permissions[field] for field in fields]
                values += [permissions["can_download_vpn"], stamp, stamp]

                with db_write_lock:
                    con = db()
                    try:
                        placeholders = ",".join("?" for _ in columns)
                        cursor = con.execute(
                            "INSERT INTO agent_accounts(%s) VALUES(%s)"
                            % (",".join(columns), placeholders),
                            tuple(values),
                        )
                        account_id = int(cursor.lastrowid)
                        for peer_id in sorted(set(peer_ids)):
                            con.execute(
                                "INSERT OR IGNORE INTO agent_account_peers(account_id,peer_id) VALUES(?,?)",
                                (account_id, peer_id),
                            )
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                    finally:
                        con.close()

                threading.Thread(
                    target=run_automatic_wireguard_sync,
                    name="agent-account-wireguard-sync",
                    daemon=True,
                ).start()
                flash("تم إنشاء حساب الوكيل", "success")
                return redirect(url_for("agent_accounts_page"))
            except sqlite3.IntegrityError:
                flash("اسم المستخدم مستخدم مسبقاً", "danger")
            except Exception as exc:
                flash("تعذر إنشاء الحساب: %s" % exc, "danger")

        return render_template("agent_account_form.html", **account_form_context())

    @login_required
    def agent_account_edit(account_id):
        account = get_agent_account(account_id)
        if not account:
            return "Not found", 404

        if request.method == "POST":
            try:
                username, display_name, password, enabled, peer_ids, permissions = (
                    account_form_data(account=account)
                )
                if password and len(password) < 8:
                    raise RuntimeError("كلمة المرور يجب أن تكون 8 أحرف على الأقل")
                stamp = datetime.now().isoformat(timespec="seconds")
                assignments = ["username=?", "display_name=?", "enabled=?"]
                values = [username, display_name, enabled]
                for field in fields:
                    assignments.append(field + "=?")
                    values.append(permissions[field])
                assignments.extend(["can_download_vpn=?", "updated_at=?"])
                values.extend([permissions["can_download_vpn"], stamp])
                if password:
                    assignments.append("password_hash=?")
                    values.append(generate_password_hash(password))
                values.append(int(account_id))

                with db_write_lock:
                    con = db()
                    try:
                        con.execute(
                            "UPDATE agent_accounts SET %s WHERE id=?"
                            % ",".join(assignments),
                            tuple(values),
                        )
                        con.execute(
                            "DELETE FROM agent_account_peers WHERE account_id=?",
                            (int(account_id),),
                        )
                        for peer_id in sorted(set(peer_ids)):
                            con.execute(
                                "INSERT OR IGNORE INTO agent_account_peers(account_id,peer_id) VALUES(?,?)",
                                (int(account_id), peer_id),
                            )
                        con.commit()
                    except Exception:
                        con.rollback()
                        raise
                    finally:
                        con.close()
                threading.Thread(
                    target=run_automatic_wireguard_sync,
                    name="agent-account-wireguard-sync",
                    daemon=True,
                ).start()
                flash("تم حفظ الصلاحيات وتطبيقها مباشرة", "success")
                return redirect(url_for("agent_accounts_page"))
            except sqlite3.IntegrityError:
                flash("اسم المستخدم مستخدم مسبقاً", "danger")
            except Exception as exc:
                flash("تعذر حفظ الحساب: %s" % exc, "danger")
            account = get_agent_account(account_id)

        con = db()
        selected = [
            int(row["peer_id"])
            for row in con.execute(
                "SELECT peer_id FROM agent_account_peers WHERE account_id=?",
                (int(account_id),),
            ).fetchall()
        ]
        con.close()
        return render_template(
            "agent_account_form.html",
            **account_form_context(account, selected),
        )

    @login_required
    def agent_account_toggle(account_id):
        con = db()
        con.execute(
            "UPDATE agent_accounts SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END, updated_at=? WHERE id=?",
            (datetime.now().isoformat(timespec="seconds"), int(account_id)),
        )
        con.commit()
        con.close()
        flash("تم تغيير حالة حساب الوكيل", "success")
        return redirect(url_for("agent_accounts_page"))

    @login_required
    def agent_account_delete(account_id):
        with db_write_lock:
            con = db()
            try:
                con.execute(
                    "UPDATE port_forwards SET owner_agent_id=0 WHERE owner_agent_id=?",
                    (int(account_id),),
                )
                con.execute("DELETE FROM agent_accounts WHERE id=?", (int(account_id),))
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                con.close()
        flash("تم حذف حساب الوكيل بدون حذف الراوترات أو المشتركين", "success")
        return redirect(url_for("agent_accounts_page"))

    app.add_url_rule(
        "/agent-accounts",
        endpoint="agent_accounts_page",
        view_func=agent_accounts_page,
        methods=["GET"],
    )
    app.add_url_rule(
        "/agent-accounts/add",
        endpoint="agent_account_add",
        view_func=agent_account_add,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/agent-accounts/<int:account_id>/edit",
        endpoint="agent_account_edit",
        view_func=agent_account_edit,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/agent-accounts/<int:account_id>/toggle",
        endpoint="agent_account_toggle",
        view_func=agent_account_toggle,
        methods=["POST"],
    )
    app.add_url_rule(
        "/agent-accounts/<int:account_id>/delete",
        endpoint="agent_account_delete",
        view_func=agent_account_delete,
        methods=["POST"],
    )
