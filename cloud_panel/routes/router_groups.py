"""Router group management routes."""

import sqlite3
from datetime import datetime
from typing import Callable

from flask import flash, redirect, render_template, request, url_for

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_router_group_routes(app, login_required: Callable) -> None:
    """Register router-group routes with stable legacy endpoints."""

    @login_required
    def router_groups_page():
        con = db()
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            peer_ids = [
                int(value)
                for value in request.form.getlist("peer_ids")
                if str(value).isdigit()
            ]
            if name:
                stamp = datetime.now().isoformat(timespec="seconds")
                try:
                    con.execute(
                        "INSERT INTO router_groups(name,notes,created_at) "
                        "VALUES(?,?,?)",
                        (name, request.form.get("notes", "").strip(), stamp),
                    )
                    group_id = con.execute(
                        "SELECT last_insert_rowid()"
                    ).fetchone()[0]
                    for peer_id in peer_ids:
                        con.execute(
                            "INSERT OR IGNORE INTO router_group_peers"
                            "(group_id,peer_id) VALUES(?,?)",
                            (group_id, peer_id),
                        )
                    con.commit()
                    flash("تم إنشاء مجموعة الراوترات", "success")
                except sqlite3.IntegrityError:
                    con.rollback()
                    flash("اسم المجموعة مستخدم", "danger")
            con.close()
            return redirect(url_for("router_groups_page"))

        groups = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM router_groups ORDER BY name"
            ).fetchall()
        ]
        peers = [
            dict(row)
            for row in con.execute(
                "SELECT id,name FROM peers ORDER BY name"
            ).fetchall()
        ]
        for group in groups:
            group["peers"] = [
                dict(row)
                for row in con.execute(
                    "SELECT p.id,p.name FROM peers p "
                    "JOIN router_group_peers x ON x.peer_id=p.id "
                    "WHERE x.group_id=? ORDER BY p.name",
                    (group["id"],),
                ).fetchall()
            ]
        con.close()
        return render_template(
            "router_groups.html",
            groups=groups,
            peers=peers,
            settings=get_settings(),
        )

    @login_required
    def router_group_delete(group_id):
        con = db()
        con.execute("DELETE FROM router_groups WHERE id=?", (group_id,))
        con.commit()
        con.close()
        flash("تم حذف المجموعة", "success")
        return redirect(url_for("router_groups_page"))

    app.add_url_rule(
        "/router-groups",
        endpoint="router_groups_page",
        view_func=router_groups_page,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/router-groups/<int:group_id>/delete",
        endpoint="router_group_delete",
        view_func=router_group_delete,
        methods=["POST"],
    )
