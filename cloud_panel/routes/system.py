"""System health, audit, and maintenance routes."""

import subprocess
from typing import Callable

from flask import flash, redirect, render_template, request, url_for

from cloud_panel.config import DEFAULT_AGENT_INTERFACE, DEFAULT_INTERFACE
from cloud_panel.database import db
from cloud_panel.services.settings import (
    get_settings,
    maintenance_enabled,
)


def _service_state(name: str) -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=3,
        )
        return "ok" if proc.stdout.strip() == "active" else "down"
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return "unknown"


def _interface_state(name: str) -> str:
    try:
        proc = subprocess.run(
            ["ip", "link", "show", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return "ok" if proc.returncode == 0 else "down"
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return "unknown"


def register_system_routes(
    app,
    login_required: Callable,
    cached_wireguard_peer_stats: Callable,
    audit_event: Callable,
) -> None:
    """Register system routes with their legacy endpoint names."""

    @login_required
    def health_center_page():
        try:
            con = db()
            con.execute("SELECT 1").fetchone()
            con.close()
            db_state = "ok"
        except Exception:
            db_state = "down"

        checks = [
            {
                "name": "قاعدة البيانات",
                "state": db_state,
                "detail": "SQLite data.db",
            },
            {
                "name": "خدمة اللوحة",
                "state": "ok",
                "detail": "Port 1994",
            },
            {
                "name": "WireGuard الراوترات",
                "state": _interface_state(DEFAULT_INTERFACE),
                "detail": DEFAULT_INTERFACE,
            },
            {
                "name": "WireGuard الوكلاء",
                "state": _interface_state(DEFAULT_AGENT_INTERFACE),
                "detail": DEFAULT_AGENT_INTERFACE,
            },
            {
                "name": "FreeRADIUS",
                "state": _service_state("freeradius"),
                "detail": "UDP 1812/1813",
            },
            {
                "name": "Nginx",
                "state": _service_state("nginx"),
                "detail": "WebFig gateway",
            },
        ]

        con = db()
        total = con.execute("SELECT COUNT(*) FROM peers").fetchone()[0]
        con.close()
        stats = cached_wireguard_peer_stats()
        online = sum(1 for value in stats.values() if value.get("online"))

        return render_template(
            "health_center.html",
            checks=checks,
            total_routers=total,
            online_routers=online,
            settings=get_settings(),
        )

    @login_required
    def audit_log_page():
        con = db()
        rows = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT 500"
            ).fetchall()
        ]
        con.close()
        return render_template(
            "audit_log.html",
            rows=rows,
            settings=get_settings(),
        )

    @login_required
    def maintenance_page():
        if request.method == "POST":
            enabled = "1" if request.form.get("enabled") == "1" else "0"
            con = db()
            con.execute(
                "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                ("maintenance_mode", enabled),
            )
            con.commit()
            con.close()
            audit_event(
                "maintenance_mode",
                "system",
                "enabled=" + enabled,
            )
            flash("تم تحديث وضع الصيانة", "success")
            return redirect(url_for("maintenance_page"))

        return render_template(
            "maintenance_settings.html",
            enabled=maintenance_enabled(),
            settings=get_settings(),
        )

    app.add_url_rule(
        "/system/health",
        endpoint="health_center_page",
        view_func=health_center_page,
        methods=["GET"],
    )
    app.add_url_rule(
        "/system/audit",
        endpoint="audit_log_page",
        view_func=audit_log_page,
        methods=["GET"],
    )
    app.add_url_rule(
        "/system/maintenance",
        endpoint="maintenance_page",
        view_func=maintenance_page,
        methods=["GET", "POST"],
    )
