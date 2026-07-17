"""WireGuard overview and server-management routes."""

from html import escape
from typing import Callable

from flask import Response, flash, redirect, render_template, request, url_for

from cloud_panel.config import APP_DIR, DEFAULT_AGENT_INTERFACE, DEFAULT_INTERFACE
from cloud_panel.database import db
from cloud_panel.services.settings import (
    SettingsValidationError,
    get_settings,
    save_settings_values,
)


def register_wireguard_routes(
    app,
    login_required: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_agent_wireguard_stats: Callable,
    cached_peer_ping: Callable,
    wireguard_interface_summary: Callable,
    run: Callable,
    refresh_runtime_caches: Callable,
    import_peers_from_ubuntu: Callable,
    ensure_all_agent_devices: Callable,
    apply_agent_wireguard: Callable,
    apply_wireguard: Callable,
) -> None:
    """Register WireGuard pages while preserving the original endpoints."""

    @login_required
    def wireguard_page():
        con = db()
        rows = con.execute("SELECT * FROM peers ORDER BY id DESC").fetchall()
        agent_rows = con.execute(
            "SELECT public_key,enabled FROM agent_devices ORDER BY id"
        ).fetchall()
        con.close()

        stats = cached_wireguard_peer_stats()
        agent_stats = cached_agent_wireguard_stats()
        peers = []
        for row in rows:
            item = dict(row)
            item["wg"] = stats.get(
                item["public_key"],
                {"handshake_text": "-", "rx": 0, "tx": 0, "online": False},
            )
            item["health"] = cached_peer_ping(item["id"])
            peers.append(item)

        peers.sort(key=lambda item: (bool(item["wg"]["online"]), item["name"].lower()))
        online_count = sum(1 for item in peers if item["wg"]["online"])
        agent_total = sum(1 for row in agent_rows if row["enabled"])
        agent_online = sum(
            1
            for row in agent_rows
            if row["enabled"] and agent_stats.get(row["public_key"], {}).get("online")
        )
        settings = get_settings()
        return render_template(
            "wireguard.html",
            peers=peers,
            online_count=online_count,
            offline_count=len(peers) - online_count,
            agent_total=agent_total,
            agent_online=agent_online,
            rx=sum(item["wg"].get("rx", 0) for item in peers),
            tx=sum(item["wg"].get("tx", 0) for item in peers),
            main_server=wireguard_interface_summary(
                settings.get("interface", DEFAULT_INTERFACE), len(peers)
            ),
            agent_server=wireguard_interface_summary(
                settings.get("agent_interface", DEFAULT_AGENT_INTERFACE), agent_total
            ),
            settings=settings,
        )

    @login_required
    def wireguard_server_action(server_key, action):
        if server_key not in ("routers", "agents") or action not in ("start", "restart"):
            return "Not found", 404
        settings = get_settings()
        interface = (
            settings.get("interface", DEFAULT_INTERFACE)
            if server_key == "routers"
            else settings.get("agent_interface", DEFAULT_AGENT_INTERFACE)
        )
        label = "خادم الراوترات" if server_key == "routers" else "خادم الوكلاء"
        try:
            run(["systemctl", action, "wg-quick@%s" % interface])
            refresh_runtime_caches()
            verb = "تشغيل" if action == "start" else "إعادة تشغيل"
            flash("تم %s %s" % (verb, label), "success")
        except Exception as exc:
            flash("تعذر تنفيذ العملية على %s: %s" % (label, exc), "danger")
        return redirect(url_for("wireguard_page"))

    @login_required
    def wireguard_server_log(server_key):
        if server_key not in ("routers", "agents"):
            return "Not found", 404
        settings = get_settings()
        interface = (
            settings.get("interface", DEFAULT_INTERFACE)
            if server_key == "routers"
            else settings.get("agent_interface", DEFAULT_AGENT_INTERFACE)
        )
        output = run(
            ["journalctl", "-u", "wg-quick@%s" % interface, "-n", "120", "--no-pager"],
            check=False,
        )
        return Response(output or "لا يوجد سجل حالياً", mimetype="text/plain")

    @login_required
    def sync_ubuntu_peers():
        try:
            count = import_peers_from_ubuntu()
            ensure_all_agent_devices()
            apply_agent_wireguard()
            if count:
                flash("تم استيراد %s وكيل جديد وتحديث NAT" % count, "success")
            else:
                flash("تمت مزامنة Ubuntu وتحديث الوكلاء وقواعد NAT", "success")
        except Exception as exc:
            flash("فشلت مزامنة Ubuntu: %s" % exc, "danger")
        return redirect(url_for("wireguard_page"))

    @login_required
    def sync_log():
        path = APP_DIR / "sync-debug.log"
        contents = path.read_text(errors="ignore") if path.exists() else "No sync log yet"
        return "<pre style='direction:ltr;text-align:left;white-space:pre-wrap'>%s</pre>" % escape(contents)

    @login_required
    def save_settings():
        try:
            save_settings_values(request.form)
        except SettingsValidationError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("wireguard_page"))
        except Exception as exc:
            flash("فشل حفظ الإعدادات: %s" % exc, "danger")
            return redirect(url_for("wireguard_page"))
        flash("تم حفظ إعدادات خادمي WireGuard", "success")
        return redirect(url_for("wireguard_page") + "#server-settings")

    @login_required
    def apply():
        try:
            apply_wireguard()
            ensure_all_agent_devices()
            apply_agent_wireguard()
            flash("تمت مزامنة WireGuard للراوترات وأجهزة الوكلاء بنجاح", "success")
        except Exception as exc:
            flash("فشل التطبيق: %s" % exc, "danger")
        return redirect(url_for("wireguard_page"))

    app.add_url_rule("/wireguard", endpoint="wireguard_page", view_func=wireguard_page)
    app.add_url_rule(
        "/wireguard/server/<server_key>/<action>", endpoint="wireguard_server_action",
        view_func=wireguard_server_action, methods=["POST"]
    )
    app.add_url_rule(
        "/wireguard/server/<server_key>/log", endpoint="wireguard_server_log",
        view_func=wireguard_server_log
    )
    app.add_url_rule(
        "/wireguard/sync-ubuntu", endpoint="sync_ubuntu_peers",
        view_func=sync_ubuntu_peers, methods=["POST"]
    )
    app.add_url_rule("/wireguard/sync-log", endpoint="sync_log", view_func=sync_log)
    app.add_url_rule(
        "/settings", endpoint="save_settings", view_func=save_settings, methods=["POST"]
    )
    app.add_url_rule(
        "/wireguard/apply", endpoint="apply", view_func=apply, methods=["POST"]
    )
