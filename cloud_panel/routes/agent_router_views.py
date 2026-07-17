"""Agent router detail, subscriber list, and status API routes."""

from typing import Callable

from flask import jsonify, render_template

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_agent_router_view_routes(
    app,
    agent_permission_required: Callable,
    current_agent_account: Callable,
    get_agent_assigned_peer: Callable,
    cached_agent_wireguard_stats: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_peer_ping: Callable,
    agent_server_ip: Callable,
    human_bytes: Callable,
    fetch_router_subscribers: Callable,
) -> None:
    """Register read-only routes for an agent's assigned router."""

    @agent_permission_required("can_view_routers")
    def agent_router_page(peer_id):
        account = current_agent_account()
        peer = get_agent_assigned_peer(account["id"], peer_id)
        if not peer:
            return "Not found", 404

        devices = []
        if account.get("can_view_vpn_access"):
            con = db()
            device_rows = con.execute(
                """
                SELECT * FROM agent_devices
                WHERE peer_id=?
                ORDER BY CASE device_type WHEN 'mobile' THEN 1 WHEN 'windows' THEN 2 ELSE 3 END
                """,
                (int(peer_id),),
            ).fetchall()
            con.close()
            agent_stats = cached_agent_wireguard_stats()
            for row in device_rows:
                item = dict(row)
                item["wg"] = agent_stats.get(
                    item["public_key"],
                    {"online": False, "handshake_text": "-"},
                )
                devices.append(item)

        subscriber_total = 0
        if account.get("can_view_subscribers"):
            con = db()
            subscriber_total = int(con.execute(
                "SELECT COUNT(*) FROM port_forwards WHERE peer_id=?",
                (int(peer_id),),
            ).fetchone()[0])
            con.close()

        peer_stats = cached_wireguard_peer_stats().get(
            peer["public_key"],
            {"online": False, "handshake_text": "-", "rx": 0, "tx": 0},
        )
        settings = get_settings()
        return render_template(
            "agent_router_portal.html",
            peer=peer,
            peer_stats=peer_stats,
            peer_ping=cached_peer_ping(peer_id),
            devices=devices,
            subscriber_total=subscriber_total,
            settings=settings,
            agent_server_ip=agent_server_ip(settings),
        )

    @agent_permission_required("can_view_subscribers")
    def agent_router_subscribers_page(peer_id):
        account = current_agent_account()
        peer_row = get_agent_assigned_peer(account["id"], peer_id)
        if not peer_row:
            return "Not found", 404
        peer = dict(peer_row)
        peer["wg"] = cached_wireguard_peer_stats().get(
            peer.get("public_key", ""),
            {"handshake_text": "-", "rx": 0, "tx": 0, "online": False},
        )
        peer["health"] = cached_peer_ping(peer["id"])
        con = db()
        forwards = [
            dict(row) for row in con.execute(
                """
                SELECT pf.*, p.name AS peer_name, p.tunnel_ip
                FROM port_forwards pf
                JOIN peers p ON p.id=pf.peer_id
                WHERE pf.peer_id=?
                ORDER BY pf.name,pf.external_port,pf.id
                """,
                (int(peer_id),),
            ).fetchall()
        ]
        con.close()
        active_count = sum(
            1 for item in forwards
            if item.get("enabled") and not item.get("last_error")
        )
        return render_template(
            "router_subscribers.html",
            peer=peer,
            forwards=forwards,
            active_count=active_count,
            inactive_count=len(forwards) - active_count,
            error_count=sum(1 for item in forwards if item.get("last_error")),
            manual_count=sum(1 for item in forwards if not item.get("auto_managed")),
            settings=get_settings(),
            agent_mode=True,
        )

    @agent_permission_required("can_view_routers")
    def agent_router_status_api(peer_id):
        account = current_agent_account()
        peer = get_agent_assigned_peer(account["id"], peer_id)
        if not peer:
            return jsonify({"error": "not found"}), 404
        wg = cached_wireguard_peer_stats().get(
            peer["public_key"],
            {"online": False, "handshake_text": "-", "rx": 0, "tx": 0},
        )
        ping = cached_peer_ping(peer_id)
        return jsonify({
            "online": bool(wg.get("online")) if account.get("can_view_router_status") else None,
            "handshake": wg.get("handshake_text", "-") if account.get("can_view_handshake") else "",
            "rx": human_bytes(wg.get("rx", 0)) if account.get("can_view_traffic") else "",
            "tx": human_bytes(wg.get("tx", 0)) if account.get("can_view_traffic") else "",
            "latency": ping.get("latency", "-") if account.get("can_view_ping") else "",
            "loss": ping.get("loss", "-") if account.get("can_view_ping") else "",
        })

    @agent_permission_required("can_view_subscribers")
    def agent_peer_subscribers_api(peer_id):
        account = current_agent_account()
        peer = get_agent_assigned_peer(account["id"], peer_id)
        if not peer:
            return jsonify({"ok": False, "error": "not found", "subscribers": []}), 404
        try:
            subscribers = fetch_router_subscribers(peer_id)
            return jsonify({
                "ok": True,
                "peer": {"id": peer["id"], "name": peer["name"], "tunnel_ip": peer["tunnel_ip"]},
                "count": len(subscribers),
                "subscribers": subscribers,
            })
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc), "subscribers": []}), 500

    app.add_url_rule("/agent/router/<int:peer_id>", endpoint="agent_router_page", view_func=agent_router_page)
    app.add_url_rule("/agent/router/<int:peer_id>/subscribers", endpoint="agent_router_subscribers_page", view_func=agent_router_subscribers_page)
    app.add_url_rule("/agent/api/router/<int:peer_id>/status", endpoint="agent_router_status_api", view_func=agent_router_status_api)
    app.add_url_rule("/agent/api/peers/<int:peer_id>/subscribers", endpoint="agent_peer_subscribers_api", view_func=agent_peer_subscribers_api)
