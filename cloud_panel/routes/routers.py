"""Router list page routes."""

from typing import Callable

from flask import jsonify, render_template

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_router_routes(
    app,
    login_required: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_peer_ping: Callable,
    cached_router_metrics: Callable,
    all_cached_router_metrics: Callable,
) -> None:
    """Register the router list page with its legacy endpoint name."""

    @login_required
    def routers_page():
        con = db()
        rows = con.execute("SELECT * FROM peers ORDER BY id DESC").fetchall()
        con.close()

        stats = cached_wireguard_peer_stats()
        peers = []
        for row in rows:
            item = dict(row)
            item["wg"] = stats.get(
                item["public_key"],
                {"handshake_text": "-", "rx": 0, "tx": 0, "online": False},
            )
            item["health"] = cached_peer_ping(item["id"])
            item["live"] = cached_router_metrics(item["id"])
            peers.append(item)

        peers.sort(
            key=lambda item: (
                bool(item["wg"]["online"]),
                item["name"].lower(),
            )
        )
        online_count = sum(1 for item in peers if item["wg"]["online"])
        return render_template(
            "routers.html",
            peers=peers,
            online_count=online_count,
            offline_count=len(peers) - online_count,
            settings=get_settings(),
        )

    app.add_url_rule(
        "/routers",
        endpoint="routers_page",
        view_func=routers_page,
        methods=["GET"],
    )

    @login_required
    def router_live_metrics_api():
        return jsonify({
            "ok": True,
            "routers": all_cached_router_metrics(),
        })

    app.add_url_rule(
        "/api/routers/live-metrics",
        endpoint="router_live_metrics_api",
        view_func=router_live_metrics_api,
        methods=["GET"],
    )
