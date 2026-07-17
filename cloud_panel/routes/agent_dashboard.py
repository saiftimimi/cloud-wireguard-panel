"""Agent dashboard and assigned-router list routes."""

from typing import Callable

from flask import render_template

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


def register_agent_dashboard_routes(
    app,
    agent_login_required: Callable,
    agent_permission_required: Callable,
    current_agent_account: Callable,
    assigned_peers_for_agent: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_peer_ping: Callable,
) -> None:
    """Register scoped agent dashboard pages."""

    def visible_router_rows(account):
        if not account or not account.get("can_view_routers"):
            return []
        peers = assigned_peers_for_agent(account["id"])
        stats = cached_wireguard_peer_stats()
        counts = {}
        if account.get("can_view_subscribers") and peers:
            peer_ids = [int(peer["id"]) for peer in peers]
            placeholders = ",".join("?" for _ in peer_ids)
            con = db()
            counts = {
                int(row["peer_id"]): int(row["subscriber_count"])
                for row in con.execute(
                    """
                    SELECT peer_id,COUNT(*) AS subscriber_count
                    FROM port_forwards
                    WHERE enabled=1 AND peer_id IN (%s)
                    GROUP BY peer_id
                    """ % placeholders,
                    tuple(peer_ids),
                ).fetchall()
            }
            con.close()

        rows = []
        for peer in peers:
            item = dict(peer)
            item["wg"] = stats.get(
                item["public_key"],
                {"online": False, "handshake_text": "-", "rx": 0, "tx": 0},
            )
            item["health"] = cached_peer_ping(item["id"])
            item["ping"] = item["health"]
            item["subscriber_count"] = counts.get(int(item["id"]), 0)
            rows.append(item)
        rows.sort(key=lambda item: (bool(item["wg"]["online"]), item["name"].lower()))
        return rows

    @agent_login_required
    def agent_dashboard():
        rows = visible_router_rows(current_agent_account())
        online_rows = [item for item in rows if item["wg"].get("online")]
        offline_rows = [item for item in rows if not item["wg"].get("online")]
        rows = offline_rows + online_rows
        return render_template(
            "dashboard.html",
            peers=rows,
            online_peers=online_rows,
            offline_peers=offline_rows,
            total=len(rows),
            online=len(online_rows),
            offline=len(offline_rows),
            rx=sum(int(item["wg"].get("rx", 0) or 0) for item in rows),
            tx=sum(int(item["wg"].get("tx", 0) or 0) for item in rows),
            settings=get_settings(),
        )

    @agent_permission_required("can_view_routers")
    def agent_routers_page():
        rows = visible_router_rows(current_agent_account())
        online_count = sum(1 for item in rows if item["wg"].get("online"))
        return render_template(
            "routers.html",
            peers=rows,
            online_count=online_count,
            offline_count=len(rows) - online_count,
            settings=get_settings(),
        )

    app.add_url_rule("/agent", endpoint="agent_dashboard", view_func=agent_dashboard)
    app.add_url_rule(
        "/agent/routers",
        endpoint="agent_routers_page",
        view_func=agent_routers_page,
    )
