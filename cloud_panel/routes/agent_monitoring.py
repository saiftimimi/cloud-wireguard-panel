"""Agent subscriber overview and dashboard status API."""

from typing import Callable, Mapping

from flask import jsonify, render_template

from cloud_panel.services.settings import get_settings


def register_agent_monitoring_routes(
    app,
    agent_login_required: Callable,
    agent_permission_required: Callable,
    current_agent_account: Callable,
    assigned_peers_for_agent: Callable,
    build_subscriber_router_cards: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_peer_ping: Callable,
    human_bytes: Callable,
    runtime_cache: Mapping,
) -> None:
    """Register read-only monitoring routes scoped by agent permissions."""

    @agent_permission_required("can_view_subscribers")
    def agent_subscribers_page():
        account = current_agent_account()
        peers = assigned_peers_for_agent(account["id"])
        router_cards = build_subscriber_router_cards(
            [peer["id"] for peer in peers]
        )
        online_count = sum(1 for item in router_cards if item["wg_online"])
        return render_template(
            "subscribers.html",
            router_cards=router_cards,
            online_count=online_count,
            offline_count=len(router_cards) - online_count,
            total_subscribers=sum(
                item["subscriber_count"] for item in router_cards
            ),
            settings=get_settings(),
        )

    @agent_login_required
    def agent_dashboard_status_api():
        account = current_agent_account()
        if not account.get("can_view_routers"):
            return jsonify({"routers": []})
        peers = assigned_peers_for_agent(account["id"])
        stats = cached_wireguard_peer_stats()
        payload = []
        for peer in peers:
            wg = stats.get(
                peer["public_key"],
                {"online": False, "handshake_text": "-", "rx": 0, "tx": 0},
            )
            ping = cached_peer_ping(peer["id"])
            payload.append({
                "id": int(peer["id"]),
                "online": (
                    bool(wg.get("online"))
                    if account.get("can_view_router_status") else None
                ),
                "handshake": (
                    wg.get("handshake_text", "-")
                    if account.get("can_view_handshake") else ""
                ),
                "rx": (
                    human_bytes(wg.get("rx", 0))
                    if account.get("can_view_traffic") else ""
                ),
                "tx": (
                    human_bytes(wg.get("tx", 0))
                    if account.get("can_view_traffic") else ""
                ),
                "latency": (
                    ping.get("latency", "-")
                    if account.get("can_view_ping") else ""
                ),
                "loss": (
                    ping.get("loss", "-")
                    if account.get("can_view_ping") else ""
                ),
            })
        return jsonify({
            "routers": payload,
            "updated_at": runtime_cache.get("updated_at", 0),
        })

    app.add_url_rule(
        "/agent/subscribers",
        endpoint="agent_subscribers_page",
        view_func=agent_subscribers_page,
    )
    app.add_url_rule(
        "/agent/api/dashboard/status",
        endpoint="agent_dashboard_status_api",
        view_func=agent_dashboard_status_api,
    )
