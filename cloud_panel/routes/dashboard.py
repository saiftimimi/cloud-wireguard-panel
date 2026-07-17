"""Dashboard route registration for Cloud WG Panel."""

from typing import Callable

from flask import render_template

from cloud_panel.services.dashboard import (
    build_dashboard_data,
)


def register_dashboard_routes(
    app,
    login_required: Callable,
    cached_wireguard_peer_stats: Callable,
    cached_peer_ping: Callable,
) -> None:
    """Register the dashboard while preserving its legacy endpoint."""

    @login_required
    def dashboard():
        dashboard_data = build_dashboard_data(
            cached_wireguard_stats=(
                cached_wireguard_peer_stats
            ),
            cached_peer_ping=cached_peer_ping,
        )

        return render_template(
            "dashboard.html",
            **dashboard_data
        )

    app.add_url_rule(
        "/",
        endpoint="dashboard",
        view_func=dashboard,
        methods=["GET"],
    )
