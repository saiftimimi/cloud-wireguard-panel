"""Dashboard data aggregation for Cloud WG Panel."""

import subprocess
from typing import Callable, Dict, List

from cloud_panel.database import db
from cloud_panel.services.settings import get_settings


DEFAULT_WIREGUARD_STATS = {
    "handshake_text": "-",
    "rx": 0,
    "tx": 0,
    "online": False,
}


def _service_is_active(
    service_name: str,
    timeout: int = 2,
) -> bool:
    """Return whether a systemd service is active."""
    try:
        result = subprocess.run(
            [
                "systemctl",
                "is-active",
                str(service_name),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            timeout=timeout,
        )

        return result.stdout.strip() == "active"
    except Exception:
        return False


def _database_is_available() -> bool:
    """Perform a lightweight SQLite health check."""
    con = None

    try:
        con = db()
        row = con.execute(
            "SELECT 1"
        ).fetchone()

        return bool(row)
    except Exception:
        return False
    finally:
        if con is not None:
            con.close()


def _wireguard_interface_is_available(
    interface_name: str,
) -> bool:
    """Return whether the management WireGuard interface exists."""
    interface_name = str(
        interface_name or ""
    ).strip()

    if not interface_name:
        return False

    try:
        result = subprocess.run(
            [
                "ip",
                "link",
                "show",
                interface_name,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )

        return result.returncode == 0
    except Exception:
        return False


def _load_dashboard_summary():
    """Load dashboard counters and recent audit operations."""
    con = db()

    try:
        subscriber_total = int(
            con.execute(
                """
                SELECT COUNT(*)
                FROM port_forwards
                WHERE enabled=1
                """
            ).fetchone()[0]
            or 0
        )

        agent_total = int(
            con.execute(
                """
                SELECT COUNT(*)
                FROM agent_accounts
                WHERE enabled=1
                """
            ).fetchone()[0]
            or 0
        )

        recent_operations = [
            dict(row)
            for row in con.execute(
                """
                SELECT
                    action,
                    target,
                    principal_name,
                    created_at
                FROM audit_log
                ORDER BY id DESC
                LIMIT 6
                """
            ).fetchall()
        ]
    finally:
        con.close()

    return {
        "subscriber_total": subscriber_total,
        "agent_total": agent_total,
        "recent_operations": recent_operations,
    }


def _load_peers() -> List[Dict]:
    """Load all managed routers ordered newest first."""
    con = db()

    try:
        rows = con.execute(
            """
            SELECT *
            FROM peers
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        con.close()

    return [
        dict(row)
        for row in rows
    ]


def build_dashboard_data(
    cached_wireguard_stats: Callable[[], Dict],
    cached_peer_ping: Callable[[int], Dict],
) -> Dict:
    """Build all template data required by dashboard.html."""
    settings = get_settings()
    wireguard_stats = (
        cached_wireguard_stats() or {}
    )

    peers = []

    for item in _load_peers():
        public_key = item.get("public_key")

        item["wg"] = dict(
            wireguard_stats.get(
                public_key,
                DEFAULT_WIREGUARD_STATS,
            )
        )

        item["health"] = cached_peer_ping(
            item["id"]
        )

        peers.append(item)

    online_peers = [
        peer
        for peer in peers
        if peer["wg"].get("online")
    ]

    offline_peers = [
        peer
        for peer in peers
        if not peer["wg"].get("online")
    ]

    # Problems remain visible at the beginning of the dashboard.
    ordered_peers = (
        offline_peers
        + online_peers
    )

    rx = sum(
        int(peer["wg"].get("rx", 0) or 0)
        for peer in ordered_peers
    )

    tx = sum(
        int(peer["wg"].get("tx", 0) or 0)
        for peer in ordered_peers
    )

    summary = _load_dashboard_summary()

    service_checks = [
        {
            "name": "WireGuard",
            "detail": "نفق إدارة الراوترات",
            "ok": _wireguard_interface_is_available(
                settings.get("interface", "")
            ),
        },
        {
            "name": "قاعدة البيانات",
            "detail": "SQLite data.db",
            "ok": _database_is_available(),
        },
        {
            "name": "FreeRADIUS",
            "detail": "خدمة المصادقة",
            "ok": _service_is_active(
                "freeradius"
            ),
        },
        {
            "name": "خدمة اللوحة",
            "detail": "Cloud WG Panel",
            "ok": True,
        },
    ]

    return {
        "peers": ordered_peers,
        "online_peers": online_peers,
        "offline_peers": offline_peers,
        "total": len(ordered_peers),
        "online": len(online_peers),
        "offline": len(offline_peers),
        "rx": rx,
        "tx": tx,
        "subscriber_total": summary[
            "subscriber_total"
        ],
        "agent_total": summary[
            "agent_total"
        ],
        "recent_operations": summary[
            "recent_operations"
        ],
        "service_checks": service_checks,
        "settings": settings,
    }
