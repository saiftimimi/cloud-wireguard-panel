"""Network, port and address validation helpers."""

import ipaddress
import subprocess
from typing import Optional

from cloud_panel.database import db


def listener_uses_port(port: int, protocol: str = "tcp") -> bool:
    """Return True when Ubuntu has a TCP or UDP listener on the port."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False

    protocol = str(protocol or "tcp").strip().lower()

    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")

    command = (
        ["ss", "-lntH"]
        if protocol == "tcp"
        else ["ss", "-lnuH"]
    )

    proc = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if proc.returncode != 0:
        return False

    suffix = ":%d" % port

    for line in proc.stdout.decode(
        errors="ignore"
    ).splitlines():
        parts = line.split()

        if (
            len(parts) >= 4
            and parts[3].endswith(suffix)
        ):
            return True

    return False


def tcp_listener_uses_port(port: int) -> bool:
    """Backward-compatible TCP-only listener check."""
    return listener_uses_port(port, "tcp")


def next_external_port(
    start: int = 10001,
    end: int = 19999,
) -> int:
    """Find an unused external WinBox port."""
    start = int(start)
    end = int(end)

    if start < 1 or end > 65535 or start > end:
        raise RuntimeError("مدى البورتات الخارجية غير صحيح")

    con = db()

    try:
        used = {
            int(row["winbox_external"])
            for row in con.execute(
                """
                SELECT winbox_external
                FROM peers
                WHERE winbox_external > 0
                """
            ).fetchall()
        }
    finally:
        con.close()

    for port in range(start, end + 1):
        if (
            port not in used
            and not tcp_listener_uses_port(port)
        ):
            return port

    raise RuntimeError(
        "لا يوجد بورت WinBox خارجي فارغ"
    )


def validate_external_port(
    port,
    peer_id: Optional[int] = None,
) -> bool:
    """Validate a WinBox external port."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise RuntimeError(
            "البورت الخارجي غير صحيح"
        )

    if port < 1 or port > 65535:
        raise RuntimeError(
            "البورت الخارجي غير صحيح"
        )

    con = db()

    try:
        if peer_id is None:
            row = con.execute(
                """
                SELECT name
                FROM peers
                WHERE winbox_external=?
                LIMIT 1
                """,
                (port,),
            ).fetchone()
        else:
            row = con.execute(
                """
                SELECT name
                FROM peers
                WHERE winbox_external=?
                  AND id<>?
                LIMIT 1
                """,
                (port, int(peer_id)),
            ).fetchone()
    finally:
        con.close()

    if row:
        raise RuntimeError(
            "البورت مستخدم من الوكيل: %s"
            % row["name"]
        )

    if tcp_listener_uses_port(port):
        raise RuntimeError(
            "البورت مستخدم من خدمة أخرى على Ubuntu"
        )

    return True


def validate_forward_protocol(value: str) -> str:
    """Normalize and validate a forwarding protocol."""
    value = str(value or "tcp").strip().lower()

    if value not in ("tcp", "udp", "both"):
        raise RuntimeError(
            "البروتوكول يجب أن يكون TCP "
            "أو UDP أو الاثنين"
        )

    return value


def normalize_internal_ip(value: str) -> str:
    """Validate and normalize an internal IPv4 address."""
    try:
        address = ipaddress.ip_address(
            str(value or "").strip()
        )
    except ValueError:
        raise RuntimeError(
            "IP المشترك الداخلي غير صحيح"
        )

    if address.version != 4:
        raise RuntimeError(
            "حالياً التحويل يدعم IPv4 فقط"
        )

    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
    ):
        raise RuntimeError(
            "IP المشترك الداخلي غير مسموح"
        )

    return str(address)
