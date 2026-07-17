"""Application and WireGuard settings services."""

import ipaddress
import re
from typing import Dict, Mapping

from cloud_panel.database import db


WIREGUARD_SETTING_FIELDS = (
    "interface",
    "endpoint",
    "port",
    "address",
    "dns",
    "mtu",
    "out_interface",
    "system_name",
    "agent_interface",
    "agent_port",
    "agent_address",
    "agent_mtu",
)

_INTERFACE_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]{1,15}$"
)


class SettingsValidationError(ValueError):
    """Raised when submitted panel settings are invalid."""


def get_settings() -> Dict[str, str]:
    """Return every setting as a key/value dictionary."""
    con = db()

    try:
        rows = con.execute(
            "SELECT key,value FROM settings"
        ).fetchall()
    finally:
        con.close()

    return {
        row["key"]: row["value"]
        for row in rows
    }


def maintenance_enabled() -> bool:
    """Return whether public maintenance mode is enabled."""
    try:
        con = db()

        try:
            row = con.execute(
                """
                SELECT value
                FROM settings
                WHERE key='maintenance_mode'
                """
            ).fetchone()
        finally:
            con.close()

        return bool(
            row
            and str(row["value"]) == "1"
        )
    except Exception:
        return False


def normalize_wireguard_settings(
    submitted: Mapping[str, object],
) -> Dict[str, str]:
    """Normalize and validate both WireGuard server settings."""
    values = {
        key: str(submitted.get(key, "") or "").strip()
        for key in WIREGUARD_SETTING_FIELDS
    }

    try:
        ipaddress.ip_interface(
            values["address"]
        )
        ipaddress.ip_interface(
            values["agent_address"]
        )

        port = int(values["port"])
        agent_port = int(values["agent_port"])

        mtu = int(values["mtu"])
        agent_mtu = int(values["agent_mtu"])

        if not 1 <= port <= 65535:
            raise ValueError

        if not 1 <= agent_port <= 65535:
            raise ValueError

        if port == agent_port:
            raise ValueError

        if not 576 <= mtu <= 9000:
            raise ValueError

        if not 576 <= agent_mtu <= 9000:
            raise ValueError

        if not _INTERFACE_PATTERN.fullmatch(
            values["interface"]
        ):
            raise ValueError

        if not _INTERFACE_PATTERN.fullmatch(
            values["agent_interface"]
        ):
            raise ValueError

        if (
            values["interface"]
            == values["agent_interface"]
        ):
            raise ValueError

    except (
        TypeError,
        ValueError,
        ipaddress.AddressValueError,
        ipaddress.NetmaskValueError,
    ) as exc:
        raise SettingsValidationError(
            "إعدادات خادمي WireGuard غير صحيحة"
        ) from exc

    values["port"] = str(port)
    values["agent_port"] = str(agent_port)
    values["mtu"] = str(mtu)
    values["agent_mtu"] = str(agent_mtu)

    return values


def save_settings_values(
    submitted: Mapping[str, object],
) -> Dict[str, str]:
    """Validate and persist WireGuard settings atomically."""
    values = normalize_wireguard_settings(
        submitted
    )

    con = db()

    try:
        con.execute("BEGIN")

        for key, value in values.items():
            con.execute(
                """
                INSERT OR REPLACE
                INTO settings(key,value)
                VALUES(?,?)
                """,
                (key, value),
            )

        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()

    return values
