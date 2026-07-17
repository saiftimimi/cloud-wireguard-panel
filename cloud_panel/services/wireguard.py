"""Core WireGuard service helpers.

This module contains framework-independent WireGuard operations.
Dependencies that belong to the Flask application are injected by
the wrappers in app.py.
"""

from datetime import datetime

import subprocess
from pathlib import Path

import ipaddress
import secrets


def clean_networks(text):
    result = []
    for item in [x.strip() for x in text.replace("\n", ",").split(",") if x.strip()]:
        ipaddress.ip_network(item, strict=False)
        result.append(item)
    return result


def next_tunnel_ip(
    *,
    get_settings,
    db,
    default_address,
):
    settings = get_settings()
    network = ipaddress.ip_network(settings.get("address", default_address), strict=False)
    server_ip = ipaddress.ip_interface(settings.get("address", default_address)).ip

    con = db()
    used = set()
    for row in con.execute("SELECT tunnel_ip FROM peers").fetchall():
        try:
            used.add(ipaddress.ip_interface(row["tunnel_ip"]).ip)
        except Exception:
            pass
    con.close()

    for host in network.hosts():
        if host == server_ip:
            continue
        if host not in used:
            return str(host) + "/32"
    raise RuntimeError("لا يوجد IP فارغ داخل شبكة WireGuard")


def wg_keypair(
    *,
    run_command,
):
    private_key = run_command(["wg", "genkey"])
    public_key = run_command(["wg", "pubkey"], input_text=private_key)
    psk = run_command(["wg", "genpsk"])
    return private_key, public_key, psk


def random_api_credentials():
    username = "cwg_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(18)
    return username, password


def peer_config(
    peer,
    *,
    get_settings,
    ensure_server_keys,
):
    settings = get_settings()
    _, server_public = ensure_server_keys(settings["interface"])
    return """[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = {dns}
MTU = {mtu}

[Peer]
PublicKey = {server_public}
PresharedKey = {psk}
Endpoint = {endpoint}:{port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
""".format(
        private_key=peer["private_key"],
        address=peer["tunnel_ip"],
        dns=settings.get("dns", "1.1.1.1"),
        mtu=settings.get("mtu", "1420"),
        server_public=server_public,
        psk=peer["preshared_key"],
        endpoint=settings["endpoint"],
        port=settings["port"],
    )


def parse_ubuntu_wireguard_peers(
    *,
    get_settings,
    command_runner=subprocess.run,
    config_directory="/etc/wireguard",
):
    """Read peers from both the live WireGuard interface and wg-quick config.

    Live `wg show ... dump` is authoritative for public key / AllowedIPs / traffic.
    The config file is used to recover comments and PresharedKey when available.
    """
    settings = get_settings()
    interface = settings.get("interface", "wg-cloud0").strip() or "wg-cloud0"
    conf_path = Path(config_directory) / ("%s.conf" % interface)

    config_by_public = {}
    config_by_ip = {}
    if conf_path.exists():
        current = None
        pending_comment = ""
        for raw_line in conf_path.read_text(errors="ignore").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                pending_comment = line.lstrip("#").strip()
                continue
            if line == "[Peer]":
                if current:
                    pub = current.get("public_key", "")
                    if pub:
                        config_by_public[pub] = current
                    for ip_value in current.get("allowed_ips", []):
                        config_by_ip[ip_value] = current
                current = {
                    "comment": pending_comment,
                    "public_key": "",
                    "preshared_key": "",
                    "allowed_ips": [],
                }
                pending_comment = ""
                continue
            if current is None or "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            if key == "PublicKey":
                current["public_key"] = value
            elif key == "PresharedKey":
                current["preshared_key"] = value
            elif key == "AllowedIPs":
                current["allowed_ips"] = [
                    item.strip() for item in value.split(",") if item.strip()
                ]
        if current:
            pub = current.get("public_key", "")
            if pub:
                config_by_public[pub] = current
            for ip_value in current.get("allowed_ips", []):
                config_by_ip[ip_value] = current

    peers = []
    proc = command_runner(
        ["wg", "show", interface, "dump"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode == 0:
        lines = proc.stdout.decode(errors="ignore").splitlines()
        for line in lines[1:]:
            cols = line.split("\t")
            if len(cols) < 8:
                continue
            public_key = cols[0].strip()
            allowed_values = [x.strip() for x in cols[3].split(",") if x.strip()]
            config_item = config_by_public.get(public_key)
            if not config_item:
                for value in allowed_values:
                    if value in config_by_ip:
                        config_item = config_by_ip[value]
                        break
            peers.append({
                "comment": (config_item or {}).get("comment", ""),
                "public_key": public_key,
                "preshared_key": (config_item or {}).get("preshared_key", ""),
                "allowed_ips": allowed_values,
                "endpoint": cols[2],
                "latest_handshake": int(cols[4] or 0),
                "rx": int(cols[5] or 0),
                "tx": int(cols[6] or 0),
            })

    # If the interface is temporarily down, still import from the config file.
    if not peers:
        peers = list(config_by_public.values())

    return peers


def import_peers_from_ubuntu(
    *,
    parse_peers,
    db,
    get_settings,
    tcp_listener_uses_port,
    regenerate_nat_rules,
    app_dir,
):
    parsed = parse_peers()
    debug_path = app_dir / "sync-debug.log"
    debug_lines = [
        "%s interface=%s found=%d" % (
            datetime.now().isoformat(timespec="seconds"),
            get_settings().get("interface", "wg-cloud0"),
            len(parsed),
        )
    ]
    if not parsed:
        debug_path.write_text("\n".join(debug_lines) + "\n")
        return 0

    con = db()
    imported = 0
    updated = 0
    skipped = 0
    try:
        used_ports = {
            int(row["winbox_external"])
            for row in con.execute(
                "SELECT winbox_external FROM peers WHERE winbox_external > 0"
            ).fetchall()
        }

        def allocate_port():
            for candidate in range(10001, 20000):
                if candidate in used_ports or tcp_listener_uses_port(candidate):
                    continue
                used_ports.add(candidate)
                return candidate
            raise RuntimeError("لا يوجد بورت WinBox خارجي فارغ")

        for item in parsed:
            public_key = (item.get("public_key") or "").strip()
            if not public_key:
                skipped += 1
                debug_lines.append("skip: missing public key")
                continue

            tunnel_ip = ""
            for allowed in item.get("allowed_ips", []):
                try:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if network.version == 4 and network.prefixlen == 32:
                        tunnel_ip = str(network.network_address) + "/32"
                        break
                except Exception:
                    continue

            if not tunnel_ip:
                skipped += 1
                debug_lines.append("skip %s: no IPv4 /32 AllowedIPs (%s)" % (
                    public_key, item.get("allowed_ips", [])
                ))
                continue

            existing = con.execute(
                "SELECT * FROM peers WHERE public_key=? OR tunnel_ip=? LIMIT 1",
                (public_key, tunnel_ip)
            ).fetchone()

            if existing:
                external = int(existing["winbox_external"] or 0)
                if external <= 0:
                    external = allocate_port()
                con.execute(
                    """UPDATE peers SET
                       public_key=?, tunnel_ip=?, source_comment=?, imported_from_wg=1,
                       mt_host=?, winbox_external=?
                       WHERE id=?""",
                    (
                        public_key,
                        tunnel_ip,
                        item.get("comment", ""),
                        tunnel_ip.split("/")[0],
                        external,
                        existing["id"],
                    )
                )
                updated += 1
                debug_lines.append("update id=%s ip=%s pub=%s port=%s" % (
                    existing["id"], tunnel_ip, public_key, external
                ))
                continue

            name = (item.get("comment") or "").strip()
            if not name:
                name = "Ubuntu Peer %s" % tunnel_ip.split("/")[0]
            external_port = allocate_port()
            peer_ip = tunnel_ip.split("/")[0]

            con.execute(
                """INSERT INTO peers(
                    name,tunnel_ip,lan_ips,public_ips,private_key,public_key,preshared_key,
                    enabled,notes,mt_host,mt_port,mt_username,mt_password_enc,mt_ssl,
                    winbox_internal,winbox_external,created_at,imported_from_wg,source_comment
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),?,?)""",
                (
                    name, tunnel_ip, "", "", "", public_key,
                    item.get("preshared_key", ""), 1,
                    "Imported automatically from Ubuntu WireGuard",
                    peer_ip, 9494, "", "", 0, 8291, external_port, 1,
                    item.get("comment", ""),
                )
            )
            imported += 1
            debug_lines.append("insert ip=%s pub=%s port=%s" % (
                tunnel_ip, public_key, external_port
            ))

        con.commit()
    except Exception as exc:
        con.rollback()
        debug_lines.append("ERROR: %s" % exc)
        debug_path.write_text("\n".join(debug_lines) + "\n")
        raise
    finally:
        con.close()

    debug_lines.append("done imported=%d updated=%d skipped=%d" % (
        imported, updated, skipped
    ))
    debug_path.write_text("\n".join(debug_lines) + "\n")
    regenerate_nat_rules()
    return imported
