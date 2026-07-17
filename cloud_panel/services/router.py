"""Router-related service functions."""

import ipaddress


def router_overview(
    peer,
    *,
    connect_peer_api,
    cloud_radius_states,
    read_winbox_internal_port,
    save_live_router_state,
):
    """Read and persist the current RouterOS overview."""

    api = connect_peer_api(peer)

    try:
        identity_rows = api.talk("/system/identity/print")
        resource_rows = api.talk("/system/resource/print")
        route_rows = api.talk("/ip/route/print")

        identity = identity_rows[0] if identity_rows else {}
        resource = resource_rows[0] if resource_rows else {}

        active_routes = sum(
            1
            for item in route_rows
            if item.get("active", "false") == "true"
            and item.get("disabled", "false") != "true"
        )

        radius_states = cloud_radius_states(api)
        winbox_port = read_winbox_internal_port(api)

        save_live_router_state(
            peer["id"],
            winbox_port=winbox_port,
            radius_states=radius_states,
        )

        return {
            "identity": identity.get("name", "-"),
            "version": resource.get("version", "-"),
            "uptime": resource.get("uptime", "-"),
            "architecture": resource.get("architecture-name", "-"),
            "board": resource.get("board-name", "-"),
            "cpu": resource.get("cpu", "-"),
            "cpu_count": resource.get("cpu-count", "-"),
            "cpu_load": resource.get("cpu-load", "0"),
            "free_memory": resource.get("free-memory", "0"),
            "total_memory": resource.get("total-memory", "0"),
            "free_hdd": resource.get("free-hdd-space", "0"),
            "active_routes": active_routes,
            "cloud_main_state": radius_states.get("main", "unknown"),
            "cloud_bypass_state": radius_states.get("bypass", "unknown"),
            "winbox_internal": winbox_port,
        }

    finally:
        api.close()


def mikrotik_api_bootstrap_script(
    peer,
    username,
    password,
    *,
    get_settings,
):
    settings = get_settings()
    source_ip = (
        str(ipaddress.ip_interface(settings["address"]).ip)
        + "/32"
    )

    return """# Cloud WG Panel - Full API bootstrap
# Paste the whole block into MikroTik Terminal

:if ([:len [/user find where name="{username}"]] = 0) do={{
  /user add name="{username}" password="{password}" group="full" comment="Managed by Cloud WG Panel - FULL"
}} else={{
  /user set [find where name="{username}"] password="{password}" group="full" disabled=no comment="Managed by Cloud WG Panel - FULL"
}}

/ip/service set [find where name="api"] port=9494 disabled=no address={source_ip}

:put "Cloud API ready with FULL permissions"
:put "Username: {username}"
:put "Password: {password}"
:put "Group: full"
""".format(
        username=username,
        password=password,
        source_ip=source_ip,
    )


def mikrotik_script(
    peer,
    *,
    get_settings,
    ensure_server_keys,
    direct_router_parameters,
    decrypt_text,
):
    if not peer["private_key"]:
        raise RuntimeError(
            "المفتاح الخاص غير متوفر لهذا الوكيل المستورد"
        )

    settings = get_settings()
    _, server_public = ensure_server_keys(settings["interface"])
    direct = direct_router_parameters(peer, settings)

    server_interface = ipaddress.ip_interface(settings["address"])
    server_ip = str(server_interface.ip) + "/32"

    peer_ip = ipaddress.ip_interface(peer["tunnel_ip"]).ip
    router_address = "%s/%s" % (
        peer_ip,
        server_interface.network.prefixlen,
    )

    api_username = peer["mt_username"] or ""
    api_password = decrypt_text(peer["mt_password_enc"])
    winbox_internal = int(peer["winbox_internal"] or 8291)

    return """# Cloud WG Panel - RouterOS 7 Full Setup
# Compatible with RouterOS 7.12+
# Shared management peer + dedicated subscriber-access peer

# 1) WireGuard interface
:if ([:len [/interface/wireguard find where name="wg-cloud"]] = 0) do={{
  /interface/wireguard add name="wg-cloud" private-key="{private}" mtu={mtu} comment="Cloud WireGuard"
}} else={{
  /interface/wireguard set [find where name="wg-cloud"] private-key="{private}" mtu={mtu} disabled=no comment="Cloud WireGuard"
}}

# 2) Management tunnel IP
:if ([:len [/ip/address find where interface="wg-cloud" and comment="Cloud WireGuard"]] = 0) do={{
  /ip/address add address={router_address} interface="wg-cloud" comment="Cloud WireGuard"
}} else={{
  /ip/address set [find where interface="wg-cloud" and comment="Cloud WireGuard"] address={router_address} interface="wg-cloud" disabled=no
}}

# 3) Pin the Cloud endpoint outside L2TP/WireGuard tunnels
# RouterOS 7.23 compatible: no :tolower command is used.
:local cloudEndpointIP "{endpoint}"
:local cloudWanGateway ""
:foreach cloudRoute in=[/ip/route find where dst-address="0.0.0.0/0" and active] do={{
  :local cloudGateway [:tostr [/ip/route get $cloudRoute gateway]]
  :local cloudIsVPN false
  :if ([:find $cloudGateway "l2tp"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "L2TP"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "wg-"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "wireguard"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "WireGuard"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "ovpn"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "OVPN"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "sstp"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "SSTP"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "pptp"] != nil) do={{ :set cloudIsVPN true }}
  :if ([:find $cloudGateway "PPTP"] != nil) do={{ :set cloudIsVPN true }}
  :if (($cloudIsVPN = false) and ($cloudWanGateway = "")) do={{
    :set cloudWanGateway $cloudGateway
  }}
}}
:if ($cloudWanGateway != "") do={{
  :local cloudEndpointRoutes [/ip/route find where comment="Cloud WireGuard Endpoint Route"]
  :if ([:len $cloudEndpointRoutes] = 0) do={{
    /ip/route add dst-address=($cloudEndpointIP . "/32") gateway=$cloudWanGateway distance=1 comment="Cloud WireGuard Endpoint Route"
  }} else={{
    :foreach cloudEndpointRoute in=$cloudEndpointRoutes do={{
      /ip/route set $cloudEndpointRoute dst-address=($cloudEndpointIP . "/32") gateway=$cloudWanGateway distance=1 disabled=no
    }}
  }}
}} else={{
  :log warning "CLOUD-WG: physical default gateway not detected; tunnel setup continues"
}}

# 4) Main management peer (repairs key, PSK, endpoint and port)
:if ([:len [/interface/wireguard/peers find where interface="wg-cloud" and comment="Cloud Server"]] = 0) do={{
  /interface/wireguard/peers add interface="wg-cloud" public-key="{server_public}" preshared-key="{psk}" endpoint-address={endpoint} endpoint-port={port} allowed-address={server_ip} persistent-keepalive=25 comment="Cloud Server"
}} else={{
  /interface/wireguard/peers set [find where interface="wg-cloud" and comment="Cloud Server"] interface="wg-cloud" public-key="{server_public}" preshared-key="{psk}" endpoint-address={endpoint} endpoint-port={port} allowed-address={server_ip} persistent-keepalive=25 disabled=no
}}

# 5) Real dedicated WireGuard interface for overlapping subscriber IPs
:foreach i in=[/interface/wireguard/peers find where interface="wg-cloud" and comment="Cloud Direct Access"] do={{ /interface/wireguard/peers remove $i }}

:if ([:len [/interface/wireguard find where name="{direct_router_interface}"]] = 0) do={{
  /interface/wireguard add name="{direct_router_interface}" private-key="{direct_router_private}" listen-port={direct_router_listen_port} mtu={mtu} comment="Cloud Direct WireGuard"
}} else={{
  /interface/wireguard set [find where name="{direct_router_interface}"] private-key="{direct_router_private}" listen-port={direct_router_listen_port} mtu={mtu} disabled=no comment="Cloud Direct WireGuard"
}}

:if ([:len [/ip/address find where interface="{direct_router_interface}" and comment="Cloud Direct WireGuard"]] = 0) do={{
  /ip/address add address={direct_router_cidr} interface="{direct_router_interface}" comment="Cloud Direct WireGuard"
}} else={{
  /ip/address set [find where interface="{direct_router_interface}" and comment="Cloud Direct WireGuard"] address={direct_router_cidr} interface="{direct_router_interface}" disabled=no
}}

:if ([:len [/interface/wireguard/peers find where interface="{direct_router_interface}" and comment="Cloud Direct Access"]] = 0) do={{
  /interface/wireguard/peers add interface="{direct_router_interface}" public-key="{direct_public}" preshared-key="{psk}" endpoint-address={endpoint} endpoint-port={direct_port} allowed-address={direct_server_ip}/32 persistent-keepalive=25 comment="Cloud Direct Access"
}} else={{
  /interface/wireguard/peers set [find where interface="{direct_router_interface}" and comment="Cloud Direct Access"] interface="{direct_router_interface}" public-key="{direct_public}" preshared-key="{psk}" endpoint-address={endpoint} endpoint-port={direct_port} allowed-address={direct_server_ip}/32 persistent-keepalive=25 disabled=no
}}

:foreach i in=[/ip/route find where comment="Cloud Agent Return Route"] do={{ /ip/route remove $i }}
:foreach i in=[/ip/route find where comment="Cloud Direct Server Route"] do={{ /ip/route remove $i }}

# 6) RouterOS firewall filter rules are not managed by the panel.
# The panel fills CloudAgentSubscribers automatically.

# 7) Dedicated API user with full permissions
:if ([:len [/user find where name="{api_username}"]] = 0) do={{
  /user add name="{api_username}" password="{api_password}" group="full" comment="Cloud WG Panel API - FULL"
}} else={{
  /user set [find where name="{api_username}"] password="{api_password}" group="full" disabled=no comment="Cloud WG Panel API - FULL"
}}

# 8) API service only. WinBox is read-only and its existing port is never changed.
/ip/service set [find where name="api"] port=9494 disabled=no address={server_ip}

# 9) RouterOS firewall policy remains fully user-managed.

# 10) Immediate handshake and final verification
# Restart both peers so a repaired key/PSK handshakes immediately.
:local cloudMainPeer [/interface/wireguard/peers find where interface="wg-cloud" and comment="Cloud Server"]
:if ([:len $cloudMainPeer] > 0) do={{
  /interface/wireguard/peers disable $cloudMainPeer
  :delay 1s
  /interface/wireguard/peers enable $cloudMainPeer
}}
:local cloudDirectPeer [/interface/wireguard/peers find where interface="{direct_router_interface}" and comment="Cloud Direct Access"]
:if ([:len $cloudDirectPeer] > 0) do={{
  /interface/wireguard/peers disable $cloudDirectPeer
  :delay 1s
  /interface/wireguard/peers enable $cloudDirectPeer
}}
:delay 5s
:put "========================================"
:put "Cloud WireGuard setup completed"
:put "Management Endpoint: {endpoint}:{port}"
:put "Direct Endpoint: {endpoint}:{direct_port}"
:put "Direct Server IP: {direct_server_ip}"
:put "API User: {api_username}"
:put "API Port: 9494"
:put "API Group: full"
:put "WinBox Port: unchanged (panel reads it automatically after API connection)"
:put "========================================"
/ping {server_ip_plain} src-address={peer_ip_plain} count=4
""".format(
        private=peer["private_key"],
        mtu=settings.get("mtu", "1420"),
        router_address=router_address,
        server_public=server_public,
        direct_public=direct["server_public"],
        psk=peer["preshared_key"],
        endpoint=settings["endpoint"],
        port=settings["port"],
        direct_port=direct["port"],
        direct_server_ip=direct["server_ip"],
        direct_server_cidr=direct["server_cidr"],
        direct_router_cidr=direct["router_cidr"],
        direct_router_private=direct["router_private"],
        direct_router_interface=direct["router_interface"],
        direct_router_listen_port=direct["router_listen_port"],
        server_ip=server_ip,
        server_ip_plain=str(server_interface.ip),
        peer_ip_plain=str(peer_ip),
        api_username=api_username,
        api_password=api_password,
        winbox_internal=winbox_internal,
    )


def provision_router_automatically(
    peer_id,
    *,
    get_peer_or_404,
    ensure_router_radius_configuration,
    install_cloud_router_guards,
    create_notification,
):
    """
    تهيئة إعدادات الراوتر فقط.

    ملاحظة:
    هذه العملية لا تنشئ ولا تغيّر ولا تحذف
    حساب إدارة الراوتر.
    """
    peer = get_peer_or_404(peer_id)

    if not peer:
        raise RuntimeError("الراوتر غير موجود")

    radius_result = ensure_router_radius_configuration(
        peer
    )
    guard_result = install_cloud_router_guards(peer_id, notify=False)

    create_notification(
        "تهيئة الراوتر",
        "تمت تهيئة RADIUS وPPP وHotspot وBYPASS للراوتر %s"
        % peer["name"],
        kind="success",
        audience="admin",
        peer_id=peer_id,
    )

    return {
        "ok": True,
        "peer_id": peer_id,
        "radius": radius_result,
        "guard": guard_result,
    }
