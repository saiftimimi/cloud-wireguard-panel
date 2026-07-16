# Cloud WG Panel v10.0.7

Stability recovery release built from the user's current server copy.

- Restores the previous classic administrator login page.
- Starts the HTTP listener immediately after an update.
- Moves slow WireGuard, iptables and MikroTik startup reconciliation to a background thread.
- Keeps the dashboard free from peer-import and iptables rebuild work.
- Preserves the Python 3.6 compatibility fixes from v10.0.6.
- Keeps the updates link visible through a scrollable sidebar.
- Does not replace data.db, .secret, WireGuard keys or server configuration.
