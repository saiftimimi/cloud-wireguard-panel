"""Process-local runtime state shared by Cloud WG Panel modules."""

import threading


DB_WRITE_LOCK = threading.RLock()
ROUTER_GUARD_LOCK = threading.RLock()

WEBFIG_SESSION_LOCK = threading.RLock()
WEBFIG_SESSIONS = {}
WEBFIG_SESSION_TTL = 900
