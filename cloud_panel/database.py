"""SQLite connection helpers for Cloud WG Panel."""

import sqlite3

from cloud_panel.config import DB_PATH


def db():
    """Return a SQLite connection compatible with the legacy application."""
    con = sqlite3.connect(
        str(DB_PATH),
        timeout=60,
        check_same_thread=False,
    )
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA foreign_keys=ON")
    return con
