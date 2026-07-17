#!/usr/bin/env python3
"""Compatibility launcher for the Cloud WireGuard Panel service."""

from cloud_panel.app import app, bootstrap_application


if __name__ == "__main__":
    bootstrap_application()
    app.run(host="0.0.0.0", port=1994, threaded=True)
