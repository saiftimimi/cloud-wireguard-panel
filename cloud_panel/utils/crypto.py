"""Encryption helpers for credentials stored by Cloud WG Panel."""

import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken

from cloud_panel.config import SECRET_PATH


def load_or_create_app_secret() -> str:
    """Load the persistent application secret or create it securely."""
    if SECRET_PATH.exists():
        existing = SECRET_PATH.read_text(
            encoding="utf-8"
        ).strip()

        if existing:
            try:
                os.chmod(str(SECRET_PATH), 0o600)
            except OSError:
                pass

            return existing

    generated = secrets.token_hex(32)

    SECRET_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    SECRET_PATH.write_text(
        generated,
        encoding="utf-8",
    )
    os.chmod(str(SECRET_PATH), 0o600)

    return generated


APP_SECRET = load_or_create_app_secret()


def cipher() -> Fernet:
    """Build the legacy-compatible Fernet cipher."""
    raw = hashlib.sha256(
        APP_SECRET.encode()
    ).digest()

    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt_text(value) -> str:
    """Encrypt text using the persistent application secret."""
    if not value:
        return ""

    return cipher().encrypt(
        str(value).encode()
    ).decode()


def decrypt_text(value) -> str:
    """Decrypt text, returning an empty string for invalid values."""
    if not value:
        return ""

    try:
        return cipher().decrypt(
            str(value).encode()
        ).decode()
    except (InvalidToken, ValueError, TypeError):
        return ""
