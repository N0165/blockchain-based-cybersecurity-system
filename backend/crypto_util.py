"""Encrypt / decrypt org Ethereum private keys at rest (demo: Fernet)."""
import base64
import hashlib
import os

from cryptography.fernet import Fernet


def _fernet_from_config(config) -> Fernet:
    key = getattr(config, "ENCRYPTION_KEY", "") or ""
    if not key:
        raw = os.environ.get("SECRET_KEY", "dev")
        digest = hashlib.sha256(raw.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    else:
        if len(key) != 44:
            digest = hashlib.sha256(key.encode()).digest()
            key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_private_key(config, hex_private_key: str) -> str:
    f = _fernet_from_config(config)
    return f.encrypt(hex_private_key.encode()).decode()


def decrypt_private_key(config, token: str) -> str:
    f = _fernet_from_config(config)
    return f.decrypt(token.encode()).decode()
