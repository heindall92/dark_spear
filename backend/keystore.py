#!/usr/bin/env python3
"""Encrypted storage for Ollama Cloud API keys — Fernet symmetric encryption
keyed off an operator-supplied passphrase, never written to disk or logged.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEYSTORE_PATH = Path.home() / ".auditor" / "keys.enc"
SALT_LEN = 16
PBKDF2_ITERATIONS = 600_000  # OWASP current guidance for PBKDF2-HMAC-SHA256


def _derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def load_or_init(passphrase: str) -> list[dict]:
    if not KEYSTORE_PATH.is_file():
        return []
    raw = KEYSTORE_PATH.read_bytes()
    salt, token = raw[:SALT_LEN], raw[SALT_LEN:]
    fernet = Fernet(_derive_fernet_key(passphrase, salt))
    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("invalid_passphrase")
    return json.loads(plaintext.decode())


def save(passphrase: str, keys: list[dict]) -> None:
    KEYSTORE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = os.urandom(SALT_LEN)
    fernet = Fernet(_derive_fernet_key(passphrase, salt))
    token = fernet.encrypt(json.dumps(keys).encode())
    # Write via a 0600-from-creation temp file + atomic rename — avoids the
    # window where write_bytes()+chmod() briefly leaves the ciphertext
    # world-readable under the process umask.
    tmp_path = KEYSTORE_PATH.with_suffix(".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, salt + token)
    finally:
        os.close(fd)
    os.replace(tmp_path, KEYSTORE_PATH)
