#!/usr/bin/env python3
"""Verifica keystore.wipe(): borra el fichero si existe, no falla si no."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import keystore  # noqa: E402

FAKE_PATH = Path("/tmp/ds-test-keys.enc")


def test_wipe_deletes_existing_file():
    keystore.KEYSTORE_PATH = FAKE_PATH
    FAKE_PATH.write_bytes(b"fake-ciphertext")
    result = keystore.wipe()
    ok = result is True and not FAKE_PATH.exists()
    print(("OK" if ok else "FAIL") + ": wipe() borra el keystore existente")
    return ok


def test_wipe_is_noop_when_absent():
    keystore.KEYSTORE_PATH = FAKE_PATH
    if FAKE_PATH.exists():
        FAKE_PATH.unlink()
    result = keystore.wipe()
    ok = result is False
    print(("OK" if ok else "FAIL") + ": wipe() no falla si el fichero no existe")
    return ok


if __name__ == "__main__":
    results = [test_wipe_deletes_existing_file(), test_wipe_is_noop_when_absent()]
    sys.exit(0 if all(results) else 1)
