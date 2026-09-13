#!/usr/bin/env python3
"""Test aislado de redact_args (backend/bridge.py) — sin levantar el servidor."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from bridge import redact_args  # noqa: E402

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


# curl -d "email=x&password=secret" (login web) — el valor de password se redacta.
curl_args = ["-s", "-i", "-b", "/tmp/c.txt", "-X", "POST", "-d", "email=u@x.com&password=supersecreto", "https://x/login"]
redacted = redact_args(curl_args)
check("curl -d con password= redacta el valor", "supersecreto" not in " ".join(redacted))
check("curl -d preserva el resto del body (email)", "email=u@x.com" in " ".join(redacted))
check("curl -d preserva la key 'password=' (solo el valor se redacta)", "password=***REDACTED***" in redacted[-2])

# hydra -p <password> (flag + valor en args separados) — el valor se redacta.
hydra_args = ["-l", "admin", "-p", "hunter2", "ssh://10.0.0.1"]
redacted_hydra = redact_args(hydra_args)
check("hydra -p <valor> redacta el valor en su propio arg", "hunter2" not in redacted_hydra)
check("hydra -p preserva el flag -p en su lugar", redacted_hydra[2] == "-p")

# netexec --password <password> — mismo patrón de flag + valor separado.
nxc_args = ["smb", "10.0.0.1", "-u", "admin", "--password", "hunter2"]
redacted_nxc = redact_args(nxc_args)
check("netexec --password <valor> redacta el valor", "hunter2" not in redacted_nxc)

# Sin credenciales: no debe tocar nada.
plain_args = ["-s", "-I", "https://x.com"]
check("args sin credenciales quedan intactos", redact_args(plain_args) == plain_args)

# _token (CSRF) no es una credencial secreta, no se redacta.
csrf_args = ["-d", "code=test&_token=abc123"]
check("_token (CSRF) no se redacta", "_token=abc123" in redact_args(csrf_args)[-1])

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
