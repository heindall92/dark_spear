#!/usr/bin/env python3
"""LAST_ACTIVITY (persistido en meta.json/expuesto por /status) se
construía con args[:4] SIN pasar por redact_args() — a diferencia del
audit_log del mismo endpoint, que sí redacta. Passwords de hydra/netexec
quedaban en claro en disco. Prueba que la MISMA lógica de redacción que
ya protege audit_log también protege el string que arma LAST_ACTIVITY."""
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


# Simula exactamente la construcción de arg_preview en el handler de /exec:
# arg_preview = " ".join(str(a) for a in redact_args(args[:4]))
def build_preview(tool, args):
    arg_preview = " ".join(str(a) for a in redact_args(args[:4]))
    return f"{tool} {arg_preview}".strip()


hydra_args = ["-l", "admin", "-p", "hunter2", "ssh://10.0.0.1"]
preview = build_preview("hydra", hydra_args)
check("hydra -p <valor> no queda en claro en el preview", "hunter2" not in preview)
check("hydra: el flag -p sigue visible (solo el valor se redacta)", "-p" in preview)

nxc_args = ["smb", "10.0.0.1", "-u", "admin", "--password", "hunter2"]
preview_nxc = build_preview("netexec", nxc_args)
check("netexec --password <valor> no queda en claro en el preview (recortado por args[:4] o redactado)",
      "hunter2" not in preview_nxc)

plain_args = ["-s", "-I", "https://x.com"]
preview_plain = build_preview("curl", plain_args)
check("args sin credenciales quedan intactos en el preview", preview_plain == "curl -s -I https://x.com")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
