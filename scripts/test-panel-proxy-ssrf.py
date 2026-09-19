#!/usr/bin/env python3
"""_validate_bridge_target() bloquea el truco de userinfo en URL: una
petición a /bridge@evil.example/exec produce url =
"http://127.0.0.1:8420@evil.example/exec", que urlparse interpreta con
hostname="evil.example" (userinfo "127.0.0.1:8420" descartado) — el
proxy terminaba conectando (y reenviando X-Auditor-Token) al host ajeno."""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "panel"))
spec = importlib.util.spec_from_file_location("panel_server", Path(__file__).parent.parent / "panel" / "server.py")
panel_server = importlib.util.module_from_spec(spec)
sys.modules["panel_server"] = panel_server
spec.loader.exec_module(panel_server)

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


f = panel_server._validate_bridge_target

check("path normal (/status) -> URL válida contra el bridge real", f("/status") == "http://127.0.0.1:8420/status")
check("path normal con subpath (/exec) -> URL válida", f("/exec") == "http://127.0.0.1:8420/exec")
check(
    "truco de userinfo (@evil.example) -> None, bloqueado",
    f("@evil.example/exec") is None,
)
check(
    "truco de userinfo con esquema embebido -> None",
    f("@evil.example:1234/exec") is None,
)
check("path vacío -> URL a la raíz del bridge", f("") == "http://127.0.0.1:8420/")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
