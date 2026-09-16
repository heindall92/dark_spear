#!/usr/bin/env python3
"""
Bug encontrado en auditoría: Handler no tenía timeout de socket — un
cliente que abre la conexión y nunca termina de mandar datos (slowloris)
cuelga el hilo del thread pool indefinido. StreamRequestHandler.timeout
(heredado por BaseHTTPRequestHandler) aplica socket.settimeout()
automáticamente en setup() cuando se define como class attribute.
"""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
spec = importlib.util.spec_from_file_location("bridge", Path(__file__).parent.parent / "backend" / "bridge.py")
bridge = importlib.util.module_from_spec(spec)
sys.modules["bridge"] = bridge
spec.loader.exec_module(bridge)

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


check("Handler define timeout de socket (evita colgar el hilo con slowloris)", getattr(bridge.Handler, "timeout", None) is not None)
check("el timeout es un número positivo razonable (no 0, no negativo)", isinstance(bridge.Handler.timeout, (int, float)) and bridge.Handler.timeout > 0)

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
