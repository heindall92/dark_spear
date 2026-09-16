#!/usr/bin/env python3
"""
Bug encontrado en auditoría: Handler._read_json() lee Content-Length bytes
sin ningún tope — un cliente (o proceso local malicioso/con bug) que mande
un Content-Length gigante hace que el servidor intente reservar/leer esa
cantidad de memoria antes de siquiera parsear el JSON. Bind es solo a
127.0.0.1 (sin atacante remoto), pero es un self-DoS barato de evitar.
"""
import importlib.util
import io
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


class FakeHandler:
    """Duck-types lo mínimo que _read_json necesita: .headers.get y .rfile.read."""
    def __init__(self, content_length, body=b""):
        self.headers = {"Content-Length": str(content_length)}
        self.rfile = io.BytesIO(body)


read_json = bridge.Handler._read_json

# Body normal, pequeño -> funciona igual que antes.
body = b'{"target": "acme.com", "scope": "acme.com"}'
result = read_json(FakeHandler(len(body), body))
check("body normal se parsea igual que antes", result == {"target": "acme.com", "scope": "acme.com"})

# Sin body -> {} (comportamiento preexistente, no debe romperse).
check("sin Content-Length -> {}", read_json(FakeHandler(0)) == {})

# Content-Length gigante -> debe rechazar ANTES de leer, no intentar
# reservar/leer esa cantidad de memoria.
huge = 10_000_000_000  # 10 GB anunciados
try:
    read_json(FakeHandler(huge, b""))
    check("Content-Length de 10GB se rechaza sin intentar leer", False)
except ValueError as e:
    check("Content-Length de 10GB se rechaza sin intentar leer", "too_large" in str(e))

# Justo en el límite (tope configurado) -> sigue funcionando.
cap = bridge.MAX_REQUEST_BODY_BYTES
at_cap_body = b'{"a":"' + b"x" * (cap - 20) + b'"}'
result_at_cap = read_json(FakeHandler(len(at_cap_body), at_cap_body))
check(f"body justo en el tope ({cap} bytes) se procesa normal", isinstance(result_at_cap, dict))

# Justo por encima del tope -> rechazado.
try:
    read_json(FakeHandler(cap + 1, b"x" * (cap + 1)))
    check("body 1 byte por encima del tope se rechaza", False)
except ValueError:
    check("body 1 byte por encima del tope se rechaza", True)

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
