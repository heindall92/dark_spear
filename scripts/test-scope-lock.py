#!/usr/bin/env python3
"""
Bug encontrado en auditoría: _target_in_scope() usaba substring puro
(`t in s or s in t`) antes de comparar hostnames reales — cualquier
target que CONTENGA el string del scope autorizado como substring
pasaba la validación, sin ser el mismo dominio ni un subdominio real.
Ej: scope="acme.com" -> target="acme.com.attacker.net" pasaba porque
"acme.com" es substring de "acme.com.attacker.net".
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


f = bridge._target_in_scope

# El bug exacto: dominio de un tercero que contiene el scope como substring.
check("target='acme.com.attacker.net' NO está en scope 'acme.com' (bug corregido)",
      f("https://acme.com.attacker.net", "https://acme.com") is False)
check("target='notacme.com' NO está en scope 'acme.com'",
      f("https://notacme.com", "https://acme.com") is False)
check("subdominio autorizado + substring ajeno: 'app.acme.com.evil.io' NO está en scope 'app.acme.com'",
      f("https://app.acme.com.evil.io", "https://app.acme.com") is False)
check("prefijo ajeno: 'evilacme.com' NO está en scope 'acme.com'",
      f("https://evilacme.com", "https://acme.com") is False)

# Casos legítimos que SÍ deben seguir pasando (normalización de _scope_host).
check("mismo host exacto", f("https://acme.com", "https://acme.com") is True)
check("target con slash final", f("https://acme.com/", "https://acme.com") is True)
check("www. se normaliza igual en ambos lados", f("https://www.acme.com", "https://acme.com") is True)
check("IP simple, mismo host", f("10.0.0.5", "10.0.0.5") is True)
check("subdominio real bajo el dominio autorizado (mail.acme.com bajo acme.com)",
      f("https://mail.acme.com", "https://acme.com") is True)

# Vacíos / basura.
check("target vacío -> False", f("", "https://acme.com") is False)
check("scope vacío -> False", f("https://acme.com", "") is False)

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
