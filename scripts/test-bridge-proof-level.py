#!/usr/bin/env python3
"""Test aislado de la validacion/clamp de proof_level en /findings/propose
(backend/bridge.py) — sin levantar el servidor, llamando directo a la
funcion que construye el dict de finding."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from bridge import normalize_proof_level, PROOF_LEVELS  # noqa: E402

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


check("PROOF_LEVELS contiene proven y detected", PROOF_LEVELS == {"proven", "detected"})
check("proof_level 'proven' valido se preserva", normalize_proof_level("proven") == "proven")
check("proof_level 'detected' valido se preserva", normalize_proof_level("detected") == "detected")
check("proof_level ausente (None) -> default detected", normalize_proof_level(None) == "detected")
check("proof_level vacio -> default detected", normalize_proof_level("") == "detected")
check("proof_level invalido/inventado -> default detected (fail closed, no confia en el cliente)", normalize_proof_level("super-proven") == "detected")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
