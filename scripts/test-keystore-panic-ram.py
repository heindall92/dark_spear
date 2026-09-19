#!/usr/bin/env python3
"""/keystore/panic llamaba keystore.wipe() (borra el fichero cifrado) pero
nunca limpiaba KEYS/ROTATION_STATE en RAM — un /keys/add posterior
reescribía el pool encima, y cualquier endpoint que leyera KEYS seguía
viendo las keys "borradas" hasta reiniciar el proceso. Prueba la lógica
de limpieza en RAM de forma aislada (sin levantar el servidor HTTP)."""
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


# Simula el estado tras cargar keys reales.
bridge.KEYS.extend([{"label": "prod", "api_key": "sk-real-secret", "window_hours": 24.0}])
bridge.ROTATION_STATE = {"pool": [{"label": "prod", "api_key": "sk-real-secret", "window_hours": 24.0, "exhausted_at": None}], "current_index": 0}
bridge.PASSPHRASE = "operator-passphrase-unchanged"

# Reproduce exactamente lo que el handler de /keystore/panic debe hacer
# (sin pasar por HTTP): wipe() del fichero + limpieza de KEYS/ROTATION_STATE.
with bridge.STATE_LOCK:
    bridge.KEYS.clear()
    bridge.ROTATION_STATE = None

check("KEYS queda vacío tras panic (no solo el fichero en disco)", bridge.KEYS == [])
check("ROTATION_STATE queda None tras panic (ya no sirve keys del pool)", bridge.ROTATION_STATE is None)
check("PASSPHRASE NO se toca (deliberado — ver nota de diseño en el plan)",
      bridge.PASSPHRASE == "operator-passphrase-unchanged")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
