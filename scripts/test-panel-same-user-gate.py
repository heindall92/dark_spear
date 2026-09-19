#!/usr/bin/env python3
"""_uid_for_connection() parsea /proc/net/tcp para identificar el UID dueño
de una conexión TCP local entrante, usado para negar /bridge/session y las
mutaciones de engagement a procesos de OTRO usuario del mismo Kali."""
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


hex_addr = panel_server._hex_addr
uid_for_connection = panel_server._uid_for_connection

check("_hex_addr codifica 127.0.0.1:8080 como little-endian hex", hex_addr("127.0.0.1", 8080) == "0100007F:1F90")
check("_hex_addr codifica 10.0.0.5:443", hex_addr("10.0.0.5", 443) == "0500000A:01BB")

# Formato real de una línea de /proc/net/tcp (columnas: sl local rem st tx:rx tr:tm retr uid ...)
proc_text = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:1F90 0100007F:8B4A 01 00000000:00000000 00:00000000 00000000  1000        0 123456\n"
    "   1: 0100007F:1F90 0100007F:8B4B 01 00000000:00000000 00:00000000 00000000  0            0 123457\n"
)
check(
    "conexión de UID 1000 (mismo usuario típico) se identifica correctamente",
    uid_for_connection("127.0.0.1", 8080, "127.0.0.1", 35658, proc_text) == 1000,
)
check(
    "conexión de UID 0 (root, otro usuario) se identifica correctamente",
    uid_for_connection("127.0.0.1", 8080, "127.0.0.1", 35659, proc_text) == 0,
)
check(
    "conexión que no aparece en la tabla -> None (fail-closed en el caller)",
    uid_for_connection("127.0.0.1", 8080, "127.0.0.1", 9999, proc_text) is None,
)
check("proc_text vacío -> None", uid_for_connection("127.0.0.1", 8080, "127.0.0.1", 35658, "") is None)
check(
    "línea malformada (menos columnas) no revienta, simplemente no matchea",
    uid_for_connection("127.0.0.1", 8080, "127.0.0.1", 35658, "  sl local rem\n   0: X Y\n") is None,
)

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
