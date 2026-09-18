#!/usr/bin/env python3
"""
HTTP Request Smuggling (CL.TE / TE.CL): sondas de timing estándar
(metodología PortSwigger) — conexión cruda, sin pasar por curl (no puede
mandar Content-Length y Transfer-Encoding ambiguos de forma fiable).
Riesgo mayor que SSTI/XXE: un desync real en producción compartida puede
afectar peticiones de otros usuarios, no solo del que prueba — por eso
vive en Fase 3 (mismo gate humano de avance de fase que wmiexec/secretsdump,
no automático ni en modo agente libre).

Este test valida:
1) build_smuggling_probe(): construye los bytes exactos de cada sonda
   (sin red).
2) send_raw_probe(): contra un servidor TCP de prueba local controlado —
   uno que cuelga tras leer Content-Length bytes (simula backend
   esperando más datos del stream chunked) y uno que responde rápido —
   confirma que el harness de timing detecta correctamente el "cuelgue"
   real vs una respuesta normal.
"""
import importlib.util
import socket
import sys
import threading
import time
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


# --- build_smuggling_probe (pura, sin red) ----------------------------------

clte = bridge.build_smuggling_probe("clte", "target.local", "/")
check("CL.TE: header Content-Length presente", b"Content-Length: 4\r\n" in clte)
check("CL.TE: header Transfer-Encoding: chunked presente", b"Transfer-Encoding: chunked\r\n" in clte)
check("CL.TE: Host correcto", b"Host: target.local\r\n" in clte)
check("CL.TE: cuerpo con chunk-size 1 + relleno tras Content-Length declarado", clte.endswith(b"1\r\nA\r\nX"))

tecl = bridge.build_smuggling_probe("tecl", "target.local", "/")
check("TE.CL: header Content-Length coincide con longitud real del cuerpo (6)", b"Content-Length: 6\r\n" in tecl)
check("TE.CL: header Transfer-Encoding: chunked presente", b"Transfer-Encoding: chunked\r\n" in tecl)
check("TE.CL: cuerpo termina en chunk 0 + relleno", tecl.endswith(b"0\r\n\r\nX"))

try:
    bridge.build_smuggling_probe("bogus", "x", "/")
    check("build_smuggling_probe kind inválido -> ValueError", False)
except ValueError:
    check("build_smuggling_probe kind inválido -> ValueError", True)


# --- send_raw_probe (red real, contra servidor de prueba local) ------------

def hang_after_n_bytes(n, port_holder, ready):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_holder.append(srv.getsockname()[1])
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.recv(n)
    time.sleep(3)  # cuelga: nunca responde (simula backend chunked esperando más)
    conn.close()
    srv.close()


def respond_fast(port_holder, ready):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_holder.append(srv.getsockname()[1])
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.recv(4096)
    conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
    conn.close()
    srv.close()


port_holder = []
ready = threading.Event()
t = threading.Thread(target=hang_after_n_bytes, args=(50, port_holder, ready), daemon=True)
t.start()
ready.wait(2)
time.sleep(0.05)
result = bridge.send_raw_probe("127.0.0.1", port_holder[0], clte, timeout=1.5)
check("servidor que cuelga -> timed_out True", result["timed_out"] is True)
check("servidor que cuelga -> elapsed_ms cerca del timeout configurado (no instantáneo)", result["elapsed_ms"] >= 1000)

port_holder2 = []
ready2 = threading.Event()
t2 = threading.Thread(target=respond_fast, args=(port_holder2, ready2), daemon=True)
t2.start()
ready2.wait(2)
time.sleep(0.05)
result2 = bridge.send_raw_probe("127.0.0.1", port_holder2[0], clte, timeout=5.0)
check("servidor que responde rápido -> timed_out False", result2["timed_out"] is False)
check("servidor que responde rápido -> elapsed_ms bajo (no esperó el timeout completo)", result2["elapsed_ms"] < 2000)
check("servidor que responde rápido -> response_snippet captura la respuesta", b"400" in result2["response_snippet"])

# host inalcanzable -> no debe lanzar excepción, debe reportar el error
result3 = bridge.send_raw_probe("127.0.0.1", 1, clte, timeout=1.0)
check("puerto cerrado/inalcanzable -> no lanza excepción, reporta error", result3.get("error") is not None)

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
