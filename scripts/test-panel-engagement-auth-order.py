#!/usr/bin/env python3
"""Verifica que panel/server.py llama _peer_is_same_user() ANTES de
_control_engagement_on_disk()/_delete_engagement_from_disk() en cada bloque
de mutación de engagement — no después. Bug original: el token solo se
usaba al reenviar al bridge, la mutación en disco corría sin chequear nada."""
import re
import sys
from pathlib import Path

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


src = Path(__file__).parent.parent.joinpath("panel", "server.py").read_text(encoding="utf-8")

# Bloque pause/resume/finish: busca el for ctrl_path... hasta la llamada a
# _control_engagement_on_disk, y exige que _peer_is_same_user() aparezca
# ANTES de esa llamada dentro del mismo bloque.
ctrl_block_m = re.search(
    r'for ctrl_path, ctrl_action in.*?_control_engagement_on_disk\(eng_name, ctrl_action\)',
    src, re.DOTALL,
)
check("bloque pause/resume/finish encontrado", ctrl_block_m is not None)
if ctrl_block_m:
    block = ctrl_block_m.group(0)
    check(
        "_peer_is_same_user() se llama ANTES de _control_engagement_on_disk()",
        block.find("_peer_is_same_user()") != -1
        and block.find("_peer_is_same_user()") < block.find("_control_engagement_on_disk("),
    )

# Bloque delete: busca desde 'if path == "/bridge/engagements/delete"' hasta
# _delete_engagement_from_disk.
del_block_m = re.search(
    r'if path == "/bridge/engagements/delete".*?_delete_engagement_from_disk\(eng_name, related=related\)',
    src, re.DOTALL,
)
check("bloque delete encontrado", del_block_m is not None)
if del_block_m:
    block = del_block_m.group(0)
    check(
        "_peer_is_same_user() se llama ANTES de _delete_engagement_from_disk()",
        block.find("_peer_is_same_user()") != -1
        and block.find("_peer_is_same_user()") < block.find("_delete_engagement_from_disk("),
    )

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
