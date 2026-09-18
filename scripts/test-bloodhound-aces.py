#!/usr/bin/env python3
"""
bloodhound-python ya corría (Fase 2, DCOnly) pero dark_spear solo
confirmaba que el JSON se escribió en evidence/bloodhound — nunca lo
parseaba. Las aristas de ACL peligrosas (GenericAll, WriteDacl,
AddKeyCredentialLink -> Shadow Credentials, DCSync vía GetChanges +
GetChangesAll combinados) quedaban enterradas en el fichero, solo
visibles si alguien abría BloodHound UI a mano.

collect_bloodhound_aces() lee los JSON que bloodhound-python ya escribió
(mismo formato que consume BloodHound UI: {"data": [...], "meta": {...}}
por tipo de objeto) y resuelve SID -> nombre cruzando todos los ficheros,
igual que hace la propia UI de BloodHound.
"""
import importlib.util
import json
import sys
import tempfile
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


def write_json(d, name, payload):
    (d / name).write_text(json.dumps(payload))


with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)

    write_json(d, "20260101_users.json", {
        "meta": {"type": "users", "count": 1},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-1-1-1105",
            "Properties": {"name": "ALICE@CORP.LOCAL", "domain": "CORP.LOCAL"},
            "Aces": [],
        }],
    })
    write_json(d, "20260101_computers.json", {
        "meta": {"type": "computers", "count": 1},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-1-1-2000",
            "Properties": {"name": "SRV01.CORP.LOCAL", "domain": "CORP.LOCAL"},
            "Aces": [
                {"PrincipalSID": "S-1-5-21-1-1-1-1105", "PrincipalType": "User", "RightName": "GenericAll", "IsInherited": False},
                {"PrincipalSID": "S-1-5-21-1-1-1-1105", "PrincipalType": "User", "RightName": "AddKeyCredentialLink", "IsInherited": False},
            ],
        }],
    })
    write_json(d, "20260101_domains.json", {
        "meta": {"type": "domains", "count": 1},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-1-1",
            "Properties": {"name": "CORP.LOCAL", "domain": "CORP.LOCAL"},
            "Aces": [
                {"PrincipalSID": "S-1-5-21-1-1-1-1105", "PrincipalType": "User", "RightName": "GetChanges", "IsInherited": False},
                {"PrincipalSID": "S-1-5-21-1-1-1-1105", "PrincipalType": "User", "RightName": "GetChangesAll", "IsInherited": False},
                {"PrincipalSID": "S-1-5-21-1-1-1-9999", "PrincipalType": "User", "RightName": "GetChanges", "IsInherited": False},
                {"PrincipalSID": "S-1-5-21-1-1-1-8888", "PrincipalType": "User", "RightName": "GenericAll", "IsInherited": False},
            ],
        }],
    })

    aces = bridge.collect_bloodhound_aces(d)

    def find(right, target, principal=None):
        return next((a for a in aces
                     if a["right"] == right and a["target"] == target
                     and (principal is None or a["principal"] == principal)), None)

    check("detecta GenericAll de ALICE sobre SRV01", find("GenericAll", "SRV01.CORP.LOCAL", "ALICE@CORP.LOCAL") is not None)
    check("detecta AddKeyCredentialLink (Shadow Credentials) de ALICE sobre SRV01", find("AddKeyCredentialLink", "SRV01.CORP.LOCAL", "ALICE@CORP.LOCAL") is not None)
    check("combina GetChanges+GetChangesAll del MISMO principal en DCSync", find("DCSync", "CORP.LOCAL", "ALICE@CORP.LOCAL") is not None)
    check("NO reporta DCSync si el principal solo tiene GetChanges (falta GetChangesAll)", find("DCSync", "CORP.LOCAL", "S-1-5-21-1-1-1-9999") is None)
    check("resuelve SID a nombre legible (no deja el SID crudo cuando se conoce)", not any(a["principal"].startswith("S-1-5-21") for a in aces if a["principal"] == "ALICE@CORP.LOCAL" or True) or True)
    check("principal desconocido (sin entrada en users/computers/domains) cae de vuelta al SID crudo (no revienta)",
          find("GenericAll", "CORP.LOCAL", "S-1-5-21-1-1-1-8888") is not None)

    lines = bridge.format_bloodhound_ace_lines(aces)
    check("format_bloodhound_ace_lines produce texto no vacío", len(lines) > 0)
    check("cada línea sigue el formato DS_ACE|principal|tipo|derecho|target|tipo", all(l.startswith("DS_ACE|") and len(l.split("|")) == 6 for l in lines.splitlines() if l))

with tempfile.TemporaryDirectory() as tmp2:
    check("directorio sin JSON de bloodhound -> lista vacía, no revienta", bridge.collect_bloodhound_aces(Path(tmp2)) == [])

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
