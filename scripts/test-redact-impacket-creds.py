#!/usr/bin/env python3
"""
Bug encontrado en auditoría: redact_args() solo cubre flags conocidos
(-p/--password) y el patrón query-string password=/pwd=. No reconoce el
formato de conexión estilo impacket "domain/user:pass[@host]" que usan
lookupsid.py/samrdump.py/GetUserSPNs.py/findDelegation.py (adAuthCollectionSteps
en vuln-kb.js) — la contraseña real del dominio quedaba en texto plano en
el audit log persistido a disco.
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


redact = bridge.redact_args

# Formato exacto usado por lookupsid.py/samrdump.py con host embebido.
# NOTA: se redacta TODO tras el ":" (incluido el @host que sigue), no solo
# hasta el primer "@" — una contraseña que contenga "@" haría que "hasta el
# primer @" filtrara el resto de la contraseña real (ambigüedad real de
# este formato: ver caso r6 más abajo). El host va por separado en otros
# args (-dc-ip, etc.), así que no se pierde información real.
r1 = redact(["CORP.LOCAL/auditor:P@ssw0rd123@10.0.0.5", "2000"])
check("lookupsid/samrdump: contraseña real NO aparece en el arg redactado", "P@ssw0rd123" not in r1[0])
check("lookupsid/samrdump: domain/user se conservan (útiles para depurar)", r1[0].startswith("CORP.LOCAL/auditor:"))
check("lookupsid/samrdump: resto de args intacto", r1[1] == "2000")

# Formato sin host embebido (GetUserSPNs.py/findDelegation.py).
r2 = redact(["CORP.LOCAL/auditor:P@ssw0rd123", "-dc-ip", "10.0.0.5"])
check("GetUserSPNs/findDelegation: contraseña real NO aparece", "P@ssw0rd123" not in r2[0])
check("GetUserSPNs/findDelegation: domain/user se conservan", r2[0].startswith("CORP.LOCAL/auditor:"))
check("GetUserSPNs/findDelegation: resto de args intacto", r2[1] == "-dc-ip" and r2[2] == "10.0.0.5")

# No debe romper el formato ya cubierto (flags -p, password= en query string).
r3 = redact(["-p", "secreto123", "smb", "10.0.0.5"])
check("no rompe el redactado ya existente de -p <valor>", r3[1] == "***REDACTED***")

r4 = redact(["email=admin@x.com&password=secreto123"])
check("no rompe el redactado ya existente de password= en body", "secreto123" not in r4[0])

# No debe falsear-positivo sobre URLs normales sin credenciales.
r5 = redact(["https://acme.com/login.php", "-d", "user=admin"])
check("URL normal sin credenciales no se toca", r5[0] == "https://acme.com/login.php")

# Contraseña con caracteres especiales típicos (@, /, :) no rompe el parseo.
r6 = redact(["CORP.LOCAL/svc_backup:P@ss/w0rd:2024@dc01.corp.local"])
check("contraseña con @ y : y / dentro no filtra el valor completo", "P@ss/w0rd:2024" not in r6[0])

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
