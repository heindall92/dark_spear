#!/usr/bin/env python3
"""
wapiti/arjun con -o //-oJ /dev/stdout fallan bajo pipe real (sin pty):
OSError: [Errno 6] No such device or address. subprocess.run del bridge
usa pipes reales, no un pty (a diferencia de una terminal interactiva,
donde el mismo comando sí funciona) -> hace falta sustituir /dev/stdout
por un tempfile real antes de ejecutar, y leerlo después.
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


# wapiti: -o /dev/stdout -> se sustituye por un tempfile real
args_in = ["-u", "http://x.com/", "-f", "json", "-o", "/dev/stdout", "-v", "0"]
new_args, tmp_path = bridge.rewrite_stdout_placeholder(args_in, "wapiti")
check("wapiti: detecta y reemplaza /dev/stdout", tmp_path is not None)
check("wapiti: el arg -o ya no apunta a /dev/stdout", "/dev/stdout" not in new_args)
check("wapiti: el resto de args queda intacto", new_args[:4] == ["-u", "http://x.com/", "-f", "json"])

# arjun: -oJ /dev/stdout -> mismo tratamiento
args_in2 = ["-u", "http://x.com/", "-oJ", "/dev/stdout", "-q"]
new_args2, tmp_path2 = bridge.rewrite_stdout_placeholder(args_in2, "arjun")
check("arjun: detecta y reemplaza /dev/stdout", tmp_path2 is not None)
check("arjun: el arg -oJ ya no apunta a /dev/stdout", "/dev/stdout" not in new_args2)

# herramientas no afectadas: no se toca nada, sin tempfile
args_in3 = ["-u", "http://x.com/"]
new_args3, tmp_path3 = bridge.rewrite_stdout_placeholder(args_in3, "nuclei")
check("nuclei: no se modifica (no usa /dev/stdout)", new_args3 == args_in3)
check("nuclei: no crea tempfile", tmp_path3 is None)

# wapiti sin /dev/stdout en args (caso raro): no rompe, no crea tempfile
args_in4 = ["-u", "http://x.com/", "-f", "html"]
new_args4, tmp_path4 = bridge.rewrite_stdout_placeholder(args_in4, "wapiti")
check("wapiti sin /dev/stdout en args: no crea tempfile", tmp_path4 is None)
check("wapiti sin /dev/stdout en args: args intactos", new_args4 == args_in4)

# read_and_cleanup_tempfile: lee contenido y borra el archivo
import tempfile as _tempfile
fd, p = _tempfile.mkstemp()
with open(p, "w", encoding="utf-8") as f:
    f.write('{"hello": "world"}')
content = bridge.read_and_cleanup_tempfile(p)
check("lee el contenido del tempfile", content == '{"hello": "world"}')
check("borra el tempfile tras leerlo", not Path(p).exists())

# tempfile inexistente (proceso falló antes de escribir nada): no crashea
check("tempfile inexistente -> string vacío, no excepción", bridge.read_and_cleanup_tempfile("/tmp/ds-no-existe-nunca-12345") == "")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
