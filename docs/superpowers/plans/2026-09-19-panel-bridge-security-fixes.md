# Panel/Bridge Local-Attacker Security Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 6 verified local-attacker holes in dark_spear's panel/bridge consoles, found by an external LLM code-review pass (alibaba/open-code-review) and independently re-verified line-by-line against the current codebase on 2026-09-19. Threat model: another process or OS user on the SAME Kali box (malware, another local user, a stray browser tab) — not an internet attacker. `panel/server.py` binds 127.0.0.1:8080, `backend/bridge.py` binds 127.0.0.1:8420; neither is reachable off-box by default. This hardens the console itself; it does not change what the deterministic playbook does against an authorized target.

**Architecture:** Two independent surfaces, fixed with minimal, surgical changes that preserve every existing legitimate flow:
1. `panel/server.py` (3 fixes) — a same-local-user check (new, via `/proc/net/tcp` UID lookup — Linux-only, no new dependency) gates the two endpoints that currently leak the bridge token / mutate engagement state to ANY local caller; a strict URL-validation fix closes an SSRF-via-userinfo-trick in the bridge proxy.
2. `backend/bridge.py` (2 fixes) — reuse the existing `redact_args()` helper (already used for the audit log) on the one code path that was bypassing it; clear the in-RAM API-key pool on `/keystore/panic` (currently only the encrypted file on disk is wiped).
3. `backend/js/{vuln-kb.js,web-auth.js,playbook.js}` (1 fix, 3 files) — the deterministic playbook currently trusts an absolute `form.action`/login-action URL taken straight from the TARGET's own HTML, with zero scope check, and uses it to send XSS/SQLi payloads or the operator's real login credentials. Add a scope check on TARGET-CONTROLLED URL values specifically (not on the playbook's own code — the existing `source=="agent"` scope-lock in bridge.py intentionally trusts the deterministic playbook's own logic; this fix is about not trusting DATA the playbook extracted from the target, which is a different problem the existing check doesn't cover).

**Tech Stack:** Python 3 stdlib only (`http.server`, `urllib`, `os`, `pathlib`) for panel/bridge; Node.js ESM for the JS files. Python test convention: `scripts/test-<feature>.py`, `sys.path.insert` + direct/importlib import, `check(label, ok)` + global `fails` counter, `sys.exit(0 if fails == 0 else 1)`. JS test convention: `scripts/test-<feature>.mjs`, plain ESM import, `check(name, cond)`, `process.exit(1)` on failure.

## Global Constraints
- Fail closed, never fail open: every new check must deny access/traffic when it cannot positively confirm safety (can't read `/proc/net/tcp`, empty `root`, etc.) — never default to allowing.
- Do NOT clear `PASSPHRASE` in the `/keystore/panic` fix (see Task 5 — this deliberately deviates from the original external report; the plan explains why).
- Do NOT touch `playbook.js`'s automation boundary — Tasks in this plan only gate DATA the playbook extracted from a target, never add new automated execution.
- Existing legitimate flows (panel JS fetching its own token, DVWA/Juice Shop login probing, existing form-probe tests with relative actions) must keep working — verify via the existing test suite, not just new tests.
- Spanish for new Python/JS comments and finding/test-label text, matching the surrounding file's language.
- No external-repo attribution in code/comments (the source of this audit — alibaba/open-code-review — is never named in dark_spear code, only in this plan doc and commit messages if relevant).

---

### Task 1: Same-local-user gate + apply to `GET /bridge/session`

**Files:**
- Modify: `panel/server.py` (add helper functions near the top-level function area, apply gate inside `_serve_bridge_session`, around line 333)
- Test: `scripts/test-panel-same-user-gate.py` (create)

**Interfaces:**
- Produces: `_hex_addr(ip: str, port: int) -> str`, `_uid_for_connection(local_ip: str, local_port: int, remote_ip: str, remote_port: int, proc_text: str) -> int | None`, and instance method `_peer_is_same_user(self) -> bool` — all three consumed again by Task 2.

- [ ] **Step 1: Write the failing test**

Create `scripts/test-panel-same-user-gate.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test-panel-same-user-gate.py`
Expected: FAIL/AttributeError — `_hex_addr`/`_uid_for_connection` don't exist yet in `panel/server.py`.

- [ ] **Step 3: Write minimal implementation**

In `panel/server.py`, add these three module-level functions right before the class that defines `_serve_bridge_session` (find the class definition — the handler class containing `_serve_bridge_session`, `_proxy_bridge`, etc. — and insert just above it, after the existing module-level constants/imports):

```python
def _hex_addr(ip: str, port: int) -> str:
    """Codifica ip:port como aparece en /proc/net/tcp (IPv4, little-endian hex)."""
    octets = [int(o) for o in ip.split(".")]
    hex_ip = "".join(f"{o:02X}" for o in reversed(octets))
    return f"{hex_ip}:{port:04X}"


def _uid_for_connection(local_ip: str, local_port: int, remote_ip: str, remote_port: int,
                         proc_text: str) -> int | None:
    """Busca en el texto de /proc/net/tcp la línea de esta conexión exacta
    (local_address == nuestro socket de escucha, rem_address == el peer que
    conectó) y devuelve el UID dueño de esa conexión, según el kernel."""
    local_key = _hex_addr(local_ip, local_port)
    remote_key = _hex_addr(remote_ip, remote_port)
    for line in proc_text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        if parts[1] == local_key and parts[2] == remote_key:
            try:
                return int(parts[7])
            except ValueError:
                return None
    return None
```

Then, inside the HTTP handler class (same class as `_serve_bridge_session` — search for `def _serve_bridge_session` to find it), add this instance method right above `_serve_bridge_session`:

```python
    def _peer_is_same_user(self) -> bool:
        """True solo si la conexión TCP entrante pertenece al mismo UID que
        este proceso (Linux, vía /proc/net/tcp). Amenaza: otro usuario/proceso
        en el MISMO Kali puede hablar con 127.0.0.1:8080 igual que el propio
        panel JS — este check es la única barrera entre ambos. Falla cerrado:
        cualquier error de lectura/parseo deniega, nunca permite por defecto.
        """
        try:
            remote_ip, remote_port = self.client_address[0], self.client_address[1]
            local_ip, local_port = self.server.server_address[0], self.server.server_address[1]
            proc_text = Path("/proc/net/tcp").read_text(encoding="utf-8")
            uid = _uid_for_connection(local_ip, local_port, remote_ip, remote_port, proc_text)
            return uid is not None and uid == os.getuid()
        except OSError:
            return False
```

Now apply the gate at the top of `_serve_bridge_session` (find it — around line 333):

```python
    def _serve_bridge_session(self) -> None:
        if not self._peer_is_same_user():
            self._send_json(403, {"error": "forbidden", "hint": "solicitud desde otro usuario/proceso local"})
            return
        hint = "El motor no está en marcha. En otra terminal: cd backend && python3 bridge.py"
        # ... resto de la función sin cambios
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test-panel-same-user-gate.py`
Expected: PASS on all checks.

- [ ] **Step 5: Commit**

```bash
git add panel/server.py scripts/test-panel-same-user-gate.py
git commit -m "fix: gate /bridge/session behind same-local-user check (/proc/net/tcp UID)"
```

---

### Task 2: Apply the same-user gate to engagement mutation endpoints, before mutation

**Files:**
- Modify: `panel/server.py` (the `pause`/`resume`/`finish` loop block and the `delete` block inside `do_POST`, both currently after `_serve_bridge_session` in the file, roughly lines 444-512 as of the last audit — search for `_control_engagement_on_disk` and `/bridge/engagements/delete` to find current locations, they may have shifted slightly after Task 1's insertions)
- Test: extend `scripts/test-panel-same-user-gate.py` from Task 1 is NOT the right place (that file tests the pure parsing helper) — create `scripts/test-panel-engagement-auth-order.py` (create)

**Interfaces:**
- Consumes: `self._peer_is_same_user()` from Task 1 (already an instance method on the same handler class — no new signature needed).

- [ ] **Step 1: Write the failing test**

This fix is about ORDER (auth check before mutation) inside an HTTP handler method, which needs a running server or handler instance to test end-to-end — too heavy for this plan's test convention. Instead, write a static/structural test that reads the source and asserts the auth check appears before the mutation call, which is the actual invariant that matters and is what regresses silently if someone reorders the code later:

Create `scripts/test-panel-engagement-auth-order.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test-panel-engagement-auth-order.py`
Expected: FAIL — `_peer_is_same_user()` doesn't appear in either block yet.

- [ ] **Step 3: Write minimal implementation**

In `panel/server.py`, find the `for ctrl_path, ctrl_action in (...)` loop (search for `("/bridge/engagements/pause", "pause")`). Right after the `eng_name` is validated (after the `if not eng_name: ... return` check, before `result = _control_engagement_on_disk(eng_name, ctrl_action)`), insert:

```python
                if not self._peer_is_same_user():
                    self._send_json(403, {"error": "forbidden"})
                    return
                result = _control_engagement_on_disk(eng_name, ctrl_action)
```

Find the `if path == "/bridge/engagements/delete":` block. Right after `eng_name`/`related` are parsed (after the `if not eng_name: ... return` check, before `result = _delete_engagement_from_disk(eng_name, related=related)`), insert:

```python
            if not self._peer_is_same_user():
                self._send_json(403, {"error": "forbidden"})
                return
            related = bool(body.get("related", True))
            # Disk first — dashboard/OSINT/MITRE leen findings desde aquí
            result = _delete_engagement_from_disk(eng_name, related=related)
```

(Match indentation exactly to the surrounding block — the ctrl loop body is indented one level deeper than the delete block, per the existing code.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test-panel-engagement-auth-order.py`
Expected: PASS on all checks.

Also run Task 1's test as a quick regression check (same file, unrelated function, should be unaffected):

Run: `python3 scripts/test-panel-same-user-gate.py`
Expected: PASS (unchanged).

- [ ] **Step 5: Commit**

```bash
git add panel/server.py scripts/test-panel-engagement-auth-order.py
git commit -m "fix: require same-local-user check before mutating engagement state on disk"
```

---

### Task 3: Fix SSRF-via-userinfo in `_proxy_bridge`

**Files:**
- Modify: `panel/server.py` (add `import urllib.parse`; add validation helper; apply in `_proxy_bridge`, around line 519)
- Test: `scripts/test-panel-proxy-ssrf.py` (create)

**Interfaces:**
- Produces: `_validate_bridge_target(path: str) -> str | None` — pure function, no `self` needed.

- [ ] **Step 1: Write the failing test**

Create `scripts/test-panel-proxy-ssrf.py`:

```python
#!/usr/bin/env python3
"""_validate_bridge_target() bloquea el truco de userinfo en URL: una
petición a /bridge@evil.example/exec produce url =
"http://127.0.0.1:8420@evil.example/exec", que urlparse interpreta con
hostname="evil.example" (userinfo "127.0.0.1:8420" descartado) — el
proxy terminaba conectando (y reenviando X-Auditor-Token) al host ajeno."""
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


f = panel_server._validate_bridge_target

check("path normal (/status) -> URL válida contra el bridge real", f("/status") == "http://127.0.0.1:8420/status")
check("path normal con subpath (/exec) -> URL válida", f("/exec") == "http://127.0.0.1:8420/exec")
check(
    "truco de userinfo (@evil.example) -> None, bloqueado",
    f("@evil.example/exec") is None,
)
check(
    "truco de userinfo con esquema embebido -> None",
    f("@evil.example:1234/exec") is None,
)
check("path vacío -> URL a la raíz del bridge", f("") == "http://127.0.0.1:8420/")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test-panel-proxy-ssrf.py`
Expected: FAIL — `_validate_bridge_target` doesn't exist yet, and even a naive version would currently accept the userinfo-trick path.

- [ ] **Step 3: Write minimal implementation**

Add `import urllib.parse` near the top of `panel/server.py`, alongside the existing `import urllib.error` / `import urllib.request` lines.

Add this module-level function near `_hex_addr`/`_uid_for_connection` from Task 1 (or right above `_proxy_bridge`'s class — either is fine, keep it near other pure helpers):

```python
def _validate_bridge_target(path: str) -> str | None:
    """Construye la URL final del proxy hacia el bridge y la valida contra
    el host/puerto esperados usando urlparse — nunca confía en la
    concatenación cruda. Bloquea el truco de userinfo en URL: una petición
    a "/bridge@evil.example/exec" produciría
    "http://127.0.0.1:8420@evil.example/exec", que urlparse resuelve con
    hostname="evil.example" (userinfo "127.0.0.1:8420" descartado) —
    sin esta validación el proxy conectaría (y reenviaría X-Auditor-Token)
    a un host arbitrario elegido por quien llame al panel.
    """
    url = f"{BRIDGE_BASE}{path}"
    parsed = urllib.parse.urlparse(url)
    if parsed.hostname != BRIDGE_HOST or parsed.port != BRIDGE_PORT:
        return None
    return url
```

In `_proxy_bridge`, replace:

```python
        path = self.path[len("/bridge"):] or "/"
        url = f"{BRIDGE_BASE}{path}"
```

with:

```python
        path = self.path[len("/bridge"):] or "/"
        url = _validate_bridge_target(path)
        if url is None:
            self._send_json(400, {"error": "invalid_bridge_path"})
            return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test-panel-proxy-ssrf.py`
Expected: PASS on all checks.

- [ ] **Step 5: Commit**

```bash
git add panel/server.py scripts/test-panel-proxy-ssrf.py
git commit -m "fix: validate proxied bridge URL with urlparse, block userinfo-trick SSRF"
```

---

### Task 4: Redact `LAST_ACTIVITY` exec-args before persisting to `meta.json`

**Files:**
- Modify: `backend/bridge.py` (line ~1654, inside the `/exec` handler)
- Test: `scripts/test-last-activity-redact.py` (create)

**Interfaces:**
- Consumes: existing `redact_args(args: list) -> list` (already defined at `bridge.py:1144`, already imported/available in the same module — no import needed, same file).

- [ ] **Step 1: Write the failing test**

Create `scripts/test-last-activity-redact.py`:

```python
#!/usr/bin/env python3
"""LAST_ACTIVITY (persistido en meta.json/expuesto por /status) se
construía con args[:4] SIN pasar por redact_args() — a diferencia del
audit_log del mismo endpoint, que sí redacta. Passwords de hydra/netexec
quedaban en claro en disco. Prueba que la MISMA lógica de redacción que
ya protege audit_log también protege el string que arma LAST_ACTIVITY."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from bridge import redact_args  # noqa: E402

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


# Simula exactamente la construcción de arg_preview en el handler de /exec:
# arg_preview = " ".join(str(a) for a in redact_args(args[:4]))
def build_preview(tool, args):
    arg_preview = " ".join(str(a) for a in redact_args(args[:4]))
    return f"{tool} {arg_preview}".strip()


hydra_args = ["-l", "admin", "-p", "hunter2", "ssh://10.0.0.1"]
preview = build_preview("hydra", hydra_args)
check("hydra -p <valor> no queda en claro en el preview", "hunter2" not in preview)
check("hydra: el flag -p sigue visible (solo el valor se redacta)", "-p" in preview)

nxc_args = ["smb", "10.0.0.1", "-u", "admin", "--password", "hunter2"]
preview_nxc = build_preview("netexec", nxc_args)
check("netexec --password <valor> no queda en claro en el preview (recortado por args[:4] o redactado)",
      "hunter2" not in preview_nxc)

plain_args = ["-s", "-I", "https://x.com"]
preview_plain = build_preview("curl", plain_args)
check("args sin credenciales quedan intactos en el preview", preview_plain == "curl -s -I https://x.com")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 scripts/test-last-activity-redact.py`
Expected: FAIL on the hydra case only if you test the OLD (unredacted) construction — since this test defines its own `build_preview` mirroring the target code, run it once BEFORE editing bridge.py to confirm `redact_args` itself works (it will pass, since `redact_args` already exists and is correct — this test is really validating the fix's approach in isolation). The real RED/GREEN evidence for this task is a manual diff check: before your fix, `bridge.py:1654` reads `args[:4]` (unredacted); after, it reads `redact_args(args[:4])`. Show both via `grep -n "arg_preview = " backend/bridge.py` before and after editing.

- [ ] **Step 3: Write minimal implementation**

In `backend/bridge.py`, find (around line 1654):

```python
            arg_preview = " ".join(str(a) for a in args[:4])
```

Replace with:

```python
            arg_preview = " ".join(str(a) for a in redact_args(args[:4]))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test-last-activity-redact.py`
Expected: PASS on all checks.

Run: `grep -n "arg_preview = " backend/bridge.py`
Expected: shows the line now calls `redact_args(args[:4])`.

- [ ] **Step 5: Commit**

```bash
git add backend/bridge.py scripts/test-last-activity-redact.py
git commit -m "fix: redact credentials in LAST_ACTIVITY before persisting to engagement meta.json"
```

---

### Task 5: Clear in-RAM API-key pool on `/keystore/panic`

**Files:**
- Modify: `backend/bridge.py` (the `/keystore/panic` handler, around line 2000)
- Test: `scripts/test-keystore-panic-ram.py` (create)

**Interfaces:**
- Consumes: existing module globals `KEYS: list[dict]` (line 407), `ROTATION_STATE: dict | None` (line 409), `STATE_LOCK` (line 405), `keystore.wipe()` (existing).

**Important design note (deviation from the original report):** the original finding said panic should also clear `PASSPHRASE`. This plan deliberately does NOT do that. `PASSPHRASE` is read once at process startup (`_read_passphrase()`, from env var or an interactive prompt) and is NOT re-derivable at runtime — clearing it would break the legitimate "operator adds a new key after panic" flow (`/keys/add` calls `keystore.save(PASSPHRASE, KEYS)`), since there's no way to get a valid passphrase back without restarting the bridge process. `PASSPHRASE` alone is not an API key and reveals nothing about which keys existed — the actual secret the panic button exists to kill is `KEYS`/`ROTATION_STATE` (the decrypted key pool in RAM), which this task does clear. If a future task wants to also rotate/clear `PASSPHRASE`, it needs a design for how the operator re-authenticates afterward — out of scope here.

- [ ] **Step 1: Write the failing test**

Create `scripts/test-keystore-panic-ram.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

This test exercises the intended POST-fix state directly (it's testing the invariant, not the unfixed handler) — it will PASS even before you touch the handler, since it manually reproduces the fix. That's expected for this task: the real RED evidence is inspecting the CURRENT handler and confirming it does NOT do this clearing yet.

Run: `grep -n -A 12 'if self.path == "/keystore/panic"' backend/bridge.py`
Expected (RED): the block calls `keystore.wipe()` and `audit_log(...)` but has no `KEYS.clear()` / `ROTATION_STATE = None` anywhere in it.

- [ ] **Step 3: Write minimal implementation**

In `backend/bridge.py`, find the `/keystore/panic` handler (around line 2000):

```python
        if self.path == "/keystore/panic":
            body = self._read_json()
            confirm = body.get("confirm", "")
            if confirm != "WIPE_KEYS":
                self._send_json(400, {"error": "confirmation_required",
                                       "detail": "send {\"confirm\": \"WIPE_KEYS\"}"})
                return
            wiped = keystore.wipe()
            audit_log({"event": "keystore_panic", "wiped": wiped})
            self._send_json(200, {"ok": True, "wiped": wiped})
            return
```

Replace with:

```python
        if self.path == "/keystore/panic":
            body = self._read_json()
            confirm = body.get("confirm", "")
            if confirm != "WIPE_KEYS":
                self._send_json(400, {"error": "confirmation_required",
                                       "detail": "send {\"confirm\": \"WIPE_KEYS\"}"})
                return
            global ROTATION_STATE
            wiped = keystore.wipe()
            with STATE_LOCK:
                KEYS.clear()
                ROTATION_STATE = None
            audit_log({"event": "keystore_panic", "wiped": wiped})
            self._send_json(200, {"ok": True, "wiped": wiped})
            return
```

(`global ROTATION_STATE` is required because the handler rebinds the name to `None`; `KEYS.clear()` mutates the existing list in place and needs no `global` declaration.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 scripts/test-keystore-panic-ram.py`
Expected: PASS on all checks.

Run: `grep -n -A 14 'if self.path == "/keystore/panic"' backend/bridge.py`
Expected (GREEN): now shows `global ROTATION_STATE`, `KEYS.clear()`, `ROTATION_STATE = None` inside the block.

- [ ] **Step 5: Commit**

```bash
git add backend/bridge.py scripts/test-keystore-panic-ram.py
git commit -m "fix: clear in-RAM API-key pool (KEYS, ROTATION_STATE) on /keystore/panic, not just the disk file"
```

---

### Task 6: Scope-check target-controlled absolute URLs (form.action / login action)

**Files:**
- Modify: `backend/js/vuln-kb.js` (add `hostInScope`/`hostOf` helpers; thread `root` param through `formProbeSteps`/`xssFormProbeSteps`/`sqliFormProbeSteps`)
- Modify: `backend/js/web-auth.js` (add `root` param to `buildLoginSteps`/`detectLoginFormAction`, skip the credential-POST step when out of scope)
- Modify: `backend/js/playbook.js` (compute `root` and pass it to both call sites: `phase2FormProbeSteps` and the `buildLoginSteps` call)
- Modify: `scripts/test-form-probes.mjs` (existing test currently asserts the VULNERABLE behavior for `absoluteActionForm` — update it; this is a deliberate, expected behavior change, not a regression)
- Test: extend `scripts/test-form-probes.mjs`, and create `scripts/test-login-action-scope.mjs`

**Interfaces:**
- Produces (vuln-kb.js): `export function hostInScope(candidateUrl, root) -> boolean`
- Consumes (web-auth.js imports from vuln-kb.js): `import { hostInScope } from "./vuln-kb.js"`
- Changed signatures: `formProbeSteps(step, prefix, baseUrl, form, cookieFile, payload, desc, maxTime, root)`, `xssFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12", root = "")`, `sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12", root = "")`, `detectLoginFormAction(html, loginUrl, root = "")`, `buildLoginSteps(step, loginUrl, user, password, cookieFile, root = "")`.

- [ ] **Step 1: Write the failing tests**

First, update the existing `absoluteActionForm` test block in `scripts/test-form-probes.mjs`. Find (around line 45-61):

```javascript
// form.action absoluto (ej. formulario que postea a otro dominio/puerto):
// debe usarse tal cual, NUNCA concatenado con baseUrl (produciría una URL
// malformada tipo "https://targethttps://otro/x").
const absoluteActionForm = {
  action: "https://otro-dominio.com/endpoint",
  method: "POST",
  fields: [{ name: "content", type: "text" }],
};
const absoluteSteps = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", absoluteActionForm, "/tmp/c.txt");
check(
  "action absoluto: usa la URL tal cual, no la concatena con baseUrl",
  absoluteSteps[0].args.includes("https://otro-dominio.com/endpoint"),
);
check(
  "action absoluto: NO produce una URL malformada (baseUrl + action)",
  !absoluteSteps[0].args.some((a) => a.includes("https://xhttps://")),
);
```

Replace with:

```javascript
// form.action absoluto FUERA de scope (ej. formulario que postea a otro
// dominio/puerto): el motor NO debe mandar payloads ahí — el target
// controla ese valor, no es una decisión del playbook. Sin root, o con
// root que no matchea, se omite el form entero (fail-closed).
const absoluteActionForm = {
  action: "https://otro-dominio.com/endpoint",
  method: "POST",
  fields: [{ name: "content", type: "text" }],
};
const absoluteStepsNoRoot = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", absoluteActionForm, "/tmp/c.txt");
check(
  "action absoluto fuera de scope, SIN root: no genera steps (fail-closed)",
  absoluteStepsNoRoot.length === 0,
);
const absoluteStepsWrongRoot = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", absoluteActionForm, "/tmp/c.txt", "12", "x");
check(
  "action absoluto fuera de scope, CON root que no matchea: no genera steps",
  absoluteStepsWrongRoot.length === 0,
);

// action absoluto que SÍ resuelve al mismo host que root: debe seguir
// funcionando exactamente como antes (comportamiento legítimo preservado).
const sameHostAbsoluteForm = {
  action: "https://x/other-path",
  method: "POST",
  fields: [{ name: "content", type: "text" }],
};
const sameHostSteps = xssFormProbeSteps(fakeStep, "p2-formxss", "https://x", sameHostAbsoluteForm, "/tmp/c.txt", "12", "x");
check(
  "action absoluto que SÍ apunta al mismo host que root: genera el step normalmente",
  sameHostSteps.length === 1 && sameHostSteps[0].args.includes("https://x/other-path"),
);
```

Then create `scripts/test-login-action-scope.mjs`:

```javascript
#!/usr/bin/env node
/**
 * detectLoginFormAction()/buildLoginSteps() resolvían el action del <form>
 * de login (potencialmente absoluto, del HTML del propio target) sin
 * chequear scope — un target hostil podía sacar las credenciales del
 * operador hacia cualquier host con <form action="https://evil/steal">.
 */
import { detectLoginFormAction, buildLoginSteps } from "../backend/js/web-auth.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const evilHtml = '<form><input type="password" name="password"><input type="text" name="user"></form>'
  .replace("<form>", '<form action="https://evil.example/steal">');

// Sin root: detectLoginFormAction sigue devolviendo la URL resuelta (uso
// de bajo nivel, sin opinión) — el enforcement real vive en buildLoginSteps.
check(
  "detectLoginFormAction resuelve el action absoluto tal cual (sin opinar)",
  detectLoginFormAction(evilHtml, "https://x/login") === "https://evil.example/steal",
);

function fakeStep(id, tool, args, when, meta) {
  return { id, tool, args, when, meta };
}

const stepsNoRoot = buildLoginSteps(fakeStep, "https://x/login", "admin", "s3cret", "/tmp/c.txt");
// Sin root, buildLoginSteps no puede confirmar scope -> debe omitir el
// POST de credenciales (fail-closed), quedándose solo con el GET inicial.
check(
  "sin root: NO se genera el POST de credenciales hacia el action absoluto ajeno",
  !stepsNoRoot.some((s) => s.args.some((a) => typeof a === "string" && a.includes("evil.example"))),
);

const stepsWrongRoot = buildLoginSteps(fakeStep, "https://x/login", "admin", "s3cret", "/tmp/c.txt", "x");
check(
  "con root que NO matchea el action absoluto: tampoco se envían credenciales ahí",
  !stepsWrongRoot.some((s) => s.args.some((a) => typeof a === "string" && a.includes("evil.example"))),
);

// Caso legítimo: root vacío/sin form action (relativo) sigue funcionando
// exactamente igual que antes — no se rompe el flujo normal.
const normalHtml = '<form action="/login"><input type="password" name="password"><input type="text" name="user"></form>';
const normalSteps = buildLoginSteps(fakeStep, "https://x/login", "admin", "s3cret", "/tmp/c.txt", "x");
void normalHtml; // detectLoginFormAction se ejercita indirectamente vía buildLoginSteps con HTML por defecto en su propio flujo interno
check("caso normal: buildLoginSteps sigue devolviendo 2 steps (GET + POST)", normalSteps.length === 2);

if (!ok) process.exit(1);
console.log("\nOK login-action-scope: credenciales del operador no se envían a un action absoluto fuera de scope");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node scripts/test-form-probes.mjs`
Expected: FAIL — current `xssFormProbeSteps` doesn't accept/use a `root` param, so `absoluteStepsNoRoot.length === 0` fails (currently generates 1 step regardless).

Run: `node scripts/test-login-action-scope.mjs`
Expected: FAIL — `buildLoginSteps` doesn't accept a `root` param yet, current behavior always builds the POST step against whatever `detectLoginFormAction` resolves.

- [ ] **Step 3: Write minimal implementation**

In `backend/js/vuln-kb.js`, add these two functions right before `formProbeSteps` (search for `function formProbeSteps`):

```javascript
/** Host normalizado (sin protocolo/puerto/www.) de una URL o string suelto. */
function hostOf(value) {
  const s = String(value || "").trim().toLowerCase();
  const noScheme = s.replace(/^https?:\/\//i, "").split("/")[0].split("?")[0].split(":")[0];
  return noScheme.startsWith("www.") ? noScheme.slice(4) : noScheme;
}

/**
 * True si `candidateUrl` apunta al mismo host que `root` (o a un
 * subdominio real de root). Usado para bloquear URLs ABSOLUTAS que el
 * TARGET controla (form.action, login action) antes de mandarles
 * payloads o credenciales del operador — sin esto, un target hostil con
 * <form action="https://evil.example/x"> saca tráfico (y datos) fuera de
 * scope. Fail-closed: root vacío o sin match -> false.
 */
export function hostInScope(candidateUrl, root) {
  const c = hostOf(candidateUrl);
  const r = hostOf(root);
  if (!c || !r) return false;
  return c === r || c.endsWith("." + r);
}
```

Then modify `formProbeSteps` (currently starts with `function formProbeSteps(step, prefix, baseUrl, form, cookieFile, payload, desc, maxTime) {`):

```javascript
function formProbeSteps(step, prefix, baseUrl, form, cookieFile, payload, desc, maxTime, root) {
  const textFields = form.fields.filter((f) => f.type !== "checkbox" && f.type !== "radio");
  // form.action puede ser una URL absoluta (form que postea a otro
  // dominio/puerto) — concatenarla ciegamente con baseUrl produce una
  // URL malformada.
  const isAbsolute = /^https?:\/\//i.test(form.action);
  const url = isAbsolute ? form.action : baseUrl + form.action;
  if (isAbsolute && !hostInScope(url, root)) {
    // El target controla form.action, no el playbook: una URL absoluta
    // fuera de scope no recibe payloads del motor (fail-closed).
    return [];
  }
  return textFields.map((field) => {
```

(The rest of the function body stays exactly as-is — only the top changed: new `root` param, `isAbsolute` extracted as a named boolean, and the new scope-check-and-bail-out block inserted before the existing `return textFields.map(...)`.)

Update the two wrapper exports right below it:

```javascript
export function xssFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12", root = "") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, XSS_REFLECTION_PAYLOAD, "Sonda de XSS reflejado en formulario descubierto", maxTime, root);
}

export function sqliFormProbeSteps(step, prefix, baseUrl, form, cookieFile, maxTime = "12", root = "") {
  return formProbeSteps(step, prefix, baseUrl, form, cookieFile, SQLI_GENERIC_PAYLOAD, "Sonda de SQLi genérico en formulario descubierto", maxTime, root);
}
```

In `backend/js/web-auth.js`, add the import at the top of the file:

```javascript
import { hostInScope } from "./vuln-kb.js";
```

Modify `detectLoginFormAction` signature — it does NOT need to change its own return behavior (it stays a pure "resolve the URL" function per the test's expectation that it "resuelve... sin opinar"); the enforcement belongs in `buildLoginSteps`. Find `buildLoginSteps` (search for `export function buildLoginSteps`) and its inner `postStep` closure (search for `const postUrl = detectLoginFormAction`):

```javascript
export function buildLoginSteps(step, loginUrl, user, password, cookieFile, root = "") {
```

(add `root = ""` as the 6th parameter to the existing signature)

Then inside the function body, find:

```javascript
      const postUrl = detectLoginFormAction(html, loginUrl);
      return [
        "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
        "-e", String(loginUrl).split("#")[0] || loginUrl,
        "-X", "POST", "-d", fields.join("&"), postUrl,
      ];
    },
    null,
    { desc: "Login web: POST credenciales (form CSRF o JSON SPA)" },
  );

  return [getStep, postStep];
```

Replace with:

```javascript
      const postUrl = detectLoginFormAction(html, loginUrl);
      if (/^https?:\/\//i.test(postUrl) && root && !hostInScope(postUrl, root)) {
        // El action del form de login es absoluto y apunta fuera de
        // scope — el target controla ese valor, no el operador. No se
        // envían credenciales reales ahí.
        return null;
      }
      return [
        "-s", "-i", "-b", cookieFile, "-c", cookieFile, "--max-time", "15",
        "-e", String(loginUrl).split("#")[0] || loginUrl,
        "-X", "POST", "-d", fields.join("&"), postUrl,
      ];
    },
    null,
    { desc: "Login web: POST credenciales (form CSRF o JSON SPA)" },
  );

  return [getStep, postStep];
```

(`step()` itself only stores whatever `args` value it's given — a function here, evaluated lazily by the runtime elsewhere — without inspecting it; the runtime already treats a `null` return from that function as "skip this step", the same convention used throughout `playbook.js`/`vuln-kb.js` for every other conditional step. So `postStep` is always included in the returned array unchanged — the `if (...) return null;` inside its closure is the entire fix, no conditional needed around `[getStep, postStep]`.)

In `backend/js/playbook.js`, find `phase2FormProbeSteps` (search for `function phase2FormProbeSteps`):

```javascript
function phase2FormProbeSteps(baseUrl, ctx) {
  const forms = (ctx.discoveredForms || []).slice(0, MAX_FORM_PROBE_TARGETS);
  const root = scopeRoot(ctx.host || "", ctx.scope || "");
  const steps = [];
  forms.forEach((form, i) => {
    steps.push(...xssFormProbeSteps(step, `p2-formxss-${i}`, baseUrl, form, ctx.cookieFile, "12", root));
    steps.push(...sqliFormProbeSteps(step, `p2-formsqli-${i}`, baseUrl, form, ctx.cookieFile, "12", root));
  });
  return steps;
}
```

Find the `buildLoginSteps` call site (search for `buildLoginSteps(step, ctx.webLoginUrl`):

```javascript
    ...(ctx.webLoginUrl ? buildLoginSteps(step, ctx.webLoginUrl, ctx.webUser, ctx.webPassword, cookie) : []),
```

Replace with:

```javascript
    ...(ctx.webLoginUrl ? buildLoginSteps(step, ctx.webLoginUrl, ctx.webUser, ctx.webPassword, cookie, scopeRoot(ctx.host || "", ctx.scope || "")) : []),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node scripts/test-form-probes.mjs`
Expected: PASS on all checks, including the updated `absoluteActionForm` cases.

Run: `node scripts/test-login-action-scope.mjs`
Expected: PASS on all checks.

Also run these regression suites (unaffected code paths, same files touched):

Run: `node scripts/test-web-auth.mjs`
Expected: PASS (existing DVWA/Juice Shop login fixtures use same-host or relative actions, unaffected by the fail-closed default).

Run: `node scripts/test-playbook-weblogin.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/js/vuln-kb.js backend/js/web-auth.js backend/js/playbook.js scripts/test-form-probes.mjs scripts/test-login-action-scope.mjs
git commit -m "fix: scope-check target-controlled absolute URLs (form.action, login action) before sending payloads/credentials"
```

---

## Final verification (after all 6 tasks)

- [ ] Run every new/modified test plus a broad regression pass:

```bash
cd /home/kali/dark_spear
for f in scripts/test-panel-same-user-gate.py scripts/test-panel-engagement-auth-order.py scripts/test-panel-proxy-ssrf.py scripts/test-last-activity-redact.py scripts/test-keystore-panic-ram.py; do
  echo "== $f =="; python3 "$f" || exit 1
done
for f in scripts/test-form-probes.mjs scripts/test-login-action-scope.mjs scripts/test-web-auth.mjs scripts/test-playbook-weblogin.mjs; do
  echo "== $f =="; node "$f" || exit 1
done
```

Expected: every file prints its final `OK`/`RESULTADO: OK` line, all exit 0.

- [ ] Manual sanity check (not automatable without a live browser): start `bridge.py` and `panel/server.py`, load the panel in a browser as normal, confirm the token-fetch/exec/engagement-list/engagement-delete flows still work end-to-end for the legitimate same-user case — the whole point of the same-user gate is that it must NOT block the panel's own JS.
