# API Key Pool + Failover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the operator register up to 10 Ollama Cloud API keys, select a subset per engagement, and have `bridge.py` transparently rotate through them on quota exhaustion so a long engagement never stops — while also expanding the tool whitelist (impacket + adscan).

**Architecture:** All rotation state and the encrypted key store live server-side in `bridge.py` (new `keystore.py` module for encryption). The browser never sees a raw API key — it only sees labels and a checkbox UI. `/llm/chat` absorbs the rotation/retry logic entirely; `js/agent.js` only needs to recognize one new terminal state (`all_keys_exhausted`) distinct from its existing generic-error handling.

**Tech Stack:** Python 3 stdlib + `cryptography` (Fernet, PBKDF2HMAC) for the keystore. Vanilla JS ES modules, no build step, no new browser dependencies.

**Spec:** `~/tools/auditor/docs/superpowers/specs/2026-08-26-api-key-pool-design.md`

## Global Constraints

- One exception to the project's zero-pip-dependency rule (see `2026-08-21-engine-implementation.md`'s constraints): `bridge.py` now imports `cryptography` for keystore encryption. It is already present system-wide in this environment (`python3 -c "import cryptography"` succeeds, v47.0.0) — no `pip install` step needed here. Note this exception if the project is ever ported to a fresh machine.
- No automated test suite (same decision as the engine plan — personal tool). Every task has a manual verification step with the exact command to run.
- Raw API keys never touch the browser, never appear in `audit_log()` entries, never get logged by `getpass`.
- `keys.enc` is written with `0o600` permissions every time it's rewritten.
- Only an explicit 429 or a response body matching `/quota|limit|rate.?limit/i` triggers key rotation. Every other failure (timeout, malformed JSON, 5xx) continues to flow through the existing `agent_error` / 5-strike path untouched.
- `DANGEROUS_TOOLS` and `ALLOWED_TOOLS` stay hand-edited, static lists — never LLM-generated or runtime-modified.

---

### Task 1: `keystore.py` — encrypted key storage module

**Files:**
- Create: `keystore.py`

**Interfaces:**
- Produces (used by Task 2, 3): `load_or_init(passphrase: str) -> list[dict]` (returns `[]` if no keystore file exists yet; raises `ValueError("invalid_passphrase")` if the file exists but the passphrase doesn't decrypt it), `save(passphrase: str, keys: list[dict]) -> None`. Each dict has shape `{"label": str, "api_key": str, "window_hours": float}`.

- [ ] **Step 1: Write `keystore.py`**

```python
#!/usr/bin/env python3
"""Encrypted storage for Ollama Cloud API keys — Fernet symmetric encryption
keyed off an operator-supplied passphrase, never written to disk or logged.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEYSTORE_PATH = Path.home() / ".auditor" / "keys.enc"
SALT_LEN = 16
PBKDF2_ITERATIONS = 480_000


def _derive_fernet_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def load_or_init(passphrase: str) -> list[dict]:
    if not KEYSTORE_PATH.is_file():
        return []
    raw = KEYSTORE_PATH.read_bytes()
    salt, token = raw[:SALT_LEN], raw[SALT_LEN:]
    fernet = Fernet(_derive_fernet_key(passphrase, salt))
    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("invalid_passphrase")
    return json.loads(plaintext.decode())


def save(passphrase: str, keys: list[dict]) -> None:
    KEYSTORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(SALT_LEN)
    fernet = Fernet(_derive_fernet_key(passphrase, salt))
    token = fernet.encrypt(json.dumps(keys).encode())
    KEYSTORE_PATH.write_bytes(salt + token)
    KEYSTORE_PATH.chmod(0o600)
```

- [ ] **Step 2: Manual verification — round trip and wrong-passphrase rejection**

Run:
```bash
cd ~/tools/auditor
python3 -c "
import keystore
keystore.save('correct-horse', [{'label': 'acct1', 'api_key': 'sk-test-123', 'window_hours': 4.0}])
loaded = keystore.load_or_init('correct-horse')
assert loaded == [{'label': 'acct1', 'api_key': 'sk-test-123', 'window_hours': 4.0}], loaded
print('round trip OK:', loaded)
try:
    keystore.load_or_init('wrong-passphrase')
    print('FAIL: wrong passphrase did not raise')
except ValueError as e:
    print('wrong passphrase correctly rejected:', e)
"
oct_perms=\$(stat -c '%a' ~/.auditor/keys.enc)
echo "permissions: \$oct_perms (expect 600)"
```
Expected: `round trip OK: [...]`, `wrong passphrase correctly rejected: invalid_passphrase`, `permissions: 600`.

- [ ] **Step 3: Clean up the test keystore and commit**

```bash
rm -f ~/.auditor/keys.enc
git add keystore.py
git commit -m "feat: add encrypted keystore module for API key pool"
```

---

### Task 2: `bridge.py` — startup passphrase prompt and global key state

**Files:**
- Modify: `bridge.py` (imports, module-level globals, `if __name__ == "__main__":` block)

**Interfaces:**
- Consumes: `keystore.load_or_init`, `keystore.save` (Task 1).
- Produces (used by Task 3, 4, 5): module globals `KEYS: list[dict]`, `PASSPHRASE: str`, `ROTATION_STATE: dict | None`.

- [ ] **Step 1: Add the import and globals**

Add near the top of `bridge.py`, after the existing imports:

```python
import getpass
import re

import keystore
```

Add near the existing `CURRENT_SCOPE` global:

```python
KEYS: list[dict] = []
PASSPHRASE: str = ""
ROTATION_STATE: dict | None = None
```

- [ ] **Step 2: Load the keystore at startup**

Replace the `if __name__ == "__main__":` block's start with:

```python
if __name__ == "__main__":
    PASSPHRASE = getpass.getpass("Auditor keystore passphrase (used to encrypt/decrypt your API keys): ")
    try:
        KEYS = keystore.load_or_init(PASSPHRASE)
    except ValueError:
        print("Wrong passphrase for existing keystore. Aborting.")
        raise SystemExit(1)
    print(f"Loaded {len(KEYS)} stored API key(s).")

    server = ThreadingHTTPServer(("127.0.0.1", 8420), Handler)
```

(the following `print("Auditor bridge listening...")` lines and `server.serve_forever()` stay as they are)

- [ ] **Step 3: Manual verification**

Run:
```bash
cd ~/tools/auditor
echo "test-pass" | python3 -c "
import getpass, sys
getpass.getpass = lambda prompt='': sys.stdin.readline().strip()
exec(open('bridge.py').read().split('if __name__')[0])
import keystore
KEYS = keystore.load_or_init('test-pass')
print('loaded', len(KEYS), 'keys with empty keystore')
"
```
Expected: `loaded 0 keys with empty keystore` (no crash on first-run/no-file case).

- [ ] **Step 4: Commit**

```bash
git add bridge.py
git commit -m "feat: load encrypted key pool at bridge.py startup"
```

---

### Task 3: `bridge.py` — `/keys/list` and `/keys/add` endpoints

**Files:**
- Modify: `bridge.py` (`do_POST`)

**Interfaces:**
- Consumes: `KEYS`, `PASSPHRASE` globals (Task 2), `keystore.save`.
- Produces (used by Task 8 UI wiring): `POST /keys/list` → `200 [{"label": str, "last4": str, "window_hours": float}, ...]`. `POST /keys/add` body `{"label": str, "api_key": str, "window_hours": float}` → `200 {"ok": true}` or `400 {"error": "label_and_api_key_required"}`.

- [ ] **Step 1: Add both endpoints inside `do_POST`, before the final `self._send_json(404, ...)` fallback**

```python
        if self.path == "/keys/list":
            global KEYS
            self._send_json(200, [
                {"label": k["label"], "last4": k["api_key"][-4:], "window_hours": k["window_hours"]}
                for k in KEYS
            ])
            return

        if self.path == "/keys/add":
            global KEYS
            body = self._read_json()
            label = body.get("label", "").strip()
            api_key = body.get("api_key", "").strip()
            window_hours = body.get("window_hours")
            if not label or not api_key or not window_hours:
                self._send_json(400, {"error": "label_and_api_key_required"})
                return
            KEYS.append({"label": label, "api_key": api_key, "window_hours": float(window_hours)})
            keystore.save(PASSPHRASE, KEYS)
            audit_log({"event": "key_added", "label": label})
            self._send_json(200, {"ok": True})
            return
```

- [ ] **Step 2: Manual verification (server running)**

In one terminal: `python3 bridge.py` (note the printed token).

In another terminal:
```bash
TOKEN="<paste the printed token>"
curl -s -X POST http://127.0.0.1:8420/keys/add \
  -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"label":"acct1","api_key":"sk-test-abcd1234","window_hours":4}'
curl -s -X POST http://127.0.0.1:8420/keys/list -H "X-Auditor-Token: $TOKEN"
```
Expected: first call `{"ok": true}`, second call `[{"label": "acct1", "last4": "1234", "window_hours": 4.0}]`.

- [ ] **Step 3: Clean up test keystore and commit**

```bash
rm -f ~/.auditor/keys.enc
git add bridge.py
git commit -m "feat: add /keys/list and /keys/add endpoints"
```

---

### Task 4: `bridge.py` — `/keys/select` endpoint and rotation state

**Files:**
- Modify: `bridge.py` (`do_POST`)

**Interfaces:**
- Consumes: `KEYS` (Task 2/3).
- Produces (used by Task 5): `ROTATION_STATE = {"pool": [{"label", "api_key", "window_hours", "exhausted_at": None}, ...], "current_index": 0}`. `POST /keys/select` body `{"labels": [str, ...]}` → `200 {"ok": true, "count": int}` or `400 {"error": "unknown_label: <label>"}`.

- [ ] **Step 1: Add the endpoint**

```python
        if self.path == "/keys/select":
            global ROTATION_STATE
            body = self._read_json()
            labels = body.get("labels", [])
            by_label = {k["label"]: k for k in KEYS}
            pool = []
            for label in labels:
                if label not in by_label:
                    self._send_json(400, {"error": f"unknown_label: {label}"})
                    return
                k = by_label[label]
                pool.append({"label": k["label"], "api_key": k["api_key"],
                             "window_hours": k["window_hours"], "exhausted_at": None})
            ROTATION_STATE = {"pool": pool, "current_index": 0}
            audit_log({"event": "keys_selected", "labels": labels})
            self._send_json(200, {"ok": True, "count": len(pool)})
            return
```

- [ ] **Step 2: Manual verification**

```bash
TOKEN="<token>"
curl -s -X POST http://127.0.0.1:8420/keys/add -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"label":"acct1","api_key":"sk-a","window_hours":4}'
curl -s -X POST http://127.0.0.1:8420/keys/select -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"labels":["acct1"]}'
curl -s -X POST http://127.0.0.1:8420/keys/select -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"labels":["does-not-exist"]}'
```
Expected: `{"ok": true, "count": 1}`, then `{"error": "unknown_label: does-not-exist"}`.

- [ ] **Step 3: Clean up and commit**

```bash
rm -f ~/.auditor/keys.enc
git add bridge.py
git commit -m "feat: add /keys/select endpoint building rotation state"
```

---

### Task 5: `bridge.py` — rotation-aware `/llm/chat`

**Files:**
- Modify: `bridge.py` (replace the existing `/llm/chat` handler added in the CORS-fix session, add helper functions)

**Interfaces:**
- Consumes: `ROTATION_STATE` (Task 4).
- Produces (used by `js/bridge_client.js`, Task 7): `POST /llm/chat` body `{"endpoint": str, "payload": dict}` (no `apiKey` field anymore — the pool supplies it). On success: forwards upstream status/body as before. On total exhaustion: `503 {"error": "all_keys_exhausted", "retry_after_hint": <seconds:number>}`. On no pool selected while using the cloud endpoint: `400 {"error": "no_keys_selected"}`.

- [ ] **Step 1: Add the helper functions above the `Handler` class**

```python
DEFAULT_CLOUD_ENDPOINT = "https://ollama.com/v1/chat/completions"


def _forward_llm_request(endpoint: str, api_key: str | None, payload: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(),
                                  headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return {"status": resp.status, "body": json.loads(resp.read())}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed_body = json.loads(raw)
        except json.JSONDecodeError:
            parsed_body = {"error": raw.decode(errors="replace")}
        return {"status": e.code, "body": parsed_body}
    except urllib.error.URLError as e:
        return {"status": 502, "body": {"error": f"upstream_unreachable: {e.reason}"}}


def _is_quota_error(result: dict) -> bool:
    if result["status"] == 429:
        return True
    return bool(re.search(r"quota|limit|rate.?limit", json.dumps(result["body"]).lower()))


def _next_available_key() -> dict | None:
    pool = ROTATION_STATE["pool"]
    n = len(pool)
    now = time.time()
    for offset in range(n):
        idx = (ROTATION_STATE["current_index"] + offset) % n
        key_record = pool[idx]
        if key_record["exhausted_at"] is None:
            ROTATION_STATE["current_index"] = idx
            return key_record
        if now - key_record["exhausted_at"] >= key_record["window_hours"] * 3600:
            key_record["exhausted_at"] = None
            ROTATION_STATE["current_index"] = idx
            return key_record
    return None


def _earliest_reset_seconds() -> float:
    now = time.time()
    remaining = [
        (kr["window_hours"] * 3600) - (now - kr["exhausted_at"])
        for kr in ROTATION_STATE["pool"] if kr["exhausted_at"] is not None
    ]
    return max(0, min(remaining)) if remaining else 0
```

- [ ] **Step 2: Replace the existing `/llm/chat` block in `do_POST`**

```python
        if self.path == "/llm/chat":
            global ROTATION_STATE
            body = self._read_json()
            endpoint = body.get("endpoint") or DEFAULT_CLOUD_ENDPOINT
            payload = body.get("payload", {})

            if endpoint not in ALLOWED_LLM_ENDPOINTS:
                self._send_json(403, {"error": "endpoint_not_allowlisted"})
                return

            if endpoint != DEFAULT_CLOUD_ENDPOINT:
                result = _forward_llm_request(endpoint, None, payload)
                self._send_json(result["status"], result["body"])
                return

            if ROTATION_STATE is None or not ROTATION_STATE["pool"]:
                self._send_json(400, {"error": "no_keys_selected"})
                return

            attempts = 0
            while attempts < len(ROTATION_STATE["pool"]):
                key_record = _next_available_key()
                if key_record is None:
                    self._send_json(503, {"error": "all_keys_exhausted",
                                           "retry_after_hint": _earliest_reset_seconds()})
                    return
                result = _forward_llm_request(endpoint, key_record["api_key"], payload)
                if _is_quota_error(result):
                    key_record["exhausted_at"] = time.time()
                    audit_log({"event": "key_exhausted", "label": key_record["label"]})
                    attempts += 1
                    continue
                self._send_json(result["status"], result["body"])
                return

            self._send_json(503, {"error": "all_keys_exhausted",
                                   "retry_after_hint": _earliest_reset_seconds()})
            return
```

- [ ] **Step 3: Manual verification — rotation on a simulated 429**

In one terminal, a tiny stub that always 429s (simulates an exhausted Ollama account):
```bash
python3 -c "
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(429)
        self.send_header('Content-Type', 'application/json')
        body = b'{\"error\":\"rate limit exceeded\"}'
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 9999), H).serve_forever()
" &
```
Add `"http://127.0.0.1:9999/"` to `ALLOWED_LLM_ENDPOINTS` temporarily for this test, restart `bridge.py`, then:
```bash
TOKEN="<token>"
curl -s -X POST http://127.0.0.1:8420/keys/add -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"label":"a1","api_key":"k1","window_hours":0.001}'
curl -s -X POST http://127.0.0.1:8420/keys/add -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"label":"a2","api_key":"k2","window_hours":0.001}'
curl -s -X POST http://127.0.0.1:8420/keys/select -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"labels":["a1","a2"]}'
curl -s -X POST http://127.0.0.1:8420/llm/chat -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"endpoint":"http://127.0.0.1:9999/","payload":{}}'
```
Expected: since the stub always 429s, both keys get marked exhausted and the final response is `{"error": "all_keys_exhausted", "retry_after_hint": <a small number>}`. Kill the stub server (`kill %1`), remove the temporary allowlist entry, and clean up `~/.auditor/keys.enc`.

- [ ] **Step 4: Commit**

```bash
rm -f ~/.auditor/keys.enc
git add bridge.py
git commit -m "feat: rotate Ollama Cloud API keys on quota exhaustion in /llm/chat"
```

---

### Task 6: `bridge.py` — expand `ALLOWED_TOOLS`

**Files:**
- Modify: `bridge.py` (`ALLOWED_TOOLS` set)

- [ ] **Step 1: Add the new tools**

```python
ALLOWED_TOOLS = {
    "nmap", "gobuster", "ffuf", "nikto", "whatweb", "hydra", "sqlmap",
    "hashcat", "john", "curl", "dig", "nslookup", "smbclient", "rpcclient",
    "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py", "wmiexec.py",
    "psexec.py", "certipy", "bloodhound-python", "ldapsearch", "enum4linux",
    "crackmapexec", "netexec", "echo",  # echo kept for manual verification
    "ntlmrelayx.py", "smbexec.py", "atexec.py", "lookupsid.py",
    "samrdump.py", "mssqlclient.py", "ticketer.py", "getST.py",
    "raiseChild.py", "dcomexec.py", "adscan",
}
```

- [ ] **Step 2: Manual verification**

```bash
python3 -c "import ast; ast.parse(open('bridge.py').read())" && echo "syntax OK"
python3 -c "
exec(open('bridge.py').read().split('if __name__')[0])
assert 'adscan' in ALLOWED_TOOLS
assert 'ticketer.py' in ALLOWED_TOOLS
print('all new tools present')
"
```

- [ ] **Step 3: Commit**

```bash
git add bridge.py
git commit -m "feat: expand ALLOWED_TOOLS with more impacket scripts and adscan"
```

---

### Task 7: `js/bridge_client.js` — key-pool client functions + quota error type

**Files:**
- Modify: `js/bridge_client.js`

**Interfaces:**
- Produces (used by Task 8, 9, 10): `class QuotaExhaustedError extends Error` with `.retryAfterHint: number`. `llmChat(endpoint: string, payload: object): Promise<object>` (apiKey removed). `listKeys(): Promise<{label, last4, window_hours}[]>`. `addKey(label: string, apiKey: string, windowHours: number): Promise<{ok: true}>`. `selectKeys(labels: string[]): Promise<{ok: true, count: number}>`.

- [ ] **Step 1: Rewrite `js/bridge_client.js`**

```javascript
const BRIDGE_URL = "http://127.0.0.1:8420";

let sessionToken = null;

export function setSessionToken(token) {
  sessionToken = token;
}

export class QuotaExhaustedError extends Error {
  constructor(retryAfterHint) {
    super("all_keys_exhausted");
    this.retryAfterHint = retryAfterHint;
  }
}

async function postJSON(path, body) {
  if (!sessionToken) {
    throw new Error("missing_session_token");
  }
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Auditor-Token": sessionToken },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (res.status === 503 && data.error === "all_keys_exhausted") {
    throw new QuotaExhaustedError(data.retry_after_hint);
  }
  if (!res.ok && res.status !== 403) {
    throw new Error(`bridge_error_${res.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

export function startEngagement(target, scope) {
  return postJSON("/engagement/start", { target, scope });
}

export function execTool(tool, args, target) {
  return postJSON("/exec", { tool, args, target });
}

export function llmChat(endpoint, payload) {
  return postJSON("/llm/chat", { endpoint, payload });
}

export function listKeys() {
  return postJSON("/keys/list", {});
}

export function addKey(label, apiKey, windowHours) {
  return postJSON("/keys/add", { label, api_key: apiKey, window_hours: windowHours });
}

export function selectKeys(labels) {
  return postJSON("/keys/select", { labels });
}
```

- [ ] **Step 2: Manual verification**

```bash
node --check js/bridge_client.js && echo "syntax OK"
```

- [ ] **Step 3: Commit**

```bash
git add js/bridge_client.js
git commit -m "feat: add key-pool client functions and QuotaExhaustedError to bridge_client.js"
```

---

### Task 8: `js/ollama.js` — drop `apiKey` param, expand tool hint list

**Files:**
- Modify: `js/ollama.js`

**Interfaces:**
- Consumes: `llmChat(endpoint, payload)` (Task 7, signature changed — no more `apiKey` argument).
- Produces (used by Task 9): `askAgent({ model, systemPrompt, userPrompt, endpoint })` (removed `apiKey` from the parameter object — callers must stop passing it).

- [ ] **Step 1: Update `ALLOWED_TOOLS_HINT`**

```javascript
const ALLOWED_TOOLS_HINT = [
  "nmap", "gobuster", "ffuf", "nikto", "whatweb", "hydra", "sqlmap",
  "hashcat", "john", "curl", "dig", "nslookup", "smbclient", "rpcclient",
  "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py", "wmiexec.py",
  "psexec.py", "certipy", "bloodhound-python", "ldapsearch", "enum4linux",
  "crackmapexec", "netexec", "echo",
  "ntlmrelayx.py", "smbexec.py", "atexec.py", "lookupsid.py",
  "samrdump.py", "mssqlclient.py", "ticketer.py", "getST.py",
  "raiseChild.py", "dcomexec.py", "adscan",
];
```

- [ ] **Step 2: Drop `apiKey` from `askAgent`'s signature and call site**

```javascript
export async function askAgent({ model, systemPrompt, userPrompt, endpoint }) {
  const url = endpoint || DEFAULT_URL;

  const data = await llmChat(url, {
    model,
    stream: false,
    messages: [
      { role: "system", content: `${systemPrompt}\n\n${RESPONSE_CONTRACT}` },
      { role: "user", content: userPrompt },
    ],
  });
```

(the rest of the function — parsing `data.choices`/`data.message`, the JSON parse/validate block — is unchanged)

- [ ] **Step 3: Manual verification**

```bash
node --check js/ollama.js && echo "syntax OK"
grep -c "apiKey" js/ollama.js
```
Expected: `syntax OK`, and the `grep -c` count is `0` (no leftover references).

- [ ] **Step 4: Commit**

```bash
git add js/ollama.js
git commit -m "feat: remove apiKey from ollama.js (bridge now owns key selection), expand tool hints"
```

---

### Task 9: `js/agent.js` — quota-exhaustion handling and expanded danger list

**Files:**
- Modify: `js/agent.js`

**Interfaces:**
- Consumes: `QuotaExhaustedError` (Task 7).
- Produces (used by Task 10 `js/main.js`): `runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota })` — `apiKey` param removed, `onWaitingForQuota(retryAfterHintSeconds)` added (optional, defaults to a no-op).

- [ ] **Step 1: Add the import and expand `DANGEROUS_TOOLS`**

```javascript
import { askAgent } from "./ollama.js";
import { execTool, QuotaExhaustedError } from "./bridge_client.js";
import { checkAndRecordAxis } from "./axis.js";
import { addStep, getSteps } from "./db.js";

export const DANGEROUS_TOOLS = new Set([
  "secretsdump.py", "secretsdump",
  "ntdsutil",
  "dcsync",
  "hashcat",
  "hydra",
  "crackmapexec", "netexec",
  "ntlmrelayx.py",
  "ticketer.py",
]);
```

- [ ] **Step 2: Update `runAgentLoop`'s signature and drop `apiKey` from the `askAgent` call**

```javascript
export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {} }) {
  let steps = await getSteps(db, engagementId);
  let axisWarning = false;
  let agentErrorHint = "";
  let consecutiveErrors = 0;

  while (true) {
    let decision;
    try {
      decision = await askAgent({
        model,
        systemPrompt,
        userPrompt: buildUserPrompt(target, steps, axisWarning) + agentErrorHint,
        endpoint,
      });
    } catch (err) {
      if (err instanceof QuotaExhaustedError) {
        const stepId = await addStep(db, {
          engagementId, tool: "(agent)", args: [],
          output: "", stderr: `all API keys exhausted, retry in ~${Math.ceil(err.retryAfterHint / 60)}min`,
          exitCode: -1, verdict: "waiting_for_quota",
        });
        const step = { id: stepId, engagementId, tool: "(agent)", args: [], verdict: "waiting_for_quota" };
        steps = [...steps, step];
        onStep(step);
        onWaitingForQuota(err.retryAfterHint);
        const waitMs = Math.max(0, Math.min(err.retryAfterHint, 300)) * 1000;
        await new Promise((resolve) => setTimeout(resolve, waitMs));
        continue;
      }
      consecutiveErrors += 1;
      const stepId = await addStep(db, {
        engagementId, tool: "(agent)", args: [],
        output: "", stderr: err.message, exitCode: -1, verdict: "agent_error",
      });
      const step = { id: stepId, engagementId, tool: "(agent)", args: [], verdict: "agent_error" };
      steps = [...steps, step];
      onStep(step);
      if (consecutiveErrors >= MAX_CONSECUTIVE_AGENT_ERRORS) {
        throw new Error(`agent_stuck: ${MAX_CONSECUTIVE_AGENT_ERRORS} consecutive malformed responses, last: ${err.message}`);
      }
      agentErrorHint = `\n\nYour last response was invalid: ${err.message}. Follow the JSON contract exactly.`;
      continue;
    }
    consecutiveErrors = 0;
    agentErrorHint = "";
```

(everything below this point — `if (decision.done)` onward — is unchanged)

- [ ] **Step 3: Manual verification**

```bash
node --check js/agent.js && echo "syntax OK"
grep -c "apiKey" js/agent.js
```
Expected: `syntax OK`, count `0`.

- [ ] **Step 4: Commit**

```bash
git add js/agent.js
git commit -m "feat: handle quota exhaustion as a distinct retry state, expand DANGEROUS_TOOLS"
```

---

### Task 10: UI markup — key management panel

**Files:**
- Modify: `index.html`, `style.css`

**Interfaces:**
- Produces (used by Task 11): DOM elements `#manage-keys-btn`, `#key-manage-panel` (hidden by default), `#key-list` (container for rendered checkboxes), `#new-key-label`, `#new-key-value`, `#new-key-window`, `#add-key-btn`, `#close-keys-btn`.

- [ ] **Step 1: Replace the API key field in `index.html`'s start panel**

Replace this line:
```html
      <input id="apikey-input" type="password" placeholder="Ollama API key (ollama.com)" autocomplete="off" />
```
with:
```html
      <button id="manage-keys-btn" type="button">Gestionar keys (0 seleccionadas)</button>
```

Add the management panel markup right after `</section>` that closes `#start-panel`:
```html
    <div id="key-manage-panel" hidden>
      <h2>API keys de Ollama Cloud</h2>
      <div id="key-list"></div>
      <h3>Agregar nueva key</h3>
      <input id="new-key-label" placeholder="Label (ej. cuenta1)" />
      <input id="new-key-value" type="password" placeholder="API key" autocomplete="off" />
      <input id="new-key-window" type="number" step="0.5" placeholder="Ventana de reset en horas (ej. 4, 24, 168)" />
      <button id="add-key-btn" type="button">Agregar key</button>
      <button id="close-keys-btn" type="button">Listo</button>
    </div>
```

- [ ] **Step 2: Add styling for the panel and per-key rows in `style.css`**

```css
#key-manage-panel { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; }
#key-manage-panel[hidden] { display: none; }
#key-manage-panel > * { max-width: 500px; width: 100%; }
#key-list { background: #1a1e33; border-radius: 10px; padding: 0.5rem 1rem; margin: 0.5rem 0; }
.key-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 0; }
.key-row label { flex: 1; }
```

- [ ] **Step 3: Manual verification**

Open `index.html` in a text viewer or `python3 -c "import html.parser; html.parser.HTMLParser().feed(open('index.html').read()); print('parses OK')"` to confirm no unclosed tags broke parsing.

- [ ] **Step 4: Commit**

```bash
git add index.html style.css
git commit -m "feat: add key management panel markup and styling"
```

---

### Task 11: `js/ui.js` + `js/main.js` — wire the key management flow

**Files:**
- Modify: `js/ui.js`, `js/main.js`

**Interfaces:**
- Consumes: `listKeys`, `addKey`, `selectKeys` (Task 7), DOM elements from Task 10.
- Produces: fully working key selection gating `#start-btn`.

- [ ] **Step 1: Add a render function to `js/ui.js`**

```javascript
export function renderKeyList(keys, selectedLabels) {
  const container = document.getElementById("key-list");
  container.innerHTML = "";
  if (keys.length === 0) {
    container.textContent = "No hay keys guardadas todavía.";
    return;
  }
  for (const k of keys) {
    const row = document.createElement("div");
    row.className = "key-row";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.id = `key-checkbox-${k.label}`;
    checkbox.checked = selectedLabels.has(k.label);
    checkbox.onchange = () => {
      if (checkbox.checked) selectedLabels.add(k.label);
      else selectedLabels.delete(k.label);
      document.getElementById("manage-keys-btn").textContent =
        `Gestionar keys (${selectedLabels.size} seleccionadas)`;
    };
    const label = document.createElement("label");
    label.htmlFor = checkbox.id;
    label.textContent = `${k.label} (****${k.last4}) — reset cada ${k.window_hours}h`;
    row.appendChild(checkbox);
    row.appendChild(label);
    container.appendChild(row);
  }
}

export function renderWaitingForQuota(retryAfterHintSeconds) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = "step waiting_for_quota";
  const minutes = Math.ceil(retryAfterHintSeconds / 60);
  div.textContent = `Todas las keys agotadas. Reintenta automáticamente en ~${minutes} min.`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}
```

- [ ] **Step 2: Wire it up in `js/main.js`**

```javascript
import { initDB, createEngagement, exportEngagementJSON } from "./db.js";
import { startEngagement, setSessionToken, listKeys, addKey, selectKeys } from "./bridge_client.js";
import { runAgentLoop } from "./agent.js";
import { renderStep, showConfirmModal, renderKeyList, renderWaitingForQuota } from "./ui.js";

async function main() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  if (!token) {
    document.getElementById("app").textContent =
      "Falta el token de sesión. Abrí la URL exacta que imprime bridge.py al arrancar (incluye ?token=...).";
    return;
  }
  setSessionToken(token);

  const db = await initDB();
  const selectedLabels = new Set();

  document.getElementById("manage-keys-btn").onclick = async () => {
    const keys = await listKeys();
    renderKeyList(keys, selectedLabels);
    document.getElementById("key-manage-panel").hidden = false;
  };

  document.getElementById("add-key-btn").onclick = async () => {
    const label = document.getElementById("new-key-label").value.trim();
    const apiKey = document.getElementById("new-key-value").value.trim();
    const windowHours = parseFloat(document.getElementById("new-key-window").value);
    if (!label || !apiKey || !windowHours) return;
    await addKey(label, apiKey, windowHours);
    document.getElementById("new-key-label").value = "";
    document.getElementById("new-key-value").value = "";
    document.getElementById("new-key-window").value = "";
    const keys = await listKeys();
    renderKeyList(keys, selectedLabels);
  };

  document.getElementById("close-keys-btn").onclick = () => {
    document.getElementById("key-manage-panel").hidden = true;
  };

  document.getElementById("start-btn").onclick = async () => {
    const target = document.getElementById("target-input").value.trim();
    const scope = document.getElementById("scope-input").value.trim();
    const model = document.getElementById("model-input").value.trim();
    const endpoint = document.getElementById("endpoint-input").value.trim() || undefined;
    if (!target || !scope || !model) return;
    if (selectedLabels.size === 0) {
      alert("Elegí al menos una API key en \"Gestionar keys\" antes de arrancar.");
      return;
    }

    await selectKeys([...selectedLabels]);
    await startEngagement(target, scope);
    const engagementId = await createEngagement(db, { target, scope });

    document.getElementById("start-panel").hidden = true;
    document.getElementById("steps-panel").hidden = false;

    document.getElementById("export-btn").onclick = async () => {
      const data = await exportEngagementJSON(db, engagementId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `auditor-export-${engagementId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    };

    const systemPrompt = `Eres un agente de pentest autorizado. Target en scope: ${target}. Trabaja paso a paso, una herramienta a la vez.`;

    runAgentLoop({
      db, engagementId, model, target, systemPrompt, endpoint,
      onStep: renderStep,
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
      onWaitingForQuota: renderWaitingForQuota,
    });
  };
}

main();
```

- [ ] **Step 3: Manual verification**

```bash
node --check js/ui.js && node --check js/main.js && echo "syntax OK"
```

Then in the real browser (per the established manual-testing pattern for this project): restart `bridge.py`, open the printed URL, click "Gestionar keys", add a test key, select it, close the panel, confirm the button label reads "(1 seleccionadas)", and confirm "Iniciar engagement" now proceeds (or shows the alert if nothing is selected).

- [ ] **Step 4: Commit**

```bash
git add js/ui.js js/main.js
git commit -m "feat: wire key management UI into the engagement start flow"
```
