# Auditor Engine (Sub-proyecto 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local, offline-first ReAct agent engine that lets the operator run an Ollama-driven pentest agent against a scoped target, with hard server-side scope-lock, a confirmation gate for destructive tools, an anti-loop axis ledger, and full IndexedDB persistence exportable to JSON.

**Architecture:** Two processes — `bridge.py` (Python stdlib only: static file server + `/engagement/start` + `/exec` with server-side scope enforcement + append-only audit log) and the browser (vanilla JS ES modules, no build step, no framework) which owns the ReAct loop, calls Ollama directly over HTTP, and persists all state in IndexedDB.

**Tech Stack:** Python 3 stdlib (`http.server`, `subprocess`, `json`), vanilla JS (ES modules, `fetch`, `indexedDB`), no npm, no pip install, no build step.

**Spec:** `~/tools/auditor/docs/superpowers/specs/2026-08-21-engine-design.md`

## Global Constraints

- Zero external dependencies — Python stdlib only, vanilla JS only (no CDN scripts, no npm packages).
- No automated test suite (spec's explicit decision — personal tool, not a distributed product). Every task instead has a **manual verification step** with the exact command/console check to run before committing.
- Every write to a real system goes through `bridge.py /exec`; nothing in JS ever runs a shell command directly.
- Scope-lock validation lives server-side in `bridge.py`, never trust the browser as the sole enforcement point.
- `DANGEROUS_TOOLS` is a static, hand-edited list in `agent.js` — never generated or modified at runtime by the LLM.
- Ollama endpoint is fixed to `http://localhost:11434` (no remote/cloud fallback in v1).

---

### Task 1: `bridge.py` — static file server + engagement scope endpoint

**Files:**
- Create: `bridge.py`

**Interfaces:**
- Produces (used by Task 2 and all browser tasks): server listening on `http://localhost:8420`; module-level `CURRENT_SCOPE: dict | None` holding `{"target": str, "scope": str}`; `POST /engagement/start` accepting `{"target": str, "scope": str}`, setting `CURRENT_SCOPE`, returning `{"ok": true}`.

- [ ] **Step 1: Write `bridge.py` skeleton**

```python
#!/usr/bin/env python3
"""Auditor engine bridge — stdlib only. Serves the static UI and executes
scoped, whitelisted-by-scope commands on behalf of the browser agent loop."""
import json
import os
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATIC_DIR = Path(__file__).parent
LOG_PATH = Path.home() / ".auditor" / "exec.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

CURRENT_SCOPE: dict | None = None


def audit_log(entry: dict) -> None:
    entry["ts"] = time.time()
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/":
            path = "/index.html"
        file_path = (STATIC_DIR / path.lstrip("/")).resolve()
        if STATIC_DIR not in file_path.parents and file_path != STATIC_DIR:
            self._send_json(403, {"error": "forbidden"})
            return
        if not file_path.is_file():
            self._send_json(404, {"error": "not found"})
            return
        content_type = "text/html"
        if file_path.suffix == ".js":
            content_type = "application/javascript"
        elif file_path.suffix == ".css":
            content_type = "text/css"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        global CURRENT_SCOPE
        if self.path == "/engagement/start":
            body = self._read_json()
            target = body.get("target", "").strip()
            scope = body.get("scope", "").strip()
            if not target or not scope:
                self._send_json(400, {"error": "target and scope required"})
                return
            CURRENT_SCOPE = {"target": target, "scope": scope}
            audit_log({"event": "engagement_start", "target": target, "scope": scope})
            self._send_json(200, {"ok": True})
            return
        self._send_json(404, {"error": "unknown endpoint"})

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8420), Handler)
    print("Auditor bridge listening on http://127.0.0.1:8420")
    server.serve_forever()
```

- [ ] **Step 2: Manual verification — server starts and serves 404 cleanly**

Run: `python3 bridge.py &` then `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8420/nope.html`
Expected: `404`. Then `kill %1` to stop the background server.

- [ ] **Step 3: Manual verification — engagement/start sets scope**

Run:
```bash
python3 bridge.py &
curl -s -X POST http://127.0.0.1:8420/engagement/start \
  -H "Content-Type: application/json" \
  -d '{"target":"10.10.11.50","scope":"10.10.11.50"}'
```
Expected: `{"ok": true}`. Confirm `~/.auditor/exec.log` has one line with `"event": "engagement_start"`. Then `kill %1`.

- [ ] **Step 4: Commit**

```bash
cd ~/tools/auditor
git add bridge.py
git commit -m "feat: bridge static server + engagement scope endpoint"
```

---

### Task 2: `bridge.py` — `/exec` with server-side scope-lock

**Files:**
- Modify: `bridge.py`

**Interfaces:**
- Consumes: `CURRENT_SCOPE` from Task 1.
- Produces (used by `bridge_client.js` in Task 5): `POST /exec` accepting `{"tool": str, "args": list[str], "target": str}`. Returns `200 {"stdout": str, "stderr": str, "exit_code": int, "verdict": "ok"|"timeout"}` on success, or `403 {"error": "scope_violation", "verdict": "scope_violation"}` if `target` does not match `CURRENT_SCOPE["scope"]` (exact match or `target` is a substring of `scope`, covering the CIDR-as-string / single-host case used in v1), or `400 {"error": "no_active_engagement"}` if `CURRENT_SCOPE` is `None`.

- [ ] **Step 1: Add `/exec` handler to `bridge.py`**

Add above `if self.path == "/engagement/start":` block inside `do_POST`, replacing the final `self._send_json(404, ...)` fallback:

```python
        if self.path == "/exec":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            tool = body.get("tool", "")
            args = body.get("args", [])
            target = body.get("target", "")
            if not tool or target not in CURRENT_SCOPE["scope"] and CURRENT_SCOPE["scope"] not in target:
                audit_log({"event": "scope_violation", "tool": tool, "target": target})
                self._send_json(403, {"error": "scope_violation", "verdict": "scope_violation"})
                return
            cmd = [tool] + [str(a) for a in args]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                result = {"stdout": proc.stdout, "stderr": proc.stderr,
                          "exit_code": proc.returncode, "verdict": "ok"}
            except subprocess.TimeoutExpired:
                result = {"stdout": "", "stderr": "timeout after 120s",
                          "exit_code": -1, "verdict": "timeout"}
            except FileNotFoundError:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
            audit_log({"event": "exec", "tool": tool, "args": args,
                       "target": target, "exit_code": result["exit_code"],
                       "verdict": result["verdict"]})
            self._send_json(200, result)
            return
        self._send_json(404, {"error": "unknown endpoint"})
```

- [ ] **Step 2: Manual verification — in-scope command executes**

Run:
```bash
python3 bridge.py &
curl -s -X POST http://127.0.0.1:8420/engagement/start \
  -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}'
curl -s -X POST http://127.0.0.1:8420/exec \
  -H "Content-Type: application/json" \
  -d '{"tool":"echo","args":["hello"],"target":"127.0.0.1"}'
```
Expected: `{"stdout": "hello\n", "stderr": "", "exit_code": 0, "verdict": "ok"}`.

- [ ] **Step 3: Manual verification — out-of-scope target is rejected**

Run: `curl -s -X POST http://127.0.0.1:8420/exec -H "Content-Type: application/json" -d '{"tool":"echo","args":["nope"],"target":"8.8.8.8"}'`
Expected: `403` with `{"error": "scope_violation", ...}`. Confirm `~/.auditor/exec.log` recorded the `scope_violation` event. Then `kill %1`.

- [ ] **Step 4: Commit**

```bash
git add bridge.py
git commit -m "feat: /exec endpoint with server-side scope-lock and audit log"
```

---

### Task 3: `js/db.js` — IndexedDB wrapper

**Files:**
- Create: `js/db.js`

**Interfaces:**
- Produces (used by Tasks 6, 7, 8):
  - `initDB(): Promise<IDBDatabase>`
  - `createEngagement(db, {target, scope}): Promise<number>` — returns `engagementId`
  - `getActiveEngagement(db): Promise<{id, target, scope, startedAt, status} | null>`
  - `addStep(db, {engagementId, tool, args, output, stderr, exitCode, verdict}): Promise<number>` — returns `stepId`
  - `getSteps(db, engagementId): Promise<Array<Step>>`
  - `addFinding(db, {engagementId, type, value, sourceStepId}): Promise<number>`
  - `getFindings(db, engagementId): Promise<Array<Finding>>`
  - `getAxisEntry(db, engagementId, tool, paramsHash): Promise<AxisEntry | null>`
  - `upsertAxisEntry(db, {engagementId, tool, paramsHash, attemptCount, lastResultHash}): Promise<void>`
  - `exportEngagementJSON(db, engagementId): Promise<object>` — `{engagement, steps, findings, axis_ledger}`

- [ ] **Step 1: Write `js/db.js`**

```javascript
const DB_NAME = "auditor";
const DB_VERSION = 1;

export function initDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      const eng = db.createObjectStore("engagement", { keyPath: "id", autoIncrement: true });
      eng.createIndex("status", "status");
      const steps = db.createObjectStore("steps", { keyPath: "id", autoIncrement: true });
      steps.createIndex("engagementId", "engagementId");
      const findings = db.createObjectStore("findings", { keyPath: "id", autoIncrement: true });
      findings.createIndex("engagementId", "engagementId");
      const axis = db.createObjectStore("axis_ledger", { keyPath: "id", autoIncrement: true });
      axis.createIndex("engagementId", "engagementId");
      axis.createIndex("lookup", ["engagementId", "tool", "paramsHash"]);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx(db, storeName, mode = "readonly") {
  return db.transaction(storeName, mode).objectStore(storeName);
}

export function createEngagement(db, { target, scope }) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "engagement", "readwrite");
    const req = store.add({ target, scope, startedAt: Date.now(), status: "active" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getActiveEngagement(db) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "engagement");
    const req = store.index("status").getAll("active");
    req.onsuccess = () => resolve(req.result[0] || null);
    req.onerror = () => reject(req.error);
  });
}

export function addStep(db, { engagementId, tool, args, output, stderr, exitCode, verdict }) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "steps", "readwrite");
    const req = store.add({ engagementId, tool, args, output, stderr, exitCode, verdict, timestamp: Date.now() });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getSteps(db, engagementId) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "steps");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function addFinding(db, { engagementId, type, value, sourceStepId }) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "findings", "readwrite");
    const req = store.add({ engagementId, type, value, sourceStepId, timestamp: Date.now() });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getFindings(db, engagementId) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "findings");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function getAxisEntry(db, engagementId, tool, paramsHash) {
  return new Promise((resolve, reject) => {
    const store = tx(db, "axis_ledger");
    const req = store.index("lookup").get([engagementId, tool, paramsHash]);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export function upsertAxisEntry(db, entry) {
  return new Promise(async (resolve, reject) => {
    const existing = await getAxisEntry(db, entry.engagementId, entry.tool, entry.paramsHash);
    const store = tx(db, "axis_ledger", "readwrite");
    const record = existing ? { ...existing, ...entry } : { ...entry };
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function exportEngagementJSON(db, engagementId) {
  const [steps, findings] = await Promise.all([
    getSteps(db, engagementId),
    getFindings(db, engagementId),
  ]);
  const axis = await new Promise((resolve, reject) => {
    const store = tx(db, "axis_ledger");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return { engagementId, steps, findings, axis_ledger: axis };
}
```

- [ ] **Step 2: Manual verification — DB round-trip in browser console**

Run: `python3 bridge.py &` (needs `index.html` to exist to load as a page — a minimal placeholder is fine here; Task 7 replaces it). Open `http://127.0.0.1:8420/` in Firefox, open DevTools console, paste:

```javascript
import("./js/db.js").then(async (m) => {
  const db = await m.initDB();
  const id = await m.createEngagement(db, { target: "127.0.0.1", scope: "127.0.0.1" });
  await m.addStep(db, { engagementId: id, tool: "echo", args: ["hi"], output: "hi\n", stderr: "", exitCode: 0, verdict: "ok" });
  console.log(await m.getSteps(db, id));
  console.log(await m.exportEngagementJSON(db, id));
});
```
Expected: array with one step object, and an export object with `steps.length === 1`.

- [ ] **Step 3: Commit**

```bash
git add js/db.js
git commit -m "feat: IndexedDB wrapper for engagement/steps/findings/axis_ledger"
```

---

### Task 4: `js/ollama.js` — Ollama client with structured tool-call contract

**Files:**
- Create: `js/ollama.js`

**Interfaces:**
- Produces (used by Task 6): `askAgent({model, systemPrompt, userPrompt}): Promise<{tool: string, args: string[], reasoning: string} | {done: true, reasoning: string}>`. Throws on network failure (caller in Task 6 handles as "bridge/ollama down").

- [ ] **Step 1: Write `js/ollama.js`**

```javascript
const OLLAMA_URL = "http://localhost:11434/api/chat";

const RESPONSE_CONTRACT = `You must respond with ONLY a JSON object, no prose, no markdown fences.
Either:
{"tool": "<binary name>", "args": ["<arg1>", "<arg2>", ...], "reasoning": "<why>"}
or, if the engagement objective is complete:
{"done": true, "reasoning": "<why>"}`;

export async function askAgent({ model, systemPrompt, userPrompt }) {
  const res = await fetch(OLLAMA_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      stream: false,
      messages: [
        { role: "system", content: `${systemPrompt}\n\n${RESPONSE_CONTRACT}` },
        { role: "user", content: userPrompt },
      ],
    }),
  });
  if (!res.ok) {
    throw new Error(`ollama_error_${res.status}`);
  }
  const data = await res.json();
  const raw = data.message?.content ?? "";
  let parsed;
  try {
    parsed = JSON.parse(raw.trim());
  } catch (e) {
    throw new Error(`ollama_invalid_json: ${raw.slice(0, 200)}`);
  }
  if (parsed.done) return { done: true, reasoning: parsed.reasoning ?? "" };
  if (!parsed.tool) throw new Error(`ollama_missing_tool_field: ${raw.slice(0, 200)}`);
  return { tool: parsed.tool, args: parsed.args ?? [], reasoning: parsed.reasoning ?? "" };
}
```

- [ ] **Step 2: Manual verification — Ollama responds and parses**

Prerequisite: `ollama serve` running and a model pulled (e.g. `ollama pull llama3.1`). In the browser console (same page as Task 3):

```javascript
import("./js/ollama.js").then(async (m) => {
  const r = await m.askAgent({
    model: "llama3.1",
    systemPrompt: "You are a pentest agent. Available tools: echo.",
    userPrompt: "Target 127.0.0.1 is in scope. Say hello using echo.",
  });
  console.log(r);
});
```
Expected: an object with a `tool` field (or `done: true`) — confirms the fetch, JSON parse, and contract enforcement work end to end against a real local model.

- [ ] **Step 3: Commit**

```bash
git add js/ollama.js
git commit -m "feat: Ollama client with structured tool-call JSON contract"
```

---

### Task 5: `js/bridge_client.js` — fetch wrapper for `bridge.py`

**Files:**
- Create: `js/bridge_client.js`

**Interfaces:**
- Produces (used by Task 6): `startEngagement(target, scope): Promise<{ok: boolean}>`, `execTool(tool, args, target): Promise<{stdout, stderr, exit_code, verdict}>`.

- [ ] **Step 1: Write `js/bridge_client.js`**

```javascript
const BRIDGE_URL = "http://127.0.0.1:8420";

async function postJSON(path, body) {
  const res = await fetch(`${BRIDGE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
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
```

- [ ] **Step 2: Manual verification — client talks to running bridge**

With `bridge.py` running (Task 2's server, restart it if killed), in browser console:

```javascript
import("./js/bridge_client.js").then(async (m) => {
  console.log(await m.startEngagement("127.0.0.1", "127.0.0.1"));
  console.log(await m.execTool("echo", ["from-client"], "127.0.0.1"));
});
```
Expected: `{ok: true}` then `{stdout: "from-client\n", ..., verdict: "ok"}`.

- [ ] **Step 3: Commit**

```bash
git add js/bridge_client.js
git commit -m "feat: browser client for bridge.py endpoints"
```

---

### Task 6: `js/axis.js` — anti-loop axis ledger

**Files:**
- Create: `js/axis.js`

**Interfaces:**
- Consumes: `getAxisEntry`, `upsertAxisEntry` from `js/db.js` (Task 3).
- Produces (used by Task 7): `paramsHash(tool, args): string`, `resultHash(output): string`, `checkAndRecordAxis(db, engagementId, tool, args, output): Promise<{attemptCount: number, warn: boolean}>` — `warn` is `true` once `attemptCount >= 3` and `lastResultHash` matches the new `resultHash` (no new information across the last 3 attempts).

- [ ] **Step 1: Write `js/axis.js`**

```javascript
import { getAxisEntry, upsertAxisEntry } from "./db.js";

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return h.toString(16);
}

export function paramsHash(tool, args) {
  return simpleHash(`${tool}:${JSON.stringify(args)}`);
}

export function resultHash(output) {
  return simpleHash(String(output).slice(0, 500));
}

export async function checkAndRecordAxis(db, engagementId, tool, args, output) {
  const pHash = paramsHash(tool, args);
  const rHash = resultHash(output);
  const existing = await getAxisEntry(db, engagementId, tool, pHash);
  const sameAsLast = existing && existing.lastResultHash === rHash;
  const attemptCount = existing ? existing.attemptCount + 1 : 1;
  await upsertAxisEntry(db, {
    engagementId,
    tool,
    paramsHash: pHash,
    attemptCount,
    lastResultHash: rHash,
  });
  const warn = attemptCount >= 3 && sameAsLast;
  return { attemptCount, warn };
}
```

- [ ] **Step 2: Manual verification — three identical attempts trigger warn**

In browser console (DB from Task 3 still has engagement `id` — reuse it, or create a fresh one):

```javascript
import("./js/axis.js").then(async (axisMod) => {
  const dbMod = await import("./js/db.js");
  const db = await dbMod.initDB();
  const engId = await dbMod.createEngagement(db, { target: "127.0.0.1", scope: "127.0.0.1" });
  let r;
  for (let i = 0; i < 3; i++) {
    r = await axisMod.checkAndRecordAxis(db, engId, "hydra", ["-l", "admin"], "same output every time");
    console.log(i, r);
  }
});
```
Expected: attempt 1 → `{attemptCount: 1, warn: false}`, attempt 2 → `{attemptCount: 2, warn: false}`, attempt 3 → `{attemptCount: 3, warn: true}`.

- [ ] **Step 3: Commit**

```bash
git add js/axis.js
git commit -m "feat: axis ledger anti-loop detector"
```

---

### Task 7: `js/agent.js` — ReAct loop with dangerous-tool confirmation gate

**Files:**
- Create: `js/agent.js`

**Interfaces:**
- Consumes: `askAgent` (Task 4), `startEngagement`/`execTool` (Task 5), `checkAndRecordAxis` (Task 6), `addStep`/`addFinding`/`getSteps` (Task 3).
- Produces (used by Task 8): `DANGEROUS_TOOLS: Set<string>`, `runAgentLoop({db, engagementId, model, target, onStep, onPauseForConfirmation}): Promise<void>` — calls `onStep(step)` after every recorded step (including rejections/violations), calls `onPauseForConfirmation(decision, resolve)` when a dangerous tool is proposed and awaits `resolve(approved: boolean)` before continuing or aborting that step. `resumeAfterConfirmation` is implemented as the `resolve` callback passed into `onPauseForConfirmation` — no separate exported function needed.

- [ ] **Step 1: Write `js/agent.js`**

```javascript
import { askAgent } from "./ollama.js";
import { execTool } from "./bridge_client.js";
import { checkAndRecordAxis } from "./axis.js";
import { addStep } from "./db.js";

export const DANGEROUS_TOOLS = new Set([
  "secretsdump.py", "secretsdump",
  "ntdsutil",
  "dcsync",
  "hashcat",
  "hydra",
]);

function buildUserPrompt(target, steps, axisWarning) {
  const history = steps
    .slice(-10)
    .map((s) => `[${s.tool} ${JSON.stringify(s.args)}] -> exit=${s.exitCode} verdict=${s.verdict}\n${(s.output || "").slice(0, 300)}`)
    .join("\n---\n");
  let prompt = `Target: ${target}\nRecent history:\n${history || "(no steps yet)"}`;
  if (axisWarning) {
    prompt += `\n\nWARNING: you already tried this exact (tool, args) 3 times with no new information. Change a parameter or try a different vector.`;
  }
  return prompt;
}

export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, onStep, onPauseForConfirmation }) {
  let steps = await (await import("./db.js")).getSteps(db, engagementId);
  let axisWarning = false;

  while (true) {
    const decision = await askAgent({
      model,
      systemPrompt,
      userPrompt: buildUserPrompt(target, steps, axisWarning),
    });

    if (decision.done) {
      return;
    }

    if (DANGEROUS_TOOLS.has(decision.tool)) {
      const approved = await new Promise((resolve) => onPauseForConfirmation(decision, resolve));
      if (!approved) {
        const stepId = await addStep(db, {
          engagementId, tool: decision.tool, args: decision.args,
          output: "", stderr: "rejected by operator", exitCode: -1, verdict: "rejected",
        });
        const step = { id: stepId, engagementId, tool: decision.tool, args: decision.args, verdict: "rejected" };
        steps = [...steps, step];
        onStep(step);
        continue;
      }
    }

    const result = await execTool(decision.tool, decision.args, target);
    const stepId = await addStep(db, {
      engagementId, tool: decision.tool, args: decision.args,
      output: result.stdout, stderr: result.stderr,
      exitCode: result.exit_code, verdict: result.verdict,
    });
    const step = { id: stepId, engagementId, tool: decision.tool, args: decision.args, ...result };
    steps = [...steps, step];
    onStep(step);

    const axisResult = await checkAndRecordAxis(db, engagementId, decision.tool, decision.args, result.stdout);
    axisWarning = axisResult.warn;
  }
}
```

- [ ] **Step 2: Manual verification — full loop with a trivial system prompt**

Prerequisite: `bridge.py` running, engagement started via `startEngagement("127.0.0.1", "127.0.0.1")`, Ollama running. In browser console:

```javascript
import("./js/agent.js").then(async (agentMod) => {
  const dbMod = await import("./js/db.js");
  const db = await dbMod.initDB();
  const eng = await dbMod.createEngagement(db, { target: "127.0.0.1", scope: "127.0.0.1" });
  const bridgeMod = await import("./js/bridge_client.js");
  await bridgeMod.startEngagement("127.0.0.1", "127.0.0.1");
  await agentMod.runAgentLoop({
    db, engagementId: eng, model: "llama3.1", target: "127.0.0.1",
    systemPrompt: "You are a pentest agent. Only tool available: echo. Run it once with args ['test'], then respond done:true.",
    onStep: (s) => console.log("STEP", s),
    onPauseForConfirmation: (decision, resolve) => { console.log("CONFIRM?", decision); resolve(true); },
  });
  console.log("loop finished");
});
```
Expected: one `STEP` log with `tool: "echo"`, then `"loop finished"` printed — confirms the full ReAct cycle (Ollama decision → exec → DB persist → axis update → done) works end to end.

- [ ] **Step 3: Manual verification — dangerous tool pauses for confirmation**

Repeat with `systemPrompt: "Only tool available: hydra. Always propose it with args ['-l','admin','127.0.0.1']. Never say done."` and in `onPauseForConfirmation`, call `resolve(false)` instead of `true`.
Expected: `CONFIRM?` logs once, then a `STEP` with `verdict: "rejected"` — confirms the gate actually blocks execution until a decision is made, and honors rejection.

- [ ] **Step 4: Commit**

```bash
git add js/agent.js
git commit -m "feat: ReAct agent loop with dangerous-tool confirmation gate"
```

---

### Task 8: UI — `index.html`, `style.css`, `js/ui.js`, `js/main.js`

**Files:**
- Create: `index.html`
- Create: `style.css`
- Create: `js/ui.js`
- Create: `js/main.js`

**Interfaces:**
- Consumes: everything from Tasks 3-7.
- Produces: a working page — start-engagement form, live steps feed, confirmation modal, export button. Nothing downstream depends on this (final task of Sub-proyecto 1).

- [ ] **Step 1: Write `index.html`**

```html
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Auditor</title>
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <main id="app">
    <section id="start-panel">
      <h1>Auditor</h1>
      <input id="target-input" placeholder="Target (IP/host)" />
      <input id="scope-input" placeholder="Scope (igual al target en v1)" />
      <input id="model-input" placeholder="Modelo Ollama (ej. llama3.1)" value="llama3.1" />
      <button id="start-btn">Iniciar engagement</button>
    </section>
    <section id="steps-panel" hidden>
      <div id="steps-feed"></div>
      <button id="export-btn">Export JSON</button>
    </section>
    <div id="confirm-modal" hidden>
      <p id="confirm-text"></p>
      <button id="confirm-approve">Aprobar</button>
      <button id="confirm-reject">Rechazar</button>
    </div>
  </main>
  <script type="module" src="/js/main.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write minimal `style.css`**

```css
body { background: #0f1220; color: #e6e6f0; font-family: system-ui, sans-serif; margin: 0; padding: 2rem; }
#app { max-width: 760px; margin: 0 auto; }
input, button { font-size: 1rem; padding: 0.5rem; margin: 0.25rem 0; display: block; width: 100%; }
button { cursor: pointer; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.2); color: inherit; border-radius: 8px; backdrop-filter: blur(6px); }
#steps-feed { display: flex; flex-direction: column; gap: 0.5rem; margin: 1rem 0; }
.step { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 10px; padding: 0.75rem; backdrop-filter: blur(6px); }
.step.rejected { border-color: #d46a6a; }
.step.scope_violation { border-color: #ff3860; }
#confirm-modal { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 2rem; }
#confirm-modal p { max-width: 500px; background: #1a1e33; padding: 1rem; border-radius: 10px; }
```

- [ ] **Step 3: Write `js/ui.js`**

```javascript
export function renderStep(step) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = `step ${step.verdict || ""}`;
  div.textContent = `[${step.tool} ${JSON.stringify(step.args)}] verdict=${step.verdict}`;
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

export function showConfirmModal(decision, onApprove, onReject) {
  const modal = document.getElementById("confirm-modal");
  const text = document.getElementById("confirm-text");
  text.textContent = `Herramienta peligrosa: ${decision.tool} ${JSON.stringify(decision.args)} — ${decision.reasoning}`;
  modal.hidden = false;
  const approveBtn = document.getElementById("confirm-approve");
  const rejectBtn = document.getElementById("confirm-reject");
  const cleanup = () => {
    modal.hidden = true;
    approveBtn.onclick = null;
    rejectBtn.onclick = null;
  };
  approveBtn.onclick = () => { cleanup(); onApprove(); };
  rejectBtn.onclick = () => { cleanup(); onReject(); };
}
```

- [ ] **Step 4: Write `js/main.js`**

```javascript
import { initDB, createEngagement, exportEngagementJSON } from "./db.js";
import { startEngagement } from "./bridge_client.js";
import { runAgentLoop } from "./agent.js";
import { renderStep, showConfirmModal } from "./ui.js";

async function main() {
  const db = await initDB();

  document.getElementById("start-btn").onclick = async () => {
    const target = document.getElementById("target-input").value.trim();
    const scope = document.getElementById("scope-input").value.trim();
    const model = document.getElementById("model-input").value.trim();
    if (!target || !scope || !model) return;

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
      db, engagementId, model, target, systemPrompt,
      onStep: renderStep,
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
    });
  };
}

main();
```

- [ ] **Step 5: Manual verification — end-to-end via real UI**

Run: `python3 bridge.py`, open `http://127.0.0.1:8420/` in a browser. Fill target/scope with a real HTB IP already solved with ghost-ops (e.g. from `ghost-ops-brain.md`), model with a pulled Ollama model, click "Iniciar engagement".
Expected: steps appear live in the feed as the agent runs; a dangerous tool (e.g. `hydra` or `hashcat`) triggers the modal and blocks until approved/rejected; clicking "Export JSON" downloads a file containing `steps`, `findings`, `axis_ledger`.

- [ ] **Step 6: Manual verification — scope-lock end-to-end**

While the engagement above is running, open the browser console and manually call `execTool("echo", ["leak"], "8.8.8.8")` (imported from `bridge_client.js`) to simulate the agent proposing an out-of-scope target.
Expected: the call resolves to `{"error": "scope_violation", "verdict": "scope_violation"}` — confirms the server-side gate holds even bypassing the agent loop entirely.

- [ ] **Step 7: Commit**

```bash
git add index.html style.css js/ui.js js/main.js
git commit -m "feat: UI wiring - start form, steps feed, confirmation modal, export"
```

---

## Post-plan validation (spec's acceptance criteria)

After Task 8, run the 4 checks from the spec's Testing section against a real HTB machine already documented in `ghost-ops-brain.md`:
1. Scope-lock rejects an out-of-scope target (covered by Task 8 Step 6).
2. Confirmation gate pauses before a dangerous action (covered by Task 7 Step 3 and Task 8 Step 5).
3. Axis ledger fires the "change tactics" warning on the 3rd repeated unproductive attempt (covered by Task 6 Step 2; verify the warning text actually reaches the LLM prompt via Task 7's `buildUserPrompt`).
4. Export JSON is complete and valid (covered by Task 8 Step 5).
