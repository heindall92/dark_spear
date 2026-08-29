# Findings Entity + Disk Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bridge.py-owned Finding entity (title/asset/severity/description/remediation/evidence) that the ReAct agent proposes as a third response type alongside tool-calls and `done`, reviewed asynchronously (non-blocking) via a UI panel, with evidence text hashed to disk only at accept time.

**Architecture:** `bridge.py` gains `FINDINGS` (in-memory list, mirrors the `KEYS`/`ROTATION_STATE` pattern) persisted to `~/.auditor/engagements/<target>_<timestamp>/findings.json` on every mutation, plus a matching `evidence/` directory for accept-time evidence files. Three new endpoints (`/findings/propose`, `/findings/list`, `/findings/review`). The LLM's JSON contract gains a third shape (`{"finding": {...}}`); the agent loop proposes it without pausing (no confirmation gate — findings are reviewed asynchronously in a panel, not blocking the ReAct loop's pace). An unused, differently-shaped IndexedDB `findings` object store from the original engine spec is removed as part of this work.

**Tech Stack:** Python 3 stdlib (`hashlib` for evidence hashing, no new dependencies), vanilla JS ES modules, no build step.

**Spec:** `~/tools/auditor/docs/superpowers/specs/2026-08-29-findings-and-disk-persistence-design.md`

## Global Constraints

- No automated test suite for this project (personal tool) — every task has a manual verification step with the exact command to run.
- Evidence text is never sent to the server before accept time — `/findings/propose` and the `reject`/`edit` actions of `/findings/review` only ever carry `evidence_step_ids` (integers), never step output text.
- `reject` never deletes a finding — it only sets `status: "rejected"`. Findings are append-only + status-mutated, never removed from `findings.json`.
- Proposing a finding must NEVER pause `runAgentLoop` — no confirmation gate, no `onPauseForConfirmation`. It's the exact opposite of the dangerous-tool gate: async review, not a blocking checkpoint.
- A malformed `/findings/propose` request (missing required field, invalid `severity`) returns `400` and must flow through `js/agent.js`'s EXISTING generic `agent_error`/5-strike path — no new error-handling branch.
- `severity` must be one of exactly: `Critical`, `High`, `Medium`, `Low`, `Info` — validated server-side on both propose and any edit that touches severity.
- IndexedDB's `DB_VERSION` bump (1 → 2) must guard existing store creation behind `event.oldVersion < 1` so upgrading an existing database doesn't throw `ConstraintError` from re-creating already-existing stores.

---

### Task 1: `bridge.py` — engagement directory, `FINDINGS` state, disk helpers

**Files:**
- Modify: `bridge.py` (module-level data/globals, `/engagement/start` handler, `do_POST`'s `global` line)

**Interfaces:**
- Produces (used by Task 2, 3): `FINDING_SEVERITIES: set[str]`, module globals `CURRENT_ENGAGEMENT_DIR: Path | None`, `FINDINGS: list[dict]`, helper functions `_sanitize_for_path(text: str) -> str`, `_save_findings() -> None` (writes `FINDINGS` to `CURRENT_ENGAGEMENT_DIR / "findings.json"`), `_next_finding_id() -> str` (returns `"f-{n}"`).
- `/engagement/start`'s response body gains `"engagement_dir": <str>` (the directory name, not the full path) alongside its existing `{"ok": true}`.

- [ ] **Step 1: Add `FINDING_SEVERITIES` and the helper functions, right after the `cumulative_phase_tools()` function (which currently ends the `PHASE_TOOLS` block) and before `class Handler`**

```python
FINDING_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

CURRENT_ENGAGEMENT_DIR: Path | None = None
FINDINGS: list[dict] = []


def _sanitize_for_path(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)[:80]


def _save_findings() -> None:
    findings_path = CURRENT_ENGAGEMENT_DIR / "findings.json"
    findings_path.write_text(json.dumps(FINDINGS, indent=2))


def _next_finding_id() -> str:
    return f"f-{len(FINDINGS) + 1}"
```

(`re` and `json` are already imported at the top of `bridge.py` — no new imports needed for this step.)

- [ ] **Step 2: Update `do_POST`'s `global` line to include the two new globals**

Current line (`bridge.py`, top of `do_POST`):
```python
        global CURRENT_SCOPE, CURRENT_PHASE, KEYS, PASSPHRASE, ROTATION_STATE
```
Replace with:
```python
        global CURRENT_SCOPE, CURRENT_PHASE, CURRENT_ENGAGEMENT_DIR, FINDINGS, KEYS, PASSPHRASE, ROTATION_STATE
```

- [ ] **Step 3: Set up the engagement directory and reset `FINDINGS` inside `/engagement/start`**

Current block:
```python
        if self.path == "/engagement/start":
            body = self._read_json()
            target = body.get("target", "").strip()
            scope = body.get("scope", "").strip()
            if not target or not scope:
                self._send_json(400, {"error": "target and scope required"})
                return
            CURRENT_SCOPE = {"target": target, "scope": scope}
            CURRENT_PHASE = 1
            audit_log({"event": "engagement_start", "target": target, "scope": scope})
            self._send_json(200, {"ok": True})
            return
```
Replace with:
```python
        if self.path == "/engagement/start":
            body = self._read_json()
            target = body.get("target", "").strip()
            scope = body.get("scope", "").strip()
            if not target or not scope:
                self._send_json(400, {"error": "target and scope required"})
                return
            CURRENT_SCOPE = {"target": target, "scope": scope}
            CURRENT_PHASE = 1
            engagement_dir_name = f"{_sanitize_for_path(target)}_{time.strftime('%Y-%m-%dT%H-%M-%S')}"
            CURRENT_ENGAGEMENT_DIR = Path.home() / ".auditor" / "engagements" / engagement_dir_name
            (CURRENT_ENGAGEMENT_DIR / "evidence").mkdir(parents=True, exist_ok=True)
            FINDINGS = []
            audit_log({"event": "engagement_start", "target": target, "scope": scope, "engagement_dir": engagement_dir_name})
            self._send_json(200, {"ok": True, "engagement_dir": engagement_dir_name})
            return
```

- [ ] **Step 4: Manual verification — server running, engagement directory created**

In one terminal: `python3 bridge.py` (note the printed token; enter any passphrase when prompted).

In another terminal:
```bash
TOKEN="<paste the printed token>"
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}'
echo
ls -la ~/.auditor/engagements/
```
Expected: JSON response includes `"engagement_dir"` matching the pattern `127.0.0.1_<timestamp>`, and `ls` shows that exact directory containing an empty `evidence/` subdirectory.

- [ ] **Step 5: Clean up test directory and commit**

```bash
rm -rf ~/.auditor/engagements/
git add bridge.py
git commit -m "feat: add engagement directory + FINDINGS state, reset on engagement start"
```

---

### Task 2: `bridge.py` — `POST /findings/propose` and `POST /findings/list`

**Files:**
- Modify: `bridge.py` (`do_POST`, insert before the final `self._send_json(404, ...)` fallback)

**Interfaces:**
- Consumes: `CURRENT_SCOPE`, `FINDING_SEVERITIES`, `FINDINGS`, `_next_finding_id()`, `_save_findings()` (Task 1).
- Produces (used by Task 5's client function): `POST /findings/propose` body `{title, asset, severity, description, remediation, evidence_step_ids}` → `200` with the created Finding object, or `400` on missing/invalid fields. `POST /findings/list` (no body) → `200` with the full `FINDINGS` list for the current engagement.

- [ ] **Step 1: Add both endpoints, right before the final `self._send_json(404, {"error": "unknown endpoint"})` fallback**

```python
        if self.path == "/findings/propose":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            title = body.get("title", "").strip()
            asset = body.get("asset", "").strip()
            severity = body.get("severity", "")
            description = body.get("description", "").strip()
            remediation = body.get("remediation", "").strip()
            evidence_step_ids = body.get("evidence_step_ids", [])
            if not title or not asset or not description or not remediation:
                self._send_json(400, {"error": "title_asset_description_remediation_required"})
                return
            if severity not in FINDING_SEVERITIES:
                self._send_json(400, {"error": f"invalid_severity: must be one of {sorted(FINDING_SEVERITIES)}"})
                return
            if not isinstance(evidence_step_ids, list):
                self._send_json(400, {"error": "evidence_step_ids_must_be_a_list"})
                return
            finding = {
                "id": _next_finding_id(),
                "title": title, "asset": asset, "severity": severity,
                "description": description, "remediation": remediation,
                "evidence_step_ids": evidence_step_ids, "evidence_hashes": [],
                "status": "proposed",
                "created_at": time.time(), "reviewed_at": None,
            }
            FINDINGS.append(finding)
            _save_findings()
            audit_log({"event": "finding_proposed", "id": finding["id"], "title": title, "severity": severity})
            self._send_json(200, finding)
            return

        if self.path == "/findings/list":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            self._send_json(200, FINDINGS)
            return
```

- [ ] **Step 2: Manual verification — propose, list, and reject-bad-input cases**

Server running (from Task 1's verification, or restart it and re-run `/engagement/start`):
```bash
TOKEN="<token>"
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}' > /dev/null
echo "-- propose a valid finding --"
curl -s -X POST http://127.0.0.1:8420/findings/propose -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"title":"Open SMB share","asset":"127.0.0.1","severity":"High","description":"Anonymous SMB access allows share enumeration.","remediation":"Disable anonymous SMB access.","evidence_step_ids":[3,7]}'
echo
echo "-- list findings --"
curl -s -X POST http://127.0.0.1:8420/findings/list -H "X-Auditor-Token: $TOKEN"
echo
echo "-- propose with invalid severity --"
curl -s -X POST http://127.0.0.1:8420/findings/propose -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"title":"x","asset":"x","severity":"Extreme","description":"x","remediation":"x","evidence_step_ids":[]}'
echo
echo "-- propose missing title --"
curl -s -X POST http://127.0.0.1:8420/findings/propose -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"title":"","asset":"x","severity":"Low","description":"x","remediation":"x","evidence_step_ids":[]}'
echo
cat ~/.auditor/engagements/*/findings.json
```
Expected: propose returns the created finding with `"id": "f-1"`, `"status": "proposed"`; list returns a one-element array matching it; the two bad-input calls each return `400` with a descriptive `error`; `findings.json` on disk contains the one valid finding.

- [ ] **Step 3: Clean up test directory and commit**

```bash
rm -rf ~/.auditor/engagements/
git add bridge.py
git commit -m "feat: add POST /findings/propose and POST /findings/list endpoints"
```

---

### Task 3: `bridge.py` — `POST /findings/review` (accept/reject/edit)

**Files:**
- Modify: `bridge.py` (add `import hashlib`, add a helper function, add the endpoint before the final 404 fallback)

**Interfaces:**
- Consumes: `CURRENT_ENGAGEMENT_DIR`, `FINDINGS`, `FINDING_SEVERITIES`, `_save_findings()` (Task 1, 2).
- Produces: `POST /findings/review` body `{finding_id, action: "accept"|"reject"|"edit", edited_fields?, evidence_texts?: [{step_id, output}]}` → `200` with the updated Finding, `404` if `finding_id` doesn't exist, `400` on an invalid `action` or invalid `severity` inside `edited_fields`.

- [ ] **Step 1: Add `import hashlib` near the top of `bridge.py`, alongside the other stdlib imports**

```python
import getpass
import hashlib
import json
```
(insert alphabetically among the existing `import` lines — `hashlib` goes between `getpass` and `json`)

- [ ] **Step 2: Add the `_apply_finding_edits` helper function, right after `_next_finding_id()` from Task 1**

```python
def _apply_finding_edits(finding: dict, edited_fields: dict) -> str | None:
    for key in ("title", "asset", "severity", "description", "remediation"):
        if key in edited_fields:
            if key == "severity" and edited_fields[key] not in FINDING_SEVERITIES:
                return f"invalid_severity: must be one of {sorted(FINDING_SEVERITIES)}"
            finding[key] = edited_fields[key]
    return None
```

- [ ] **Step 3: Add the `/findings/review` endpoint, right before the final `self._send_json(404, {"error": "unknown endpoint"})` fallback**

```python
        if self.path == "/findings/review":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            finding_id = body.get("finding_id", "")
            action = body.get("action", "")
            finding = next((f for f in FINDINGS if f["id"] == finding_id), None)
            if finding is None:
                self._send_json(404, {"error": "finding_not_found"})
                return
            if action not in {"accept", "reject", "edit"}:
                self._send_json(400, {"error": "invalid_action"})
                return

            if action in ("edit", "accept"):
                error = _apply_finding_edits(finding, body.get("edited_fields", {}))
                if error:
                    self._send_json(400, {"error": error})
                    return

            if action == "edit":
                finding["status"] = "edited"
                finding["reviewed_at"] = time.time()
            elif action == "reject":
                finding["status"] = "rejected"
                finding["reviewed_at"] = time.time()
            elif action == "accept":
                evidence_texts = body.get("evidence_texts", [])
                hashes = []
                for entry in evidence_texts:
                    output = entry.get("output", "")
                    digest = hashlib.sha256(output.encode()).hexdigest()
                    (CURRENT_ENGAGEMENT_DIR / "evidence" / f"{digest}.txt").write_text(output)
                    hashes.append(digest)
                finding["evidence_hashes"] = hashes
                finding["status"] = "accepted"
                finding["reviewed_at"] = time.time()

            _save_findings()
            audit_log({"event": "finding_reviewed", "id": finding_id, "action": action})
            self._send_json(200, finding)
            return
```

- [ ] **Step 4: Manual verification — reject, edit, and accept (with evidence hashing) paths**

Server running (restart and re-run `/engagement/start` if needed):
```bash
TOKEN="<token>"
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}' > /dev/null
FID=$(curl -s -X POST http://127.0.0.1:8420/findings/propose -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"title":"Open SMB share","asset":"127.0.0.1","severity":"High","description":"desc","remediation":"rem","evidence_step_ids":[1]}' | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "finding id: $FID"

echo "-- reject a second finding, confirm status but NOT deleted --"
FID2=$(curl -s -X POST http://127.0.0.1:8420/findings/propose -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"title":"noise","asset":"127.0.0.1","severity":"Info","description":"d","remediation":"r","evidence_step_ids":[]}' | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
curl -s -X POST http://127.0.0.1:8420/findings/review -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d "{\"finding_id\":\"$FID2\",\"action\":\"reject\"}"
echo
echo "-- confirm the rejected finding is still present in /findings/list (not deleted) --"
curl -s -X POST http://127.0.0.1:8420/findings/list -H "X-Auditor-Token: $TOKEN" | python3 -c "import json,sys; data=json.load(sys.stdin); ids=[f['id'] for f in data]; print('all ids still present:', ids)"

echo "-- edit the first finding's title --"
curl -s -X POST http://127.0.0.1:8420/findings/review -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d "{\"finding_id\":\"$FID\",\"action\":\"edit\",\"edited_fields\":{\"title\":\"Anonymous SMB access\"}}"
echo

echo "-- accept with fabricated evidence, confirm hash matches --"
curl -s -X POST http://127.0.0.1:8420/findings/review -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d "{\"finding_id\":\"$FID\",\"action\":\"accept\",\"evidence_texts\":[{\"step_id\":1,\"output\":\"smbclient -L output showing anonymous access\"}]}"
echo
echo -n "smbclient -L output showing anonymous access" | sha256sum
ls ~/.auditor/engagements/*/evidence/
```
Expected: reject response shows `"status": "rejected"`; the `/findings/list` follow-up call shows both `id`s still present (not gone); edit response shows the new title and `"status": "edited"`; accept response shows `"status": "accepted"` and `"evidence_hashes": ["<hash>"]` where `<hash>` matches the `sha256sum` output exactly; the evidence directory contains a file named `<hash>.txt`.

- [ ] **Step 5: Manual verification — findings.json survives a `bridge.py` restart**

With the accepted finding from Step 4 still in `findings.json`, note the exact engagement directory path, then kill and restart `bridge.py` (new passphrase entry is fine — the keystore is unrelated to this check):
```bash
ENGAGEMENT_DIR=$(ls -d ~/.auditor/engagements/*/ | head -1)
echo "before restart:"
cat "${ENGAGEMENT_DIR}findings.json"
```
Stop `bridge.py` (Ctrl-C or kill the tmux/background process), restart it (`python3 bridge.py`, re-enter a passphrase), then WITHOUT calling `/engagement/start` again (that would create a new timestamped directory — this check is about on-disk durability of the file itself surviving a process restart, not session resumption, which this project's `CURRENT_SCOPE`/`CURRENT_PHASE` don't support either):
```bash
echo "after restart, same file read directly from disk:"
cat "${ENGAGEMENT_DIR}findings.json"
```
Expected: both `cat` calls print identical JSON content — the file on disk is unaffected by the server process restarting, confirming durability. (This does NOT test that `/findings/list` can serve the old engagement's data after a restart without re-starting that engagement — that's out of scope, matching how `/exec`/`/phase/advance` already require a fresh `/engagement/start` after any `bridge.py` restart.)

- [ ] **Step 6: Clean up test directory and commit**

```bash
rm -rf ~/.auditor/engagements/
git add bridge.py
git commit -m "feat: add POST /findings/review endpoint (accept/reject/edit)"
```

---

### Task 4: `js/db.js` — remove old `findings` store, add `getStepsByIds`

**Files:**
- Modify: `js/db.js`

**Interfaces:**
- Removes: `addFinding`, `getFindings` (unused, wrong-shape leftover from the original engine spec), and the `findings` object store from `initDB`.
- Produces (used by Task 10): `getStepsByIds(db, stepIds: number[]): Promise<(object|undefined)[]>` — looks up steps by primary key, preserving `stepIds`' order; an ID with no matching step resolves to `undefined` at that position (caller filters).
- Modifies: `exportEngagementJSON` drops the `findings` key from its return value (the old store it read from no longer exists).

- [ ] **Step 1: Bump `DB_VERSION` and guard the existing store-creation code behind `event.oldVersion`, removing the old `findings` store creation and adding its deletion for upgrading databases**

Current `initDB`:
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
```
Replace with:
```javascript
const DB_NAME = "auditor";
const DB_VERSION = 2;

export function initDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (event.oldVersion < 1) {
        const eng = db.createObjectStore("engagement", { keyPath: "id", autoIncrement: true });
        eng.createIndex("status", "status");
        const steps = db.createObjectStore("steps", { keyPath: "id", autoIncrement: true });
        steps.createIndex("engagementId", "engagementId");
        const axis = db.createObjectStore("axis_ledger", { keyPath: "id", autoIncrement: true });
        axis.createIndex("engagementId", "engagementId");
        axis.createIndex("lookup", ["engagementId", "tool", "paramsHash"]);
      }
      if (event.oldVersion < 2) {
        if (db.objectStoreNames.contains("findings")) {
          db.deleteObjectStore("findings");
        }
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
```

- [ ] **Step 2: Remove `addFinding` and `getFindings`**

Delete these two functions entirely:
```javascript
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
```

- [ ] **Step 3: Update `exportEngagementJSON` to stop reading from the removed store**

Current:
```javascript
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
Replace with:
```javascript
export async function exportEngagementJSON(db, engagementId) {
  const steps = await getSteps(db, engagementId);
  const axis = await new Promise((resolve, reject) => {
    const store = tx(db, "axis_ledger");
    const req = store.index("engagementId").getAll(engagementId);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return { engagementId, steps, axis_ledger: axis };
}
```

- [ ] **Step 4: Add `getStepsByIds`, near `getSteps`**

```javascript
export function getStepsByIds(db, stepIds) {
  return new Promise((resolve, reject) => {
    if (stepIds.length === 0) {
      resolve([]);
      return;
    }
    const store = tx(db, "steps");
    const results = [];
    let remaining = stepIds.length;
    for (const id of stepIds) {
      const req = store.get(id);
      req.onsuccess = () => {
        results.push(req.result);
        remaining -= 1;
        if (remaining === 0) resolve(results);
      };
      req.onerror = () => reject(req.error);
    }
  });
}
```

- [ ] **Step 5: Manual verification**

```bash
cd ~/tools/auditor
node --check js/db.js && echo "syntax OK"
grep -c "addFinding\|getFindings" js/db.js
```
Expected: `syntax OK`, and the `grep -c` count is `0` (both removed functions fully gone; note `getStepsByIds` doesn't match this pattern so it won't falsely inflate the count).

Then in a real browser (per this project's established manual-testing pattern): open the app fresh (or with an existing `auditor` IndexedDB from before this change), open DevTools → Application → IndexedDB → `auditor`, confirm only `engagement`, `steps`, `axis_ledger` object stores exist (no `findings`).

- [ ] **Step 6: Commit**

```bash
git add js/db.js
git commit -m "feat: remove unused IndexedDB findings store, add getStepsByIds"
```

---

### Task 5: `js/bridge_client.js` — findings client functions

**Files:**
- Modify: `js/bridge_client.js`

**Interfaces:**
- Consumes: `postJSON` (existing internal helper).
- Produces (used by Task 7, 10): `proposeFinding(finding: object): Promise<object>`, `listFindings(): Promise<object[]>`, `reviewFinding(findingId: string, action: string, extra?: object): Promise<object>`.

- [ ] **Step 1: Add the three functions, next to the other endpoint wrappers (e.g. after `advancePhase`)**

```javascript
export function proposeFinding(finding) {
  return postJSON("/findings/propose", finding);
}

export function listFindings() {
  return postJSON("/findings/list", {});
}

export function reviewFinding(findingId, action, extra = {}) {
  return postJSON("/findings/review", { finding_id: findingId, action, ...extra });
}
```

- [ ] **Step 2: Manual verification**

```bash
cd ~/tools/auditor
node --check js/bridge_client.js && echo "syntax OK"
grep -n "export function proposeFinding\|export function listFindings\|export function reviewFinding" js/bridge_client.js
```

- [ ] **Step 3: Commit**

```bash
git add js/bridge_client.js
git commit -m "feat: add proposeFinding/listFindings/reviewFinding client functions"
```

---

### Task 6: `js/ollama.js` — third response shape (`finding`)

**Files:**
- Modify: `js/ollama.js`

**Interfaces:**
- Produces (used by Task 7): `askAgent(...)` may now resolve to `{ finding: object, reasoning: string }` in addition to its existing `{ done: true, ... }` and `{ tool, args, reasoning }` shapes.

- [ ] **Step 1: Update `RESPONSE_CONTRACT` to document the third shape**

Current:
```javascript
const RESPONSE_CONTRACT = `You must respond with ONLY a JSON object, no prose, no markdown fences.
Either:
{"tool": "<binary name>", "args": ["<arg1>", "<arg2>", ...], "reasoning": "<why>"}
or, if the engagement objective is complete:
{"done": true, "reasoning": "<why>"}

"tool" must be exactly one binary name from this list — never a shell like
bash/sh/zsh/cmd/powershell, never a full command string:
${ALLOWED_TOOLS_HINT.join(", ")}
"args" is that binary's own argv, each element a SEPARATE argument (the way
you'd pass them to subprocess.run(["tool", "arg1", "arg2"]), never one
combined command string.`;
```
Replace with:
```javascript
const RESPONSE_CONTRACT = `You must respond with ONLY a JSON object, no prose, no markdown fences.
Either:
{"tool": "<binary name>", "args": ["<arg1>", "<arg2>", ...], "reasoning": "<why>"}
or, if the engagement objective is complete:
{"done": true, "reasoning": "<why>"}
or, if you have gathered enough evidence to report a real vulnerability finding:
{"finding": {"title": "<short title>", "asset": "<host/url/target this applies to>",
  "severity": "Critical"|"High"|"Medium"|"Low"|"Info",
  "description": "<what it is and why it matters>",
  "remediation": "<how to fix it>",
  "evidence_step_ids": [<step ids from Recent history that prove this>]},
 "reasoning": "<why you're reporting this now>"}

"tool" must be exactly one binary name from this list — never a shell like
bash/sh/zsh/cmd/powershell, never a full command string:
${ALLOWED_TOOLS_HINT.join(", ")}
"args" is that binary's own argv, each element a SEPARATE argument (the way
you'd pass them to subprocess.run(["tool", "arg1", "arg2"]), never one
combined command string.
Reporting a finding does NOT end the engagement — keep working after it.`;
```

- [ ] **Step 2: Add the `finding` branch to `askAgent`, between the existing `done` check and the `tool` check**

Current:
```javascript
  if (parsed.done) return { done: true, reasoning: parsed.reasoning ?? "" };
  if (!parsed.tool) throw new Error(`ollama_missing_tool_field: ${raw.slice(0, 200)}`);
```
Replace with:
```javascript
  if (parsed.done) return { done: true, reasoning: parsed.reasoning ?? "" };
  if (parsed.finding) return { finding: parsed.finding, reasoning: parsed.reasoning ?? "" };
  if (!parsed.tool) throw new Error(`ollama_missing_tool_field: ${raw.slice(0, 200)}`);
```

- [ ] **Step 3: Manual verification**

```bash
cd ~/tools/auditor
node --check js/ollama.js && echo "syntax OK"
grep -n 'parsed.finding' js/ollama.js
```

- [ ] **Step 4: Commit**

```bash
git add js/ollama.js
git commit -m "feat: add finding response shape to the LLM JSON contract"
```

---

### Task 7: `js/agent.js` — non-blocking finding proposal in the loop

**Files:**
- Modify: `js/agent.js`

**Interfaces:**
- Consumes: `proposeFinding` (Task 5).
- Produces: `runAgentLoop({..., onFindingProposed = () => {}, ...})` gains an `onFindingProposed` optional callback, called with the created Finding object whenever the LLM proposes one.

- [ ] **Step 1: Add `proposeFinding` to the existing `bridge_client.js` import**

Current:
```javascript
import { execTool, QuotaExhaustedError } from "./bridge_client.js";
```
Replace with:
```javascript
import { execTool, QuotaExhaustedError, proposeFinding } from "./bridge_client.js";
```

- [ ] **Step 2: Add `onFindingProposed` to `runAgentLoop`'s signature**

Current:
```javascript
export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {}, phaseState }) {
```
Replace with:
```javascript
export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {}, onFindingProposed = () => {}, phaseState }) {
```

- [ ] **Step 3: Add the finding branch, right after `if (decision.done) { return; }`**

Current:
```javascript
    if (decision.done) {
      return;
    }

    if (isDangerous(decision.tool, decision.args)) {
```
Replace with:
```javascript
    if (decision.done) {
      return;
    }

    if (decision.finding) {
      const finding = await proposeFinding(decision.finding);
      onFindingProposed(finding);
      continue;
    }

    if (isDangerous(decision.tool, decision.args)) {
```

(This does NOT go through `addStep`/the axis ledger — a finding proposal is not a tool execution. It also does not pause via `onPauseForConfirmation` — review happens asynchronously in the UI, per the Global Constraints. If `proposeFinding`'s underlying `postJSON` call throws — e.g. the server returns `400` for a missing field — that exception propagates up out of the `try` block that already wraps the `askAgent` call... actually verify this: `decision` is produced INSIDE the existing `try`/`catch` around `askAgent`, but `decision.finding`'s branch here is OUTSIDE that `try` block, after `consecutiveErrors = 0` already ran. A `proposeFinding` failure here is NOT currently caught by the existing catch block. See the note in Step 4 below — this is a real design point to verify, not assume.)

- [ ] **Step 4: Verify (and fix if needed) that a `proposeFinding` failure is NOT silently unhandled**

Read the surrounding code carefully: the `try { decision = await askAgent(...) } catch (err) { ... }` block only wraps the `askAgent` call. Everything after it — `if (decision.done)`, the new `if (decision.finding)` block, `isDangerous`, `execTool` — runs OUTSIDE that try/catch, in the loop body directly. This means a thrown error from `execTool` today would ALSO propagate uncaught out of `runAgentLoop` (this is pre-existing behavior, not something this task changes) — so a thrown error from `proposeFinding` behaves consistently with how `execTool` already behaves: it propagates out of `runAgentLoop`, out of the `#start-btn` click handler's async function, becoming an unhandled promise rejection in the browser console, and the loop silently stops (no further `onStep`/`onFindingProposed` calls, no visible UI error). This matches `execTool`'s existing failure behavior exactly — it is NOT a regression introduced by this task, just worth confirming explicitly rather than assuming. Do not add new error handling here; the Global Constraint about the 5-strike path applies to `askAgent`/JSON-parsing failures (which DO flow through the existing catch), not to `execTool`/`proposeFinding`'s network-level failures (which never did, for either function, before or after this task).

- [ ] **Step 5: Manual verification**

```bash
cd ~/tools/auditor
node --check js/agent.js && echo "syntax OK"
grep -n "onFindingProposed\|proposeFinding" js/agent.js
```

- [ ] **Step 6: Commit**

```bash
git add js/agent.js
git commit -m "feat: handle finding proposals in the agent loop without blocking"
```

---

### Task 8: UI markup — findings button + panel

**Files:**
- Modify: `index.html` (`#phase-bar`, and add a new `#findings-panel` after `#key-manage-panel`)
- Modify: `style.css`

**Interfaces:**
- Produces (used by Task 9, 10): DOM elements `#findings-btn`, `#findings-panel` (hidden by default), `#findings-list` (container), `#close-findings-btn`.

- [ ] **Step 1: Add `#findings-btn` to `#phase-bar`**

Current:
```html
      <div id="phase-bar">
        <span id="phase-indicator">Fase 1/4: Intelligence Gathering</span>
        <button id="advance-phase-btn" type="button">Avanzar fase</button>
      </div>
```
Replace with:
```html
      <div id="phase-bar">
        <span id="phase-indicator">Fase 1/4: Intelligence Gathering</span>
        <button id="advance-phase-btn" type="button">Avanzar fase</button>
        <button id="findings-btn" type="button">Hallazgos (0 pendientes)</button>
      </div>
```

- [ ] **Step 2: Add the findings panel markup, right after `#key-manage-panel`'s closing `</div>`**

```html
    <div id="findings-panel" hidden>
      <h2>Hallazgos</h2>
      <div id="findings-list"></div>
      <button id="close-findings-btn" type="button">Cerrar</button>
    </div>
```

- [ ] **Step 3: Add styling to `style.css` (append at the end of the file)**

```css
#findings-panel { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 2rem; }
#findings-panel[hidden] { display: none; }
#findings-panel > * { max-width: 600px; width: 100%; }
#findings-list { display: flex; flex-direction: column; gap: 0.75rem; margin: 0.5rem 0; max-height: 70vh; overflow-y: auto; }
.finding-card { background: #1a1e33; border-radius: 10px; padding: 1rem; border: 1px solid rgba(255,255,255,0.12); }
.finding-card input, .finding-card textarea, .finding-card select { width: 100%; box-sizing: border-box; }
.severity-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 6px; font-size: 0.75rem; font-weight: bold; margin-bottom: 0.5rem; }
.severity-Critical { background: #ff3860; }
.severity-High { background: #ff7a3d; }
.severity-Medium { background: #ffc23d; color: #1a1a1a; }
.severity-Low { background: #3dd9ff; color: #1a1a1a; }
.severity-Info { background: rgba(255,255,255,0.2); }
.finding-marker { cursor: pointer; border-color: #3dd9ff; }
```

- [ ] **Step 4: Manual verification**

```bash
cd ~/tools/auditor
python3 -c "import html.parser; html.parser.HTMLParser().feed(open('index.html').read()); print('index.html parses OK')"
grep -n 'id="findings-btn"\|id="findings-panel"\|id="findings-list"\|id="close-findings-btn"' index.html
```
Expected: parses OK, all four IDs found.

- [ ] **Step 5: Commit**

```bash
git add index.html style.css
git commit -m "feat: add findings button and review panel markup"
```

---

### Task 9: `js/ui.js` — findings panel + feed marker rendering

**Files:**
- Modify: `js/ui.js`

**Interfaces:**
- Produces (used by Task 10): `renderFindingsPanel(findings: object[], callbacks: {onAccept, onReject}): void` — `onAccept(findingId: string, editedFields: object, evidenceStepIds: number[])`, `onReject(findingId: string)`. `renderFindingMarker(finding: object): void`.

- [ ] **Step 1: Add both functions, at the end of the file**

```javascript
export function renderFindingsPanel(findings, { onAccept, onReject }) {
  const container = document.getElementById("findings-list");
  container.innerHTML = "";
  const pending = findings.filter((f) => f.status === "proposed" || f.status === "edited");
  const others = findings.filter((f) => f.status === "accepted" || f.status === "rejected");
  for (const f of [...pending, ...others]) {
    const card = document.createElement("div");
    card.className = "finding-card";

    const badge = document.createElement("span");
    badge.className = `severity-badge severity-${f.severity}`;
    badge.textContent = `${f.severity} — ${f.status}`;
    card.appendChild(badge);

    const titleInput = document.createElement("input");
    titleInput.value = f.title;
    card.appendChild(titleInput);

    const assetInput = document.createElement("input");
    assetInput.value = f.asset;
    card.appendChild(assetInput);

    const severitySelect = document.createElement("select");
    for (const sev of ["Critical", "High", "Medium", "Low", "Info"]) {
      const opt = document.createElement("option");
      opt.value = sev;
      opt.textContent = sev;
      if (sev === f.severity) opt.selected = true;
      severitySelect.appendChild(opt);
    }
    card.appendChild(severitySelect);

    const descInput = document.createElement("textarea");
    descInput.value = f.description;
    card.appendChild(descInput);

    const remInput = document.createElement("textarea");
    remInput.value = f.remediation;
    card.appendChild(remInput);

    const evidenceLine = document.createElement("div");
    evidenceLine.textContent = `Evidencia: steps ${f.evidence_step_ids.join(", ") || "(ninguno)"}`;
    card.appendChild(evidenceLine);

    if (f.status === "proposed" || f.status === "edited") {
      const acceptBtn = document.createElement("button");
      acceptBtn.textContent = "Aceptar";
      acceptBtn.onclick = () => onAccept(f.id, {
        title: titleInput.value,
        asset: assetInput.value,
        severity: severitySelect.value,
        description: descInput.value,
        remediation: remInput.value,
      }, f.evidence_step_ids);
      card.appendChild(acceptBtn);

      const rejectBtn = document.createElement("button");
      rejectBtn.textContent = "Rechazar";
      rejectBtn.onclick = () => onReject(f.id);
      card.appendChild(rejectBtn);
    }

    container.appendChild(card);
  }
}

export function renderFindingMarker(finding) {
  const feed = document.getElementById("steps-feed");
  const div = document.createElement("div");
  div.className = "step finding-marker";
  div.textContent = `💡 Hallazgo propuesto: ${finding.title}`;
  div.onclick = () => { document.getElementById("findings-panel").hidden = false; };
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}
```

- [ ] **Step 2: Manual verification**

```bash
cd ~/tools/auditor
node --check js/ui.js && echo "syntax OK"
grep -n "export function renderFindingsPanel\|export function renderFindingMarker" js/ui.js
```

- [ ] **Step 3: Commit**

```bash
git add js/ui.js
git commit -m "feat: add findings panel and feed-marker rendering"
```

---

### Task 10: `js/main.js` — wire the findings flow end to end

**Files:**
- Modify: `js/main.js`

**Interfaces:**
- Consumes: `proposeFinding`/`listFindings`/`reviewFinding` (Task 5), `getStepsByIds` (Task 4), `renderFindingsPanel`/`renderFindingMarker` (Task 9), `#findings-btn`/`#findings-panel`/`#close-findings-btn` (Task 8).
- Produces: a working findings review flow — proposals from the agent loop update the button's pending count and drop a feed marker; opening the panel lists all findings; Accept gathers evidence from IndexedDB and commits it server-side; Reject marks without deleting.

- [ ] **Step 1: Update the import lines**

Current:
```javascript
import { initDB, createEngagement, exportEngagementJSON } from "./db.js";
import { startEngagement, setSessionToken, listKeys, addKey, selectKeys, advancePhase } from "./bridge_client.js";
import { runAgentLoop, PHASE_NAMES } from "./agent.js";
import { renderStep, showConfirmModal, renderKeyList, renderWaitingForQuota, renderPhaseIndicator } from "./ui.js";
```
Replace with:
```javascript
import { initDB, createEngagement, exportEngagementJSON, getStepsByIds } from "./db.js";
import { startEngagement, setSessionToken, listKeys, addKey, selectKeys, advancePhase, listFindings, reviewFinding } from "./bridge_client.js";
import { runAgentLoop, PHASE_NAMES } from "./agent.js";
import { renderStep, showConfirmModal, renderKeyList, renderWaitingForQuota, renderPhaseIndicator, renderFindingsPanel, renderFindingMarker } from "./ui.js";
```

- [ ] **Step 2: Add `refreshFindingsPanel` and wire `#findings-btn`/`#close-findings-btn`, right after the existing `close-keys-btn` handler (before `document.getElementById("start-btn").onclick = ...`)**

```javascript
  async function refreshFindingsPanel() {
    const findings = await listFindings();
    const pendingCount = findings.filter((f) => f.status === "proposed").length;
    document.getElementById("findings-btn").textContent = `Hallazgos (${pendingCount} pendientes)`;
    renderFindingsPanel(findings, {
      onAccept: async (id, editedFields, evidenceStepIds) => {
        const steps = await getStepsByIds(db, evidenceStepIds);
        const evidence_texts = steps.filter(Boolean).map((s) => ({ step_id: s.id, output: s.output }));
        await reviewFinding(id, "accept", { edited_fields: editedFields, evidence_texts });
        await refreshFindingsPanel();
      },
      onReject: async (id) => {
        await reviewFinding(id, "reject");
        await refreshFindingsPanel();
      },
    });
  }

  document.getElementById("findings-btn").onclick = async () => {
    await refreshFindingsPanel();
    document.getElementById("findings-panel").hidden = false;
  };

  document.getElementById("close-findings-btn").onclick = () => {
    document.getElementById("findings-panel").hidden = true;
  };
```

- [ ] **Step 3: Pass `onFindingProposed` into the `runAgentLoop({...})` call**

Current:
```javascript
    runAgentLoop({
      db, engagementId, model, target, systemPrompt, endpoint, phaseState,
      onStep: renderStep,
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
      onWaitingForQuota: renderWaitingForQuota,
    });
```
Replace with:
```javascript
    runAgentLoop({
      db, engagementId, model, target, systemPrompt, endpoint, phaseState,
      onStep: renderStep,
      onPauseForConfirmation: (decision, resolve) => {
        showConfirmModal(decision, () => resolve(true), () => resolve(false));
      },
      onWaitingForQuota: renderWaitingForQuota,
      onFindingProposed: async (finding) => {
        renderFindingMarker(finding);
        await refreshFindingsPanel();
      },
    });
```

- [ ] **Step 4: Manual verification**

```bash
cd ~/tools/auditor
node --check js/main.js && echo "syntax OK"
```

Then in a real browser (per this project's established manual-testing pattern): restart `bridge.py`, open the printed URL, start an engagement. Confirm `#findings-btn` reads "Hallazgos (0 pendientes)". Manually trigger a proposal via curl (`/findings/propose`, same body shape as Task 2's verification) while the page is open, then click `#findings-btn` — confirm it now shows "Hallazgos (1 pendientes)" and the panel lists the finding with editable fields. Click **Aceptar**, confirm the panel refreshes showing `status: accepted` and no longer offers Accept/Reject buttons for it (note: since the curl-proposed finding's `evidence_step_ids` likely don't correspond to real steps in this session's IndexedDB, `getStepsByIds` will resolve `undefined` for them — confirm this doesn't throw, and that the finding still accepts successfully with an empty or partial `evidence_hashes`, matching the spec's "partial evidence is allowed" rule).

- [ ] **Step 5: Commit**

```bash
git add js/main.js
git commit -m "feat: wire findings review flow into the engagement UI"
```
