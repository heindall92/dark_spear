# PTES Phase FSM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a server-enforced 4-phase PTES-style state machine (Intelligence Gathering → Enumeration/Vuln Analysis → Exploitation → Post-Exploitation) that gates which tools `/exec` will run, cumulative and operator-advanced, so the ReAct agent can't jump straight to exploitation without doing recon first.

**Architecture:** `bridge.py` gains a hand-maintained `PHASE_TOOLS` table and a `CURRENT_PHASE` global (same lifecycle/trust model as the existing `CURRENT_SCOPE`/`ALLOWED_TOOLS`/`DANGEROUS_TOOLS` machinery — server is the enforcement boundary, LLM is never trusted to self-limit). `/exec` gains one more check between the existing `tool_not_allowlisted` and scope-lock checks. A new `POST /phase/advance` endpoint lets the operator manually advance (no heuristics, no exit conditions — the button click is the human decision). `js/agent.js` gets a mirrored `PHASE_TOOLS`/`PHASE_NAMES` hint table (same hand-sync convention already used for `ALLOWED_TOOLS`/`ALLOWED_TOOLS_HINT`) so the per-iteration prompt tells the model what's currently available, cutting down on wasted `phase_locked` rejections without the server ever trusting that hint.

**Tech Stack:** Python 3 stdlib (no new dependencies), vanilla JS ES modules, no build step.

**Spec:** `~/tools/auditor/docs/superpowers/specs/2026-08-28-ptes-fsm-design.md`

## Global Constraints

- No automated test suite for this project (personal tool) — every task has a manual verification step with the exact command to run.
- `PHASE_TOOLS`/`PHASE_NAMES` are hand-edited, static data — never LLM-generated or runtime-modified, same governance as `ALLOWED_TOOLS`/`DANGEROUS_TOOLS`.
- The phase gate and the `DANGEROUS_TOOLS`/argument-pattern gate are fully independent checks. Never let one short-circuit or replace the other — a phase-unlocked tool must still be able to trigger the confirmation modal.
- Phases are cumulative: advancing to phase N adds phase N's tools to what's already unlocked, never removes access to earlier phases' tools.
- `POST /phase/advance` is unconditional (capped at phase 4, no-op past that) — no exit-condition checks, no heuristics, no confirmation modal. The operator's click is the only gate.
- Every tool named in `PHASE_TOOLS` must already be in `ALLOWED_TOOLS` (or added by this plan) — the phase table is a partition/subset annotation on top of the existing whitelist, never an independent tool list.

---

### Task 1: `bridge.py` — `PHASE_TOOLS`/`PHASE_NAMES` data + `cumulative_phase_tools()` + `CURRENT_PHASE` global

**Files:**
- Modify: `bridge.py` (module-level data near `ALLOWED_TOOLS`, `CURRENT_SCOPE` global, `/engagement/start` handler, `do_POST`'s `global` line)

**Interfaces:**
- Produces (used by Task 3, 4, and mirrored by Task 6): `PHASE_NAMES: dict[int, str]`, `PHASE_TOOLS: dict[int, set[str]]`, `MAX_PHASE: int`, `cumulative_phase_tools(phase: int) -> set[str]`, module global `CURRENT_PHASE: int`.

- [ ] **Step 1: Add `PHASE_NAMES`, `PHASE_TOOLS`, `MAX_PHASE`, and `cumulative_phase_tools()` right after the existing `ALLOWED_TOOLS` set (after its closing `}`, currently ending around line 57)**

```python
PHASE_NAMES = {
    1: "Intelligence Gathering",
    2: "Enumeration & Vulnerability Analysis",
    3: "Exploitation",
    4: "Post-Exploitation",
}

# Hand-maintained partition of ALLOWED_TOOLS into PTES-style phases. Every
# tool listed here must also be in ALLOWED_TOOLS — this is a subset
# annotation on top of the whitelist, not an independent tool list. Phases
# are cumulative (see cumulative_phase_tools) — this dict holds only each
# phase's OWN additions, not the running total.
PHASE_TOOLS = {
    1: {"nmap", "whatweb", "dig", "nslookup", "dnsrecon", "ldapsearch",
        "enum4linux", "rpcclient", "echo"},
    2: {"gobuster", "ffuf", "nikto", "smbclient", "GetNPUsers.py",
        "GetUserSPNs.py", "bloodhound-python", "lookupsid.py", "samrdump.py",
        "searchsploit", "adscan", "certipy"},
    3: {"sqlmap", "hydra", "secretsdump.py", "wmiexec.py", "psexec.py",
        "smbexec.py", "atexec.py", "dcomexec.py", "mssqlclient.py",
        "ntlmrelayx.py", "crackmapexec", "netexec", "ticketer.py",
        "getST.py", "raiseChild.py"},
    4: {"hashcat", "john"},
}

MAX_PHASE = max(PHASE_TOOLS)


def cumulative_phase_tools(phase: int) -> set[str]:
    result: set[str] = set()
    for n in range(1, phase + 1):
        result |= PHASE_TOOLS.get(n, set())
    return result
```

- [ ] **Step 2: Add the `CURRENT_PHASE` global next to `CURRENT_SCOPE` (currently `bridge.py:60`)**

```python
CURRENT_SCOPE: dict | None = None
CURRENT_PHASE: int = 1
```

- [ ] **Step 3: Reset `CURRENT_PHASE` to `1` inside the `/engagement/start` handler, and declare it in `do_POST`'s `global` line**

Change the `global` line at the top of `do_POST` (currently `bridge.py:195`):
```python
        global CURRENT_SCOPE, CURRENT_PHASE, KEYS, PASSPHRASE, ROTATION_STATE
```

Inside the `/engagement/start` block (currently `bridge.py:204-212`), add the reset right after `CURRENT_SCOPE` is set:
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

- [ ] **Step 4: Manual verification — data integrity and reset behavior**

```bash
cd ~/tools/auditor
python3 -c "
import runpy
mod = runpy.run_path('bridge.py', run_name='not_main')
PHASE_TOOLS = mod['PHASE_TOOLS']
ALLOWED_TOOLS = mod['ALLOWED_TOOLS']
cumulative_phase_tools = mod['cumulative_phase_tools']

# every phase tool must be in ALLOWED_TOOLS
all_phase_tools = set().union(*PHASE_TOOLS.values())
missing = all_phase_tools - ALLOWED_TOOLS
assert not missing, f'phase tools missing from ALLOWED_TOOLS: {missing}'
print('all phase tools are in ALLOWED_TOOLS: OK')

assert cumulative_phase_tools(1) == PHASE_TOOLS[1]
assert cumulative_phase_tools(2) == PHASE_TOOLS[1] | PHASE_TOOLS[2]
assert cumulative_phase_tools(4) == all_phase_tools
print('cumulative_phase_tools OK')
"
python3 -m py_compile bridge.py && echo "syntax OK"
```
Note: this test will FAIL until Task 2 adds `dnsrecon` and `searchsploit` to `ALLOWED_TOOLS` — that's expected and fine, since Task 2 runs immediately after this one in the same plan. If you want a green run at this step specifically, temporarily comment out the `assert not missing` line, confirm the rest passes, then restore it — Task 2's own verification step re-confirms the full assertion holds after that task lands.

- [ ] **Step 5: Commit**

```bash
git add bridge.py
git commit -m "feat: add PHASE_TOOLS/PHASE_NAMES data and CURRENT_PHASE state, reset on engagement start"
```

---

### Task 2: `bridge.py` + `js/ollama.js` — add `dnsrecon` and `searchsploit` to both tool lists

**Files:**
- Modify: `bridge.py` (`ALLOWED_TOOLS` set, currently `bridge.py:48-57`)
- Modify: `js/ollama.js` (`ALLOWED_TOOLS_HINT` array)

**Interfaces:**
- Produces: `ALLOWED_TOOLS` and `ALLOWED_TOOLS_HINT` both gain `"dnsrecon"` and `"searchsploit"`, keeping the two lists in sync (per the existing hand-written comment above `ALLOWED_TOOLS_HINT`). This also makes Task 1's `PHASE_TOOLS` fully valid (both new tools are referenced by phases 1 and 2 respectively) — do this task immediately after Task 1, before Task 3/4's `/exec`-based verification needs both tools to actually be whitelisted.

- [ ] **Step 1: Add both tools to `bridge.py`'s `ALLOWED_TOOLS`**

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
    "dnsrecon", "searchsploit",
}
```

- [ ] **Step 2: Add both tools to `js/ollama.js`'s `ALLOWED_TOOLS_HINT`**

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
  "dnsrecon", "searchsploit",
];
```

- [ ] **Step 3: Manual verification**

```bash
cd ~/tools/auditor
python3 -m py_compile bridge.py && echo "py syntax OK"
node --check js/ollama.js && echo "js syntax OK"
python3 -c "
import runpy
mod = runpy.run_path('bridge.py', run_name='not_main')
PHASE_TOOLS = mod['PHASE_TOOLS']
ALLOWED_TOOLS = mod['ALLOWED_TOOLS']
all_phase_tools = set().union(*PHASE_TOOLS.values())
missing = all_phase_tools - ALLOWED_TOOLS
assert not missing, f'phase tools missing from ALLOWED_TOOLS: {missing}'
print('Task 1 assertion now fully passes: OK')
"
grep -c '"dnsrecon"' js/ollama.js
grep -c '"searchsploit"' js/ollama.js
```
Expected: both syntax checks pass, the phase-tools assertion now passes (was expected to fail at Task 1's verification), and each `grep -c` returns `1`.

- [ ] **Step 4: Commit**

```bash
git add bridge.py js/ollama.js
git commit -m "feat: add dnsrecon and searchsploit to the tool whitelist"
```

---

### Task 3: `bridge.py` — `phase_locked` check in `/exec`

**Files:**
- Modify: `bridge.py` (`/exec` handler, currently `bridge.py:216` onward)

**Interfaces:**
- Consumes: `CURRENT_PHASE`, `cumulative_phase_tools()` (Task 1).
- Produces (used by Task 6's prompt-recovery flow, which needs no code change — verdict flows through the existing generic step-recording path): `/exec` response on phase violation: `403 {"error": "phase_locked", "verdict": "phase_locked", "tool": <str>, "current_phase": <int>}`.

- [ ] **Step 1: Insert the phase check between the existing `tool_not_allowlisted` check and the scope-lock check**

Current code (`bridge.py`, inside the `/exec` block):
```python
            if tool not in ALLOWED_TOOLS:
                audit_log({"event": "tool_not_allowlisted", "tool": tool})
                self._send_json(403, {"error": "tool_not_allowlisted", "verdict": "tool_not_allowlisted"})
                return

            scope = CURRENT_SCOPE["scope"]
```

Replace with:
```python
            if tool not in ALLOWED_TOOLS:
                audit_log({"event": "tool_not_allowlisted", "tool": tool})
                self._send_json(403, {"error": "tool_not_allowlisted", "verdict": "tool_not_allowlisted"})
                return

            if tool not in cumulative_phase_tools(CURRENT_PHASE):
                audit_log({"event": "phase_locked", "tool": tool, "current_phase": CURRENT_PHASE})
                self._send_json(403, {"error": "phase_locked", "verdict": "phase_locked",
                                       "tool": tool, "current_phase": CURRENT_PHASE})
                return

            scope = CURRENT_SCOPE["scope"]
```

- [ ] **Step 2: Manual verification — server running, phase-locked and phase-unlocked tools**

In one terminal: `python3 bridge.py` (note the printed token; enter any passphrase when prompted).

In another terminal:
```bash
TOKEN="<paste the printed token>"
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}'
echo
echo "-- phase 1 tool (nmap), should work through to the exec attempt (command-not-found is fine if nmap isn't installed) --"
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"nmap","args":["-V"],"target":"127.0.0.1"}'
echo
echo "-- phase 3 tool (sqlmap) while still in phase 1, should be phase_locked --"
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"sqlmap","args":["--version"],"target":"127.0.0.1"}'
echo
```
Expected: the `nmap` call proceeds to actual execution (verdict `ok`, `timeout`, or `error` for command-not-found — anything but `phase_locked`). The `sqlmap` call returns `{"error": "phase_locked", "verdict": "phase_locked", "tool": "sqlmap", "current_phase": 1}`.

- [ ] **Step 3: Commit**

```bash
git add bridge.py
git commit -m "feat: enforce phase-locked tool gate in /exec"
```

---

### Task 4: `bridge.py` — `POST /phase/advance` endpoint

**Files:**
- Modify: `bridge.py` (`do_POST`, insert before the final `self._send_json(404, ...)` fallback — currently `bridge.py:367`)

**Interfaces:**
- Consumes: `CURRENT_PHASE`, `MAX_PHASE`, `cumulative_phase_tools()`, `PHASE_TOOLS` (Task 1).
- Produces (used by Task 5's client function): `POST /phase/advance` (no body) → `200 {"ok": true, "phase": <int>, "unlocked_tools": [<str>, ...]}` on a real advance, or `200 {"ok": true, "phase": <int>, "already_at_max": true}` if already at `MAX_PHASE`.

- [ ] **Step 1: Add the endpoint, right before the final unknown-endpoint fallback**

```python
        if self.path == "/phase/advance":
            global CURRENT_PHASE
            if CURRENT_PHASE >= MAX_PHASE:
                self._send_json(200, {"ok": True, "phase": CURRENT_PHASE, "already_at_max": True})
                return
            CURRENT_PHASE += 1
            audit_log({"event": "phase_advanced", "from": CURRENT_PHASE - 1, "to": CURRENT_PHASE})
            self._send_json(200, {"ok": True, "phase": CURRENT_PHASE,
                                   "unlocked_tools": sorted(PHASE_TOOLS.get(CURRENT_PHASE, set()))})
            return
```

Note: `CURRENT_PHASE` is already declared in `do_POST`'s top-level `global` line from Task 1 — this inner `global CURRENT_PHASE` inside the `if` block is technically redundant with that outer declaration but harmless (same pattern already exists elsewhere in this file for other globals); keep it for local readability of this block in isolation.

- [ ] **Step 2: Manual verification — advance through all 4 phases, confirm cap**

Server still running from Task 3's verification (or restart it):
```bash
TOKEN="<token>"
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}' > /dev/null
for i in 1 2 3 4 5; do
  echo "-- advance call $i --"
  curl -s -X POST http://127.0.0.1:8420/phase/advance -H "X-Auditor-Token: $TOKEN"
  echo
done
```
Expected: calls 1-3 return `{"ok": true, "phase": 2, ...}`, `{"ok": true, "phase": 3, ...}`, `{"ok": true, "phase": 4, ...}` each with a populated `unlocked_tools`. Calls 4 and 5 (already at phase 4) both return `{"ok": true, "phase": 4, "already_at_max": true}`.

Also confirm a phase-3 tool now works without `phase_locked` (pool is cumulative):
```bash
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"sqlmap","args":["--version"],"target":"127.0.0.1"}'
```
Expected: no longer `phase_locked` (command-not-found is fine if `sqlmap` isn't installed in this sandbox).

Also confirm `dnsrecon` (phase 1) and `searchsploit` (phase 2) both run through `/exec` without `phase_locked` now that the pool has advanced past both their phases — this also exercises Task 2's whitelist addition end-to-end (command-not-found is fine — the point is the phase gate, not whether the binary is installed):
```bash
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"dnsrecon","args":["-h"],"target":"127.0.0.1"}'
echo
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"searchsploit","args":["-h"],"target":"127.0.0.1"}'
```

Finally, confirm `CURRENT_PHASE` resets on a new engagement (no phase state leaking across engagements) — restart a fresh engagement and re-check the phase-3 tool:
```bash
curl -s -X POST http://127.0.0.1:8420/engagement/start -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"target":"127.0.0.1","scope":"127.0.0.1"}' > /dev/null
curl -s -X POST http://127.0.0.1:8420/exec -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" -d '{"tool":"sqlmap","args":["--version"],"target":"127.0.0.1"}'
```
Expected: back to `phase_locked` — confirms the new `/engagement/start` call reset `CURRENT_PHASE` to `1` even though the previous engagement had advanced it to 4.

- [ ] **Step 3: Commit**

```bash
git add bridge.py
git commit -m "feat: add POST /phase/advance endpoint"
```

---

### Task 5: `js/bridge_client.js` — `advancePhase()` client function

**Files:**
- Modify: `js/bridge_client.js`

**Interfaces:**
- Consumes: `postJSON` (existing internal helper).
- Produces (used by Task 8): `advancePhase(): Promise<{ok: true, phase: number, unlocked_tools?: string[], already_at_max?: boolean}>`.

- [ ] **Step 1: Add the function, next to the other endpoint wrappers (e.g. after `selectKeys`)**

```javascript
export function advancePhase() {
  return postJSON("/phase/advance", {});
}
```

- [ ] **Step 2: Manual verification**

```bash
cd ~/tools/auditor
node --check js/bridge_client.js && echo "syntax OK"
grep -n "export function advancePhase" js/bridge_client.js
```

- [ ] **Step 3: Commit**

```bash
git add js/bridge_client.js
git commit -m "feat: add advancePhase() client function"
```

---

### Task 6: `js/agent.js` — mirrored phase data, phase-aware prompt, `phaseState` param

**Files:**
- Modify: `js/agent.js`

**Interfaces:**
- Produces (used by Task 8): exported `PHASE_NAMES: {[phase: number]: string}`, `cumulativePhaseTools(phase: number): Set<string>` (local hint helper, mirrors `bridge.py`'s — never used for enforcement, only for prompt text). `buildUserPrompt` gains a 4th parameter `phase`. `runAgentLoop({..., phaseState, ...})` gains a `phaseState` parameter: `{current: number}`, read fresh on every loop iteration (a plain number argument would be captured once by value and never see updates from the UI's advance-phase button while the loop is running).

- [ ] **Step 1: Add the mirrored phase data near the top of the file, after the `DANGEROUS_ARG_PATTERNS` block and before `isDangerous`**

```javascript
// Mirrors bridge.py's PHASE_TOOLS/PHASE_NAMES by hand (same convention as
// ALLOWED_TOOLS_HINT in ollama.js) — this is a PROMPT HINT only, never
// enforcement. The server is the only thing that actually blocks a
// phase-locked tool; this just cuts down on wasted rejected attempts.
export const PHASE_NAMES = {
  1: "Intelligence Gathering",
  2: "Enumeration & Vulnerability Analysis",
  3: "Exploitation",
  4: "Post-Exploitation",
};

const PHASE_TOOLS = {
  1: ["nmap", "whatweb", "dig", "nslookup", "dnsrecon", "ldapsearch",
      "enum4linux", "rpcclient", "echo"],
  2: ["gobuster", "ffuf", "nikto", "smbclient", "GetNPUsers.py",
      "GetUserSPNs.py", "bloodhound-python", "lookupsid.py", "samrdump.py",
      "searchsploit", "adscan", "certipy"],
  3: ["sqlmap", "hydra", "secretsdump.py", "wmiexec.py", "psexec.py",
      "smbexec.py", "atexec.py", "dcomexec.py", "mssqlclient.py",
      "ntlmrelayx.py", "crackmapexec", "netexec", "ticketer.py",
      "getST.py", "raiseChild.py"],
  4: ["hashcat", "john"],
};

export function cumulativePhaseTools(phase) {
  const result = new Set();
  for (let n = 1; n <= phase; n += 1) {
    for (const tool of PHASE_TOOLS[n] || []) result.add(tool);
  }
  return result;
}
```

- [ ] **Step 2: Update `buildUserPrompt` to accept and inject the current phase**

Replace:
```javascript
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
```
with:
```javascript
function buildUserPrompt(target, steps, axisWarning, phase) {
  const history = steps
    .slice(-10)
    .map((s) => `[${s.tool} ${JSON.stringify(s.args)}] -> exit=${s.exitCode} verdict=${s.verdict}\n${(s.output || "").slice(0, 300)}`)
    .join("\n---\n");
  const toolsNow = [...cumulativePhaseTools(phase)].join(", ");
  let prompt = `Target: ${target}\nFase actual: ${phase}/4 — ${PHASE_NAMES[phase]}.\nTools disponibles ahora: ${toolsNow}.\nRecent history:\n${history || "(no steps yet)"}`;
  if (axisWarning) {
    prompt += `\n\nWARNING: you already tried this exact (tool, args) 3 times with no new information. Change a parameter or try a different vector.`;
  }
  return prompt;
}
```

- [ ] **Step 3: Thread `phaseState` through `runAgentLoop`'s signature and its `buildUserPrompt` call**

Change the signature line:
```javascript
export async function runAgentLoop({ db, engagementId, model, target, systemPrompt, endpoint, onStep, onPauseForConfirmation, onWaitingForQuota = () => {}, phaseState }) {
```

Change the `buildUserPrompt` call inside the `askAgent` invocation from:
```javascript
        userPrompt: buildUserPrompt(target, steps, axisWarning) + agentErrorHint,
```
to:
```javascript
        userPrompt: buildUserPrompt(target, steps, axisWarning, phaseState.current) + agentErrorHint,
```

(Every other line in `runAgentLoop` is unchanged — the `if (decision.done)` block onward, the dangerous-tool gate, `execTool` call, and axis tracking are untouched. A `phase_locked` result from `execTool` flows through the exact same generic step-recording path already used for `scope_violation`/`tool_not_allowlisted` — no new branch needed.)

- [ ] **Step 4: Manual verification**

```bash
cd ~/tools/auditor
node --check js/agent.js && echo "syntax OK"
node -e "
const { cumulativePhaseTools, PHASE_NAMES } = await import('./js/agent.js');
const p1 = cumulativePhaseTools(1);
const p2 = cumulativePhaseTools(2);
if (!p1.has('nmap')) throw new Error('phase 1 missing nmap');
if (p1.has('sqlmap')) throw new Error('phase 1 should not have sqlmap yet');
if (!p2.has('nmap') || !p2.has('gobuster')) throw new Error('phase 2 should be cumulative');
if (PHASE_NAMES[3] !== 'Exploitation') throw new Error('PHASE_NAMES[3] wrong');
console.log('cumulativePhaseTools + PHASE_NAMES OK');
" --input-type=module
```
Expected: `syntax OK` and `cumulativePhaseTools + PHASE_NAMES OK`, no thrown errors.

- [ ] **Step 5: Commit**

```bash
git add js/agent.js
git commit -m "feat: inject current phase and available tools into agent prompt"
```

---

### Task 7: UI markup — phase indicator + advance button

**Files:**
- Modify: `index.html` (`#steps-panel`, currently `index.html:30-33`)
- Modify: `style.css`

**Interfaces:**
- Produces (used by Task 8): DOM elements `#phase-indicator` (text content, no interaction) and `#advance-phase-btn` (button).

- [ ] **Step 1: Add the two elements inside `#steps-panel`, before `#export-btn`**

Replace:
```html
    <section id="steps-panel" hidden>
      <div id="steps-feed"></div>
      <button id="export-btn">Export JSON</button>
    </section>
```
with:
```html
    <section id="steps-panel" hidden>
      <div id="phase-bar">
        <span id="phase-indicator">Fase 1/4: Intelligence Gathering</span>
        <button id="advance-phase-btn" type="button">Avanzar fase</button>
      </div>
      <div id="steps-feed"></div>
      <button id="export-btn">Export JSON</button>
    </section>
```

- [ ] **Step 2: Add styling for `#phase-bar` in `style.css` (append at the end of the file)**

```css
#phase-bar { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; padding: 0.5rem 0.75rem; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12); border-radius: 10px; }
#phase-indicator { font-size: 0.9rem; opacity: 0.85; }
#advance-phase-btn { width: auto; margin: 0; }
#advance-phase-btn:disabled { opacity: 0.4; cursor: not-allowed; }
```

- [ ] **Step 3: Manual verification**

```bash
cd ~/tools/auditor
python3 -c "import html.parser; html.parser.HTMLParser().feed(open('index.html').read()); print('index.html parses OK')"
grep -n 'id="phase-indicator"\|id="advance-phase-btn"' index.html
```
Expected: parses OK, both IDs found.

- [ ] **Step 4: Commit**

```bash
git add index.html style.css
git commit -m "feat: add phase indicator and advance-phase button markup"
```

---

### Task 8: `js/ui.js` + `js/main.js` — wire the phase indicator and advance button

**Files:**
- Modify: `js/ui.js`
- Modify: `js/main.js`

**Interfaces:**
- Consumes: `advancePhase()` (Task 5), `PHASE_NAMES` (Task 6), `#phase-indicator`/`#advance-phase-btn` (Task 7).
- Produces: a working phase indicator that updates on advance, gated at phase 4, and `phaseState` threaded into `runAgentLoop`.

- [ ] **Step 1: Add `renderPhaseIndicator` to `js/ui.js`, next to the other render functions**

```javascript
export function renderPhaseIndicator(phase, phaseNames) {
  document.getElementById("phase-indicator").textContent = `Fase ${phase}/4: ${phaseNames[phase]}`;
  document.getElementById("advance-phase-btn").disabled = phase >= 4;
}
```

- [ ] **Step 2: Wire it in `js/main.js`**

Add to the import lines at the top:
```javascript
import { advancePhase } from "./bridge_client.js";
import { PHASE_NAMES } from "./agent.js";
import { renderStep, showConfirmModal, renderKeyList, renderWaitingForQuota, renderPhaseIndicator } from "./ui.js";
```
(merge with the existing `bridge_client.js`/`ui.js` import lines rather than duplicating them — this project's `main.js` already imports several names from each of those two modules.)

Inside the `#start-btn` click handler, right after `document.getElementById("steps-panel").hidden = false;`, add:
```javascript
    const phaseState = { current: 1 };
    renderPhaseIndicator(phaseState.current, PHASE_NAMES);

    document.getElementById("advance-phase-btn").onclick = async () => {
      const result = await advancePhase();
      phaseState.current = result.phase;
      renderPhaseIndicator(phaseState.current, PHASE_NAMES);
    };
```

Add `phaseState` to the `runAgentLoop({...})` call's argument object (alongside `db, engagementId, model, target, systemPrompt, endpoint`):
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

- [ ] **Step 3: Manual verification**

```bash
cd ~/tools/auditor
node --check js/ui.js && node --check js/main.js && echo "syntax OK"
```

Then in a real browser (per the established manual-testing pattern for this project): restart `bridge.py`, open the printed URL, start an engagement, confirm the indicator reads "Fase 1/4: Intelligence Gathering" and the button is enabled. Click it 3 times, confirm the indicator advances through phases 2, 3, 4 and the button disables at phase 4. Have the agent attempt a phase-3 tool while still at phase 1 (or just watch a real session) and confirm the resulting step renders with `verdict=phase_locked` in the feed, same as any other step.

Also confirm the phase gate and the dangerous-tool gate stay fully independent: once advanced to phase 3 (where `secretsdump.py` is phase-unlocked), have the agent attempt `secretsdump.py` and confirm the existing confirmation modal (`showConfirmModal`, unrelated to this plan's changes) still pops up before it runs — phase-unlocking a tool must never bypass its danger gate.

- [ ] **Step 4: Commit**

```bash
git add js/ui.js js/main.js
git commit -m "feat: wire phase indicator and advance-phase button into the engagement UI"
```
