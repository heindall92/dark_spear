# 3 Architecture Patterns Implementation Plan (Exploit-to-Prove Gate / Session Watchdog / Silence-over-False-Positive)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire 3 previously-designed architecture patterns into dark_spear's finding/playbook pipeline: a `proof_level` tag distinguishing signature-based detection from actively-proven exploitation, a centralized `shouldReport()` gate that silently drops weak/unsupported findings instead of surfacing false positives, and a stall/watchdog timeout on the freeform agent decision loop.

**Architecture:** All 3 patterns hook into 2 existing choke points already used by every finding-producing code path: the `add()` helper inside `collectHeuristicFindings()` (backend/js/finding-heuristics.js) and `recordProposedFinding()` (backend/js/agent.js), plus the `/findings/propose` handler (backend/bridge.py) for server-side persistence. The watchdog hooks into the existing `Promise.race([llm, watch])` pattern already used in `runAgentLoop()`'s freeform decision loop (backend/js/agent.js) for phase-change interruption — a third race participant is added for stall detection. No new files; no schema migration (findings are stored as JSON dicts in a list, not a SQL table).

**Tech Stack:** Vanilla JS (ES modules, no build step) for backend/js/*, Python 3 stdlib (http.server based) for backend/bridge.py. Tests: `node scripts/test-*.mjs` (assert via exit code) and `python3 scripts/test-*.py` (same convention).

**Spec:** No separate spec doc — design was worked out directly in this planning session by reading the actual choke points (`add()` at backend/js/finding-heuristics.js:309, `recordProposedFinding()` at backend/js/agent.js:156, `/findings/propose` at backend/bridge.py:2081, and the `Promise.race` stall point at backend/js/agent.js:639-658). Prior one-line pattern names came from `~/.claude/projects/-home-kali/memory/project_dark_spear_tool_integrations_roadmap.md` (section "3 patrones arquitectura pendientes de diseño").

## Global Constraints

- Never name the external repos that originated these pattern names, in any committed code or doc — same rule as the rest of the roadmap (see `feedback_no_external_attribution_dark_spear` memory).
- Follow the existing `sync-engine-js.py` requirement: after any edit to `backend/js/*.js`, run `python3 scripts/sync-engine-js.py` before committing, so `panel/vendor/` stays in sync.
- Commit with `git commit -m "..."` WITHOUT a trailing pathspec (repo-specific gotcha — passing paths to `git commit` re-reads the working tree and breaks staged-only commits).
- Each task ends with its own green test run and its own commit — do not batch commits across tasks.

---

## File Structure

- `backend/js/finding-heuristics.js` — add `shouldReport(payload)` (pure, exported for testing) + extend `add()` with a 6th optional `proofLevel` param; wire the JWT alg=none call site to pass `"proven"`.
- `backend/js/vuln-kb.js` — tag `sqlmapFindings()` return objects with `proofLevel: "proven"` (only finding-producer outside the `add()` helper that represents genuinely proven exploitation today).
- `backend/js/agent.js` — call `shouldReport()` inside `recordProposedFinding()` before `proposeFinding()`; add pure `stallExceeded(lastProgressAt, now, timeoutMs)` + `STALL_TIMEOUT_MS` constant; wire a 3rd `Promise.race` participant in the freeform decision loop that resolves `{ stalled: true }` when exceeded.
- `backend/bridge.py` — accept optional `proof_level` in `/findings/propose` body, validate against `PROOF_LEVELS = {"proven", "detected"}`, default to `"detected"` when absent/invalid, store on the finding dict.
- `scripts/test-should-report-gate.mjs` — new test for `shouldReport()`.
- `scripts/test-proof-level-tagging.mjs` — new test for `add()`'s proofLevel param + `sqlmapFindings()` tagging.
- `scripts/test-stall-detector.mjs` — new test for `stallExceeded()`.
- `scripts/test-bridge-proof-level.py` — new test for `/findings/propose` proof_level handling (isolated call into the handler logic the same way `test-bridge-redact.py` isolates `redact_args`).

---

### Task 1: Silence-over-false-positive gate — `shouldReport()`

**Files:**
- Modify: `backend/js/finding-heuristics.js` (add exported `shouldReport` function near top-level, after imports/before `buildProbeIndex`; wire into `add()` at line 309)
- Modify: `backend/js/agent.js:156` (`recordProposedFinding`) — call `shouldReport` before `proposeFinding`
- Test: `scripts/test-should-report-gate.mjs`

**Interfaces:**
- Produces: `export function shouldReport(payload)` — `payload` shape: `{ title, severity, description, remediation, evidence_step_ids }` (same shape already used everywhere — see `add()` at finding-heuristics.js:309-318 and `sqlmapFindings()` return objects). Returns `boolean`. Rule: for `severity` of `"Critical"` or `"High"`, require at least one of: (a) non-empty `evidence_step_ids` array, or (b) `description` matching `/EVIDENCE|confirm|HTTP\s*2\d\d|HTTP\s*\d{3}/i`. Any other severity (`Medium`/`Low`/`Info`) always returns `true` (heuristic low-severity findings are informational by nature and already reviewed manually in the panel). Never throws — malformed payload returns `false` (fail closed, matches [[feedback_no_external_attribution_dark_spear]]-adjacent fail-closed conventions already used for scope-lock).
- Consumes: nothing new — reads only fields already present on every finding payload in the codebase today.

- [ ] **Step 1: Write the failing test**

Create `scripts/test-should-report-gate.mjs`:

```js
#!/usr/bin/env node
/**
 * shouldReport(): silence-over-false-positive gate. Critical/High findings
 * without any evidence signal must be silently dropped before they ever
 * reach proposeFinding() — never surfaced to the user as a maybe-wrong
 * high-severity claim.
 */
import { shouldReport } from "../backend/js/finding-heuristics.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check(
  "Critical sin evidence_step_ids ni marcador EVIDENCE en description -> false",
  shouldReport({ title: "X", severity: "Critical", description: "sin nada raro aqui", evidence_step_ids: [] }) === false,
);

check(
  "High con evidence_step_ids no vacío -> true",
  shouldReport({ title: "X", severity: "High", description: "sin marcador", evidence_step_ids: ["p1-curl-x"] }) === true,
);

check(
  "Critical con descripcion que contiene EVIDENCE: -> true",
  shouldReport({ title: "X", severity: "Critical", description: "EVIDENCE: HTTP 200 en /admin", evidence_step_ids: [] }) === true,
);

check(
  "Critical con HTTP 2xx en la descripcion (sin la palabra EVIDENCE) -> true",
  shouldReport({ title: "X", severity: "Critical", description: "respondio HTTP 200 en vez de 401/403", evidence_step_ids: [] }) === true,
);

check(
  "Medium sin evidencia -> true (severidad baja siempre pasa)",
  shouldReport({ title: "X", severity: "Medium", description: "nada", evidence_step_ids: [] }) === true,
);

check(
  "Info sin evidencia -> true",
  shouldReport({ title: "X", severity: "Info", description: "nada", evidence_step_ids: [] }) === true,
);

check(
  "payload malformado (severity ausente) -> false (fail closed)",
  shouldReport({ title: "X", description: "nada" }) === false,
);

check(
  "payload null -> false (fail closed, nunca revienta)",
  shouldReport(null) === false,
);

process.exit(ok ? 0 : 1);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node scripts/test-should-report-gate.mjs`
Expected: fails immediately with `SyntaxError` / `does not provide an export named 'shouldReport'` (function doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

In `backend/js/finding-heuristics.js`, add near the top of the file (after existing imports, before `function buildProbeIndex`):

```js
/**
 * Silence-over-false-positive gate: a Critical/High finding with zero
 * evidence signal (no evidence_step_ids, no evidence marker in the
 * description) never reaches the user as a finding — it is dropped
 * silently rather than risk reporting something unconfirmed at high
 * severity. Medium/Low/Info stay reportable as-is: they are already
 * informational/manually-reviewed by convention across this file.
 * Never throws: any malformed payload fails closed (false).
 */
const EVIDENCE_MARKER_RE = /EVIDENCE|confirm|HTTP\s*2\d\d|HTTP\s*\d{3}/i;

export function shouldReport(payload) {
  if (!payload || typeof payload !== "object") return false;
  const severity = payload.severity;
  if (severity !== "Critical" && severity !== "High") {
    return severity === "Medium" || severity === "Low" || severity === "Info";
  }
  const hasEvidenceIds = Array.isArray(payload.evidence_step_ids) && payload.evidence_step_ids.length > 0;
  const hasEvidenceMarker = EVIDENCE_MARKER_RE.test(String(payload.description || ""));
  return hasEvidenceIds || hasEvidenceMarker;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node scripts/test-should-report-gate.mjs`
Expected: all 8 checks print `OK`, exit code 0.

- [ ] **Step 5: Wire the gate into `recordProposedFinding()`**

In `backend/js/agent.js`, add the import at the top (line 5, same import line already pulling from finding-heuristics.js):

```js
import { collectHeuristicFindings, heuristicAssetFromTarget, shouldReport } from "./finding-heuristics.js";
```

Then in `recordProposedFinding()` (currently starting at line 156), add the gate as the very first check, before the duplicate-fingerprint check:

```js
async function recordProposedFinding(db, engagementId, payload, seenFindings, reportedTitles, onFindingProposed, onStep, phase) {
  if (!shouldReport(payload)) {
    onStep(normalizeStep(null, engagementId, {
      tool: "(agent)", args: [],
      stderr: `Hallazgo descartado por falta de evidencia suficiente para severidad ${payload && payload.severity}: ${payload && payload.title}`,
      verdict: "status",
      phase,
    }));
    return false;
  }
  const fp = findingFingerprint(payload.title, payload.asset);
  // ... rest unchanged
```

This affects all 3 call sites of `recordProposedFinding` uniformly (heuristic findings, semgrep-scan findings, and LLM-proposed findings), since they all funnel through this one function.

- [ ] **Step 6: Run full JS test suite to check for regressions**

Run: `for f in scripts/test-*.mjs; do node "$f" || echo "FAILED: $f"; done`
Expected: no new failures beyond the 2 pre-existing live-target failures already documented in the roadmap memory (`test-playbook-dvwa.mjs`/`test-playbook-juiceshop-phase1.mjs`, require a live localhost:3000 target).

- [ ] **Step 7: Sync engine and commit**

```bash
python3 scripts/sync-engine-js.py
git add backend/js/finding-heuristics.js backend/js/agent.js scripts/test-should-report-gate.mjs panel/vendor
git commit -m "feat: add shouldReport() silence-over-false-positive gate before proposeFinding"
```

---

### Task 2: Exploit-to-prove gate — `proof_level` tagging

**Files:**
- Modify: `backend/js/finding-heuristics.js` — extend `add()` (line 309) with 6th param `proofLevel = "detected"`; pass `"proven"` at the JWT alg=none call site (currently line 777-782)
- Modify: `backend/js/vuln-kb.js` — add `proofLevel: "proven"` to both return objects in `sqlmapFindings()` (lines 2833-2838 and 2845-2850)
- Modify: `backend/bridge.py` — accept/validate/store `proof_level` in the `/findings/propose` handler (around line 2095-2122)
- Test: `scripts/test-proof-level-tagging.mjs`, `scripts/test-bridge-proof-level.py`

**Interfaces:**
- Produces: `add(title, severity, description, remediation, evidenceIds = [], proofLevel = "detected")` — every finding object pushed by `add()` now carries a `proofLevel` field. `sqlmapFindings(stdout)` return objects now include `proofLevel: "proven"`.
- Produces (bridge.py): the finding dict returned by `/findings/propose` and stored in `FINDINGS`/`findings_ref` now includes a `"proof_level"` key, always one of `"proven"` or `"detected"` regardless of what the client sent (server-side default/clamp, same defensive pattern already used for `severity` via `FINDING_SEVERITIES`).
- Consumes: nothing new from other tasks.

- [ ] **Step 1: Write the failing JS test**

Create `scripts/test-proof-level-tagging.mjs`:

```js
#!/usr/bin/env node
/**
 * proofLevel: distinguishes findings backed by actual exploitation
 * ("proven" — sqlmap extracted real DB names, JWT alg=none bypass accepted
 * by the server) from findings backed only by signature/version detection
 * ("detected" — the default for everything else, e.g. nuclei/testssl).
 */
import { collectHeuristicFindings } from "../backend/js/finding-heuristics.js";
import { sqlmapFindings } from "../backend/js/vuln-kb.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

const sqlmapOut = "Parameter: id (GET)\n    Type: boolean-based blind\nsqlmap identified the following injection point(s)";
const sqlmapOnly = sqlmapFindings(sqlmapOut);
check("sqlmapFindings sin parametros detectables -> proofLevel proven", sqlmapOnly.length === 0 || sqlmapOnly[0].proofLevel === "proven");

const sqlmapWithParam = "Parameter: id (GET)\nsqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:\n---\nParameter: id (GET)\n    Type: boolean-based blind\n---";
const found = sqlmapFindings(sqlmapWithParam);
check("sqlmapFindings con parametro -> al menos 1 finding proofLevel proven", found.length > 0 && found.every((f) => f.proofLevel === "proven"));

const stepRecords = [{ id: "p1-jwt-algnone-1", text: "DS_HTTP:200\n{\"role\":\"admin\"}" }];
const jwtFindings = collectHeuristicFindings("", "https://x.example.com", {}, stepRecords)
  .filter((f) => /alg=none/i.test(f.title));
check("bypass JWT alg=none confirmado -> proofLevel proven", jwtFindings.length > 0 && jwtFindings.every((f) => f.proofLevel === "proven"));

const dvwaStepRecords = [{ id: "head-root", text: "<title>Login :: Damn Vulnerable Web Application</title>" }];
const dvwaFindings = collectHeuristicFindings("", "https://x.example.com", {}, dvwaStepRecords)
  .filter((f) => /DVWA expuesta/i.test(f.title));
check("deteccion pasiva DVWA -> proofLevel detected (default)", dvwaFindings.length > 0 && dvwaFindings.every((f) => f.proofLevel === "detected"));

process.exit(ok ? 0 : 1);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node scripts/test-proof-level-tagging.mjs`
Expected: FAIL — `proofLevel` is `undefined` on all objects (field doesn't exist yet).

- [ ] **Step 3: Implement `add()` extension in `backend/js/finding-heuristics.js`**

Replace the current `add()` (lines 309-318):

```js
  function add(title, severity, description, remediation, evidenceIds = [], proofLevel = "detected") {
    findings.push({
      title,
      asset: asset || "unknown",
      severity,
      description,
      remediation,
      evidence_step_ids: evidenceIds,
      proofLevel,
    });
  }
```

Then update the JWT alg=none call site (currently lines 777-782) to pass `"proven"` as the 6th arg (5th arg `evidenceIds` stays `[]` since this call site never passed one):

```js
      add(
        `Bypass de autorización con JWT alg=none en ${path}`,
        "Critical",
        `Al reforjar el JWT capturado con header {"alg":"none"} y firma vacía, ${path} respondió HTTP 2xx en vez de 401/403 (CWE-347): el backend no verifica el algoritmo de firma antes de confiar en los claims del token, aceptando un token sin firmar con los mismos datos (rol, usuario) que el original.`,
        "Verificar siempre el algoritmo de firma en servidor con una allow-list explícita (nunca leerlo del propio token); rechazar alg=none de forma explícita; actualizar la librería JWT.",
        [],
        "proven",
      );
```

- [ ] **Step 4: Implement `sqlmapFindings()` tagging in `backend/js/vuln-kb.js`**

In the no-params-extracted branch (currently lines 2833-2838), add `proofLevel: "proven"`:

```js
    return [{
      title: "Inyección SQL confirmada por sqlmap",
      severity: "Critical",
      description: "sqlmap confirmó al menos un punto de inyección SQL explotable durante el descubrimiento automático de formularios (--forms --crawl).",
      remediation: "Revisar el reporte completo de sqlmap (--dump-all para el detalle); migrar a consultas parametrizadas en el/los formulario(s) afectado(s).",
      proofLevel: "proven",
    }];
```

And in the per-parameter loop (currently lines 2845-2850):

```js
    out.push({
      title: `Inyección SQL confirmada por sqlmap en parámetro «${param}»`,
      severity: "Critical",
      description: `sqlmap confirmó explotación real (no solo sospecha) del parámetro «${param}» durante el descubrimiento automático de formularios.${types[i] ? ` Tipo: ${types[i]}.` : ""}`,
      remediation: "Migrar a consultas parametrizadas/prepared statements en el punto exacto; ejecutar sqlmap --dump-all solo con autorización explícita para medir el alcance real de los datos expuestos.",
      proofLevel: "proven",
    });
```

- [ ] **Step 5: Run JS test to verify it passes**

Run: `node scripts/test-proof-level-tagging.mjs`
Expected: all 4 checks `OK`, exit 0.

- [ ] **Step 6: Write the failing Python test**

Create `scripts/test-bridge-proof-level.py`:

```python
#!/usr/bin/env python3
"""Test aislado de la validacion/clamp de proof_level en /findings/propose
(backend/bridge.py) — sin levantar el servidor, llamando directo a la
funcion que construye el dict de finding."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from bridge import normalize_proof_level, PROOF_LEVELS  # noqa: E402

fails = 0


def check(label, ok):
    global fails
    print(f"{'OK' if ok else 'FAIL'}: {label}")
    if not ok:
        fails += 1


check("PROOF_LEVELS contiene proven y detected", PROOF_LEVELS == {"proven", "detected"})
check("proof_level 'proven' valido se preserva", normalize_proof_level("proven") == "proven")
check("proof_level 'detected' valido se preserva", normalize_proof_level("detected") == "detected")
check("proof_level ausente (None) -> default detected", normalize_proof_level(None) == "detected")
check("proof_level vacio -> default detected", normalize_proof_level("") == "detected")
check("proof_level invalido/inventado -> default detected (fail closed, no confia en el cliente)", normalize_proof_level("super-proven") == "detected")

print()
print("RESULTADO: OK — todas pasaron" if fails == 0 else f"RESULTADO: FAIL — {fails} fallo(s)")
sys.exit(0 if fails == 0 else 1)
```

- [ ] **Step 7: Run Python test to verify it fails**

Run: `python3 scripts/test-bridge-proof-level.py`
Expected: `ImportError: cannot import name 'normalize_proof_level'` (function doesn't exist yet).

- [ ] **Step 8: Implement in `backend/bridge.py`**

Near `FINDING_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}` (line 411), add:

```python
PROOF_LEVELS = {"proven", "detected"}


def normalize_proof_level(value):
    """Server-side clamp: never trust the client's proof_level blindly —
    same defensive posture as severity validation. Missing/invalid/empty
    always falls back to the conservative default ("detected", i.e. not
    yet actively exploited), never to "proven"."""
    if value in PROOF_LEVELS:
        return value
    return "detected"
```

Then in the `/findings/propose` handler, right after `evidence_step_ids = body.get("evidence_step_ids", [])` (line 2100), add:

```python
            proof_level = normalize_proof_level(body.get("proof_level"))
```

And add `"proof_level": proof_level,` to the `finding` dict construction (currently lines 2114-2122), right after the `"evidence_step_ids"`/`"evidence_hashes"` line:

```python
            finding = {
                "id": _next_finding_id_for(findings_ref),
                "title": title, "asset": asset, "severity": severity,
                "description": description, "remediation": remediation,
                "evidence_step_ids": evidence_step_ids, "evidence_hashes": [],
                "proof_level": proof_level,
                "status": "proposed",
                "fingerprint": _finding_fingerprint(title, asset),
                "created_at": time.time(), "reviewed_at": None,
            }
```

- [ ] **Step 9: Run Python test to verify it passes**

Run: `python3 scripts/test-bridge-proof-level.py`
Expected: all 6 checks `OK`, exit 0.

- [ ] **Step 10: Sync engine and commit**

```bash
python3 scripts/sync-engine-js.py
git add backend/js/finding-heuristics.js backend/js/vuln-kb.js backend/bridge.py scripts/test-proof-level-tagging.mjs scripts/test-bridge-proof-level.py panel/vendor
git commit -m "feat: add proof_level (proven/detected) exploit-to-prove tagging to findings"
```

---

### Task 3: Session watchdog / stall detector

**Files:**
- Modify: `backend/js/agent.js` — add pure `stallExceeded()` + `STALL_TIMEOUT_MS` constant near `MAX_CONSECUTIVE_AGENT_ERRORS` (line 469); wire a 3rd race participant into the freeform decision loop (lines 639-658)
- Test: `scripts/test-stall-detector.mjs`

**Interfaces:**
- Produces: `export const STALL_TIMEOUT_MS = 8 * 60 * 1000;` and `export function stallExceeded(lastProgressAt, now, timeoutMs = STALL_TIMEOUT_MS)` — pure function, returns `boolean`. `true` when `now - lastProgressAt >= timeoutMs`.
- Consumes: nothing new from other tasks. The wiring step (Step 5 below) touches the existing `Promise.race([llm, watch])` in `runAgentLoop()` — this part is orchestration glue, same as the rest of `runAgentLoop`, and is intentionally NOT unit-tested (the codebase has no test coverage for `runAgentLoop` itself today — see `scripts/test-agent-output-sanitization.mjs`, the only existing agent.js test, which only covers the pure `sanitizeUntrustedOutput` function). Only the pure `stallExceeded()` helper gets a dedicated test.

- [ ] **Step 1: Write the failing test**

Create `scripts/test-stall-detector.mjs`:

```js
#!/usr/bin/env node
/**
 * stallExceeded(): session watchdog. The freeform agent decision loop
 * calls askAgent() in a Promise.race against phase-change; if the model
 * endpoint hangs (Ollama down, network stall) with no phase change either,
 * nothing today ever cuts the wait — the run hangs forever with no
 * user-visible signal. This pure helper decides when that has happened,
 * so the loop can end the run cleanly instead of hanging.
 */
import { stallExceeded, STALL_TIMEOUT_MS } from "../backend/js/agent.js";

let ok = true;
function check(name, cond) {
  console.log((cond ? "OK" : "FAIL") + `: ${name}`);
  ok = ok && cond;
}

check("STALL_TIMEOUT_MS es un numero positivo razonable (entre 1 y 30 min)", STALL_TIMEOUT_MS >= 60000 && STALL_TIMEOUT_MS <= 30 * 60 * 1000);

const t0 = 1000000;
check("justo antes del timeout -> false", stallExceeded(t0, t0 + STALL_TIMEOUT_MS - 1, STALL_TIMEOUT_MS) === false);
check("exactamente en el timeout -> true", stallExceeded(t0, t0 + STALL_TIMEOUT_MS, STALL_TIMEOUT_MS) === true);
check("mucho despues del timeout -> true", stallExceeded(t0, t0 + STALL_TIMEOUT_MS * 10, STALL_TIMEOUT_MS) === true);
check("sin tiempo transcurrido -> false", stallExceeded(t0, t0, STALL_TIMEOUT_MS) === false);
check("usa STALL_TIMEOUT_MS como default si no se pasa timeoutMs", stallExceeded(t0, t0 + STALL_TIMEOUT_MS + 1) === true);

process.exit(ok ? 0 : 1);
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node scripts/test-stall-detector.mjs`
Expected: FAIL — `does not provide an export named 'stallExceeded'`.

- [ ] **Step 3: Implement the pure helper**

In `backend/js/agent.js`, near `const MAX_CONSECUTIVE_AGENT_ERRORS = 5;` (line 469), add:

```js
/**
 * Session watchdog / stall detector: if the freeform decision loop makes
 * no progress (no LLM response, no phase change) for STALL_TIMEOUT_MS,
 * the run is considered stalled. Without this, an Ollama endpoint that
 * hangs mid-request (not a clean error, just never resolving) leaves the
 * whole engagement stuck forever with no visible signal to the operator.
 */
export const STALL_TIMEOUT_MS = 8 * 60 * 1000;

export function stallExceeded(lastProgressAt, now, timeoutMs = STALL_TIMEOUT_MS) {
  return now - lastProgressAt >= timeoutMs;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node scripts/test-stall-detector.mjs`
Expected: all 6 checks `OK`, exit 0.

- [ ] **Step 5: Wire the stall race into the freeform decision loop**

In `backend/js/agent.js`, inside `runAgentLoop()`'s `while (true)` loop (currently starting line 619), the existing race block (lines 631-658) reads:

```js
      const bumpAtStart = phaseState.bump || 0;
      const phaseAtStart = phaseState.current;
      const llm = askAgent({
        model,
        systemPrompt,
        userPrompt: buildUserPrompt(target, steps, axisWarning, phaseState.current, reportedTitles) + agentErrorHint,
        endpoint,
      }).then((d) => ({ decision: d }));
      const watch = (async () => {
        while (true) {
          await new Promise((r) => setTimeout(r, 400));
          if ((phaseState.bump || 0) !== bumpAtStart || phaseState.current !== phaseAtStart) {
            return { phaseChanged: true };
          }
        }
      })();
      const winner = await Promise.race([llm, watch]);
      if (winner.phaseChanged) {
        lastPlaybookPhase = 0;
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: `Fase cambiada a ${phaseState.current} — ejecutando playbook…`,
          verdict: "status",
          phase: phaseState.current,
        }));
        continue;
      }
      decision = winner.decision;
```

Replace it with (adds `loopStartedAt` + a 3rd race participant `stall`, and a `winner.stalled` branch that returns instead of hanging):

```js
      const bumpAtStart = phaseState.bump || 0;
      const phaseAtStart = phaseState.current;
      const loopStartedAt = Date.now();
      const llm = askAgent({
        model,
        systemPrompt,
        userPrompt: buildUserPrompt(target, steps, axisWarning, phaseState.current, reportedTitles) + agentErrorHint,
        endpoint,
      }).then((d) => ({ decision: d }));
      const watch = (async () => {
        while (true) {
          await new Promise((r) => setTimeout(r, 400));
          if ((phaseState.bump || 0) !== bumpAtStart || phaseState.current !== phaseAtStart) {
            return { phaseChanged: true };
          }
        }
      })();
      const stall = (async () => {
        while (true) {
          await new Promise((r) => setTimeout(r, 5000));
          if (stallExceeded(loopStartedAt, Date.now())) {
            return { stalled: true };
          }
        }
      })();
      const winner = await Promise.race([llm, watch, stall]);
      if (winner.stalled) {
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: `Watchdog: sin respuesta del modelo tras ${Math.round(STALL_TIMEOUT_MS / 60000)} min. Deteniendo el run (revisa el endpoint del modelo).`,
          verdict: "agent_error",
          phase: phaseState.current,
        }));
        return;
      }
      if (winner.phaseChanged) {
        lastPlaybookPhase = 0;
        onStep(normalizeStep(null, engagementId, {
          tool: "(agent)", args: [],
          stderr: `Fase cambiada a ${phaseState.current} — ejecutando playbook…`,
          verdict: "status",
          phase: phaseState.current,
        }));
        continue;
      }
      decision = winner.decision;
```

Note: the orphaned `watch`/`stall` polling loops from a resolved-but-not-won race keep running harmlessly in the background until the process's next relevant state change makes their condition true (or forever, bounded by nothing) — this matches the exact pre-existing behavior of the `watch` loop already in this code before this change (it was never cleaned up either), so this is not a new leak class, just the same accepted pattern applied twice instead of once.

- [ ] **Step 6: Run full JS test suite to check for regressions**

Run: `for f in scripts/test-*.mjs; do node "$f" || echo "FAILED: $f"; done`
Expected: no new failures beyond the 2 pre-existing live-target failures.

- [ ] **Step 7: Sync engine and commit**

```bash
python3 scripts/sync-engine-js.py
git add backend/js/agent.js scripts/test-stall-detector.mjs panel/vendor
git commit -m "feat: add session watchdog/stall detector to freeform agent decision loop"
```

---

## Final Integration Check (run after all 3 tasks, before merge)

- [ ] Run every test in `scripts/`: `for f in scripts/test-*.mjs; do node "$f" || echo "FAILED: $f"; done && for f in scripts/test-*.py; do python3 "$f" || echo "FAILED: $f"; done`
- [ ] Confirm `panel/vendor/` reflects the latest `backend/js/` (re-run `python3 scripts/sync-engine-js.py`, check `git status` shows no diff).
- [ ] Confirm no external-repo attribution leaked into any commit message or file in this branch (check against the project's no-attribution convention).
