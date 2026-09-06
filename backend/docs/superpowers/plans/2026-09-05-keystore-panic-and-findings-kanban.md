# Vault Panic Button + Findings Kanban Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two gaps found during an internal security/UX audit of Dark Spear's vault and findings lifecycle — a keystore panic button, and an explicit post-acceptance reporting lifecycle for findings (Kanban: accepted → verifying → reported) — without duplicating capability Dark Spear already has.

**Architecture:** Both features extend existing modules rather than adding new ones. Panic button is a new function in `keystore.py` plus one HTTP endpoint in `bridge.py`, wired to a button in `panel/settings.html`. Findings Kanban extends the existing `status` enum on the finding dict (already `proposed|accepted|rejected|edited`) with two new values, adds one new `/findings/review` action (`verify`) and one (`mark_reported`), and adds a status column/filter to the existing findings UI (`panel/vulnerabilities.html` or `panel/findings-summary.html` — confirmed at Task 3).

**Tech Stack:** Python 3 stdlib `http.server` (`bridge.py`), `cryptography` (Fernet/PBKDF2, `keystore.py`), vanilla JS + static HTML (`panel/`).

**Spec:** This plan is self-contained; no separate design doc. Rationale for scope: an internal capability audit found that most of the hardening ideas considered are already implemented in Dark Spear, in mature form:
- Playbook fase-por-fase → `backend/js/playbook.js` (4 PTES phases, ~60 probes, already gated).
- Anti-alucinación → `bridge.py` scope-lock + tool whitelist + human approval gate (enforced server-side, not just prompt text).
- Server stateless → intentionally NOT applicable: Dark Spear persists engagement state to disk on purpose (chain-of-custody requirement for evidence), which is the correct tradeoff for this product.
- Vault cifrado → `backend/keystore.py` already does Fernet + PBKDF2 (600k iterations) for the API key pool. Missing: panic button. → **Task 1**.
- Engagement workspace aislado → `bridge.py` `ENGAGEMENTS_ROOT`, `_engagement_dir_safe()`, per-engagement `findings.json` + `evidence/` dir already implement this, with path-traversal guarding. Nothing to add.
- Kanban hallazgos → `bridge.py` `/findings/review` already has `proposed/accepted/rejected/edited`, which is a review gate, not a post-acceptance reporting pipeline. Missing: verifying/reported states. → **Task 2**.

Two other candidate targets were considered and ruled out: a config/memory backup repo with no executable pentest code surface, and an existing HTB-methodology skill with its own established phase structure predating this audit. Both are out of scope for this plan.

## Global Constraints

- Never write the vault passphrase to disk or to `audit_log()` — existing rule in `keystore.py`, must hold for every new function added.
- All new `bridge.py` endpoints must go through the existing `_engagement_mismatch()` / `CURRENT_SCOPE` checks used by every other findings endpoint — no new endpoint bypasses scope-lock.
- Every finding status transition must call `audit_log()` with `event` + `id` + `action`, matching the existing convention at bridge.py:1615.
- Follow existing code style: stdlib-only in `bridge.py` where possible, `cryptography` already a declared dependency in `requirements.txt` — do not add new third-party packages.

---

## File Structure

- Modify: `backend/keystore.py` — add `wipe()` function.
- Modify: `backend/bridge.py` — add `POST /keystore/panic` handler; extend `/findings/review` action set.
- Modify: `panel/vendor/engine/js/` — this is a synced copy of `backend/js/`; not touched by this plan (no engine changes needed).
- Modify: `panel/settings.html` — add "Panic button" UI control (button + confirmation modal + fetch call).
- Modify: `panel/vulnerabilities.html` (confirmed as the findings list page at Task 3) — add status column/filter showing `verifying`/`reported`.
- Test: `backend/tests/test_keystore_panic.py` (new file, plain `unittest`, matching whatever test runner the repo already uses — confirmed at Task 1 Step 0).
- Test: `backend/tests/test_findings_kanban.py` (new file).

---

### Task 0: Confirm test runner and settings.html conventions

**Files:**
- Read: `backend/requirements.txt`
- Read: `backend/docs/superpowers/plans/2026-08-29-findings-and-disk-persistence-implementation.md` (for how that feature's tests were structured/run)
- Read: `panel/settings.html`

**Interfaces:** None — this is a research-only task, no code changes.

- [ ] **Step 1: Find how existing backend tests run**

```bash
grep -rn "unittest\|pytest" /home/kali/dark_spear/backend/docs/superpowers/plans/2026-08-29-findings-and-disk-persistence-implementation.md
find /home/kali/dark_spear/backend -iname "test_*.py" -o -iname "*_test.py"
```

Record the exact command used to run backend tests (e.g. `python3 -m unittest discover backend/tests` or `pytest backend/tests`). Use that exact command in every "Run test" step below — do not assume `pytest` is installed if the repo only uses stdlib `unittest`.

- [ ] **Step 2: Read `panel/settings.html` structure**

```bash
sed -n '1,60p' /home/kali/dark_spear/panel/settings.html
grep -n "fetch(\|X-Auditor-Token\|<script" /home/kali/dark_spear/panel/settings.html
```

Confirm: (a) how existing settings.html buttons call the backend (likely `fetch('http://127.0.0.1:8420/...', {headers: {'X-Auditor-Token': ...}})` per the README's panel/motor pairing), (b) whether there's an existing confirmation-modal pattern to reuse rather than inventing a new one. Note the exact fetch helper name if `panel/vendor/panel-live.js` wraps it.

- [ ] **Step 3: Confirm findings list page**

```bash
grep -ln "status.*accepted\|findings/list" /home/kali/dark_spear/panel/*.html
```

The plan currently assumes `panel/vulnerabilities.html` renders the accepted-findings list. If `findings-summary.html` or another page is the actual live list (check which one calls `/findings/list`), use that file for Task 3 instead — file path substitution only, no other change.

---

### Task 1: Keystore panic button

**Files:**
- Modify: `backend/keystore.py`
- Modify: `backend/bridge.py`
- Modify: `panel/settings.html`
- Test: `backend/tests/test_keystore_panic.py`

**Interfaces:**
- Consumes: `keystore.KEYSTORE_PATH` (existing, `Path.home() / ".auditor" / "keys.enc"`).
- Produces: `keystore.wipe() -> bool` (returns `True` if a file was deleted, `False` if there was nothing to delete — never raises for "file didn't exist").

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_keystore_panic.py
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import keystore


class TestKeystorePanic(unittest.TestCase):
    def test_wipe_deletes_existing_keystore_file(self):
        with mock.patch.object(keystore, "KEYSTORE_PATH", Path("/tmp/ds_test_keys.enc")):
            keystore.KEYSTORE_PATH.write_bytes(b"fake-ciphertext")
            result = keystore.wipe()
            self.assertTrue(result)
            self.assertFalse(keystore.KEYSTORE_PATH.exists())

    def test_wipe_is_noop_when_file_absent(self):
        with mock.patch.object(keystore, "KEYSTORE_PATH", Path("/tmp/ds_test_keys_missing.enc")):
            if keystore.KEYSTORE_PATH.exists():
                keystore.KEYSTORE_PATH.unlink()
            result = keystore.wipe()
            self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest backend.tests.test_keystore_panic -v` (adjust to the exact command confirmed in Task 0 Step 1)
Expected: FAIL with `AttributeError: module 'keystore' has no attribute 'wipe'`

- [ ] **Step 3: Implement `wipe()` in `keystore.py`**

Add after the existing `save()` function (after line 63):

```python
def wipe() -> bool:
    """Delete the encrypted keystore file. Used by the panel's panic button.

    Never touches engagement data or findings — this only destroys the
    Ollama Cloud API key pool, so a compromised or coerced operator can
    kill token access without losing case evidence.
    """
    if not KEYSTORE_PATH.is_file():
        return False
    KEYSTORE_PATH.unlink()
    return True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest backend.tests.test_keystore_panic -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Add the `/keystore/panic` endpoint in `bridge.py`**

Find the existing auth-gated `POST` dispatch block (same `if self.path == "/findings/review":` style seen at bridge.py:1558) and add, in the same handler method, before or after the findings block:

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

Place it inside the same auth-checked block that guards `/findings/propose` and `/findings/review` (confirm the exact auth check — likely a token check earlier in `do_POST` — by reading ~20 lines above bridge.py:1488, and put the panic endpoint behind the same check, never behind a weaker one).

- [ ] **Step 6: Add the panic button UI to `panel/settings.html`**

Using the fetch pattern and confirmation-modal convention confirmed in Task 0 Step 2, add a button in the danger-zone/security section of `settings.html`:

```html
<button id="panic-btn" class="btn-danger">Borrar pool de claves (panic button)</button>
<script>
document.getElementById('panic-btn').addEventListener('click', async () => {
  if (!confirm('Esto borra el pool cifrado de API keys de Ollama Cloud. No afecta hallazgos ni evidencia. ¿Continuar?')) return;
  const res = await fetch(ENGINE_BASE_URL + '/keystore/panic', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Auditor-Token': getAuditorToken() },
    body: JSON.stringify({ confirm: 'WIPE_KEYS' }),
  });
  const data = await res.json();
  alert(data.ok ? 'Pool de claves borrado.' : 'Error: ' + (data.error || 'desconocido'));
});
</script>
```

Replace `ENGINE_BASE_URL` and `getAuditorToken()` with whatever the existing settings.html page actually uses to reach the engine (confirmed in Task 0 Step 2) — do not invent new token-discovery logic, reuse what the panel already has for every other backend call on that page.

- [ ] **Step 7: Manual verification**

```bash
cd /home/kali/dark_spear && ./scripts/start-dark-spear.sh
```

Open the panel, go to Settings, click the panic button, confirm the dialog, confirm the alert shows success, and confirm `~/.auditor/keys.enc` no longer exists:

```bash
ls -la ~/.auditor/keys.enc   # expect: No such file or directory
```

Then confirm engagement data is untouched:

```bash
ls ~/.auditor/engagements/   # expect: unchanged from before the panic click
```

- [ ] **Step 8: Commit**

```bash
cd /home/kali/dark_spear
git add backend/keystore.py backend/bridge.py backend/tests/test_keystore_panic.py panel/settings.html
git commit -m "feat: add keystore panic button (wipe API key pool on demand)"
```

---

### Task 2: Findings Kanban — verifying/reported states

**Files:**
- Modify: `backend/bridge.py`
- Test: `backend/tests/test_findings_kanban.py`

**Interfaces:**
- Consumes: existing finding dict shape `{"id", "status", "reviewed_at", "evidence_hashes", ...}` and existing `_save_findings()`, `_save_findings_to_dir()`, `_engagement_mismatch()`, `_engagement_dir_safe()`, `audit_log()` (all already defined in `bridge.py`, same signatures used at bridge.py:1558-1617).
- Produces: `/findings/review` now also accepts `action: "verify"` (sets `status: "verifying"`) and `action: "mark_reported"` (sets `status: "reported"`, requires the finding to already be `"accepted"` or `"verifying"`).

**State machine:** `proposed → accepted → verifying → reported` (or `proposed → rejected` / `proposed → edited → accepted → ...`). `reported` is terminal — a finding already `reported` cannot be re-verified or re-reported without going through `edit` first, matching the existing pattern where `edit` is the escape hatch for any correction.

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_findings_kanban.py
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bridge


class TestFindingsKanban(unittest.TestCase):
    def setUp(self):
        bridge.FINDINGS = [{
            "id": "f1",
            "status": "accepted",
            "title": "Test finding",
            "evidence_hashes": [],
        }]
        bridge.CURRENT_SCOPE = "test-scope"
        bridge.CURRENT_ENGAGEMENT_DIR = None

    def test_verify_transitions_accepted_to_verifying(self):
        finding = next(f for f in bridge.FINDINGS if f["id"] == "f1")
        self.assertEqual(finding["status"], "accepted")
        # Directly exercise the transition logic (extracted as a pure
        # function in Step 3) rather than spinning up the HTTP server.
        error = bridge._apply_finding_status_transition(finding, "verify")
        self.assertIsNone(error)
        self.assertEqual(finding["status"], "verifying")

    def test_mark_reported_requires_accepted_or_verifying(self):
        finding = next(f for f in bridge.FINDINGS if f["id"] == "f1")
        finding["status"] = "proposed"
        error = bridge._apply_finding_status_transition(finding, "mark_reported")
        self.assertEqual(error, "invalid_transition")
        self.assertEqual(finding["status"], "proposed")

    def test_mark_reported_from_verifying_succeeds(self):
        finding = next(f for f in bridge.FINDINGS if f["id"] == "f1")
        finding["status"] = "verifying"
        error = bridge._apply_finding_status_transition(finding, "mark_reported")
        self.assertIsNone(error)
        self.assertEqual(finding["status"], "reported")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest backend.tests.test_findings_kanban -v`
Expected: FAIL with `AttributeError: module 'bridge' has no attribute '_apply_finding_status_transition'`

- [ ] **Step 3: Extract and implement `_apply_finding_status_transition()`**

Add this pure helper near `_apply_finding_edits()` in `bridge.py` (same module, findable via `grep -n "_apply_finding_edits" backend/bridge.py`):

```python
def _apply_finding_status_transition(finding: dict, action: str) -> str | None:
    """Applies a Kanban status transition to `finding` in place.

    Returns None on success, or an error string on invalid transition.
    Does not touch evidence, disk persistence, or audit_log — callers
    (the /findings/review handler) do that, same as the existing
    accept/reject/edit branches.
    """
    if action == "verify":
        if finding["status"] != "accepted":
            return "invalid_transition"
        finding["status"] = "verifying"
        finding["reviewed_at"] = time.time()
        return None
    if action == "mark_reported":
        if finding["status"] not in ("accepted", "verifying"):
            return "invalid_transition"
        finding["status"] = "reported"
        finding["reviewed_at"] = time.time()
        return None
    return "invalid_action"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest backend.tests.test_findings_kanban -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire the new actions into `/findings/review`**

Modify bridge.py:1580 and the branch chain at 1590-1609. Change:

```python
            if action not in {"accept", "reject", "edit"}:
                self._send_json(400, {"error": "invalid_action"})
                return
```

to:

```python
            if action not in {"accept", "reject", "edit", "verify", "mark_reported"}:
                self._send_json(400, {"error": "invalid_action"})
                return
```

And after the existing `elif action == "accept":` block (ending at bridge.py:1609, right before `if disk_dir is not None:`), add:

```python
            elif action in ("verify", "mark_reported"):
                error = bridge._apply_finding_status_transition(finding, action)
                if error:
                    self._send_json(409 if error == "invalid_transition" else 400,
                                     {"error": error})
                    return
```

(Use `_apply_finding_status_transition` unqualified, not `bridge._apply_finding_status_transition`, since this edit lives inside `bridge.py` itself — the `bridge.` prefix above is only for the test file, which imports the module.)

- [ ] **Step 6: Run the full existing findings test suite to check no regression**

Run: `python3 -m unittest discover backend/tests -v` (or the exact command from Task 0 Step 1)
Expected: all prior tests (including whatever covers `/findings/review` accept/reject/edit today) still PASS, plus the 3 new Kanban tests.

- [ ] **Step 7: Manual verification against the running engine**

```bash
cd /home/kali/dark_spear && ./scripts/start-dark-spear.sh
```

In another terminal, with an active engagement and at least one `accepted` finding (or via the panel), exercise the new transitions directly against the engine:

```bash
TOKEN=$(cat ~/.auditor/session.token)
curl -s -X POST http://127.0.0.1:8420/findings/review \
  -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"finding_id":"<id-of-an-accepted-finding>","action":"verify"}'
# expect: {"...,"status":"verifying",...}

curl -s -X POST http://127.0.0.1:8420/findings/review \
  -H "X-Auditor-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"finding_id":"<same-id>","action":"mark_reported"}'
# expect: {"...,"status":"reported",...}
```

- [ ] **Step 8: Commit**

```bash
cd /home/kali/dark_spear
git add backend/bridge.py backend/tests/test_findings_kanban.py
git commit -m "feat: add verifying/reported states to findings review lifecycle"
```

---

### Task 3: Surface Kanban states in the panel UI

**Files:**
- Modify: whichever file Task 0 Step 3 confirmed as the live findings list (`panel/vulnerabilities.html` assumed).

**Interfaces:**
- Consumes: `/findings/list` response, each finding now possibly carrying `status: "verifying"` or `"reported"` in addition to the existing four values.
- Produces: no new interface — this is a pure rendering change.

- [ ] **Step 1: Read current status rendering**

```bash
grep -n "status" /home/kali/dark_spear/panel/vulnerabilities.html
```

Find how `accepted`/`rejected` are currently mapped to a badge/color (likely a JS `switch` or object lookup in an inline `<script>` or in `panel/vendor/panel-live.js`).

- [ ] **Step 2: Add the two new statuses to that same lookup**

Add `verifying` and `reported` entries following the exact pattern already used for `accepted`/`rejected` (same object shape, same CSS class naming convention — e.g. if `accepted` maps to class `badge-success`, follow whatever naming scheme is already there for the new ones, such as `badge-info` for `verifying` and `badge-neutral` for `reported`). Do not introduce a new badge component — reuse the existing one.

- [ ] **Step 3: Manual verification**

With the engine running and a finding pushed through `verify` then `mark_reported` (Task 2 Step 7), reload the panel page and confirm the badge text/color updates to reflect each new status.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/dark_spear
git add panel/vulnerabilities.html
git commit -m "feat: render verifying/reported finding statuses in the panel"
```

---

## Self-Review

**Spec coverage:** Both real gaps identified in the audit (vault panic button, findings reporting Kanban) have tasks. The already-implemented capabilities are documented as "nothing to add" with the file evidence backing that claim, so a future reader doesn't re-propose them. The two other candidate targets are explicitly ruled out with reasoning.

**Placeholder scan:** No TBD/TODO. Task 0 has open confirmations (exact test-runner command, exact settings.html fetch helper name, exact findings-list file) because this plan was written without running code in the target repo this session — each is a concrete, scripted lookup step, not a vague "figure it out."

**Type consistency:** `keystore.wipe() -> bool` used consistently in Task 1 test and implementation. `_apply_finding_status_transition(finding: dict, action: str) -> str | None` used consistently in Task 2 test (via `bridge._apply_finding_status_transition`) and implementation (unqualified, same module).
