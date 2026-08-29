# PTES Phase State Machine (FSM) for Tool Gating

Status: approved by user 2026-08-28, ready for implementation plan.

## Problem

Auditor's ReAct agent picks whichever whitelisted tool it wants, in whatever
order, for the whole engagement. Nothing stops it from jumping straight to
credential dumping before finishing recon, or bouncing between unrelated
attack vectors without depth. External review (Gemini, Cursor) both flagged
this: the tool needs a structural methodology, not just a flat whitelist, so
the agent behaves like a disciplined junior pentester instead of a chatbot
that happens to run binaries.

This is the first of several methodology pieces raised in review (PTES-phase
gating, MITRE ATT&CK technique tracking, domain-specific playbooks for AD/
local-privesc/API, and an automatic success/failure heuristic for phase
transitions). Building all of them at once was rejected as too large for one
spec — see "Non-goals" below for what's explicitly deferred to later specs.

## Non-goals

- **MITRE ATT&CK technique tagging** — separate spec/sub-project.
- **Domain-specific playbooks** (AD enumeration flow, local privesc flow, API
  testing flow) — separate spec/sub-project. This FSM provides the phase
  scaffolding those playbooks will eventually hang off of, but doesn't build
  them.
- **Automatic phase-transition heuristics** ("if this phase produced no new
  findings, force a transition" or exit-condition checks like "must have
  found an open port before enumeration"). Explicitly deferred by the user.
  This spec's phase transitions are 100% operator-triggered.
- **Automatic rollback on failed exploitation.** Doesn't apply — phases are
  cumulative (see below), so nothing is ever removed and there's nothing to
  roll back from.
- **Interactive/session-based tools** (`msfconsole`, `evil-winrm`). Both are
  REPLs, not one-shot commands — they don't fit the existing
  `subprocess.run(cmd, timeout=120)` model, which waits for the process to
  exit on its own. Bolting them on requires a session/C2 architecture change,
  deferred to its own design.
- **Tools requiring remote code execution on a compromised host**
  (`linpeas.sh`, `winpeas.exe`). `bridge.py` only executes processes locally
  on the operator's own Kali box — there's no mechanism today to run a
  script inside a compromised remote target. Running linpeas locally against
  the operator's own machine has no post-exploitation value. Deferred until
  a remote-exec/session mechanism exists (same blocker as evil-winrm above).

## Phases and tool mapping

Four phases, loosely modeled on PTES's technical phases (pre-engagement,
threat modeling, and reporting are out of scope here — they're not
tool-execution phases):

1. **Intelligence Gathering** — unauthenticated discovery.
2. **Enumeration & Vulnerability Analysis** — deeper, still mostly
   unauthenticated or low-privilege enumeration.
3. **Exploitation** — credential attacks, authenticated abuse, initial
   access.
4. **Post-Exploitation** — what you do once you have a foothold/credentials.

**Phases are cumulative**: advancing to phase N adds phase N's tools to what
was already unlocked — it never removes access to earlier-phase tools. A
real engagement loops back to recon constantly (new host found during
post-exploitation, e.g.); gating that would be friction with no security
benefit, since scope-lock and the dangerous-tool gate already do the actual
risk-relevant enforcement.

| Phase | Tools unlocked at this phase |
|---|---|
| 1. Intelligence Gathering | `nmap`, `whatweb`, `dig`, `nslookup`, `dnsrecon`, `ldapsearch`, `enum4linux`, `rpcclient`, `echo` |
| 2. Enumeration & Vuln Analysis | `gobuster`, `ffuf`, `nikto`, `smbclient`, `GetNPUsers.py`, `GetUserSPNs.py`, `bloodhound-python`, `lookupsid.py`, `samrdump.py`, `searchsploit`, `adscan`, `certipy` |
| 3. Exploitation | `sqlmap`, `hydra`, `secretsdump.py`, `wmiexec.py`, `psexec.py`, `smbexec.py`, `atexec.py`, `dcomexec.py`, `mssqlclient.py`, `ntlmrelayx.py`, `crackmapexec`, `netexec`, `ticketer.py`, `getST.py`, `raiseChild.py` |
| 4. Post-Exploitation | `hashcat`, `john` |

`dnsrecon` and `searchsploit` are new to `ALLOWED_TOOLS` — added as part of
this spec (both are one-shot CLI tools, no architecture change needed).

Every tool above must already be in `ALLOWED_TOOLS` (or added by this spec).
This mapping is a hand-maintained table in `bridge.py`, same maintenance
model as `ALLOWED_TOOLS`/`DANGEROUS_TOOLS` — never LLM-generated or
runtime-modified.

## Enforcement (server-side, bridge.py)

`bridge.py` gains a module global `CURRENT_PHASE: int`, reset to `1` on every
`/engagement/start` (same lifecycle as `CURRENT_SCOPE`).

`/exec`'s existing check order gains one step, inserted after the
`ALLOWED_TOOLS` check and before the scope-lock check:

1. `tool not in ALLOWED_TOOLS` → `403 tool_not_allowlisted` (unchanged).
2. **New:** `tool not in cumulative_phase_tools(CURRENT_PHASE)` → `403`
   `{"error": "phase_locked", "verdict": "phase_locked", "tool": tool,
   "current_phase": CURRENT_PHASE}`. `cumulative_phase_tools(n)` is the union
   of every phase's tool set from 1 through `n`.
3. Scope-lock check (unchanged).
4. `DANGEROUS_TOOLS`/argument-pattern gate — **unchanged, fully orthogonal**.
   A tool can be phase-unlocked and still trigger the confirmation modal
   (e.g. `secretsdump.py` in phase 3 still pauses for operator approval); the
   phase gate and the danger gate are two independent checks with two
   independent purposes (methodology discipline vs. blast-radius control).

This mirrors the existing scope-lock pattern exactly: trust nothing from the
LLM, the server is the enforcement boundary.

## Phase advancement

New endpoint, token-gated like the other state-changing POSTs:

- `POST /phase/advance` (no body) → increments `CURRENT_PHASE` by 1, capped
  at 4 (no-op with `{"ok": true, "phase": 4, "already_at_max": true}` if
  already at 4). Otherwise `{"ok": true, "phase": <new_phase>,
  "unlocked_tools": [<this phase's additions>]}`.
- No exit-condition checks, no heuristic, no confirmation modal — the button
  click itself is the human decision, same trust model as the user choosing
  "manual button" over an LLM-proposed `advance_phase` action.
- `audit_log({"event": "phase_advanced", "from": old, "to": new})`.

## LLM prompt integration

`js/ollama.js` is **untouched**. `RESPONSE_CONTRACT` keeps listing the full
39-tool universe — that's a JSON-format contract (valid tool *names*), not an
enforcement mechanism, and was never meant to be phase-aware.

`js/agent.js`'s `buildUserPrompt` (which already injects target, recent
step history, and the axis anti-loop warning per iteration) gains one more
injected line:

```
Fase actual: <N>/4 — <nombre de fase>.
Tools disponibles ahora: <cumulative_phase_tools(N), comma-joined>.
```

If the model proposes a tool outside the current phase anyway, `/exec`
rejects it with `phase_locked` (see above) — that step gets recorded with
`verdict: "phase_locked"`, the model sees the rejection message on the next
iteration (same recovery pattern already used for `scope_violation` and
`tool_not_allowlisted`), and self-corrects. No special-casing needed in
`js/agent.js`'s error handling — `phase_locked` flows through the same path
as any other non-2xx `execTool` result already does.

## UI

- `#phase-indicator` in `steps-panel`, near `#export-btn`: renders
  `"Fase <N>/4: <nombre>"`.
- `#advance-phase-btn` next to it: calls a new `advancePhase()` function in
  `js/bridge_client.js` (`POST /phase/advance`), then updates the indicator
  text. Disabled (or hidden) once `CURRENT_PHASE === 4`.
- `js/main.js` initializes the indicator to phase 1 when an engagement
  starts (matching the server's reset-to-1 behavior), and wires the button's
  `onclick`.
- A `phase_locked` step renders in the existing steps feed like any other
  step (no new UI component needed) — `renderStep` already handles arbitrary
  `verdict` values via `div.className = \`step ${step.verdict}\``.

## Testing

No automated suite for this project (same as prior specs) — manual
verification only:

- Start an engagement, confirm phase 1 tools work via `/exec` and phase 2+
  tools 403 with `phase_locked`.
- Call `/phase/advance`, confirm phase 2 tools now work and phase 1 tools
  *still* work (cumulative, not exclusive).
- Advance to phase 4, confirm `/phase/advance` again returns
  `already_at_max: true` and doesn't error.
- Confirm a dangerous tool (e.g. `secretsdump.py`) still triggers the
  confirmation modal once phase-unlocked — phase gate and danger gate don't
  interfere with each other.
- Confirm `dnsrecon`/`searchsploit` are runnable (command-not-found is an
  acceptable outcome without the binary installed, same convention as the
  prior spec's whitelist testing).
- Restart `bridge.py` mid-engagement (or start a new engagement) and confirm
  `CURRENT_PHASE` resets to 1 — no phase state leaks across engagements.
