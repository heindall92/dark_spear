# API Key Pool + Failover, and Expanded Tool Whitelist

Status: approved by user 2026-08-26, ready for implementation plan.

## Problem

Auditor runs long engagements against Ollama Cloud. A single API key can run out
of its quota mid-engagement (windows vary: 4h, 24h, weekly depending on the
account/plan), forcing the operator to stop and wait. The user has up to 10
Ollama Cloud accounts and wants the engine to consume them in sequence,
automatically, so a quota exhaustion never stops the analysis — and never
repeats work already done.

Separately, the tool whitelist needs to grow: more impacket scripts, and
`adscan` (AD enumeration CLI) in its non-interactive mode.

## Non-goals

- Sliver (C2 framework) integration — explicitly deferred. Sliver is a
  client/server system with persistent sessions and implants; it does not fit
  the current one-shot `subprocess.run([tool, *args])` execution model. It
  gets its own sub-project and design later.
- Parallel use of multiple keys at once. Consumption is strictly sequential:
  key 1 until exhausted, then key 2, ... then key 10, cycling back once
  reset windows allow it.
- Automatic detection of quota-reset timing from API response headers. The
  user configures each key's reset window by hand at add-time.

## Key storage

- File: `~/.auditor/keys.enc`, permissions `600`.
- Encrypted with a passphrase the operator enters at `bridge.py` startup via
  `getpass` (never echoed, never logged, never appears in the audit log).
- Encryption: `cryptography`'s `Fernet` (already available in the venv used by
  other project tooling), key derived from the passphrase via
  `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC` with a random salt
  stored alongside the ciphertext (not secret, just needed for derivation).
- Decrypted content lives only in the `bridge.py` process memory as a Python
  list, for the lifetime of the process. Never re-serialized to disk in
  plaintext, never sent to the browser as a bulk blob (the UI only ever sees
  labels + last-4-chars, never full keys).
- Record shape (post-decryption, in memory):
  ```python
  {"label": str, "api_key": str, "window_hours": float}
  ```

## UI flow

- Start panel gets a "Gestionar keys" button opening a small management view:
  - Lists existing keys as `label (****last4)` with a checkbox "use in this
    engagement" and its configured `window_hours`.
  - "Add key" form: label, key (password-masked input), window_hours (numeric,
    free-form so 4, 24, or 168 for weekly all work).
  - First run (no `keys.enc` yet): the same "Add key" form, no list.
- The existing single `apikey-input` field is removed from the main start
  form; API key selection now happens entirely through key-pool management.
  `model-input` and `endpoint-input` stay as they are — the pool applies to
  Ollama Cloud auth, not to model/endpoint choice.
- "Iniciar engagement" is disabled until at least one key is checked.

## Bridge-side key pool endpoints (new, token-gated like existing POSTs)

- `POST /keys/list` → returns `[{label, last4, window_hours}]` (never the key
  itself).
- `POST /keys/add` → body `{label, api_key, window_hours}`, appends to the
  in-memory list, re-encrypts and rewrites `keys.enc`.
- `POST /keys/select` → body `{labels: [str, ...]}`, sets the active pool
  for the current engagement in the order given. This is the rotation order.

## Rotation engine (bridge.py, server-side — not the browser)

`bridge.py` owns rotation state, not `ollama.js`, because the browser only
ever talks to the bridge's `/llm/chat` proxy (already true post-CORS-fix) and
never sees raw keys.

State per engagement (in-memory, keyed by the active pool from `/keys/select`):
```python
{
  "pool": [{"label", "api_key", "window_hours", "exhausted_at": float|None}, ...],
  "current_index": int,
}
```

On every `/llm/chat` call:
1. Skip forward past any key whose `exhausted_at` is set but
   `now - exhausted_at < window_hours * 3600` (still in cooldown).
2. If no key is available at all → return `503 {"error": "all_keys_exhausted",
   "retry_after_hint": <seconds until the earliest key resets>}` instead of
   proxying. (See "Full exhaustion" below for what the frontend does with this.)
3. Use the first available key at or after `current_index`, forward the
   request to Ollama as today.
4. If Ollama responds `429`, or `200`/other status with a body whose error
   message matches `/quota|limit|rate.?limit/i`: mark that key's
   `exhausted_at = now`, advance `current_index` to the next available key,
   and **retry the same request body immediately** against the new key
   (still inside the same `/llm/chat` call — the browser only sees the final
   outcome, one HTTP round trip from its point of view).
5. Any other error (timeout, malformed response, 5xx) is forwarded as-is —
   does not touch key state. This matches the existing rule: only an explicit
   quota/rate-limit signal rotates keys; everything else goes through the
   agent loop's existing `agent_error` / 5-strike handling untouched.

This keeps `js/agent.js` and `js/ollama.js` almost untouched — the failover
is invisible below the `/llm/chat` boundary, consistent with the existing
"bridge does the trusted, stateful, security-relevant work; browser JS just
orchestrates" split.

## Full exhaustion (all selected keys in cooldown)

- `/llm/chat` returns `503 all_keys_exhausted` as above.
- `js/agent.js`'s loop catches this specific error (distinct from generic
  `agent_error`) and instead of counting it toward the 5-strike abort, records
  a step with `verdict: "waiting_for_quota"` and calls a new
  `onWaitingForQuota(retryAfterHint)` callback instead of continuing the
  `while(true)` immediately.
- The UI shows this state clearly (e.g. "Todas las keys agotadas. Reintenta
  automáticamente en ~Xh Ym.") in the steps feed.
- The bridge itself runs a lightweight timer (checked lazily on next
  `/llm/chat` call — no need for a background thread) that re-evaluates key
  availability. The frontend's retry mechanism: `runAgentLoop` sleeps a short
  fixed interval (e.g. 5 minutes, capped, non-busy-wait via `setTimeout`)
  and retries the same pending decision request. No engagement state is
  lost — `steps` already in IndexedDB stay put; the loop resumes exactly
  where it paused, same as normal `agent_error` recovery already does.

## Tool whitelist expansion

`ALLOWED_TOOLS` in `bridge.py` and `ALLOWED_TOOLS_HINT` in `ollama.js` (kept
in sync by hand, per the existing code comment) gain:

- Impacket: `ntlmrelayx.py`, `smbexec.py`, `atexec.py`, `lookupsid.py`,
  `samrdump.py`, `mssqlclient.py`, `ticketer.py`, `getST.py`, `raiseChild.py`,
  `dcomexec.py`.
- `adscan`, used in its non-interactive CI mode
  (`adscan ci auth --type audit --interface <iface> --domain <domain>
  --dc-ip <ip> -u <user> -p <pass>`), which fits the existing one-shot
  `subprocess.run` model without changes to the exec endpoint.

`js/agent.js`'s `DANGEROUS_TOOLS` / `DANGEROUS_ARG_PATTERNS` gate is reviewed
against the new tools: `ntlmrelayx.py`, `secretsdump`-equivalents reachable
via `dcomexec.py`/`atexec.py` with credential-dumping flags, and `ticketer.py`
(forges Kerberos tickets — golden/silver ticket territory) are added to
`DANGEROUS_TOOLS` since they're credential-theft/persistence primitives, same
risk class as the tools already gated there.

## Testing

- Bridge-side: unit-style manual test hitting `/llm/chat` with a mocked
  429 response (temporary stub endpoint or a local HTTP server that returns
  429 once then 200) to confirm rotation advances `current_index` and retries
  transparently.
- Full exhaustion path: force all pool keys into `exhausted_at` state
  manually (short `window_hours` like 0.01h for the test) and confirm the
  `waiting_for_quota` verdict appears and the loop resumes after the window.
- Encryption round-trip: add a key, restart `bridge.py`, confirm the same
  passphrase decrypts and the key is usable — wrong passphrase must fail
  loudly, not silently produce garbage keys.
- Tool whitelist: confirm `adscan ci auth ...` and each new impacket script
  round-trips through `/exec` (command-not-found is an acceptable outcome in
  a sandbox without the binary installed — the point is the whitelist gate
  and scope-lock still apply correctly, same as the existing tools).
