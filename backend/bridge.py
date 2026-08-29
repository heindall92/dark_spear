#!/usr/bin/env python3
"""Auditor engine bridge — stdlib only. Serves the static UI and executes
scoped, whitelisted-by-scope commands on behalf of the browser agent loop.

Security model: this process can run arbitrary pentest binaries on the
operator's machine, so it is treated as a local privileged service, not a
toy dev server.
- A random per-run token gates every state-changing endpoint (defeats CSRF
  and DNS-rebinding: an attacker page cannot read/guess the token, and a
  simple cross-origin form POST cannot set a custom header).
- The Host header is checked against an allowlist (defense-in-depth against
  DNS rebinding even if the token were somehow leaked).
- Only binaries in ALLOWED_TOOLS can be executed, on top of the scope-lock
  on the target — this is a baseline safety net against a compromised/
  malformed request asking for something destructive and unrelated to
  pentesting (e.g. "rm"), independent of the scope check.
"""
import getpass
import json
import re
import secrets
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import keystore

# Endpoints the LLM proxy is allowed to forward to — the API key travels in
# the Authorization header, so this can't become an open relay to arbitrary
# hosts even though the key itself never touches disk.
ALLOWED_LLM_ENDPOINTS = {
    "https://ollama.com/v1/chat/completions",
    "http://127.0.0.1:11434/v1/chat/completions",
    "http://localhost:11434/v1/chat/completions",
}

STATIC_DIR = Path(__file__).parent
LOG_PATH = Path.home() / ".auditor" / "exec.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {"127.0.0.1:8420", "localhost:8420"}

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
        "enum4linux", "rpcclient", "echo", "curl"},
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

AUTH_TOKEN = secrets.token_hex(16)
CURRENT_SCOPE: dict | None = None
CURRENT_PHASE: int = 1
MAX_KEYS = 10

# ThreadingHTTPServer runs one thread per request. This tool is designed for
# a single operator driving one sequential agent loop, but /keys/add,
# /keys/select, and /llm/chat's rotation all mutate shared KEYS/
# ROTATION_STATE globals — guard those mutations against a stray concurrent
# request (e.g. two browser tabs) corrupting state.
STATE_LOCK = threading.Lock()

KEYS: list[dict] = []
PASSPHRASE: str = ""
ROTATION_STATE: dict | None = None

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


def audit_log(entry: dict) -> None:
    entry["ts"] = time.time()
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


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
    if 200 <= result["status"] < 300:
        return False
    return bool(re.search(r"quota|rate.?limit", json.dumps(result["body"]).lower()))


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


MAX_OUTPUT_CHARS = 20_000  # keeps a single tool's output from blowing the LLM's context window


def _truncate_output(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    omitted = len(text) - MAX_OUTPUT_CHARS
    return text[:MAX_OUTPUT_CHARS] + f"\n[... truncated, {omitted} more chars omitted ...]"


def _earliest_reset_seconds() -> float:
    now = time.time()
    remaining = [
        (kr["window_hours"] * 3600) - (now - kr["exhausted_at"])
        for kr in ROTATION_STATE["pool"] if kr["exhausted_at"] is not None
    ]
    return max(0, min(remaining)) if remaining else 0


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

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def _auth_ok(self) -> bool:
        return self.headers.get("X-Auditor-Token", "") == AUTH_TOKEN

    def do_GET(self) -> None:
        if not self._host_ok():
            self._send_json(403, {"error": "forbidden_host"})
            return
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
        global CURRENT_SCOPE, CURRENT_PHASE, CURRENT_ENGAGEMENT_DIR, FINDINGS, KEYS, PASSPHRASE, ROTATION_STATE
        if not self._host_ok():
            self._send_json(403, {"error": "forbidden_host"})
            return
        if not self._auth_ok():
            audit_log({"event": "auth_rejected", "path": self.path})
            self._send_json(401, {"error": "invalid_or_missing_token"})
            return

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

        if self.path == "/exec":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            tool = body.get("tool", "")
            args = body.get("args", [])
            target = body.get("target", "")

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
            in_scope = target and (target in scope or scope in target)
            if not in_scope:
                audit_log({"event": "scope_violation", "tool": tool, "target": target})
                self._send_json(403, {"error": "scope_violation", "verdict": "scope_violation"})
                return

            # Resolve to the actual binary PATH would pick before running it,
            # so the audit log records exactly what executed (not just the
            # whitelisted name) — closes the gap between "name we approved"
            # and "binary that actually ran" if PATH ever resolves oddly.
            resolved = shutil.which(tool)
            if resolved is None:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
                audit_log({"event": "exec", "tool": tool, "args": args,
                           "target": target, "exit_code": result["exit_code"],
                           "verdict": result["verdict"]})
                self._send_json(200, result)
                return

            cmd = [resolved] + [str(a) for a in args]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                result = {"stdout": _truncate_output(proc.stdout),
                          "stderr": _truncate_output(proc.stderr),
                          "exit_code": proc.returncode, "verdict": "ok"}
            except subprocess.TimeoutExpired:
                result = {"stdout": "", "stderr": "timeout after 120s",
                          "exit_code": -1, "verdict": "timeout"}
            except FileNotFoundError:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
            audit_log({"event": "exec", "tool": tool, "resolved_path": resolved,
                       "args": args, "target": target,
                       "exit_code": result["exit_code"], "verdict": result["verdict"]})
            self._send_json(200, result)
            return

        if self.path == "/llm/chat":
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
                with STATE_LOCK:
                    key_record = _next_available_key()
                if key_record is None:
                    with STATE_LOCK:
                        retry_hint = _earliest_reset_seconds()
                    self._send_json(503, {"error": "all_keys_exhausted",
                                           "retry_after_hint": retry_hint})
                    return
                # The upstream HTTP call happens OUTSIDE the lock — it's slow
                # (seconds), and holding the lock during network I/O would
                # serialize unrelated requests (e.g. /keys/list) behind it.
                result = _forward_llm_request(endpoint, key_record["api_key"], payload)
                if _is_quota_error(result):
                    with STATE_LOCK:
                        key_record["exhausted_at"] = time.time()
                    audit_log({"event": "key_exhausted", "label": key_record["label"]})
                    attempts += 1
                    continue
                self._send_json(result["status"], result["body"])
                return

            with STATE_LOCK:
                retry_hint = _earliest_reset_seconds()
            self._send_json(503, {"error": "all_keys_exhausted",
                                   "retry_after_hint": retry_hint})
            return

        if self.path == "/keys/list":
            self._send_json(200, [
                {"label": k["label"], "last4": k["api_key"][-4:], "window_hours": k["window_hours"]}
                for k in KEYS
            ])
            return

        if self.path == "/keys/add":
            body = self._read_json()
            label = body.get("label", "").strip()
            api_key = body.get("api_key", "").strip()
            window_hours_raw = body.get("window_hours")
            if not label or not api_key or not window_hours_raw:
                self._send_json(400, {"error": "label_and_api_key_required"})
                return
            try:
                window_hours = float(window_hours_raw)
            except (TypeError, ValueError):
                self._send_json(400, {"error": "window_hours_must_be_a_number"})
                return
            if window_hours <= 0:
                self._send_json(400, {"error": "window_hours_must_be_positive"})
                return
            with STATE_LOCK:
                if len(KEYS) >= MAX_KEYS:
                    self._send_json(400, {"error": f"key_pool_full: max {MAX_KEYS} keys"})
                    return
                KEYS.append({"label": label, "api_key": api_key, "window_hours": window_hours})
                keystore.save(PASSPHRASE, KEYS)
            audit_log({"event": "key_added", "label": label})
            self._send_json(200, {"ok": True})
            return

        if self.path == "/keys/select":
            body = self._read_json()
            labels = body.get("labels", [])
            with STATE_LOCK:
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

        if self.path == "/phase/advance":
            if CURRENT_PHASE >= MAX_PHASE:
                self._send_json(200, {"ok": True, "phase": CURRENT_PHASE, "already_at_max": True})
                return
            CURRENT_PHASE += 1
            audit_log({"event": "phase_advanced", "from": CURRENT_PHASE - 1, "to": CURRENT_PHASE})
            self._send_json(200, {"ok": True, "phase": CURRENT_PHASE,
                                   "unlocked_tools": sorted(PHASE_TOOLS.get(CURRENT_PHASE, set()))})
            return

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

        self._send_json(404, {"error": "unknown endpoint"})

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


if __name__ == "__main__":
    PASSPHRASE = getpass.getpass("Auditor keystore passphrase (used to encrypt/decrypt your API keys): ")
    try:
        KEYS = keystore.load_or_init(PASSPHRASE)
    except ValueError:
        print("Wrong passphrase for existing keystore. Aborting.")
        raise SystemExit(1)
    print(f"Loaded {len(KEYS)} stored API key(s).")

    server = ThreadingHTTPServer(("127.0.0.1", 8420), Handler)
    print("Auditor bridge listening on http://127.0.0.1:8420")
    print(f"Session token (needed by the UI, auto-filled via URL): {AUTH_TOKEN}")
    print(f"Open: http://127.0.0.1:8420/?token={AUTH_TOKEN}")
    server.serve_forever()
