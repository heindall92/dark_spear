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
import hashlib
import importlib.util
import os
import json
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
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

ALLOWED_LLM_MODELS_ENDPOINTS = {
    "https://ollama.com/v1/models",
    "http://127.0.0.1:11434/v1/models",
    "http://localhost:11434/v1/models",
}

STATIC_DIR = Path(__file__).resolve().parent
LOG_PATH = Path.home() / ".auditor" / "exec.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {"127.0.0.1:8420", "localhost:8420"}
CORS_ORIGINS = {
    "http://127.0.0.1:8080",
    "http://localhost:8080",
}

ALLOWED_TOOLS = {
    "nmap", "gobuster", "ffuf", "feroxbuster", "nikto", "whatweb", "wafw00f", "nuclei", "subfinder", "httpx", "testssl.sh", "semgrep", "hydra", "sqlmap",
    "katana",
    "wapiti", "arjun", "dalfox",
    "wpscan",
    "hashcat", "john", "curl", "dig", "nslookup", "smbclient", "rpcclient",
    "GetNPUsers.py", "GetUserSPNs.py", "secretsdump.py", "wmiexec.py",
    "psexec.py", "certipy", "bloodhound-python", "ldapsearch", "enum4linux",
    "crackmapexec", "netexec", "echo",  # echo kept for manual verification
    "ntlmrelayx.py", "smbexec.py", "atexec.py", "lookupsid.py",
    "samrdump.py", "mssqlclient.py", "ticketer.py", "getST.py",
    "raiseChild.py", "dcomexec.py", "adscan", "findDelegation.py",
    "dnsrecon", "searchsploit",
    "ufw", "iptables", "nft",
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
    1: {"nmap", "whatweb", "wafw00f", "subfinder", "httpx", "testssl.sh", "semgrep", "dig", "nslookup", "dnsrecon", "ldapsearch",
        "enum4linux", "rpcclient", "smbclient", "netexec", "echo", "curl", "ufw", "iptables", "nft"},
    2: {"gobuster", "ffuf", "feroxbuster", "nikto", "wpscan", "nuclei", "katana", "wapiti", "arjun", "dalfox", "GetNPUsers.py",
        "GetUserSPNs.py", "bloodhound-python", "lookupsid.py", "samrdump.py",
        "searchsploit", "adscan", "certipy", "findDelegation.py"},
    3: {"sqlmap", "hydra", "secretsdump.py", "wmiexec.py", "psexec.py",
        "smbexec.py", "atexec.py", "dcomexec.py", "mssqlclient.py",
        "ntlmrelayx.py", "crackmapexec", "netexec", "ticketer.py",
        "getST.py", "raiseChild.py"},
    4: {"hashcat", "john"},
}

# Herramientas de análisis estático que operan sobre un fichero en disco,
# no sobre una URL de red — distinto del modelo de /exec (tool+args contra
# el target). Reciben el contenido ya filtrado por otra sonda, se escribe
# a un fichero temporal 0600 y se borra al terminar; nunca se guarda en
# el engagement ni se expone la ruta del fichero al cliente.
SCAN_SOURCE_TOOLS: dict[str, list[str]] = {
    "semgrep": ["--config=p/owasp-top-ten", "--json", "--timeout", "30", "--quiet"],
}
MAX_SCAN_SOURCE_BYTES = 500_000

MAX_PHASE = max(PHASE_TOOLS)

# Kali packages Impacket as impacket-* wrappers; upstream docs / our playbook
# still name the scripts GetNPUsers.py, lookupsid.py, etc. Resolve either.
TOOL_PATH_ALIASES: dict[str, tuple[str, ...]] = {
    "GetNPUsers.py": ("GetNPUsers.py", "impacket-GetNPUsers"),
    "GetUserSPNs.py": ("GetUserSPNs.py", "impacket-GetUserSPNs"),
    "lookupsid.py": ("lookupsid.py", "impacket-lookupsid"),
    "samrdump.py": ("samrdump.py", "impacket-samrdump"),
    "secretsdump.py": ("secretsdump.py", "impacket-secretsdump"),
    "wmiexec.py": ("wmiexec.py", "impacket-wmiexec"),
    "psexec.py": ("psexec.py", "impacket-psexec"),
    "smbexec.py": ("smbexec.py", "impacket-smbexec"),
    "atexec.py": ("atexec.py", "impacket-atexec"),
    "dcomexec.py": ("dcomexec.py", "impacket-dcomexec"),
    "ntlmrelayx.py": ("ntlmrelayx.py", "impacket-ntlmrelayx"),
    "mssqlclient.py": ("mssqlclient.py", "impacket-mssqlclient"),
    "ticketer.py": ("ticketer.py", "impacket-ticketer"),
    "getST.py": ("getST.py", "impacket-getST"),
    "raiseChild.py": ("raiseChild.py", "impacket-raiseChild"),
    "findDelegation.py": ("findDelegation.py", "impacket-findDelegation"),
    "certipy": ("certipy", "certipy-ad"),
}


def resolve_tool_path(tool: str) -> str | None:
    for name in TOOL_PATH_ALIASES.get(tool, (tool,)):
        path = shutil.which(name)
        if path:
            return path
    return None


# wapiti (-o) y arjun (-oJ) solo saben escribir JSON en un archivo real:
# abren el destino en modo "w+" (lectura+escritura), y un pipe real (lo que
# subprocess.run usa, a diferencia de un pty interactivo) no soporta eso ->
# OSError: [Errno 6] No such device or address. Los args builders de
# vuln-kb.js siguen usando el literal "/dev/stdout" (simple, testeable);
# aquí se sustituye por un tempfile real antes de ejecutar.
STDOUT_REDIRECT_FLAGS = {
    "wapiti": "-o",
    "arjun": "-oJ",
}


def rewrite_stdout_placeholder(args: list, tool: str) -> tuple[list, str | None]:
    flag = STDOUT_REDIRECT_FLAGS.get(tool)
    if not flag:
        return args, None
    try:
        idx = args.index(flag)
    except ValueError:
        return args, None
    if idx + 1 >= len(args) or args[idx + 1] != "/dev/stdout":
        return args, None
    fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix=f"ds-{tool}-")
    os.close(fd)
    new_args = list(args)
    new_args[idx + 1] = tmp_path
    return new_args, tmp_path


def read_and_cleanup_tempfile(path: str) -> str:
    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return content


def cumulative_phase_tools(phase: int) -> set[str]:
    result: set[str] = set()
    for n in range(1, phase + 1):
        result |= PHASE_TOOLS.get(n, set())
    return result

AUTH_TOKEN = secrets.token_hex(16)
SESSION_FILE = Path.home() / ".auditor" / "session.token"
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
ENGAGEMENT_STARTED_AT: float | None = None
LAST_ACTIVITY: str = ""
EXEC_STEP_COUNT: int = 0
ENGAGEMENT_PAUSED: bool = False
SCAN_HISTORY: list[dict] = []
HISTORY_FILE = Path.home() / ".auditor" / "scan_history.json"
ENGAGEMENTS_ROOT = Path.home() / ".auditor" / "engagements"


def _sanitize_for_path(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)[:80]


def _scope_host(value: str) -> str:
    """Hostname[:port] comparable: strips scheme, slash, www, default 80/443."""
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return (value or "").strip().lower().rstrip("/")
    host = (parsed.hostname or "").lower()
    if not host:
        return raw.rstrip("/")
    if host.startswith("www."):
        host = host[4:]
    port = parsed.port
    scheme = (parsed.scheme or "http").lower()
    default = 443 if scheme == "https" else 80
    if port and port != default:
        return f"{host}:{port}"
    return host


def _target_in_scope(target: str, scope: str) -> bool:
    t = (target or "").strip()
    s = (scope or "").strip()
    if not t or not s:
        return False
    if t in s or s in t:
        return True
    th = _scope_host(t)
    sh = _scope_host(s)
    return bool(th and sh and th == sh)


def _engagement_mismatch(body: dict | None) -> dict | None:
    req = str((body or {}).get("engagement_dir") or "").strip()
    active = CURRENT_ENGAGEMENT_DIR.name if CURRENT_ENGAGEMENT_DIR is not None else ""
    if req and active and req != active:
        return {
            "error": "engagement_superseded",
            "verdict": "engagement_superseded",
            "engagement_dir": req,
            "active_engagement_dir": active,
        }
    return None


def _save_findings_to_dir(eng_dir: Path, findings: list) -> None:
    (eng_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")


def _save_findings() -> None:
    if CURRENT_ENGAGEMENT_DIR is None:
        return
    _save_findings_to_dir(CURRENT_ENGAGEMENT_DIR, FINDINGS)


def _engagement_meta_path() -> Path | None:
    if CURRENT_ENGAGEMENT_DIR is None:
        return None
    return CURRENT_ENGAGEMENT_DIR / "meta.json"


def _save_engagement_meta() -> None:
    path = _engagement_meta_path()
    if path is None:
        return
    prev: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prev = loaded
        except (OSError, json.JSONDecodeError):
            prev = {}
    scope = CURRENT_SCOPE or {}
    meta = {
        **prev,
        "started_at": ENGAGEMENT_STARTED_AT,
        "step_count": EXEC_STEP_COUNT,
        "phase": CURRENT_PHASE,
        "last_activity": LAST_ACTIVITY,
        "target": scope.get("target") or prev.get("target") or "",
        "scope": scope.get("scope") or prev.get("scope") or "",
        "name": scope.get("name") or prev.get("name") or "",
        "objective": scope.get("objective") or prev.get("objective") or "",
        "use_ai": bool(scope.get("use_ai", prev.get("use_ai", True))),
        "status": "paused" if ENGAGEMENT_PAUSED else "running",
    }
    path.write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _read_dir_meta(eng_dir: Path) -> dict:
    meta_path = eng_dir / "meta.json"
    if not meta_path.is_file():
        return {}
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _load_engagement_meta() -> dict:
    path = _engagement_meta_path()
    if path is None or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _count_exec_log_steps(since_ts: float | None) -> int:
    if not LOG_PATH.is_file() or since_ts is None:
        return 0
    count = 0
    try:
        with LOG_PATH.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("event") != "exec":
                    continue
                if float(entry.get("ts") or 0) >= since_ts:
                    count += 1
    except OSError:
        pass
    return count


def _hydrate_engagement_metrics() -> None:
    """Recover elapsed/step counters for runs started before meta tracking."""
    global ENGAGEMENT_STARTED_AT, EXEC_STEP_COUNT, LAST_ACTIVITY
    meta = _load_engagement_meta()
    if ENGAGEMENT_STARTED_AT is None and meta.get("started_at"):
        ENGAGEMENT_STARTED_AT = float(meta["started_at"])
    if EXEC_STEP_COUNT == 0 and meta.get("step_count"):
        EXEC_STEP_COUNT = int(meta["step_count"])
    if not LAST_ACTIVITY and meta.get("last_activity"):
        LAST_ACTIVITY = str(meta["last_activity"])
    if ENGAGEMENT_STARTED_AT is None and CURRENT_ENGAGEMENT_DIR is not None:
        try:
            ENGAGEMENT_STARTED_AT = CURRENT_ENGAGEMENT_DIR.stat().st_mtime
        except OSError:
            pass
    if EXEC_STEP_COUNT == 0 and ENGAGEMENT_STARTED_AT:
        EXEC_STEP_COUNT = _count_exec_log_steps(ENGAGEMENT_STARTED_AT)


def _engagement_dir_safe(name: str) -> Path | None:
    """Resolve engagement folder by basename only (no path traversal)."""
    raw = (name or "").strip()
    if not raw or "/" in raw or "\\" in raw or ".." in raw:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", raw):
        return None
    path = (ENGAGEMENTS_ROOT / raw).resolve()
    try:
        path.relative_to(ENGAGEMENTS_ROOT.resolve())
    except ValueError:
        return None
    if not path.is_dir():
        return None
    return path


def _load_findings_from_dir(eng_dir: Path) -> list[dict]:
    findings_path = eng_dir / "findings.json"
    if not findings_path.is_file():
        return []
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _clear_active_engagement_if(eng_name: str) -> None:
    global CURRENT_SCOPE, CURRENT_PHASE, CURRENT_ENGAGEMENT_DIR, FINDINGS
    global ENGAGEMENT_STARTED_AT, LAST_ACTIVITY, EXEC_STEP_COUNT, ENGAGEMENT_PAUSED
    if CURRENT_ENGAGEMENT_DIR is None or CURRENT_ENGAGEMENT_DIR.name != eng_name:
        return
    CURRENT_SCOPE = None
    CURRENT_PHASE = 1
    CURRENT_ENGAGEMENT_DIR = None
    FINDINGS = []
    ENGAGEMENT_STARTED_AT = None
    LAST_ACTIVITY = ""
    EXEC_STEP_COUNT = 0
    ENGAGEMENT_PAUSED = False


def _resolve_engagement_name(eng_name: str | None) -> str:
    name = (eng_name or "").strip()
    if name:
        return name
    if CURRENT_ENGAGEMENT_DIR is not None:
        return CURRENT_ENGAGEMENT_DIR.name
    return ""


def _patch_disk_meta(eng_name: str, patch: dict) -> None:
    path = _engagement_dir_safe(eng_name)
    if path is None:
        return
    meta = _read_dir_meta(path)
    meta.update(patch)
    try:
        (path / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except OSError:
        pass


def _patch_history(eng_name: str, patch: dict) -> None:
    for row in SCAN_HISTORY:
        if row.get("engagement_dir") == eng_name:
            row.update(patch)
            break
    _save_scan_history()


def _pause_engagement(eng_name: str | None = None) -> dict:
    global ENGAGEMENT_PAUSED, LAST_ACTIVITY
    name = _resolve_engagement_name(eng_name)
    if not name:
        return {"error": "engagement_dir_required"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return {"error": "invalid_engagement_dir"}
    if _engagement_dir_safe(name) is None and (
        CURRENT_ENGAGEMENT_DIR is None or CURRENT_ENGAGEMENT_DIR.name != name
    ):
        return {"error": "engagement_not_found"}
    if CURRENT_ENGAGEMENT_DIR is not None and CURRENT_ENGAGEMENT_DIR.name == name and CURRENT_SCOPE:
        ENGAGEMENT_PAUSED = True
        LAST_ACTIVITY = "Pausado por operador"
        _save_engagement_meta()
    _patch_disk_meta(name, {"status": "paused", "paused_at": time.time()})
    _patch_history(name, {"status": "paused"})
    audit_log({"event": "engagement_paused", "engagement_dir": name})
    return {"ok": True, "status": "paused", "engagement_dir": name}


def _resume_engagement(eng_name: str | None = None) -> dict:
    global ENGAGEMENT_PAUSED, LAST_ACTIVITY
    name = _resolve_engagement_name(eng_name)
    if not name:
        return {"error": "engagement_dir_required"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return {"error": "invalid_engagement_dir"}
    meta = _read_dir_meta(_engagement_dir_safe(name) or Path("/nonexistent"))
    if meta.get("status") == "completed":
        return {"error": "engagement_completed"}
    is_current = (
        CURRENT_ENGAGEMENT_DIR is not None
        and CURRENT_ENGAGEMENT_DIR.name == name
        and CURRENT_SCOPE is not None
    )
    if not is_current:
        if _engagement_dir_safe(name) is None:
            return {"error": "engagement_not_found"}
        _patch_disk_meta(name, {"status": "running"})
        _patch_history(name, {"status": "running"})
        return {
            "ok": True,
            "status": "running",
            "engagement_dir": name,
            "needs_engagement_page": True,
        }
    ENGAGEMENT_PAUSED = False
    LAST_ACTIVITY = "Reanudado"
    _patch_disk_meta(name, {"status": "running"})
    _patch_history(name, {"status": "running"})
    _save_engagement_meta()
    audit_log({"event": "engagement_resumed", "engagement_dir": name})
    return {"ok": True, "status": "running", "engagement_dir": name}


def _finish_engagement(eng_name: str | None = None) -> dict:
    global CURRENT_SCOPE, CURRENT_PHASE, CURRENT_ENGAGEMENT_DIR, FINDINGS
    global ENGAGEMENT_STARTED_AT, LAST_ACTIVITY, EXEC_STEP_COUNT, ENGAGEMENT_PAUSED
    name = _resolve_engagement_name(eng_name)
    if not name:
        return {"error": "engagement_dir_required"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return {"error": "invalid_engagement_dir"}
    is_current = CURRENT_ENGAGEMENT_DIR is not None and CURRENT_ENGAGEMENT_DIR.name == name
    path = _engagement_dir_safe(name)
    if path is None and not is_current:
        return {"error": "engagement_not_found"}
    if is_current:
        _save_findings()
        phase = CURRENT_PHASE
        steps = EXEC_STEP_COUNT
    else:
        meta = _read_dir_meta(path) if path else {}
        phase = meta.get("phase") or 1
        steps = meta.get("step_count") or 0
    finished_at = time.time()
    _patch_disk_meta(name, {
        "status": "completed",
        "completed_at": finished_at,
        "phase": phase,
        "step_count": steps,
    })
    _patch_history(name, {"status": "completed", "phase": phase})
    if is_current:
        CURRENT_SCOPE = None
        CURRENT_PHASE = 1
        CURRENT_ENGAGEMENT_DIR = None
        FINDINGS = []
        ENGAGEMENT_STARTED_AT = None
        LAST_ACTIVITY = ""
        EXEC_STEP_COUNT = 0
        ENGAGEMENT_PAUSED = False
    audit_log({"event": "engagement_finished", "engagement_dir": name})
    return {"ok": True, "status": "completed", "engagement_dir": name}


def _related_engagement_ids(eng_name: str) -> list[str]:
    """Same normalized target (or same display name) — cleans duplicate cards."""
    ids = [eng_name]
    seed_path = _engagement_dir_safe(eng_name)
    seed_target = ""
    seed_name = ""
    if seed_path is not None:
        meta = _read_dir_meta(seed_path)
        seed_target = _normalize_target_key(str(meta.get("target") or _target_from_dirname(eng_name)))
        seed_name = (meta.get("name") or meta.get("objective") or "").strip().lower()
    else:
        seed_target = _normalize_target_key(_target_from_dirname(eng_name))
    if not ENGAGEMENTS_ROOT.is_dir():
        return ids
    for child in ENGAGEMENTS_ROOT.iterdir():
        if not child.is_dir() or child.name in ids:
            continue
        meta = _read_dir_meta(child)
        t = _normalize_target_key(str(meta.get("target") or _target_from_dirname(child.name)))
        n = (meta.get("name") or meta.get("objective") or "").strip().lower()
        if seed_name and n and n == seed_name:
            ids.append(child.name)
        elif (not seed_name) and (not n) and seed_target and t == seed_target:
            ids.append(child.name)
    return ids


def _delete_engagement(eng_name: str, related: bool = True) -> dict:
    names = _related_engagement_ids(eng_name) if related else [eng_name]
    deleted: list[str] = []
    for name in names:
        path = _engagement_dir_safe(name)
        _clear_active_engagement_if(name)
        if path is not None:
            shutil.rmtree(path, ignore_errors=True)
        deleted.append(name)
    global SCAN_HISTORY
    gone = set(deleted)
    SCAN_HISTORY[:] = [h for h in SCAN_HISTORY if h.get("engagement_dir") not in gone]
    _save_scan_history()
    audit_log({"event": "engagement_deleted", "engagement_dirs": deleted, "related": related})
    return {"ok": True, "deleted": deleted, "count": len(deleted)}


def _target_from_dirname(eng_id: str) -> str:
    """Invert sanitize: 127.0.0.1_8888_2026-… → 127.0.0.1:8888."""
    if "_20" not in eng_id:
        return eng_id
    base = eng_id.rsplit("_20", 1)[0]
    m = re.fullmatch(r"(.+)_(\d{1,5})", base)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    return base


def _normalize_target_key(target: str) -> str:
    t = (target or "").strip().lower()
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "_20" in t:
        t = t.rsplit("_20", 1)[0]
    t = t.replace("_", ".")
    m = re.fullmatch(r"(.+)\.(\d{1,5})", t)
    if m:
        t = f"{m.group(1)}:{m.group(2)}"
    return t


def _previous_scan_for_scope(scope: str, exclude_dir: str | None) -> dict:
    """Último engagement completado del mismo host/scope (delta OSINT)."""
    key = _scope_host(scope or "")
    empty = {"engagement_dir": None, "findings": []}
    if not key or not ENGAGEMENTS_ROOT.is_dir():
        return empty
    candidates = []
    for child in ENGAGEMENTS_ROOT.iterdir():
        if not child.is_dir() or child.name == exclude_dir:
            continue
        meta = _read_dir_meta(child)
        hist = next((h for h in SCAN_HISTORY if h.get("engagement_dir") == child.name), {})
        tgt = (
            hist.get("scope")
            or meta.get("scope")
            or hist.get("target")
            or meta.get("target")
            or ""
        )
        if _scope_host(str(tgt)) != key:
            continue
        status = str(hist.get("status") or meta.get("status") or "completed")
        if status in ("running", "paused"):
            continue
        findings = _load_findings_from_dir(child)
        titles = [
            {
                "title": f.get("title") or "",
                "severity": f.get("severity") or "",
                "asset": f.get("asset") or "",
            }
            for f in findings
            if f.get("status") != "rejected" and f.get("title")
        ]
        if not titles:
            continue
        ts = hist.get("started_at") or meta.get("started_at") or child.stat().st_mtime
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            ts_f = 0.0
        candidates.append((ts_f, child.name, titles))
    if not candidates:
        return empty
    candidates.sort(key=lambda x: x[0], reverse=True)
    _, name, titles = candidates[0]
    return {"engagement_dir": name, "findings": titles}


def _dedupe_engagement_rows(rows: list[dict]) -> list[dict]:
    """One card per name/objective, or per target if unnamed — keep more findings."""
    best: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        name = (row.get("name") or row.get("objective") or "").strip().lower()
        raw_target = str(row.get("target") or "")
        if not raw_target or "_20" in raw_target:
            raw_target = str(row.get("id") or raw_target)
        key = name or ("t:" + _normalize_target_key(raw_target or str(row.get("id") or "")))
        if not key or key == "t:":
            key = "id:" + str(row.get("id") or len(order))
        prev = best.get(key)
        if prev is None:
            best[key] = dict(row)
            best[key]["run_count"] = 1
            disp = _normalize_target_key(str(best[key].get("target") or best[key].get("id") or ""))
            if disp:
                best[key]["target"] = disp
            order.append(key)
            continue
        runs = int(prev.get("run_count") or 1) + 1
        prev_n = int(prev.get("findings_count") or 0)
        cur_n = int(row.get("findings_count") or 0)
        if prev.get("active") and not row.get("active"):
            pick = prev
        elif row.get("active") and not prev.get("active"):
            pick = row
        elif cur_n > prev_n:
            pick = row
        elif cur_n < prev_n:
            pick = prev
        else:
            prev_ts = float(prev.get("started_at") or 0)
            cur_ts = float(row.get("started_at") or 0)
            pick = row if cur_ts >= prev_ts else prev
        merged = dict(pick)
        merged["run_count"] = runs
        merged["findings_count"] = max(prev_n, cur_n)
        merged["name"] = pick.get("name") or prev.get("name") or row.get("name") or ""
        disp = _normalize_target_key(str(merged.get("target") or merged.get("id") or ""))
        if disp:
            merged["target"] = disp
        scope = str(merged.get("scope") or "")
        if re.search(r"\.\d{1,5}$", scope) and ":" not in scope:
            merged["scope"] = scope.rsplit(".", 1)[0]
        best[key] = merged
    return [best[k] for k in order]


def _list_engagements() -> list[dict]:
    """Cards for MITRE / scans: disk engagements + active run + history."""
    by_id: dict[str, dict] = {}
    history_by_dir = {
        h.get("engagement_dir"): h
        for h in SCAN_HISTORY
        if h.get("engagement_dir")
    }

    if ENGAGEMENTS_ROOT.is_dir():
        for child in sorted(ENGAGEMENTS_ROOT.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not child.is_dir():
                continue
            name = child.name
            findings = _load_findings_from_dir(child)
            hist = history_by_dir.get(name) or {}
            disk_meta = _read_dir_meta(child)
            target = hist.get("target") or disk_meta.get("target") or ""
            if not target and "_20" in name:
                target = _target_from_dirname(name)
            scope = hist.get("scope") or disk_meta.get("scope") or ""
            if not scope:
                scope = target.split(":")[0] if target else name
            mtime = child.stat().st_mtime
            display_name = (
                hist.get("name")
                or disk_meta.get("name")
                or hist.get("objective")
                or disk_meta.get("objective")
                or ""
            )
            by_id[name] = {
                "id": name,
                "engagement_dir": name,
                "target": target or name,
                "scope": scope,
                "name": display_name,
                "objective": hist.get("objective") or disk_meta.get("objective") or display_name,
                "use_ai": bool(hist.get("use_ai", disk_meta.get("use_ai", True))),
                "started_at": hist.get("started_at") or disk_meta.get("started_at") or mtime,
                "status": hist.get("status") or disk_meta.get("status") or "completed",
                "phase": hist.get("phase") or disk_meta.get("phase"),
                "findings_count": len([f for f in findings if f.get("status") != "rejected"]),
                "active": (hist.get("status") or disk_meta.get("status") or "completed") in ("running", "paused"),
            }

    if CURRENT_ENGAGEMENT_DIR is not None and CURRENT_SCOPE is not None:
        _hydrate_engagement_metrics()
        name = CURRENT_ENGAGEMENT_DIR.name
        pending = sum(1 for f in FINDINGS if f.get("status") == "proposed")
        accepted = sum(1 for f in FINDINGS if f.get("status") == "accepted")
        display_name = CURRENT_SCOPE.get("name") or CURRENT_SCOPE.get("objective") or ""
        by_id[name] = {
            "id": name,
            "engagement_dir": name,
            "target": CURRENT_SCOPE.get("target") or name,
            "scope": CURRENT_SCOPE.get("scope") or "",
            "name": display_name,
            "objective": CURRENT_SCOPE.get("objective") or display_name,
            "use_ai": bool(CURRENT_SCOPE.get("use_ai", True)),
            "started_at": ENGAGEMENT_STARTED_AT or time.time(),
            "status": "paused" if ENGAGEMENT_PAUSED else "running",
            "phase": CURRENT_PHASE,
            "findings_count": len([f for f in FINDINGS if f.get("status") != "rejected"]),
            "findings_pending": pending,
            "findings_accepted": accepted,
            "step_count": EXEC_STEP_COUNT,
            "active": True,
            "paused": ENGAGEMENT_PAUSED,
        }

    rows = list(by_id.values())
    rows.sort(key=lambda r: r.get("started_at") or 0, reverse=True)
    return _dedupe_engagement_rows(rows)[:40]


def _finding_fingerprint(title: str, asset: str = "") -> str:
    blob = f"{title} {asset}".lower()
    if ("cookie" in blob or "session" in blob) and any(
        w in blob for w in ("security", "httponly", "secure", "low")
    ):
        return f"cookie-session:{(asset or '').lower()}"
    words = sorted(set(re.findall(r"[a-z0-9]{4,}", blob)))[:6]
    if words:
        return "-".join(words)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _existing_finding_in(findings: list, title: str, asset: str) -> dict | None:
    fp = _finding_fingerprint(title, asset)
    for finding in findings:
        if finding.get("status") == "rejected":
            continue
        stored = finding.get("fingerprint") or _finding_fingerprint(
            finding.get("title", ""), finding.get("asset", "")
        )
        if stored == fp:
            return finding
    return None


def _existing_finding(title: str, asset: str) -> dict | None:
    return _existing_finding_in(FINDINGS, title, asset)


def _next_finding_id_for(findings: list) -> str:
    return f"f-{len(findings) + 1}"


def _next_finding_id() -> str:
    return _next_finding_id_for(FINDINGS)


def _apply_finding_edits(finding: dict, edited_fields: dict) -> str | None:
    for key in ("title", "asset", "severity", "description", "remediation"):
        if key in edited_fields:
            if key == "severity" and edited_fields[key] not in FINDING_SEVERITIES:
                return f"invalid_severity: must be one of {sorted(FINDING_SEVERITIES)}"
            finding[key] = edited_fields[key]
    return None


def _apply_finding_status_transition(finding: dict, action: str) -> str | None:
    """Applies a post-acceptance reporting-lifecycle transition in place.

    proposed -> accepted -> verifying -> reported (reported is terminal;
    correcting a reported finding goes through "edit" first, same escape
    hatch the accept/reject/edit flow already uses).

    Returns None on success, or an error string on invalid transition.
    Does not touch evidence, disk persistence, or audit_log — the caller
    (/findings/review handler) does that, same as the accept/reject/edit
    branches.
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


_REDACT_KEY_RE = re.compile(r"((?:^|[&?])(?:password|pwd)=)[^&\s]*", re.IGNORECASE)
_REDACT_FLAG_NAMES = {"-p", "--password", "-pass", "--pass"}


def redact_args(args: list) -> list:
    """Enmascara credenciales antes de persistirlas en audit_log.

    Cubre dos patrones: (1) curl -d "email=x&password=secret" — la key
    password=/pwd= dentro de un body concatenado en un solo arg (regex
    inline, sin tocar el resto del body); (2) hydra -p <valor> / netexec
    --password <valor> — flag y valor en args SEPARADOS, se redacta el arg
    que sigue al flag conocido. _token (CSRF) no se toca: no es secreto de
    cuenta, es útil para depurar un login fallido.
    """
    redacted = []
    redact_next = False
    for a in args:
        s = str(a)
        if redact_next:
            redacted.append("***REDACTED***")
            redact_next = False
            continue
        if s.lower() in _REDACT_FLAG_NAMES:
            redacted.append(s)
            redact_next = True
            continue
        redacted.append(_REDACT_KEY_RE.sub(r"\1***REDACTED***", s))
    return redacted


def audit_log(entry: dict) -> None:
    entry["ts"] = time.time()
    with LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _load_scan_history() -> list[dict]:
    try:
        if HISTORY_FILE.is_file():
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return []


def _save_scan_history() -> None:
    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        HISTORY_FILE.write_text(json.dumps(SCAN_HISTORY[:50], indent=2), encoding="utf-8")
    except OSError:
        pass


DEFAULT_CLOUD_ENDPOINT = "https://ollama.com/v1/chat/completions"


def _models_url_from_chat_endpoint(endpoint: str) -> str | None:
    endpoint = endpoint.strip()
    if endpoint.endswith("/chat/completions"):
        return endpoint[: -len("/chat/completions")] + "/models"
    if endpoint.rstrip("/").endswith("/v1"):
        return endpoint.rstrip("/") + "/models"
    return None


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


def _forward_llm_get(endpoint: str, api_key: str | None) -> dict:
    headers: dict[str, str] = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(endpoint, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
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


def _parse_models_response(body: dict | list) -> list[str]:
    if isinstance(body, list):
        ids = [str(item.get("name") or item.get("id") or item.get("model") or "") for item in body]
    elif isinstance(body, dict):
        data = body.get("data") or body.get("models") or []
        ids = [str(item.get("id") or item.get("name") or item.get("model") or "") for item in data]
    else:
        return []
    return sorted({model_id for model_id in ids if model_id})


def _is_quota_error(result: dict) -> bool:
    # 429 = rate-limited, 402 = no credit/plan expired on this account — both
    # mean "this key is done for now, try the next one", not a real API
    # failure. Neither should ever surface to the model as "invalid JSON".
    if result["status"] in (402, 429):
        return True
    if 200 <= result["status"] < 300:
        return False
    return bool(re.search(r"quota|rate.?limit|payment.?required|insufficient.?credit", json.dumps(result["body"]).lower()))


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
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def _truncate_output(text: str) -> str:
    text = _strip_ansi(text)
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
    def _apply_cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in CORS_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auditor-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Vary", "Origin")

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors()
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
        # No /session HTTP endpoint: AUTH_TOKEN is never disclosed over the
        # network to an unauthenticated caller. It travels two ways only:
        # the printed startup URL, and SESSION_FILE (0600, same local user)
        # for the panel to read directly off disk — see _read_passphrase's
        # sibling write below and panel/server.py's _bridge_session_token.
        if path == "/":
            path = "/index.html"
        file_path = (STATIC_DIR / path.lstrip("/")).resolve()
        if STATIC_DIR not in file_path.parents and file_path != STATIC_DIR:
            self._send_json(403, {"error": "forbidden"})
            return
        if not file_path.is_file():
            self._send_json(404, {"error": "not found"})
            return
        content_type = "text/html; charset=utf-8"
        if file_path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif file_path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self._apply_cors()
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        if not self._host_ok():
            self._send_json(403, {"error": "forbidden_host"})
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._apply_cors()
        self.end_headers()

    def do_POST(self) -> None:
        try:
            self._handle_post()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
        except Exception as e:
            audit_log({"event": "handler_error", "path": self.path, "error": str(e)})
            self._send_json(500, {"error": "internal_error", "detail": str(e)})

    def _handle_post(self) -> None:
        global CURRENT_SCOPE, CURRENT_PHASE, CURRENT_ENGAGEMENT_DIR, FINDINGS, KEYS, PASSPHRASE, ROTATION_STATE
        global ENGAGEMENT_STARTED_AT, LAST_ACTIVITY, EXEC_STEP_COUNT, SCAN_HISTORY, ENGAGEMENT_PAUSED
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
            name = (body.get("name") or body.get("objective") or "").strip()
            objective = (body.get("objective") or name).strip()
            use_ai = bool(body.get("use_ai", True))
            if not target or not scope:
                self._send_json(400, {"error": "target and scope required"})
                return
            prev_dir = None
            if CURRENT_ENGAGEMENT_DIR is not None and CURRENT_SCOPE is not None:
                prev_dir = CURRENT_ENGAGEMENT_DIR.name
                _save_findings()
                _save_engagement_meta()
            CURRENT_SCOPE = {
                "target": target,
                "scope": scope,
                "name": name,
                "objective": objective,
                "use_ai": use_ai,
            }
            CURRENT_PHASE = 1
            ENGAGEMENT_PAUSED = False
            ENGAGEMENT_STARTED_AT = time.time()
            EXEC_STEP_COUNT = 0
            LAST_ACTIVITY = "Engagement iniciado" + (" (playbook)" if not use_ai else " (IA)")
            engagement_dir_name = f"{_sanitize_for_path(target)}_{time.strftime('%Y-%m-%dT%H-%M-%S')}"
            CURRENT_ENGAGEMENT_DIR = Path.home() / ".auditor" / "engagements" / engagement_dir_name
            (CURRENT_ENGAGEMENT_DIR / "evidence").mkdir(parents=True, exist_ok=True)
            FINDINGS = []
            SCAN_HISTORY.insert(0, {
                "target": target,
                "scope": scope,
                "name": name,
                "objective": objective,
                "use_ai": use_ai,
                "started_at": ENGAGEMENT_STARTED_AT,
                "engagement_dir": engagement_dir_name,
                "status": "running",
                "phase": 1,
            })
            _save_scan_history()
            _save_engagement_meta()
            if prev_dir and prev_dir != engagement_dir_name:
                _patch_disk_meta(prev_dir, {
                    "status": "superseded",
                    "superseded_at": time.time(),
                    "superseded_by": engagement_dir_name,
                })
                _patch_history(prev_dir, {"status": "superseded"})
                audit_log({
                    "event": "engagement_superseded",
                    "engagement_dir": prev_dir,
                    "by": engagement_dir_name,
                })
            audit_log({
                "event": "engagement_start",
                "target": target,
                "scope": scope,
                "name": name,
                "use_ai": use_ai,
                "engagement_dir": engagement_dir_name,
                "superseded": prev_dir,
            })
            self._send_json(200, {
                "ok": True,
                "engagement_dir": engagement_dir_name,
                "name": name,
                "use_ai": use_ai,
                "superseded": prev_dir,
            })
            return

        if self.path == "/exec":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            tool = body.get("tool", "")
            args = body.get("args", [])
            target = body.get("target", "")
            mismatch = _engagement_mismatch(body)
            if mismatch:
                audit_log({
                    "event": "engagement_superseded",
                    "tool": tool,
                    "engagement_dir": mismatch.get("engagement_dir"),
                    "active": mismatch.get("active_engagement_dir"),
                })
                self._send_json(409, mismatch)
                return

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
            in_scope = _target_in_scope(target, scope)
            if not in_scope:
                audit_log({"event": "scope_violation", "tool": tool, "target": target, "scope": scope})
                self._send_json(403, {"error": "scope_violation", "verdict": "scope_violation"})
                return

            # Resolve to the actual binary PATH would pick before running it,
            # so the audit log records exactly what executed (not just the
            # whitelisted name) — closes the gap between "name we approved"
            # and "binary that actually ran" if PATH ever resolves oddly.
            # Also maps GetNPUsers.py → impacket-GetNPUsers on Kali.
            resolved = resolve_tool_path(tool)
            if resolved is None:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
                audit_log({"event": "exec", "tool": tool, "args": redact_args(args),
                           "target": target, "exit_code": result["exit_code"],
                           "verdict": result["verdict"]})
                self._send_json(200, result)
                return

            exec_args, stdout_tmp_path = rewrite_stdout_placeholder([str(a) for a in args], tool)
            cmd = [resolved] + exec_args
            timeout_s = 300 if tool in ("nikto", "bloodhound-python", "wpscan", "katana", "wapiti") else 120
            run_cwd = None
            if tool == "bloodhound-python" and CURRENT_ENGAGEMENT_DIR is not None:
                # JSON/zip del ingestor → evidence del engagement (no cwd del bridge).
                run_cwd = str(CURRENT_ENGAGEMENT_DIR / "evidence" / "bloodhound")
                Path(run_cwd).mkdir(parents=True, exist_ok=True)
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_s,
                    cwd=run_cwd,
                )
                result = {"stdout": _truncate_output(proc.stdout),
                          "stderr": _truncate_output(proc.stderr),
                          "exit_code": proc.returncode, "verdict": "ok"}
                if run_cwd:
                    result["cwd"] = run_cwd
            except subprocess.TimeoutExpired as exc:
                # Conservar stdout parcial (p. ej. katana ya listó URLs antes
                # del corte): sin esto el playbook marca timeout vacío y no
                # emite finding ni tarjeta útil en el feed.
                partial_out = exc.stdout if isinstance(exc.stdout, str) else (
                    exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
                )
                partial_err = exc.stderr if isinstance(exc.stderr, str) else (
                    exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
                )
                err_bits = [partial_err.strip(), f"timeout after {timeout_s}s"]
                result = {
                    "stdout": _truncate_output(partial_out),
                    "stderr": _truncate_output("\n".join(b for b in err_bits if b)),
                    "exit_code": -1,
                    "verdict": "timeout",
                }
                if run_cwd:
                    result["cwd"] = run_cwd
            except FileNotFoundError:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
            except OSError as e:
                result = {"stdout": "", "stderr": str(e),
                          "exit_code": -1, "verdict": "error"}
            if stdout_tmp_path:
                # wapiti/arjun escribieron su JSON real en el tempfile (ver
                # rewrite_stdout_placeholder); su stdout de proceso queda
                # vacío/con logs, así que el contenido útil se agrega aquí.
                file_content = _truncate_output(read_and_cleanup_tempfile(stdout_tmp_path))
                if file_content:
                    result["stdout"] = f"{result['stdout']}\n{file_content}".strip() if result.get("stdout") else file_content
            audit_log({"event": "exec", "tool": tool, "resolved_path": resolved,
                       "args": redact_args(args), "target": target,
                       "cwd": run_cwd,
                       "exit_code": result["exit_code"], "verdict": result["verdict"]})
            EXEC_STEP_COUNT += 1
            arg_preview = " ".join(str(a) for a in args[:4])
            LAST_ACTIVITY = f"{tool} {arg_preview}".strip()
            _save_engagement_meta()
            self._send_json(200, result)
            return

        if self.path == "/llm/models":
            body = self._read_json()
            chat_endpoint = (body.get("endpoint") or DEFAULT_CLOUD_ENDPOINT).strip()
            models_url = _models_url_from_chat_endpoint(chat_endpoint)
            if not models_url or models_url not in ALLOWED_LLM_MODELS_ENDPOINTS:
                self._send_json(403, {"error": "endpoint_not_allowlisted"})
                return

            api_key = None
            if models_url.startswith("https://ollama.com/"):
                with STATE_LOCK:
                    if ROTATION_STATE and ROTATION_STATE["pool"]:
                        api_key = ROTATION_STATE["pool"][0]["api_key"]
                    elif KEYS:
                        api_key = KEYS[0]["api_key"]
                if not api_key:
                    self._send_json(400, {"error": "no_keys_for_models"})
                    return

            result = _forward_llm_get(models_url, api_key)
            if not (200 <= result["status"] < 300):
                self._send_json(result["status"], {
                    "error": "models_fetch_failed",
                    "detail": result["body"],
                })
                return
            models = _parse_models_response(result["body"])
            self._send_json(200, {"models": models})
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
            verify = body.get("verify", True)
            if not api_key:
                self._send_json(400, {"error": "api_key_required"})
                return
            if not label:
                label = f"ollama-{api_key[-4:]}"
            try:
                window_hours = float(window_hours_raw) if window_hours_raw not in (None, "") else 24.0
            except (TypeError, ValueError):
                self._send_json(400, {"error": "window_hours_must_be_a_number"})
                return
            if window_hours <= 0:
                self._send_json(400, {"error": "window_hours_must_be_positive"})
                return

            models: list[str] = []
            if verify:
                verify_result = _forward_llm_get("https://ollama.com/v1/models", api_key)
                if not (200 <= verify_result["status"] < 300):
                    self._send_json(400, {
                        "error": "invalid_api_key",
                        "detail": verify_result["body"],
                    })
                    return
                models = _parse_models_response(verify_result["body"])
                if not models:
                    self._send_json(400, {"error": "invalid_api_key", "detail": "no_models_returned"})
                    return

            with STATE_LOCK:
                if len(KEYS) >= MAX_KEYS:
                    self._send_json(400, {"error": f"key_pool_full: max {MAX_KEYS} keys"})
                    return
                existing_labels = {k["label"] for k in KEYS}
                final_label = label
                suffix = 2
                while final_label in existing_labels:
                    final_label = f"{label}-{suffix}"
                    suffix += 1
                KEYS.append({"label": final_label, "api_key": api_key, "window_hours": window_hours})
                keystore.save(PASSPHRASE, KEYS)
            audit_log({"event": "key_added", "label": final_label, "verified": bool(verify)})
            self._send_json(200, {
                "ok": True,
                "label": final_label,
                "verified": bool(verify),
                "models": models,
            })
            return

        if self.path == "/keys/delete":
            body = self._read_json()
            label = body.get("label", "").strip()
            if not label:
                self._send_json(400, {"error": "label_required"})
                return
            with STATE_LOCK:
                before = len(KEYS)
                KEYS[:] = [k for k in KEYS if k["label"] != label]
                if len(KEYS) == before:
                    self._send_json(404, {"error": "label_not_found"})
                    return
                keystore.save(PASSPHRASE, KEYS)
            audit_log({"event": "key_deleted", "label": label})
            self._send_json(200, {"ok": True})
            return

        if self.path == "/keys/update":
            body = self._read_json()
            label = body.get("label", "").strip()
            if not label:
                self._send_json(400, {"error": "label_required"})
                return
            window_hours_raw = body.get("window_hours")
            new_label = body.get("new_label", "").strip()
            with STATE_LOCK:
                record = next((k for k in KEYS if k["label"] == label), None)
                if record is None:
                    self._send_json(404, {"error": "label_not_found"})
                    return
                if window_hours_raw not in (None, ""):
                    try:
                        window_hours = float(window_hours_raw)
                    except (TypeError, ValueError):
                        self._send_json(400, {"error": "window_hours_must_be_a_number"})
                        return
                    if window_hours <= 0:
                        self._send_json(400, {"error": "window_hours_must_be_positive"})
                        return
                    record["window_hours"] = window_hours
                if new_label and new_label != label:
                    if any(k["label"] == new_label for k in KEYS if k is not record):
                        self._send_json(400, {"error": "label_already_exists"})
                        return
                    record["label"] = new_label
                keystore.save(PASSPHRASE, KEYS)
                out = {
                    "label": record["label"],
                    "last4": record["api_key"][-4:],
                    "window_hours": record["window_hours"],
                }
            audit_log({"event": "key_updated", "label": out["label"]})
            self._send_json(200, {"ok": True, **out})
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

        if self.path == "/status":
            if CURRENT_SCOPE is None:
                self._send_json(200, {"active": False, "history": SCAN_HISTORY[:20]})
                return
            _hydrate_engagement_metrics()
            pending = sum(1 for f in FINDINGS if f["status"] == "proposed")
            accepted = sum(1 for f in FINDINGS if f["status"] == "accepted")
            elapsed = int(time.time() - ENGAGEMENT_STARTED_AT) if ENGAGEMENT_STARTED_AT else 0
            phase_floor = max(0, (CURRENT_PHASE - 1) * 25)
            step_bonus = min(EXEC_STEP_COUNT, 12) * 2
            progress = min(99, max(5, phase_floor + step_bonus)) if CURRENT_SCOPE else 0
            badge = "Paused" if ENGAGEMENT_PAUSED else (
                "Scanning" if CURRENT_PHASE <= 1 else "Analyzing" if CURRENT_PHASE <= 2 else "Exploiting"
            )
            prev_dir = CURRENT_ENGAGEMENT_DIR.name if CURRENT_ENGAGEMENT_DIR else None
            previous_scan = _previous_scan_for_scope(
                CURRENT_SCOPE.get("scope") or CURRENT_SCOPE.get("target") or "",
                prev_dir,
            )
            self._send_json(200, {
                "active": True,
                "paused": ENGAGEMENT_PAUSED,
                "run_status": "paused" if ENGAGEMENT_PAUSED else "running",
                "target": CURRENT_SCOPE["target"],
                "scope": CURRENT_SCOPE["scope"],
                "name": CURRENT_SCOPE.get("name") or "",
                "objective": CURRENT_SCOPE.get("objective") or "",
                "use_ai": bool(CURRENT_SCOPE.get("use_ai", True)),
                "phase": CURRENT_PHASE,
                "max_phase": MAX_PHASE,
                "phase_name": PHASE_NAMES.get(CURRENT_PHASE, ""),
                "findings_pending": pending,
                "findings_accepted": accepted,
                "started_at": ENGAGEMENT_STARTED_AT,
                "elapsed_seconds": elapsed,
                "progress_pct": progress,
                "current_activity": LAST_ACTIVITY or "—",
                "step_count": EXEC_STEP_COUNT,
                "status_badge": badge,
                "engagement_dir": CURRENT_ENGAGEMENT_DIR.name if CURRENT_ENGAGEMENT_DIR else None,
                "history": SCAN_HISTORY[:20],
                "previous_scan": previous_scan,
            })
            return

        if self.path == "/engagements/list":
            self._send_json(200, {"engagements": _list_engagements()})
            return

        if self.path == "/engagements/delete":
            body = self._read_json()
            eng_name = (body.get("engagement_dir") or body.get("id") or "").strip()
            if not eng_name:
                self._send_json(400, {"error": "engagement_dir_required"})
                return
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", eng_name):
                self._send_json(400, {"error": "invalid_engagement_dir"})
                return
            related = bool(body.get("related", True))
            result = _delete_engagement(eng_name, related=related)
            self._send_json(200, result)
            return

        if self.path == "/engagements/pause":
            body = self._read_json()
            eng_name = (body.get("engagement_dir") or body.get("id") or "").strip() or None
            result = _pause_engagement(eng_name)
            code = 400 if result.get("error") else 200
            self._send_json(code, result)
            return

        if self.path == "/engagements/resume":
            body = self._read_json()
            eng_name = (body.get("engagement_dir") or body.get("id") or "").strip() or None
            result = _resume_engagement(eng_name)
            code = 400 if result.get("error") else 200
            self._send_json(code, result)
            return

        if self.path == "/engagements/finish":
            body = self._read_json()
            eng_name = (body.get("engagement_dir") or body.get("id") or "").strip() or None
            result = _finish_engagement(eng_name)
            code = 400 if result.get("error") else 200
            self._send_json(code, result)
            return

        if self.path == "/engagements/findings":
            body = self._read_json()
            eng_name = (body.get("engagement_dir") or body.get("id") or "").strip()
            if not eng_name:
                self._send_json(400, {"error": "engagement_dir_required"})
                return
            # Active in-memory engagement
            if (
                CURRENT_ENGAGEMENT_DIR is not None
                and CURRENT_ENGAGEMENT_DIR.name == eng_name
            ):
                self._send_json(200, {"engagement_dir": eng_name, "findings": FINDINGS, "active": True})
                return
            eng_path = _engagement_dir_safe(eng_name)
            if eng_path is None:
                self._send_json(404, {"error": "engagement_not_found"})
                return
            self._send_json(200, {
                "engagement_dir": eng_name,
                "findings": _load_findings_from_dir(eng_path),
                "active": False,
            })
            return

        if self.path == "/phase/advance":
            body = self._read_json()
            mismatch = _engagement_mismatch(body)
            if mismatch:
                self._send_json(409, mismatch)
                return
            if CURRENT_PHASE >= MAX_PHASE:
                self._send_json(200, {"ok": True, "phase": CURRENT_PHASE, "already_at_max": True})
                return
            CURRENT_PHASE += 1
            LAST_ACTIVITY = f"Fase {CURRENT_PHASE}: {PHASE_NAMES.get(CURRENT_PHASE, '')}"
            _save_engagement_meta()
            audit_log({"event": "phase_advanced", "from": CURRENT_PHASE - 1, "to": CURRENT_PHASE})
            self._send_json(200, {"ok": True, "phase": CURRENT_PHASE,
                                   "unlocked_tools": sorted(PHASE_TOOLS.get(CURRENT_PHASE, set()))})
            return

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

        if self.path == "/tools/scan-source":
            if CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            body = self._read_json()
            tool = body.get("tool", "")
            content = body.get("content", "")
            filename = body.get("filename", "leaked")
            target = body.get("target", "")

            if tool not in SCAN_SOURCE_TOOLS:
                audit_log({"event": "scan_source_tool_not_allowlisted", "tool": tool})
                self._send_json(403, {"error": "tool_not_allowlisted", "verdict": "tool_not_allowlisted"})
                return
            if tool not in cumulative_phase_tools(CURRENT_PHASE):
                audit_log({"event": "phase_locked", "tool": tool, "current_phase": CURRENT_PHASE})
                self._send_json(403, {"error": "phase_locked", "verdict": "phase_locked"})
                return
            scope = CURRENT_SCOPE["scope"]
            if not _target_in_scope(target, scope):
                audit_log({"event": "scope_violation", "tool": tool, "target": target, "scope": scope})
                self._send_json(403, {"error": "scope_violation", "verdict": "scope_violation"})
                return
            if not isinstance(content, str) or not content.strip():
                self._send_json(400, {"error": "empty_content"})
                return
            if len(content.encode("utf-8", errors="replace")) > MAX_SCAN_SOURCE_BYTES:
                self._send_json(400, {"error": "content_too_large"})
                return

            resolved = resolve_tool_path(tool)
            if resolved is None:
                result = {"stdout": "", "stderr": f"{tool}: command not found",
                          "exit_code": -1, "verdict": "error"}
                self._send_json(200, result)
                return

            # Nombre de fichero saneado (solo la extensión importa para el
            # analizador de lenguaje del tool) — nunca se usa el filename
            # del cliente como ruta real, solo como sufijo.
            safe_suffix = "".join(c for c in os.path.splitext(filename)[1] if c.isalnum() or c == ".")[:10] or ".txt"
            fd, tmp_path = tempfile.mkstemp(suffix=safe_suffix, prefix="ds-scan-")
            try:
                os.chmod(tmp_path, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)
                cmd = [resolved] + SCAN_SOURCE_TOOLS[tool] + [tmp_path]
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True,
                                           encoding="utf-8", errors="replace", timeout=45)
                    stdout = _truncate_output(proc.stdout).replace(tmp_path, filename)
                    stderr = _truncate_output(proc.stderr).replace(tmp_path, filename)
                    result = {"stdout": stdout, "stderr": stderr,
                              "exit_code": proc.returncode, "verdict": "ok"}
                except subprocess.TimeoutExpired:
                    result = {"stdout": "", "stderr": f"{tool}: timeout", "exit_code": -1, "verdict": "timeout"}
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            audit_log({"event": "scan_source", "tool": tool, "filename": filename,
                       "bytes": len(content), "exit_code": result["exit_code"]})
            self._send_json(200, result)
            return

        if self.path == "/findings/propose":
            body = self._read_json()
            mismatch = _engagement_mismatch(body)
            disk_dir = None
            findings_ref = FINDINGS
            if mismatch:
                disk_dir = _engagement_dir_safe(str(body.get("engagement_dir") or ""))
                if disk_dir is None:
                    self._send_json(409, mismatch)
                    return
                findings_ref = _load_findings_from_dir(disk_dir)
            elif CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
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
            existing = _existing_finding_in(findings_ref, title, asset)
            if existing:
                self._send_json(200, {**existing, "duplicate": True})
                return
            finding = {
                "id": _next_finding_id_for(findings_ref),
                "title": title, "asset": asset, "severity": severity,
                "description": description, "remediation": remediation,
                "evidence_step_ids": evidence_step_ids, "evidence_hashes": [],
                "status": "proposed",
                "fingerprint": _finding_fingerprint(title, asset),
                "created_at": time.time(), "reviewed_at": None,
            }
            findings_ref.append(finding)
            if disk_dir is not None:
                _save_findings_to_dir(disk_dir, findings_ref)
            else:
                _save_findings()
            audit_log({"event": "finding_proposed", "id": finding["id"], "title": title, "severity": severity})
            self._send_json(200, finding)
            return

        if self.path == "/findings/list":
            body = self._read_json()
            req_dir = str(body.get("engagement_dir") or "").strip()
            if req_dir:
                if CURRENT_ENGAGEMENT_DIR is not None and CURRENT_ENGAGEMENT_DIR.name == req_dir:
                    self._send_json(200, FINDINGS)
                    return
                eng_path = _engagement_dir_safe(req_dir)
                if eng_path is None:
                    self._send_json(200, [])
                    return
                self._send_json(200, _load_findings_from_dir(eng_path))
                return
            if CURRENT_SCOPE is None:
                self._send_json(200, [])
                return
            self._send_json(200, FINDINGS)
            return

        if self.path == "/findings/review":
            body = self._read_json()
            mismatch = _engagement_mismatch(body)
            finding_id = body.get("finding_id", "")
            action = body.get("action", "")
            disk_dir = None
            findings_ref = FINDINGS
            evidence_root = CURRENT_ENGAGEMENT_DIR
            if mismatch:
                disk_dir = _engagement_dir_safe(str(body.get("engagement_dir") or ""))
                if disk_dir is None:
                    self._send_json(409, mismatch)
                    return
                findings_ref = _load_findings_from_dir(disk_dir)
                evidence_root = disk_dir
            elif CURRENT_SCOPE is None:
                self._send_json(400, {"error": "no_active_engagement"})
                return
            finding = next((f for f in findings_ref if f["id"] == finding_id), None)
            if finding is None:
                self._send_json(404, {"error": "finding_not_found"})
                return
            if action not in {"accept", "reject", "edit", "verify", "mark_reported"}:
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
                if evidence_root is not None:
                    (evidence_root / "evidence").mkdir(parents=True, exist_ok=True)
                    for entry in evidence_texts:
                        output = entry.get("output", "")
                        output_bytes = output.encode("utf-8")
                        digest = hashlib.sha256(output_bytes).hexdigest()
                        (evidence_root / "evidence" / f"{digest}.txt").write_bytes(output_bytes)
                        hashes.append(digest)
                finding["evidence_hashes"] = hashes
                finding["status"] = "accepted"
                finding["reviewed_at"] = time.time()
            elif action in ("verify", "mark_reported"):
                error = _apply_finding_status_transition(finding, action)
                if error:
                    self._send_json(409 if error == "invalid_transition" else 400,
                                     {"error": error})
                    return

            if disk_dir is not None:
                _save_findings_to_dir(disk_dir, findings_ref)
            else:
                _save_findings()
            audit_log({"event": "finding_reviewed", "id": finding_id, "action": action})
            self._send_json(200, finding)
            return

        self._send_json(404, {"error": "unknown endpoint"})

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


def _read_passphrase() -> str:
    env = os.environ.get("AUDITOR_KEYSTORE_PASSPHRASE")
    if env is not None:
        return env
    prompt = "Auditor keystore passphrase (used to encrypt/decrypt your API keys): "
    try:
        if sys.stdin.isatty():
            return getpass.getpass(prompt)
    except (EOFError, OSError):
        pass
    return input(prompt)


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


def _start_embedded_panel():
    """Sirve panel/ en 127.0.0.1:8080 en un hilo. Ctrl+C del motor también lo baja."""
    if os.environ.get("AUDITOR_NO_PANEL", "").strip() in {"1", "true", "yes"}:
        print("Panel: omitido (AUDITOR_NO_PANEL). Arráncalo a mano: cd panel && python3 server.py")
        return None
    if _port_open("127.0.0.1", 8080):
        print("Panel: ya había algo en http://127.0.0.1:8080/ — no abro otro.")
        return None
    panel_py = Path(__file__).resolve().parent.parent / "panel" / "server.py"
    if not panel_py.is_file():
        print(f"Panel: no encontré {panel_py}")
        print("  Arráncalo a mano: cd panel && python3 server.py")
        return None
    spec = importlib.util.spec_from_file_location("ds_panel_server", panel_py)
    if spec is None or spec.loader is None:
        print("Panel: no pude cargar panel/server.py")
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", 8080), mod.PanelHandler)
    except OSError as e:
        print(f"Panel: no se pudo abrir 127.0.0.1:8080 ({e}).")
        print("  Si quedó un server.py viejo: fuser -k 8080/tcp")
        return None
    thread = threading.Thread(target=httpd.serve_forever, name="ds-panel", daemon=True)
    thread.start()
    print("Panel:    http://127.0.0.1:8080/start-engagement.html")
    return httpd


if __name__ == "__main__":
    PASSPHRASE = _read_passphrase()
    try:
        KEYS = keystore.load_or_init(PASSPHRASE)
    except ValueError:
        print("Passphrase incorrecta para el keystore existente (~/.auditor/keys.enc).")
        print("Si la olvidaste, bórralo y vuelve a arrancar (tendrás que reingresar las API keys):")
        print("  rm ~/.auditor/keys.enc")
        raise SystemExit(1)
    SCAN_HISTORY = _load_scan_history()
    print(f"Loaded {len(KEYS)} stored API key(s).")

    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.parent.chmod(0o700)
    fd = os.open(str(SESSION_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, AUTH_TOKEN.encode("utf-8"))
    finally:
        os.close(fd)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 8420), Handler)
    except OSError as e:
        print(f"No se pudo abrir 127.0.0.1:8420 ({e}).")
        print("Hay otra instancia de bridge.py (u otro proceso) usando el puerto. Ciérrala y reintenta:")
        print("  fuser -k 8420/tcp")
        print("  python3 bridge.py")
        raise SystemExit(1)

    print("=" * 56)
    print("  Dark Spear — motor + consola")
    print("  Motor:  http://127.0.0.1:8420/")
    panel_httpd = _start_embedded_panel()
    print("  Abre el panel (no uses file://):")
    print("    http://127.0.0.1:8080/start-engagement.html")
    print("  Ctrl+C detiene motor y panel")
    print("=" * 56)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDeteniendo…")
    finally:
        if panel_httpd is not None:
            try:
                panel_httpd.shutdown()
            except Exception:
                pass
            panel_httpd.server_close()
        server.server_close()
