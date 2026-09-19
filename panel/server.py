#!/usr/bin/env python3
"""Servidor local del panel visual Auditor SecOps Console."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 8420
BRIDGE_BASE = f"http://{BRIDGE_HOST}:{BRIDGE_PORT}"
SESSION_FILE = Path.home() / ".auditor" / "session.token"
ENGAGEMENTS_ROOT = Path.home() / ".auditor" / "engagements"
HISTORY_FILE = Path.home() / ".auditor" / "scan_history.json"
OLLAMA_MODELS_URL = "https://ollama.com/v1/models"
# Fixed, never reflected — this panel is the only origin allowed to read
# responses (including ones carrying the session token) from this server.
PANEL_ORIGIN = "http://127.0.0.1:8080"


def _read_json_file(path: Path, default):
    if not path.is_file():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data
    except (OSError, json.JSONDecodeError):
        return default


def _safe_engagement_dir(name: str) -> Path | None:
    raw = (name or "").strip()
    if not raw or "/" in raw or "\\" in raw or ".." in raw:
        return None
    if any(c for c in raw if not (c.isalnum() or c in "_.-")):
        return None
    path = (ENGAGEMENTS_ROOT / raw).resolve()
    try:
        path.relative_to(ENGAGEMENTS_ROOT.resolve())
    except ValueError:
        return None
    return path if path.is_dir() else None


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


def _list_engagements_from_disk() -> list[dict]:
    """Fallback when bridge is down — same card shape as bridge /engagements/list."""
    history = _read_json_file(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []
    history_by_dir = {
        h.get("engagement_dir"): h
        for h in history
        if isinstance(h, dict) and h.get("engagement_dir")
    }
    rows: list[dict] = []
    if not ENGAGEMENTS_ROOT.is_dir():
        return rows
    for child in sorted(ENGAGEMENTS_ROOT.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if not child.is_dir():
            continue
        eng_id = child.name
        findings = _read_json_file(child / "findings.json", [])
        if not isinstance(findings, list):
            findings = []
        meta = _read_json_file(child / "meta.json", {})
        if not isinstance(meta, dict):
            meta = {}
        hist = history_by_dir.get(eng_id) or {}
        target = hist.get("target") or meta.get("target") or ""
        if not target and "_20" in eng_id:
            target = _target_from_dirname(eng_id)
        scope = hist.get("scope") or meta.get("scope") or ""
        if not scope:
            scope = target.split(":")[0] if target else eng_id
        display_name = (
            hist.get("name")
            or meta.get("name")
            or hist.get("objective")
            or meta.get("objective")
            or ""
        )
        rows.append({
            "id": eng_id,
            "engagement_dir": eng_id,
            "target": target or eng_id,
            "scope": scope,
            "name": display_name,
            "objective": hist.get("objective") or meta.get("objective") or display_name,
            "use_ai": bool(hist.get("use_ai", meta.get("use_ai", True))),
            "started_at": hist.get("started_at") or meta.get("started_at") or child.stat().st_mtime,
            "status": hist.get("status") or "completed",
            "phase": hist.get("phase") or meta.get("phase"),
            "findings_count": len([f for f in findings if isinstance(f, dict) and f.get("status") != "rejected"]),
            "active": False,
            "from_disk": True,
        })
    return _dedupe_engagement_rows(rows)[:40]


def _findings_from_disk(eng_name: str) -> dict | None:
    eng_path = _safe_engagement_dir(eng_name)
    if eng_path is None:
        return None
    findings = _read_json_file(eng_path / "findings.json", [])
    if not isinstance(findings, list):
        findings = []
    return {"engagement_dir": eng_name, "findings": findings, "active": False, "from_disk": True}


def _related_engagement_ids_disk(eng_name: str) -> list[str]:
    ids = [eng_name]
    seed = _safe_engagement_dir(eng_name)
    seed_target = ""
    seed_name = ""
    if seed is not None:
        meta = _read_json_file(seed / "meta.json", {})
        if not isinstance(meta, dict):
            meta = {}
        seed_target = _normalize_target_key(str(meta.get("target") or _target_from_dirname(eng_name)))
        seed_name = (meta.get("name") or meta.get("objective") or "").strip().lower()
    else:
        seed_target = _normalize_target_key(_target_from_dirname(eng_name))
    if not ENGAGEMENTS_ROOT.is_dir():
        return ids
    for child in ENGAGEMENTS_ROOT.iterdir():
        if not child.is_dir() or child.name in ids:
            continue
        meta = _read_json_file(child / "meta.json", {})
        if not isinstance(meta, dict):
            meta = {}
        t = _normalize_target_key(str(meta.get("target") or _target_from_dirname(child.name)))
        n = (meta.get("name") or meta.get("objective") or "").strip().lower()
        if seed_name and n and n == seed_name:
            ids.append(child.name)
        elif (not seed_name) and (not n) and seed_target and t == seed_target:
            ids.append(child.name)
    return ids


def _control_engagement_on_disk(eng_name: str, action: str) -> dict:
    import time as _time
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", eng_name or ""):
        return {"error": "invalid_engagement_dir"}
    path = _safe_engagement_dir(eng_name)
    if path is None:
        return {"error": "engagement_not_found"}
    meta = _read_json_file(path / "meta.json", {})
    if not isinstance(meta, dict):
        meta = {}
    if action == "pause":
        meta["status"] = "paused"
        meta["paused_at"] = _time.time()
    elif action == "resume":
        if meta.get("status") == "completed":
            return {"error": "engagement_completed"}
        meta["status"] = "running"
        meta.pop("paused_at", None)
    elif action == "finish":
        meta["status"] = "completed"
        meta["completed_at"] = _time.time()
    else:
        return {"error": "invalid_action"}
    try:
        (path / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except OSError:
        return {"error": "write_failed"}
    history = _read_json_file(HISTORY_FILE, [])
    if isinstance(history, list):
        for row in history:
            if isinstance(row, dict) and row.get("engagement_dir") == eng_name:
                row["status"] = meta.get("status")
                if action == "finish":
                    row["phase"] = meta.get("phase") or row.get("phase")
                break
        try:
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            HISTORY_FILE.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")
        except OSError:
            pass
    return {"ok": True, "status": meta.get("status"), "engagement_dir": eng_name, "from_disk": True}


def _delete_engagement_from_disk(eng_name: str, related: bool = True) -> dict:
    import shutil
    names = _related_engagement_ids_disk(eng_name) if related else [eng_name]
    deleted: list[str] = []
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name or ""):
            continue
        path = _safe_engagement_dir(name)
        if path is not None:
            shutil.rmtree(path, ignore_errors=True)
        deleted.append(name)
    history = _read_json_file(HISTORY_FILE, [])
    if isinstance(history, list):
        gone = set(deleted)
        history = [h for h in history if isinstance(h, dict) and h.get("engagement_dir") not in gone]
        try:
            HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            HISTORY_FILE.write_text(json.dumps(history[:50], indent=2), encoding="utf-8")
        except OSError:
            pass
    return {"ok": True, "deleted": deleted, "count": len(deleted), "from_disk": True}


def _validate_bridge_target(path: str) -> str | None:
    """Construye la URL final del proxy hacia el bridge y la valida contra
    el host/puerto esperados usando urlparse — nunca confía en la
    concatenación cruda. Bloquea el truco de userinfo en URL: una petición
    a "/bridge@evil.example/exec" produciría
    "http://127.0.0.1:8420@evil.example/exec", que urlparse resuelve con
    hostname="evil.example" (userinfo "127.0.0.1:8420" descartado) —
    sin esta validación el proxy conectaría (y reenviaría X-Auditor-Token)
    a un host arbitrario elegido por quien llame al panel.
    """
    url = f"{BRIDGE_BASE}{path or '/'}"
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname != BRIDGE_HOST or parsed.port != BRIDGE_PORT:
            return None
    except ValueError:
        return None
    return url


def _hex_addr(ip: str, port: int) -> str:
    """Codifica ip:port como aparece en /proc/net/tcp (IPv4, little-endian hex)."""
    octets = [int(o) for o in ip.split(".")]
    hex_ip = "".join(f"{o:02X}" for o in reversed(octets))
    return f"{hex_ip}:{port:04X}"


def _uid_for_connection(local_ip: str, local_port: int, remote_ip: str, remote_port: int,
                         proc_text: str) -> int | None:
    """Busca en el texto de /proc/net/tcp la línea de esta conexión exacta
    (local_address == nuestro socket de escucha, rem_address == el peer que
    conectó) y devuelve el UID dueño de esa conexión, según el kernel."""
    local_key = _hex_addr(local_ip, local_port)
    remote_key = _hex_addr(remote_ip, remote_port)
    for line in proc_text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        if parts[1] == local_key and parts[2] == remote_key:
            try:
                return int(parts[7])
            except ValueError:
                return None
    return None


class PanelHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def end_headers(self) -> None:
        path = (self.path or "").split("?")[0]
        if (
            path.endswith((".js", ".mjs", ".css", ".html"))
            or path.endswith("BUILD")
            or path in ("/", "")
        ):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        super().end_headers()

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", PANEL_ORIGIN)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def _bridge_session_token(self) -> str | None:
        # File-only: bridge.py never exposes AUTH_TOKEN over HTTP, so this
        # is the sole discovery path. SESSION_FILE is 0600, written by
        # bridge.py at startup, readable only by this same local user.
        try:
            if SESSION_FILE.is_file():
                token = SESSION_FILE.read_text(encoding="utf-8").strip()
                if token:
                    return token
        except OSError:
            pass
        return None

    def _peer_is_same_user(self) -> bool:
        """True solo si la conexión TCP entrante pertenece al mismo UID que
        este proceso (Linux, vía /proc/net/tcp). Amenaza: otro usuario/proceso
        en el MISMO Kali puede hablar con 127.0.0.1:8080 igual que el propio
        panel JS — este check es la única barrera entre ambos. Falla cerrado:
        cualquier error de lectura/parseo deniega, nunca permite por defecto.
        """
        try:
            remote_ip, remote_port = self.client_address[0], self.client_address[1]
            local_ip, local_port = self.server.server_address[0], self.server.server_address[1]
            proc_text = Path("/proc/net/tcp").read_text(encoding="utf-8")
            uid = _uid_for_connection(local_ip, local_port, remote_ip, remote_port, proc_text)
            return uid is not None and uid == os.getuid()
        except OSError:
            return False

    def _serve_bridge_session(self) -> None:
        if not self._peer_is_same_user():
            self._send_json(403, {"error": "forbidden", "hint": "solicitud desde otro usuario/proceso local"})
            return
        hint = "El motor no está en marcha. En otra terminal: cd backend && python3 bridge.py"
        if not bridge_listening():
            self._send_json(503, {
                "error": "bridge_down",
                "hint": hint,
            })
            return
        token = self._bridge_session_token()
        if token:
            self._send_json(200, {"ok": True, "token": token, "features": {"keys_delete": True, "keys_update": True}})
        else:
            self._send_json(503, {
                "error": "session_unavailable",
                "hint": hint,
            })

    def _verify_ollama_key(self) -> None:
        try:
            body = self._read_json_body()
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid_json"})
            return
        api_key = str(body.get("api_key", "")).strip()
        if not api_key:
            self._send_json(400, {"error": "api_key_required"})
            return
        req = urllib.request.Request(
            OLLAMA_MODELS_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as err:
            detail = err.read().decode(errors="replace")
            self._send_json(400, {"error": "invalid_api_key", "detail": detail})
            return
        except urllib.error.URLError as err:
            self._send_json(502, {"error": "ollama_unreachable", "detail": str(err.reason)})
            return
        models = sorted({
            str(item.get("id") or item.get("name") or "")
            for item in (data.get("data") or [])
            if item.get("id") or item.get("name")
        })
        if not models:
            self._send_json(400, {"error": "invalid_api_key", "detail": "no_models_returned"})
            return
        self._send_json(200, {"ok": True, "verified": True, "models": models})

    def do_OPTIONS(self) -> None:
        if self.path.startswith("/bridge") or self.path.startswith("/api/"):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", PANEL_ORIGIN)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auditor-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()
            return
        super().do_OPTIONS()

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/bridge/session":
            self._serve_bridge_session()
            return
        if self.path.startswith("/bridge"):
            self._proxy_bridge()
            return
        super().do_GET()

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if path == "/api/verify-ollama-key":
            self._verify_ollama_key()
            return
        if path == "/bridge/status":
            if not bridge_listening():
                self._send_json(200, {
                    "active": False,
                    "bridge": "down",
                    "hint": "Motor apagado. Arranca: cd backend && python3 bridge.py",
                })
                return
        if path == "/bridge/engagements/list":
            if not bridge_listening():
                self._send_json(200, {
                    "engagements": _list_engagements_from_disk(),
                    "bridge": "down",
                    "hint": "Motor apagado: lista desde disco. Arranca: cd backend && python3 bridge.py",
                })
                return
        if path == "/bridge/engagements/findings":
            if not bridge_listening():
                try:
                    body = self._read_json_body()
                except json.JSONDecodeError:
                    self._send_json(400, {"error": "invalid_json"})
                    return
                eng_name = str(body.get("engagement_dir") or body.get("id") or "").strip()
                if not eng_name:
                    self._send_json(400, {"error": "engagement_dir_required"})
                    return
                payload = _findings_from_disk(eng_name)
                if payload is None:
                    self._send_json(404, {"error": "engagement_not_found"})
                    return
                self._send_json(200, payload)
                return
        for ctrl_path, ctrl_action in (
            ("/bridge/engagements/pause", "pause"),
            ("/bridge/engagements/resume", "resume"),
            ("/bridge/engagements/finish", "finish"),
        ):
            if path == ctrl_path:
                try:
                    body = self._read_json_body()
                except json.JSONDecodeError:
                    self._send_json(400, {"error": "invalid_json"})
                    return
                eng_name = str(body.get("engagement_dir") or body.get("id") or "").strip()
                if not eng_name:
                    self._send_json(400, {"error": "engagement_dir_required"})
                    return
                if not self._peer_is_same_user():
                    self._send_json(403, {"error": "forbidden"})
                    return
                result = _control_engagement_on_disk(eng_name, ctrl_action)
                if bridge_listening() and not result.get("error"):
                    try:
                        headers = {"Content-Type": "application/json"}
                        token = self.headers.get("X-Auditor-Token") or self._bridge_session_token()
                        if token:
                            headers["X-Auditor-Token"] = token
                        req = urllib.request.Request(
                            f"{BRIDGE_BASE}/engagements/{ctrl_action}",
                            data=json.dumps({"engagement_dir": eng_name}).encode(),
                            headers=headers,
                            method="POST",
                        )
                        with urllib.request.urlopen(req, timeout=30) as resp:
                            result["bridge"] = json.loads(resp.read().decode() or "{}")
                    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as err:
                        result["bridge_error"] = str(getattr(err, "reason", None) or err)
                code = 400 if result.get("error") else 200
                self._send_json(code, result)
                return
        if path == "/bridge/engagements/delete":
            try:
                body = self._read_json_body()
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid_json"})
                return
            eng_name = str(body.get("engagement_dir") or body.get("id") or "").strip()
            if not eng_name:
                self._send_json(400, {"error": "engagement_dir_required"})
                return
            if not self._peer_is_same_user():
                self._send_json(403, {"error": "forbidden"})
                return
            related = bool(body.get("related", True))
            # Disk first — dashboard/OSINT/MITRE leen findings desde aquí
            result = _delete_engagement_from_disk(eng_name, related=related)
            if bridge_listening():
                try:
                    headers = {"Content-Type": "application/json"}
                    token = self.headers.get("X-Auditor-Token") or self._bridge_session_token()
                    if token:
                        headers["X-Auditor-Token"] = token
                    req = urllib.request.Request(
                        f"{BRIDGE_BASE}/engagements/delete",
                        data=json.dumps({
                            "engagement_dir": eng_name,
                            "related": related,
                        }).encode(),
                        headers=headers,
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        bridge_payload = json.loads(resp.read().decode() or "{}")
                    result["bridge"] = bridge_payload
                except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as err:
                    result["bridge_error"] = str(getattr(err, "reason", None) or err)
            self._send_json(200, result)
            return
        if self.path.startswith("/bridge"):
            self._proxy_bridge()
            return
        super().do_POST()

    def _proxy_bridge(self) -> None:
        path = self.path[len("/bridge"):] or "/"
        url = _validate_bridge_target(path)
        if url is None:
            self._send_json(400, {"error": "invalid_bridge_path"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None
        headers = {}
        for name in ("Content-Type", "X-Auditor-Token"):
            value = self.headers.get(name)
            if value:
                headers[name] = value
        req = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                for name, value in resp.headers.items():
                    if name.lower() in {"transfer-encoding", "connection"}:
                        continue
                    self.send_header(name, value)
                self.send_header("Access-Control-Allow-Origin", PANEL_ORIGIN)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except urllib.error.HTTPError as err:
            payload = err.read()
            self.send_response(err.code)
            self.send_header("Content-Type", err.headers.get("Content-Type", "application/json"))
            self.send_header("Access-Control-Allow-Origin", PANEL_ORIGIN)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except urllib.error.URLError as err:
            # Read-only fallbacks if the motor dies mid-request
            norm = path.rstrip("/")
            if norm == "/engagements/list":
                self._send_json(200, {
                    "engagements": _list_engagements_from_disk(),
                    "bridge": "down",
                    "hint": "Motor apagado: lista desde disco. Arranca: cd backend && python3 bridge.py",
                })
                return
            if norm == "/status":
                self._send_json(200, {
                    "active": False,
                    "bridge": "down",
                    "hint": "Motor apagado. Arranca: cd backend && python3 bridge.py",
                })
                return
            msg = json.dumps({"error": "bridge_unreachable", "detail": str(err.reason)}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)


def bridge_listening() -> bool:
    try:
        with socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=0.4):
            return True
    except OSError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Auditor SecOps Console — servidor local")
    parser.add_argument("--host", default="127.0.0.1", help="Interfaz de escucha")
    parser.add_argument("--port", type=int, default=8080, help="Puerto HTTP")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), PanelHandler)
    print("=" * 56)
    print("  Dark Spear — Consola SecOps")
    print("  Panel: http://%s:%s/" % (args.host, args.port))
    if bridge_listening():
        print("  Motor: http://%s:%s/ (detectado, proxy /bridge)" % (BRIDGE_HOST, BRIDGE_PORT))
    else:
        print("  Motor: NO detectado en %s:%s" % (BRIDGE_HOST, BRIDGE_PORT))
        print("  Inicia el motor en otra terminal:")
        print("    cd backend && python3 bridge.py")
    print("  Ctrl+C para detener el panel")
    print("=" * 56)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
