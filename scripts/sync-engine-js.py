#!/usr/bin/env python3
"""Sync backend/js agent modules into panel/vendor/engine/js (same-origin for the panel)."""

from datetime import datetime, timezone
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "backend" / "js"
DST = ROOT / "panel" / "vendor" / "engine" / "js"
ENGINE_DIR = DST.parent

FILES = [
    "agent.js",
    "axis.js",
    "bridge_client.js",
    "db.js",
    "finding-heuristics.js",
    "main.js",
    "ollama.js",
    "playbook.js",
    "ui.js",
    "vuln-kb.js",
]


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        shutil.copy2(SRC / name, DST / name)
        print(f"  synced {name}")
    build = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    (ENGINE_DIR / "BUILD").write_text(build + "\n", encoding="utf-8")
    print(f"  BUILD → {build}")
    print(f"Done → {DST}")


if __name__ == "__main__":
    main()
