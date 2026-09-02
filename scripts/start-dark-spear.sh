#!/usr/bin/env bash
# Arranca motor (8420) + panel (8080) con un solo proceso.
# Uso: ./scripts/start-dark-spear.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
exec python3 bridge.py
