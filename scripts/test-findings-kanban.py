#!/usr/bin/env python3
"""Verifica _apply_finding_status_transition(): accepted->verifying->reported."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import bridge  # noqa: E402


def test_verify_from_accepted():
    finding = {"id": "f1", "status": "accepted"}
    error = bridge._apply_finding_status_transition(finding, "verify")
    ok = error is None and finding["status"] == "verifying"
    print(("OK" if ok else "FAIL") + ": verify transiciona accepted -> verifying")
    return ok


def test_mark_reported_rejects_from_proposed():
    finding = {"id": "f2", "status": "proposed"}
    error = bridge._apply_finding_status_transition(finding, "mark_reported")
    ok = error == "invalid_transition" and finding["status"] == "proposed"
    print(("OK" if ok else "FAIL") + ": mark_reported rechaza desde proposed")
    return ok


def test_mark_reported_from_verifying():
    finding = {"id": "f3", "status": "verifying"}
    error = bridge._apply_finding_status_transition(finding, "mark_reported")
    ok = error is None and finding["status"] == "reported"
    print(("OK" if ok else "FAIL") + ": mark_reported transiciona verifying -> reported")
    return ok


def test_mark_reported_from_accepted_directly():
    finding = {"id": "f4", "status": "accepted"}
    error = bridge._apply_finding_status_transition(finding, "mark_reported")
    ok = error is None and finding["status"] == "reported"
    print(("OK" if ok else "FAIL") + ": mark_reported permite saltar verifying desde accepted")
    return ok


if __name__ == "__main__":
    results = [
        test_verify_from_accepted(),
        test_mark_reported_rejects_from_proposed(),
        test_mark_reported_from_verifying(),
        test_mark_reported_from_accepted_directly(),
    ]
    sys.exit(0 if all(results) else 1)
