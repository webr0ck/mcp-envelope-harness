"""Socket-level acceptance test for the comparative cross-boundary scenario."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_cross_boundary_demo_proves_safety_and_utility(tmp_path):
    root = Path(__file__).resolve().parent.parent
    run_dir = tmp_path / "federation"
    completed = subprocess.run(
        [sys.executable, "-m", "federation.run_demo", "--run-dir", str(run_dir)],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

    evidence = json.loads((run_dir / "evidence.json").read_text(encoding="utf-8"))
    by_case = {case["case"]: case for case in evidence["cases"]}
    assert evidence["all_passed"] is True
    assert by_case["unsigned_default_trusted_public"]["report_executed"] is True
    assert by_case["unsigned_default_untrusted_internal"]["report_executed"] is False
    assert by_case["signed_internal"]["report_executed"] is True
    assert by_case["signed_public"]["decision"]["action"] == "refuse_privileged"
    assert by_case["relay_raises_rank"]["decision"]["verdict"] == "rejected"
    assert (run_dir / "relay.jsonl").read_text(encoding="utf-8").count("relay->org-b") == 5
