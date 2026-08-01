"""Cross-platform orchestrator for the three-process federation demo."""
from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_port(port: int, process: subprocess.Popen, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"process exited during startup: {detail}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} did not become ready")


def _stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(run_dir: Path) -> int:
    org_a_port = _free_port()
    relay_port = _free_port()
    org_a_anchor = run_dir / "org_a" / "public" / "labeler_ca.pem"
    org_b_anchor = run_dir / "org_b" / "trust" / "org_a_labeler_ca.pem"
    capture = run_dir / "relay.jsonl"
    evidence = run_dir / "evidence.json"
    for old in (capture, evidence, org_a_anchor, org_b_anchor):
        old.unlink(missing_ok=True)

    producer = None
    relay = None
    try:
        producer = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "federation.producer",
                "--port",
                str(org_a_port),
                "--anchor-out",
                str(org_a_anchor),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_port(org_a_port, producer)
        if not org_a_anchor.exists():
            raise RuntimeError("Org A did not publish its trust anchor")

        org_b_anchor.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(org_a_anchor, org_b_anchor)

        relay = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "federation.relay",
                "--port",
                str(relay_port),
                "--upstream",
                f"http://127.0.0.1:{org_a_port}",
                "--capture",
                str(capture),
            ],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_port(relay_port, relay)

        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "federation.consumer",
                "--relay-url",
                f"http://127.0.0.1:{relay_port}",
                "--anchor",
                str(org_b_anchor),
                "--evidence",
                str(evidence),
            ],
            cwd=ROOT,
            check=False,
            text=True,
        )
        return completed.returncode
    finally:
        _stop(relay)
        _stop(producer)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the cross-boundary envelope demo")
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=ROOT / ".run" / "federation",
        help="generated trust material, capture, and evidence directory",
    )
    args = parser.parse_args()
    return run(args.run_dir.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
