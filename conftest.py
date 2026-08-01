"""Re-mint the harness PKI when its leaf has expired.

The labeler leaf is deliberately short-lived (15 minutes — short-lived signing
certs are part of what SPEC-0001 argues for). The side effect is that a reader
who runs `python -m apt.setup`, reads the README for twenty minutes, and then
runs pytest gets `chain_validation_failed` with no indication that the cause is
wall-clock rather than a broken repository.

Re-minting only when the leaf is actually missing or expired keeps every test
that depends on a stable anchor within a session working, and keeps the failure
mode of a genuinely broken chain intact.
"""
from __future__ import annotations

from datetime import UTC, datetime


def pytest_configure(config):
    """Runs before test modules are imported — some of them load the anchor at
    import time, so a fixture would be too late."""
    from apt import scenario
    from producer.signer import Pki

    leaf = scenario.PKI_DIR / "leaf.pem"
    if leaf.exists():
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(leaf.read_bytes())
        if cert.not_valid_after_utc > datetime.now(UTC):
            return  # still valid — leave the on-disk anchor exactly as it is

    scenario.PKI_DIR.mkdir(parents=True, exist_ok=True)
    Pki().save(scenario.PKI_DIR)
