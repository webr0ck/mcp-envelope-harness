"""Ephemeral labeler PKI + envelope signer for the harness producer.

The shipped wheel ships only the VERIFIER (and jcs). It does NOT ship a signer,
so the producer has to build the _meta envelope itself. This is a faithful,
minimal port of mcp-security-platform proxy/app/services/trust_labeler.py `_sign`
(the source of truth), reusing the wheel's OWN jcs canonicalization so signer and
verifier agree byte-for-byte. Crypto is delegated to `cryptography`; we do NOT
hand-roll ECDSA.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mcp_trust_verifier import TRUST_ENVELOPE_KEY
from mcp_trust_verifier.jcs import jcs_signed_input, jcs_tool_result

MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
_TIER_LABELS = {0: "untrustedPublic", 1: "trustedPublic", 2: "internal", 3: "user", 4: "system"}


class Pki:
    """An ephemeral sub-CA + labeler leaf. `sub_ca_pem` is what a consumer pins."""

    def __init__(self, cn: str = "Harness MCP Labeler", leaf_ttl_minutes: int = 15):
        now = datetime.now(UTC)
        self.sub_ca_key = ec.generate_private_key(ec.SECP256R1())
        sub_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{cn} Sub-CA")])
        self.sub_ca = (
            x509.CertificateBuilder().subject_name(sub_subj).issuer_name(sub_subj)
            .public_key(self.sub_ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.sub_ca_key, hashes.SHA256())
        )
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.harness.internal")])
        self.leaf = (
            x509.CertificateBuilder().subject_name(leaf_subj).issuer_name(self.sub_ca.subject)
            .public_key(self.leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(minutes=leaf_ttl_minutes))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=False, crl_sign=False,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([MCP_LABELER_OID]), critical=False)
            .sign(self.sub_ca_key, hashes.SHA256())
        )

    @property
    def sub_ca_pem(self) -> bytes:
        return self.sub_ca.public_bytes(serialization.Encoding.PEM)

    # ── persistence ───────────────────────────────────────────────────────────
    # The 8-case demo signs in one process, so an ephemeral in-memory Pki is enough.
    # The APT scenario runs TWO separate MCP server processes that must sign under the
    # SAME pinned sub-CA (otherwise the consumer would need two anchors and "one pinned
    # root" stops being the claim), so the key material has to round-trip through disk.
    # ponytail: unencrypted PEM in .run/ — throwaway per-run keys, never leaves the box.

    def save(self, d) -> "Path":
        d = Path(d)
        d.mkdir(parents=True, exist_ok=True)
        no_enc = serialization.NoEncryption()
        pk = serialization.PrivateFormat.PKCS8
        (d / "sub_ca.pem").write_bytes(self.sub_ca_pem)
        (d / "sub_ca_key.pem").write_bytes(
            self.sub_ca_key.private_bytes(serialization.Encoding.PEM, pk, no_enc)
        )
        (d / "leaf.pem").write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
        (d / "leaf_key.pem").write_bytes(
            self.leaf_key.private_bytes(serialization.Encoding.PEM, pk, no_enc)
        )
        return d

    @classmethod
    def load(cls, d) -> "Pki":
        d = Path(d)
        self = cls.__new__(cls)  # bypass __init__: reuse the saved keys, don't mint new ones
        self.sub_ca = x509.load_pem_x509_certificate((d / "sub_ca.pem").read_bytes())
        self.sub_ca_key = serialization.load_pem_private_key(
            (d / "sub_ca_key.pem").read_bytes(), password=None
        )
        self.leaf = x509.load_pem_x509_certificate((d / "leaf.pem").read_bytes())
        self.leaf_key = serialization.load_pem_private_key(
            (d / "leaf_key.pem").read_bytes(), password=None
        )
        return self

    def _x5c(self) -> list[str]:
        return [
            base64.b64encode(self.leaf.public_bytes(serialization.Encoding.DER)).decode(),
            base64.b64encode(self.sub_ca.public_bytes(serialization.Encoding.DER)).decode(),
        ]

    def sign_envelope(
        self,
        *,
        content: list,
        tool_name: str,
        server_id: str,
        result_id: str,
        trust_tier: int = 0,
        sensitivity: str = "low",
        signed_at_skew_seconds: int = 0,  # negative = backdate (stale demo)
    ) -> dict:
        """Return the trust-envelope dict (goes under result._meta[TRUST_ENVELOPE_KEY])."""
        safe_tier = trust_tier if 0 <= trust_tier <= 4 else 0
        label = {
            "source": _TIER_LABELS[safe_tier],
            "integrity_rank": safe_tier,
            "sensitivity": sensitivity,
            "attribution": [{
                "principal": self.leaf.subject.rfc4514_string(),
                "cert_fp": "sha256:" + self.leaf.fingerprint(hashes.SHA256()).hex(),
            }],
        }
        content_hash = "sha256:" + hashlib.sha256(
            jcs_tool_result(content=content, structured_content=None)
        ).hexdigest()
        nonce = secrets.token_urlsafe(16)
        signed_at_dt = datetime.now(UTC) + timedelta(seconds=signed_at_skew_seconds)
        signed_at = signed_at_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        sig_der = self.leaf_key.sign(
            jcs_signed_input(
                label=label, content_hash=content_hash, nonce=nonce, signed_at=signed_at,
                result_id=result_id, tool_name=tool_name, server_id=server_id,
            ),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "label": label,
            "binding": {"content_hash": content_hash, "nonce": nonce, "signed_at": signed_at},
            "call_context": {"server_id": server_id, "result_id": result_id, "tool_name": tool_name},
            "sig": {"alg": "ES256", "x5c": self._x5c(), "value": base64.urlsafe_b64encode(sig_der).rstrip(b"=").decode()},
        }


def build_result(pki: Pki, content: list, *, tool_name: str, server_id: str, result_id: str,
                 trust_tier: int = 0, signed_at_skew_seconds: int = 0, layer_b: bool = False) -> dict:
    """Assemble the MCP-ish CallToolResult dict: {content, _meta{envelope}}.

    Layer B (advisory wrap) is applied to content BEFORE signing so the signed
    content_hash covers the wrapped text (Layer A authoritative over B).
    """
    from producer.layer_b import wrap_content_layer_b  # local port, see module
    eff = wrap_content_layer_b(content=content, trust_tier=trust_tier,
                               tool_name=tool_name, server_id=server_id) if layer_b else content
    env = pki.sign_envelope(content=eff, tool_name=tool_name, server_id=server_id,
                            result_id=result_id, trust_tier=trust_tier,
                            signed_at_skew_seconds=signed_at_skew_seconds)
    return {"content": eff, "_meta": {TRUST_ENVELOPE_KEY: env}}
