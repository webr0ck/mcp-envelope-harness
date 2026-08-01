from __future__ import annotations

import json
from pathlib import Path

from manual_lab.core import ManualEnvelopeLab, POISON_MARKERS
from manual_lab.outbound import _validate_public_url, append_http_log, recent_http_logs


INDEX = Path(__file__).resolve().parent / "index.html"
README = Path(__file__).resolve().parent / "README.md"


def _run(tmp_path, scenario):
    lab = ManualEnvelopeLab(tmp_path)
    return lab, lab.run(lab.scenario(scenario))


def test_valid_signed_result_proceeds(tmp_path):
    _, result = _run(tmp_path, "valid")
    consumer = result["consumer"]
    assert consumer["verdict"] == "accepted"
    assert consumer["action"] == "proceed"
    assert consumer["content_withheld"] is False


def test_signed_low_integrity_malicious_result_is_blocked(tmp_path):
    _, result = _run(tmp_path, "malicious_blocked")
    consumer = result["consumer"]
    assert consumer["verdict"] == "accepted"
    assert consumer["integrity_rank"] == 0
    assert consumer["action"] == "refuse_privileged"
    assert consumer["content_withheld"] is True
    assert consumer["poison_delivered"] is False


def test_missing_envelope_passes_only_when_protection_is_off(tmp_path):
    _, result = _run(tmp_path, "malicious_no_envelope_unprotected")
    consumer = result["consumer"]
    assert consumer["verdict"] == "not_run"
    assert consumer["action"] == "proceed_unverified"
    assert consumer["poison_delivered"] is True
    assert all(marker in consumer["delivered_text"] for marker in POISON_MARKERS)


def test_missing_envelope_fails_closed_when_protected(tmp_path):
    _, result = _run(tmp_path, "malicious_no_envelope_protected")
    consumer = result["consumer"]
    assert consumer["verdict"] == "rejected"
    assert consumer["reason"] == "no_envelope"
    assert consumer["action"] == "refuse"
    assert consumer["poison_delivered"] is False


def test_post_signing_tamper_is_detected(tmp_path):
    _, result = _run(tmp_path, "tampered_blocked")
    consumer = result["consumer"]
    assert consumer["verdict"] == "rejected"
    assert consumer["reason"].startswith("content_hash_mismatch")
    assert consumer["action"] == "refuse"


def test_rogue_signer_is_not_trusted(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    config = lab.scenario("valid")
    config["envelope"] = "rogue"
    result = lab.run(config)
    consumer = result["consumer"]
    assert consumer["verdict"] == "rejected"
    assert consumer["reason"] == "chain_validation_failed"
    assert consumer["action"] == "refuse"


def test_each_run_gets_a_fresh_trust_anchor(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    config = lab.scenario("valid")
    first = lab.run(config)
    second = lab.run(config)
    assert first["anchor_path"] != second["anchor_path"]
    assert first["producer"]["envelope"]["present"] is True
    assert second["producer"]["envelope"]["present"] is True
    assert first["consumer"]["action"] == "proceed"
    assert second["consumer"]["action"] == "proceed"


def test_all_three_sides_share_run_id_and_are_logged(tmp_path):
    lab, result = _run(tmp_path, "valid")
    run_id = result["run_id"]
    logs = lab.recent_logs()
    assert logs.keys() == {"producer", "wire", "consumer"}
    assert all(side[-1]["run_id"] == run_id for side in logs.values())
    assert all(side[-1]["origin"] == "ui" for side in logs.values())
    for path in (lab.producer_log, lab.wire_log, lab.consumer_log):
        assert json.loads(path.read_text().splitlines()[-1])["run_id"] == run_id


def test_logs_retain_exact_signed_and_wire_evidence(tmp_path):
    lab, result = _run(tmp_path, "valid")
    logs = lab.recent_logs(1)

    assert logs["producer"][0]["exact_result"] == result["raw"]["producer_result"]
    assert logs["wire"][0]["exact_result"] == result["raw"]["wire_result"]
    assert logs["producer"][0]["crypto"]["algorithm"] == "ES256"
    assert logs["producer"][0]["crypto"]["signed_input_utf8"]
    assert logs["producer"][0]["crypto"]["signature"]
    assert len(logs["producer"][0]["crypto"]["certificate_chain_x5c"]) == 2


def test_ui_lists_exact_connector_tools_and_harness_returns():
    html = INDEX.read_text(encoding="utf-8")
    for tool_name in (
        "read_news",
        "list_pull_requests",
        "get_last_jira_ticket",
        "inspect_envelope_lab_state",
    ):
        assert f"<code>{tool_name}</code>" in html
    assert "Tools visible to the harness" in html
    assert html.count("Harness receives") == 4
    assert "fetch_unsigned_unprotected" not in html
    assert "fetch_signed_unenforced" not in html
    assert "fetch_with_envelope_protection" not in html
    assert "Configured payload targets" in html
    assert "Publish to MCP → run evidence" in html
    assert "UI simulation requests" in html
    assert "MCP harness requests" in html
    assert "Annotation versus enforcement" in html
    assert "Malicious text reaches Claude" in html
    assert "Malicious text still reaches Claude" in html
    assert "Original text is withheld" in html
    assert "Outbound request validator" in html
    assert "Base64 encode / decode" in html
    assert "Recent outbound requests" in html
    assert "/api/http-logs" in html
    assert 'data-format="curl"' in html
    assert 'data-format="telnet"' in html
    assert 'data-format="nc"' in html
    assert "asdasdasd.requestcatcher.com" not in html


def test_outbound_validator_rejects_private_and_credentialed_urls(monkeypatch):
    monkeypatch.setattr(
        "manual_lab.outbound.socket.getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 80))],
    )
    try:
        _validate_public_url("http://localhost/test")
    except ValueError as exc:
        assert "private or non-public" in str(exc)
    else:
        raise AssertionError("private target was accepted")

    try:
        _validate_public_url("https://user:pass@example.com/test")
    except ValueError as exc:
        assert "credentials" in str(exc)
    else:
        raise AssertionError("credentialed URL was accepted")


def test_outbound_validator_allows_the_lab_health_endpoint():
    assert (
        _validate_public_url("http://100.119.138.35:8900/api/health")
        == "http://100.119.138.35:8900/api/health"
    )


def test_outbound_logs_round_trip(tmp_path):
    path = tmp_path / "outbound.jsonl"
    record = {"request_id": "http-test", "request": {"method": "GET"}}
    append_http_log(path, record)
    assert recent_http_logs(path) == [record]


def test_connector_config_validates_and_preserves_delivery_targets(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    config = lab.scenario("malicious_blocked")
    config["target_tools"] = ["get_last_jira_ticket", "read_news"]

    published = lab.publish_connector_config(config)

    assert published["target_tools"] == ["read_news", "get_last_jira_ticket"]
    assert lab.connector_config() == published


def test_connector_config_rejects_unknown_delivery_target(tmp_path):
    lab = ManualEnvelopeLab(tmp_path)
    config = lab.scenario("valid")
    config["target_tools"] = ["delete_everything"]

    try:
        lab.publish_connector_config(config)
    except ValueError as exc:
        assert "unknown target_tools" in str(exc)
    else:
        raise AssertionError("unknown connector target was accepted")


def test_readme_covers_installation_and_complete_harness_procedure():
    readme = README.read_text(encoding="utf-8")
    for heading in (
        "## Install with Python",
        "## Run with Podman or Docker",
        "## Connect an MCP harness",
        "### Test 1 — annotation versus enforcement",
        "### Test 2 — target only one tool",
        "### Test 3 — every built-in preset",
        "### Test 4 — every envelope option",
        "### Test 5 — integrity-floor boundary",
        "## Reset to a safe state",
    ):
        assert heading in readme
