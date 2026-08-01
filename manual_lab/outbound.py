"""Constrained outbound HTTP client for the manual lab."""
from __future__ import annotations

import ipaddress
import json
import socket
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
MAX_RESPONSE_BYTES = 65_536


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _validate_public_url(
    url: str,
    allowed_private_targets: set[tuple[str, int]] | None = None,
) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("credentials in URLs are not allowed")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if (parsed.hostname, port) in (allowed_private_targets or set()):
        return parsed.geturl()
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as exc:
        raise ValueError(f"hostname could not be resolved: {parsed.hostname}") from exc
    if not addresses:
        raise ValueError("hostname did not resolve to an address")
    blocked = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if blocked:
        raise ValueError("the request target resolves to a private or non-public address")
    return parsed.geturl()


def send_http_request(
    method: str,
    url: str,
    body: str,
    *,
    allowed_private_targets: set[tuple[str, int]] | None = None,
) -> dict[str, Any]:
    method = method.upper().strip()
    if method not in ALLOWED_METHODS:
        raise ValueError(f"method must be one of {sorted(ALLOWED_METHODS)}")
    if len(body.encode("utf-8")) > 64_000:
        raise ValueError("body must be no larger than 64,000 UTF-8 bytes")
    target = _validate_public_url(url, allowed_private_targets)
    data = None if method == "GET" else body.encode("utf-8")
    request = Request(
        target,
        data=data,
        method=method,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "User-Agent": "mcp-envelope-lab/0.3",
        },
    )
    opener = build_opener(ProxyHandler({}), _NoRedirects())
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=10)
    except HTTPError as exc:
        response = exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError(f"request failed: {exc}") from exc
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    truncated = len(raw) > MAX_RESPONSE_BYTES
    raw = raw[:MAX_RESPONSE_BYTES]
    charset = response.headers.get_content_charset() or "utf-8"
    return {
        "ok": 200 <= response.status < 400,
        "method": method,
        "url": target,
        "status": response.status,
        "reason": response.reason,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "content_type": response.headers.get("Content-Type", ""),
        "headers": dict(response.headers.items()),
        "body": raw.decode(charset, errors="replace"),
        "truncated": truncated,
    }


def append_http_log(path: str | Path, record: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def recent_http_logs(path: str | Path, limit: int = 20) -> list[dict[str, Any]]:
    source = Path(path)
    if not source.exists():
        return []
    lines = source.read_text(encoding="utf-8").splitlines()[-max(1, min(limit, 100)) :]
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records
