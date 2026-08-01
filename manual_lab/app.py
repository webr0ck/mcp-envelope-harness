"""FastAPI control surface for the manual trust-envelope lab."""
from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pydantic import BaseModel, Field

from manual_lab.connector import build_server
from manual_lab.core import CONNECTOR_TOOL_NAMES, ManualEnvelopeLab, config_identity
from manual_lab.outbound import (
    ALLOWED_METHODS,
    append_http_log,
    recent_http_logs,
    send_http_request,
)


ROOT = Path(__file__).resolve().parent.parent
INDEX = Path(__file__).resolve().parent / "index.html"
EVIDENCE = ROOT / ".run" / "manual_lab"
HTTP_LOG = EVIDENCE / "outbound.jsonl"
SELF_URL = os.environ.get("MANUAL_LAB_SELF_URL", "http://127.0.0.1:8900").rstrip("/")
_self_url = urlsplit(SELF_URL)
if _self_url.scheme not in {"http", "https"} or not _self_url.hostname:
    raise RuntimeError("MANUAL_LAB_SELF_URL must be an absolute http:// or https:// URL")
SELF_TARGET = {
    (
        _self_url.hostname,
        _self_url.port or (443 if _self_url.scheme == "https" else 80),
    )
}

lab = ManualEnvelopeLab(EVIDENCE)
mcp_server = build_server(lab)
mcp_sessions = StreamableHTTPSessionManager(
    app=mcp_server,
    json_response=True,
    stateless=True,
)


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    async with mcp_sessions.run():
        yield


app = FastAPI(
    title="MCP Trust Envelope Manual Lab",
    version="0.2.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)
app.mount("/mcp", mcp_sessions.handle_request)


class RunRequest(BaseModel):
    content: str
    trust_tier: int = 0
    required_integrity: int = 1
    envelope: str = "valid"
    protection: str = "enforce"
    tool_name: str = "manual_response"
    target_tools: list[str] = Field(default_factory=lambda: list(CONNECTOR_TOOL_NAMES))


class HttpRequest(BaseModel):
    method: str = "POST"
    url: str = Field(min_length=1, max_length=2_048)
    body: str = Field(default="", max_length=64_000)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/scenarios")
def scenarios() -> dict[str, dict[str, Any]]:
    return lab.scenarios()


@app.post("/api/run")
def run(request: RunRequest) -> dict[str, Any]:
    try:
        raw_config = request.model_dump()
        published_config = lab.publish_connector_config(raw_config)
        result = lab.run(published_config, origin="ui")
        result["config"] = published_config
        result["submission"] = config_identity(published_config)
        result["published_config"] = published_config
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/logs")
def logs(limit: int = 25) -> dict[str, list[dict[str, Any]]]:
    return lab.recent_logs(limit)


@app.get("/api/connector/config")
def connector_config() -> dict[str, Any]:
    return lab.connector_config()


@app.put("/api/connector/config")
def publish_connector_config(request: RunRequest) -> dict[str, Any]:
    try:
        return {"ok": True, "config": lab.publish_connector_config(request.model_dump())}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "evidence_dir": str(EVIDENCE),
        "anchor": str(lab.anchor_path),
        "mcp_streamable_http": "/mcp/",
        "self_test_url": f"{SELF_URL}/api/health",
    }


@app.post("/api/http-request")
def http_request(request: HttpRequest) -> dict[str, Any]:
    request_id = f"http-{int(time.time())}-{secrets.token_hex(4)}"
    started_at = time.time()
    request_record = {
        "method": request.method.upper(),
        "url": request.url,
        "body": request.body,
    }
    if request.method.upper() not in ALLOWED_METHODS:
        raise HTTPException(status_code=422, detail="unsupported HTTP method")
    try:
        result = send_http_request(
            request.method,
            request.url,
            request.body,
            allowed_private_targets=SELF_TARGET,
        )
    except ValueError as exc:
        append_http_log(
            HTTP_LOG,
            {
                "request_id": request_id,
                "ts": started_at,
                "request": request_record,
                "response": None,
                "error": str(exc),
            },
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    append_http_log(
        HTTP_LOG,
        {
            "request_id": request_id,
            "ts": started_at,
            "request": request_record,
            "response": result,
            "error": None,
        },
    )
    result["request_id"] = request_id
    return result


@app.get("/api/http-logs")
def http_logs(limit: int = 20) -> dict[str, Any]:
    return {"records": recent_http_logs(HTTP_LOG, limit), "path": str(HTTP_LOG)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8900)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
