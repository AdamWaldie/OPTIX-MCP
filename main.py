from __future__ import annotations

import hashlib
import os
import re as _re
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from mcp.server import Server
from mcp.server.sse import SseServerTransport, TransportSecuritySettings

import client as optix_client
from auth import require_api_key
from models import HealthStatus
from tools import register_tools

load_dotenv()

MCP_SERVER_VERSION = "1.0.0"
OPTIX_API_URL = os.environ.get("OPTIX_API_URL", "http://localhost:5000")
MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8090"))

_security_settings = TransportSecuritySettings(
    enable_dns_rebinding_protection=os.environ.get(
        "MCP_ENABLE_DNS_PROTECTION", "false"
    ).lower()
    not in ("false", "0", "no"),
    allowed_hosts=list(
        filter(None, os.environ.get("MCP_ALLOWED_HOSTS", "").split(","))
    ),
    allowed_origins=list(
        filter(None, os.environ.get("MCP_ALLOWED_ORIGINS", "").split(","))
    ),
)

mcp_server = Server("optix-mcp")
register_tools(mcp_server)

sse_transport = SseServerTransport("/mcp/messages", security_settings=_security_settings)

_SESSION_REGISTRY_MAX = 2048
_session_owners: "OrderedDict[str, str]" = OrderedDict()


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode(), usedforsecurity=False).hexdigest()


def _register_session(session_id: str, key_hash: str) -> None:
    if len(_session_owners) >= _SESSION_REGISTRY_MAX:
        _session_owners.popitem(last=False)
    _session_owners[session_id] = key_hash


def _verify_session(session_id: Optional[str], api_key: str) -> None:
    if session_id is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "Missing session_id query parameter"},
        )
    expected = _session_owners.get(session_id)
    if expected is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "Session not found — it may have expired or never been opened"},
        )
    if expected != _hash_key(api_key):
        raise HTTPException(
            status_code=403,
            detail={"error": "API key does not match the session owner"},
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="OPTIX MCP Server",
    description=(
        "Model Context Protocol server that wraps the OPTIX threat intelligence API. "
        "Exposes analyst-friendly tools for querying threat feeds, searching indicators, "
        "reporting incidents, fetching entity intelligence, and checking account credit status."
    ),
    version=MCP_SERVER_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthStatus, tags=["Health"])
async def health_check() -> HealthStatus:
    connected = await optix_client.probe_health()
    return HealthStatus(
        status="ok" if connected else "degraded",
        version=MCP_SERVER_VERSION,
        optix_connected=connected,
        optix_url=OPTIX_API_URL,
        timestamp=datetime.now(timezone.utc),
    )


@app.get("/mcp", tags=["MCP"])
async def mcp_sse_endpoint(request: Request, api_key: str = Depends(require_api_key)):
    """
    SSE endpoint for MCP clients (Claude Desktop, Cursor, etc.).
    Validates X-API-Key against OPTIX. The session is bound to the validated
    key — subsequent POST /mcp/messages requests for this session are only
    accepted if they carry the same key.
    """
    key_hash = _hash_key(api_key)

    async def _tracking_send(message: dict) -> None:
        if message.get("type") == "http.response.body":
            body = message.get("body", b"")
            m = _re.search(rb"session_id=([a-zA-Z0-9_-]+)", body)
            if m:
                session_id = m.group(1).decode()
                _register_session(session_id, key_hash)
        await request._send(message)

    async with sse_transport.connect_sse(
        request.scope, request.receive, _tracking_send
    ) as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )


@app.post("/mcp/messages", tags=["MCP"])
async def mcp_post_messages(request: Request, api_key: str = Depends(require_api_key)):
    """
    Receives POST messages from MCP clients linked to an existing SSE session.
    Validates both that the API key is valid (via require_api_key) AND that it
    matches the key used to open the target SSE session (session-to-owner binding).
    Requests carrying a valid-but-different key are rejected with 403 before they
    reach the transport layer.
    """
    session_id = request.query_params.get("session_id")
    _verify_session(session_id, api_key)
    await sse_transport.handle_post_message(
        request.scope, request.receive, request._send
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=MCP_HOST,
        port=MCP_PORT,
        reload=False,
        log_level="info",
    )
