from __future__ import annotations

import hashlib
import os
import re as _re
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from mcp.server import Server
from mcp.server.sse import SseServerTransport, TransportSecuritySettings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

import client as optix_client
from auth import optional_api_key
from models import HealthStatus
from prompts import register_prompts
import tools as _tools_module
from tools import register_tools, TOOL_REGISTRY

load_dotenv()

MCP_SERVER_VERSION = "1.0.0"
_START_TIME = time.monotonic()
OPTIX_API_URL = os.environ.get("OPTIX_API_URL", "https://optixthreatintelligence.co.uk")
MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "8090"))

# ---------------------------------------------------------------------------
# Rate limiting — sliding-window counters keyed by client IP.
#
# MCP_ANON_RATE_LIMIT  : max requests per minute for unauthenticated callers
#                        (default 20).  Set to 0 to disable.
# MCP_AUTH_RATE_LIMIT  : max requests per minute for authenticated callers
#                        (default 600 — effectively a safety ceiling only).
#                        Set to 0 to exempt authenticated callers entirely.
# MCP_TRUST_PROXY      : set to "true" / "1" / "yes" when the MCP server sits
#                        behind a trusted reverse proxy (e.g. nginx or the Node
#                        Express layer).  When enabled, the leftmost address in
#                        X-Forwarded-For is used as the rate-limit key so that
#                        all clients do not collapse to a single proxy IP.
#                        Leave unset (the default) when the server is directly
#                        reachable, to prevent IP spoofing via crafted headers.
# ---------------------------------------------------------------------------
_MCP_ANON_RATE_LIMIT: int = int(os.environ.get("MCP_ANON_RATE_LIMIT", "20"))
_MCP_AUTH_RATE_LIMIT: int = int(os.environ.get("MCP_AUTH_RATE_LIMIT", "600"))
_MCP_TRUST_PROXY: bool = os.environ.get("MCP_TRUST_PROXY", "false").lower() in (
    "true", "1", "yes"
)
_RATE_WINDOW_SECONDS: float = 60.0

# ip -> deque of monotonic timestamps (one deque per IP per auth tier)
_anon_hits: dict[str, deque[float]] = {}
_auth_hits: dict[str, deque[float]] = {}

# Bound the number of tracked IPs to avoid unbounded memory growth.
_RATE_REGISTRY_MAX = 4096


def _prune_hits(hits: deque[float], now: float) -> None:
    """Remove timestamps that have fallen outside the sliding window."""
    while hits and now - hits[0] >= _RATE_WINDOW_SECONDS:
        hits.popleft()


def _check_rate(
    registry: dict[str, deque[float]],
    ip: str,
    limit: int,
) -> None:
    """Record a hit for *ip* and raise 429 if the limit is exceeded."""
    now = time.monotonic()
    if ip not in registry:
        if len(registry) >= _RATE_REGISTRY_MAX:
            # Evict the oldest-inserted entry to keep memory bounded.
            oldest = next(iter(registry))
            del registry[oldest]
        registry[ip] = deque()
    hits = registry[ip]
    _prune_hits(hits, now)
    if len(hits) >= limit:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too Many Requests",
                "detail": (
                    f"Anonymous MCP connections are limited to {limit} per minute "
                    "per IP address. Provide a valid X-API-Key to raise this limit."
                    if registry is _anon_hits
                    else f"Authenticated MCP connections are limited to {limit} per minute per IP address."
                ),
            },
            headers={"Retry-After": str(int(_RATE_WINDOW_SECONDS))},
        )
    hits.append(now)


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
register_prompts(mcp_server)

sse_transport = SseServerTransport("/mcp/messages", security_settings=_security_settings)

# Streamable HTTP session manager for modern MCP clients (Smithery, Claude.ai, etc.).
# json_response=True returns compact JSON per POST (rather than SSE stream per response),
# which is the most broadly compatible option for scanners and proxied deployments.
# stateless=False keeps a live MCP session per mcp-session-id so tool results and
# conversation context are accessible across turns (multi-turn Claude.ai / Smithery).
# session_idle_timeout evicts sessions that have received no traffic for 30 minutes,
# bounding memory consumption without any manual cleanup code.
# ClosedResourceError from early-disconnect probes (e.g. Smithery manifest scans) is
# caught inside handle_request and suppressed in the endpoint below so it never
# propagates to the ASGI layer.
_streamable_manager = StreamableHTTPSessionManager(
    mcp_server,
    json_response=True,
    stateless=False,
    session_idle_timeout=1800,  # 30 minutes; evicts abandoned sessions automatically
)

# anyio exception types that indicate the client closed the connection before we
# finished writing. These are raised by handle_request() when a probe or scanner
# (e.g. Smithery manifest scanner) disconnects immediately after sending the
# request body. We suppress them so uvicorn never sees an unhandled exception.
_CLOSED_RESOURCE_EXC_NAMES = frozenset(
    {"ClosedResourceError", "BrokenResourceError", "EndOfStream"}
)

_SESSION_REGISTRY_MAX = 2048
_session_owners: "OrderedDict[str, str]" = OrderedDict()


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode(), usedforsecurity=False).hexdigest()


def _register_session(session_id: str, key_hash: str) -> None:
    if len(_session_owners) >= _SESSION_REGISTRY_MAX:
        _session_owners.popitem(last=False)
    _session_owners[session_id] = key_hash


def _client_ip(request: Request) -> str:
    """Return the effective client IP for rate-limiting purposes.

    When MCP_TRUST_PROXY is enabled the leftmost value of X-Forwarded-For is
    used so that real client addresses are preserved when the server sits behind
    a trusted reverse proxy (e.g. the Node.js Express layer or nginx).
    When MCP_TRUST_PROXY is *not* set (the default) the raw ASGI client address
    is used to prevent IP spoofing via crafted X-Forwarded-For headers.
    """
    if _MCP_TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip() or "unknown"
    return request.client.host if request.client else "unknown"


async def _mcp_rate_limit(
    request: Request,
    api_key: str = Depends(optional_api_key),
) -> str:
    """FastAPI dependency that enforces per-IP rate limits on MCP endpoints.

    Anonymous callers (no API key) are subject to MCP_ANON_RATE_LIMIT requests
    per minute (default 20).  Authenticated callers are subject to
    MCP_AUTH_RATE_LIMIT requests per minute (default 600), which acts as a
    safety ceiling rather than a practical throttle.  Setting either limit to 0
    skips the check for that tier entirely.

    The check runs *before* any MCP transport code is invoked, so rejected
    requests never reach _streamable_manager or sse_transport.
    """
    ip = _client_ip(request)
    if api_key:
        if _MCP_AUTH_RATE_LIMIT > 0:
            _check_rate(_auth_hits, ip, _MCP_AUTH_RATE_LIMIT)
    else:
        if _MCP_ANON_RATE_LIMIT > 0:
            _check_rate(_anon_hits, ip, _MCP_ANON_RATE_LIMIT)
    return api_key


async def _require_localhost(request: Request) -> None:
    """Dependency that restricts access to requests originating from localhost only.

    Applied to unauthenticated internal-only endpoints (e.g. /admin/tools).
    The MCP server binds to 127.0.0.1, so this guard is a belt-and-suspenders
    check ensuring unauthenticated routes are never reachable from external IPs
    even if port-forwarding or proxy config changes.
    """
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(
            status_code=403,
            detail={"error": "This endpoint is internal and not accessible externally."},
        )


def _key_hash_or_sentinel(api_key: str) -> str:
    """Return the SHA-256 hash of api_key, or the sentinel '' for anonymous callers."""
    return _hash_key(api_key) if api_key else ""


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
    caller_hash = _key_hash_or_sentinel(api_key)
    # '' == '' for anonymous ↔ anonymous; hash == hash for authenticated.
    # Mismatches (anon trying an authenticated session, or vice versa) are rejected.
    if expected != caller_hash:
        raise HTTPException(
            status_code=403,
            detail={"error": "API key does not match the session owner"},
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-populate TOOL_REGISTRY at startup so /admin/tools is ready before
    # any MCP client connects. We read _preload_tools_fn from the tools module
    # at runtime (not at import time) to pick up the value set by register_tools().
    try:
        preloader = getattr(_tools_module, "_preload_tools_fn", None)
        if callable(preloader):
            await preloader()
    except Exception:
        pass
    # The streamable HTTP session manager requires a live task group for its
    # internal lifecycle management (even in stateless mode).
    async with _streamable_manager.run():
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
        uptime_seconds=time.monotonic() - _START_TIME,
    )


@app.get("/admin/tools", tags=["Admin"])
async def admin_tools(_: None = Depends(_require_localhost)) -> list[dict]:
    """
    Internal endpoint — returns the registered tool list as plain JSON without
    requiring an MCP session or API key authentication. Only accessible from
    the Node.js Express layer (127.0.0.1 proxy), never exposed directly to the
    public internet.
    """
    return [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema,
        }
        for t in TOOL_REGISTRY
    ]


@app.get("/mcp", tags=["MCP"])
async def mcp_sse_endpoint(request: Request, api_key: str = Depends(_mcp_rate_limit)):
    """
    SSE endpoint for MCP clients (Claude Desktop, Cursor, etc.).
    Opening a connection and listing tools requires no credentials; invoking
    a tool requires a valid X-API-Key (enforced at the MCP layer).  The session
    is bound to the key used at open-time — subsequent POST /mcp/messages
    requests are only accepted with the same key (or no key for anonymous sessions).
    """
    key_hash = _key_hash_or_sentinel(api_key)

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


@app.post("/mcp", tags=["MCP"])
async def mcp_streamable_endpoint(request: Request, api_key: str = Depends(_mcp_rate_limit)):
    """
    Streamable HTTP endpoint for modern MCP clients (Smithery, Claude.ai, etc.).
    Uses the MCP 2025-03-26 streamable HTTP transport.

    initialize and tools/list are open to unauthenticated callers so that
    scanners (Smithery, Claude.ai discovery) can see the tool manifest without
    credentials.  Tool invocation is gated at the MCP layer by get_current_api_key().

    Session-owner binding: anonymous sessions (sentinel '') only accept messages
    without a key; authenticated sessions only accept the original key hash.
    Mismatches are rejected with 403 before reaching the transport layer.

    ClosedResourceError / BrokenResourceError / EndOfStream are suppressed here —
    they arise when a client (e.g. Smithery manifest scanner) closes the TCP
    connection before the response is fully written.
    """
    key_hash = _key_hash_or_sentinel(api_key)
    incoming_sid = request.headers.get("mcp-session-id")

    # Verify ownership of an existing session before forwarding the request.
    if incoming_sid is not None:
        expected = _session_owners.get(incoming_sid)
        if expected is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "Session not found — it may have expired or never been opened"},
            )
        if expected != key_hash:
            raise HTTPException(
                status_code=403,
                detail={"error": "API key does not match the session owner"},
            )

    # Intercept response to capture the mcp-session-id assigned by the manager
    # and register the owner so subsequent requests can be verified.
    async def _tracking_send(message: object) -> None:
        if isinstance(message, dict) and message.get("type") == "http.response.start":
            for name, value in message.get("headers", []):
                if name.lower() == b"mcp-session-id":
                    sid = value.decode()
                    if sid not in _session_owners:
                        _register_session(sid, key_hash)
                    break
        await request._send(message)

    try:
        await _streamable_manager.handle_request(
            request.scope, request.receive, _tracking_send
        )
    except BaseException as exc:
        if type(exc).__name__ in _CLOSED_RESOURCE_EXC_NAMES:
            return
        raise


@app.post("/mcp/messages", tags=["MCP"])
async def mcp_post_messages(request: Request, api_key: str = Depends(optional_api_key)):
    """
    Receives POST messages from MCP clients linked to an existing SSE session.
    Verifies that the key (or lack of key) matches the one used to open the
    target SSE session (session-to-owner binding).  Unauthenticated messages
    are accepted for anonymous sessions; authenticated messages are accepted only
    when the key hash matches the session owner recorded at open-time.
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
