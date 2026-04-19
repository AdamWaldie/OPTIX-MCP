from __future__ import annotations

import contextvars
import os
from typing import Optional

import httpx
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from exceptions import OptixAuthError
from models import AuthContext

OPTIX_API_URL = os.environ.get("OPTIX_API_URL", "https://optixthreatintelligence.co.uk")
OPTIX_INTERNAL_SECRET = os.environ.get("OPTIX_INTERNAL_SECRET", "")

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

current_auth: contextvars.ContextVar[Optional[AuthContext]] = contextvars.ContextVar(
    "current_auth", default=None
)
current_api_key: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "current_api_key", default=None
)


async def _validate_key_with_optix(api_key: str) -> AuthContext:
    """Validate an API key by calling /api/user/credit-status, which requires
    authentication (requireAuth middleware in OPTIX).  A 401/403 from that
    endpoint proves the key is invalid; a 2xx response simultaneously gives us
    the credit balance so we do not need a second round-trip.
    """
    if OPTIX_INTERNAL_SECRET and api_key == OPTIX_INTERNAL_SECRET:
        return AuthContext(
            api_key_id=0,
            api_key_name="internal",
            user_id=None,
            org_id=None,
            permissions=["*"],
            credit_balance=None,
            credit_allocation=None,
            is_credit_exempt=True,
            credit_reset_date=None,
            is_org_pool=False,
        )

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            # /api/user/credit-status is protected by requireAuth — a 401/403
            # here means the API key is genuinely rejected by OPTIX.
            resp = await client.get(
                f"{OPTIX_API_URL}/api/user/credit-status",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                },
            )
    except httpx.TimeoutException:
        raise OptixAuthError("OPTIX backend timed out during API key validation", 503)
    except httpx.RequestError as exc:
        raise OptixAuthError(f"Could not reach OPTIX backend: {exc}", 503)

    if resp.status_code == 401:
        raise OptixAuthError("Invalid or expired API key", 401)
    if resp.status_code == 403:
        raise OptixAuthError("API key is disabled or lacks permissions", 403)
    if resp.status_code == 429:
        raise OptixAuthError("API key rate limit exceeded", 429)
    if not resp.is_success:
        raise OptixAuthError(
            f"API key validation failed — OPTIX returned {resp.status_code}", 401
        )

    try:
        credit_data = resp.json()
    except Exception:
        credit_data = {}

    is_exempt = credit_data.get("isExempt") or credit_data.get("isInfinite") or False
    is_org_pool = credit_data.get("isOrgPool") or False
    balance = credit_data.get("balance")
    allocation = credit_data.get("allocation")
    reset_date = credit_data.get("resetDate")

    return AuthContext(
        api_key_id=0,
        api_key_name="api-key",
        user_id=None,
        org_id=None,
        permissions=[],
        credit_balance=int(balance) if balance is not None else None,
        credit_allocation=int(allocation) if allocation is not None else None,
        is_credit_exempt=bool(is_exempt),
        credit_reset_date=str(reset_date) if reset_date else None,
        is_org_pool=bool(is_org_pool),
    )


async def require_api_key(x_api_key: Optional[str] = Security(_api_key_header)) -> str:
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Missing API key",
                "detail": "Provide your OPTIX API key in the X-API-Key request header.",
                "docs": "See README.md for instructions on obtaining an API key.",
            },
        )
    try:
        auth_ctx = await _validate_key_with_optix(x_api_key)
        current_auth.set(auth_ctx)
        current_api_key.set(x_api_key)
        return x_api_key
    except OptixAuthError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "error": exc.message,
                "detail": "The supplied X-API-Key was rejected by the OPTIX backend.",
            },
        )


def get_current_api_key() -> str:
    key = current_api_key.get()
    if not key:
        raise OptixAuthError("No authenticated API key in current context", 401)
    return key


def get_current_auth() -> AuthContext:
    ctx = current_auth.get()
    if not ctx:
        raise OptixAuthError("No auth context in current request", 401)
    return ctx


async def refresh_auth_balance(api_key: str) -> None:
    """Re-fetch credit status from OPTIX and update the current auth context.

    Called after every successful credit-consuming operation so that subsequent
    calls to get_current_auth() reflect the post-deduction balance without
    requiring the analyst to call get_account_status explicitly.
    """
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(
                f"{OPTIX_API_URL}/api/user/credit-status",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                },
            )
        if not resp.is_success:
            return
        credit_data = resp.json()
        ctx = current_auth.get()
        if ctx is None:
            return
        balance = credit_data.get("balance")
        is_org_pool = credit_data.get("isOrgPool") or False
        updated = ctx.model_copy(update={
            "credit_balance": int(balance) if balance is not None else ctx.credit_balance,
            "is_org_pool": bool(is_org_pool),
        })
        current_auth.set(updated)
    except Exception:
        pass
