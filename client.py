from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Optional

import httpx

from exceptions import OptixApiError, OptixAuthError, OptixCreditError, OptixNotFoundError
from models import (
    AccountStatus,
    AttackMatrixEntry,
    AttackMatrixResult,
    CoverageGap,
    CoverageGapsResult,
    CreditStatus,
    DetectionRule,
    Document,
    DocumentPage,
    Entity,
    EntityQueryResult,
    HeadlinesResult,
    Headline,
    IOCContext,
    IncidentConfirmation,
    Indicator,
    IntelligenceReport,
    IntelligenceReportPage,
    ResearchJobResult,
    SavedView,
    SearchHit,
    SearchResponse,
    ThreatCard,
    ThreatFeedEntry,
    ThreatFeedPage,
    TradecraftQueryResult,
    TriageResult,
    VoteResult,
    WatchlistAction,
    WatchlistEntry,
)

OPTIX_API_URL = os.environ.get("OPTIX_API_URL", "http://localhost:5000")
REQUEST_TIMEOUT = float(os.environ.get("OPTIX_REQUEST_TIMEOUT", "30"))


def _severity_from_score(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _build_headers(api_key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


async def _get(
    api_key: str,
    path: str,
    params: Optional[dict[str, Any]] = None,
) -> Any:
    url = f"{OPTIX_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, headers=_build_headers(api_key), params=params)
    except httpx.TimeoutException as exc:
        raise OptixApiError(f"OPTIX request timed out: {exc}", 504)
    except httpx.RequestError as exc:
        raise OptixApiError(f"OPTIX is unreachable: {exc}", 502)

    if resp.status_code == 401:
        raise OptixAuthError("API key rejected by OPTIX backend", 401)
    if resp.status_code == 403:
        raise OptixAuthError("Insufficient permissions for this operation", 403)
    if resp.status_code == 404:
        raise OptixNotFoundError()
    if not resp.is_success:
        try:
            detail = resp.json().get("message") or resp.json().get("error") or resp.text[:200]
        except Exception:
            detail = resp.text[:200]
        raise OptixApiError(f"OPTIX error {resp.status_code}: {detail}", 502)

    return resp.json()


async def _post(
    api_key: str,
    path: str,
    body: dict[str, Any],
) -> Any:
    url = f"{OPTIX_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.post(url, headers=_build_headers(api_key), json=body)
    except httpx.TimeoutException as exc:
        raise OptixApiError(f"OPTIX request timed out: {exc}", 504)
    except httpx.RequestError as exc:
        raise OptixApiError(f"OPTIX is unreachable: {exc}", 502)

    if resp.status_code == 401:
        raise OptixAuthError("API key rejected by OPTIX backend", 401)
    if resp.status_code == 403:
        raise OptixAuthError("Insufficient permissions for this operation", 403)
    if resp.status_code == 402:
        try:
            body_data = resp.json()
            balance = int(body_data.get("balance", 0))
            required = int(body_data.get("required", 40))
        except Exception:
            balance, required = 0, 40
        raise OptixCreditError(balance=balance, required=required)
    if not resp.is_success:
        try:
            body_data = resp.json()
            detail = body_data.get("message") or body_data.get("error") or resp.text[:200]
        except Exception:
            detail = resp.text[:200]
        raise OptixApiError(f"OPTIX error {resp.status_code}: {detail}", 502)

    return resp.json()


async def _delete(
    api_key: str,
    path: str,
    params: Optional[dict[str, Any]] = None,
) -> Any:
    url = f"{OPTIX_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.delete(url, headers=_build_headers(api_key), params=params)
    except httpx.TimeoutException as exc:
        raise OptixApiError(f"OPTIX request timed out: {exc}", 504)
    except httpx.RequestError as exc:
        raise OptixApiError(f"OPTIX is unreachable: {exc}", 502)

    if resp.status_code == 401:
        raise OptixAuthError("API key rejected by OPTIX backend", 401)
    if resp.status_code == 403:
        raise OptixAuthError("Insufficient permissions for this operation", 403)
    if resp.status_code == 404:
        raise OptixNotFoundError()
    if not resp.is_success:
        try:
            detail = resp.json().get("message") or resp.json().get("error") or resp.text[:200]
        except Exception:
            detail = resp.text[:200]
        raise OptixApiError(f"OPTIX error {resp.status_code}: {detail}", 502)

    try:
        return resp.json()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Credit status
# ---------------------------------------------------------------------------

async def get_credit_status(api_key: str) -> AccountStatus:
    try:
        data = await _get(api_key, "/api/user/credit-status")
    except OptixApiError:
        data = {}

    is_exempt = data.get("isExempt") or data.get("isInfinite") or False
    is_org_pool = data.get("isOrgPool") or False
    balance = data.get("balance")
    allocation = data.get("allocation")
    used = data.get("usedThisMonth")
    reset_date = data.get("resetDate")

    tier: Optional[str] = None
    if allocation == 20:
        tier = "free"
    elif allocation == 150:
        tier = "individual"
    elif allocation == 500:
        tier = "team"
    elif allocation == 1500:
        tier = "enterprise"

    credit = CreditStatus(
        balance=int(balance) if balance is not None else None,
        allocation=int(allocation) if allocation is not None else None,
        used_this_month=int(used) if used is not None else None,
        is_exempt=bool(is_exempt),
        is_org_pool=bool(is_org_pool),
        reset_date=str(reset_date) if reset_date else None,
        tier=tier,
    )

    return AccountStatus(
        credits=credit,
        org_id=None,
        report_cost=40,
    )


# ---------------------------------------------------------------------------
# Threat feed
# ---------------------------------------------------------------------------

async def get_threat_feed(
    api_key: str,
    limit: int = 20,
    offset: int = 0,
    severity_filter: Optional[str] = None,
    tlp_filter: Optional[str] = None,
    since: Optional[str] = None,
) -> ThreatFeedPage:
    page = max(1, (offset // limit) + 1) if limit > 0 else 1
    params: dict[str, Any] = {
        "feed": "true",
        "page": page,
        "limit": min(limit, 100),
        "sortBy": "date",
        "sortDir": "desc",
    }
    if since:
        params["publishedAfter"] = since
    if severity_filter:
        score_map = {"critical": 0.8, "high": 0.6, "medium": 0.4, "low": 0.0}
        score_min = score_map.get(severity_filter.lower())
        if score_min is not None:
            params["scoreMin"] = score_min

    data = await _get(api_key, "/api/documents", params)

    raw_items: list[dict[str, Any]] = []
    total = 0
    if isinstance(data, dict):
        raw_items = data.get("data", data.get("documents", []))
        total = data.get("total", len(raw_items))
    elif isinstance(data, list):
        raw_items = data
        total = len(data)

    def _resolve_tlp(doc: dict[str, Any]) -> str:
        _CLEAR_ALIASES = {"TLP:CLEAR", "TLP:WHITE"}
        for field in ("tlp", "tlpLevel", "tlp_level", "tlpLabel"):
            raw = doc.get(field)
            if raw and isinstance(raw, str):
                normalized = raw.upper().strip()
                return "TLP:WHITE" if normalized in _CLEAR_ALIASES else normalized
        sharing = doc.get("sharingScope") or doc.get("sharing_scope") or ""
        if sharing == "public":
            return "TLP:WHITE"
        if sharing == "org":
            return "TLP:GREEN"
        return "TLP:AMBER"

    items: list[ThreatFeedEntry] = []
    for doc in raw_items:
        score = float(doc.get("cyberScore") or doc.get("cyber_score") or 0.0)
        severity = _severity_from_score(score)
        if severity_filter and severity != severity_filter.lower():
            continue

        tlp_val = _resolve_tlp(doc)

        if tlp_filter and tlp_val != tlp_filter.upper():
            continue

        entities = doc.get("entities") or []
        ioc_count = len([e for e in entities if isinstance(e, dict) and e.get("type") == "IOC"])

        items.append(
            ThreatFeedEntry(
                id=doc["id"],
                title=doc.get("title") or "Untitled",
                severity=severity,
                tlp=tlp_val,
                ioc_count=ioc_count,
                published_at=_parse_dt(doc.get("publishedAt") or doc.get("published_at")),
                ingested_at=_parse_dt(doc.get("ingestedAt") or doc.get("ingested_at")) or datetime.utcnow(),
                source=doc.get("publisher"),
                summary=doc.get("summary"),
                cyber_score=score,
                url=doc.get("url"),
                content_types=doc.get("contentTypes") or doc.get("content_types") or [],
            )
        )

    return ThreatFeedPage(
        items=items,
        total=total,
        page=page,
        limit=limit,
        has_more=(page * limit) < total,
    )


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------

async def search_indicator(
    api_key: str,
    value: str,
    type_hint: Optional[str] = None,
) -> list[Indicator]:
    params: dict[str, Any] = {"q": value, "limit": 20}
    if type_hint:
        params["type"] = type_hint

    data = await _get(api_key, "/api/entities/search", params)

    results: list[dict[str, Any]] = []
    if isinstance(data, dict):
        results = data.get("results", [])
    elif isinstance(data, list):
        results = data

    _INDICATOR_TYPES = frozenset(
        ["IOC", "IP", "DOMAIN", "HASH", "URL", "EMAIL", "INDICATOR", "INFRASTRUCTURE"]
    )

    indicators: list[Indicator] = []
    for ent in results:
        ent_type = ent.get("type") or ""
        ent_type_upper = ent_type.upper()

        is_indicator = any(t in ent_type_upper for t in _INDICATOR_TYPES)

        if type_hint:
            if ent_type.upper() != type_hint.upper():
                continue
        elif not is_indicator:
            continue

        linked_docs = []
        if ent.get("documentId"):
            linked_docs = [ent["documentId"]]

        aliases = ent.get("aliases") or []
        if isinstance(aliases, str):
            try:
                import json as _json
                aliases = _json.loads(aliases)
            except Exception:
                aliases = []

        indicators.append(
            Indicator(
                id=ent["id"],
                value=ent.get("name") or value,
                type=ent_type or "IOC",
                confidence=float(ent.get("confidence") or 0.5),
                first_seen=_parse_dt(ent.get("firstSeen") or ent.get("first_seen")),
                last_seen=_parse_dt(ent.get("lastSeen") or ent.get("last_seen")),
                tags=[],
                tlp=None,
                linked_report_ids=linked_docs,
                description=ent.get("description"),
            )
        )

    return indicators


# ---------------------------------------------------------------------------
# Incident reporting
# ---------------------------------------------------------------------------

_TLP_MAP: dict[str, str] = {
    "TLP:WHITE": "TLP:CLEAR",
    "TLP:CLEAR": "TLP:CLEAR",
    "TLP:GREEN": "TLP:GREEN",
    "TLP:AMBER": "TLP:AMBER",
}


async def report_incident(
    api_key: str,
    title: str,
    description: str,
    severity: str,
    tlp: str = "TLP:GREEN",
    indicators: Optional[list[str]] = None,
    analyst_notes: Optional[str] = None,
) -> IncidentConfirmation:
    ioc_list = indicators or []

    query_parts: list[str] = [
        f"Severity: {severity.upper()}",
        description,
    ]
    if analyst_notes:
        query_parts.append(f"Analyst notes: {analyst_notes}")
    if ioc_list:
        query_parts.append("Indicators: " + ", ".join(ioc_list))

    query = "\n\n".join(query_parts)

    optix_tlp = _TLP_MAP.get(tlp.upper())
    if optix_tlp is None:
        valid = ", ".join(_TLP_MAP.keys())
        raise OptixApiError(
            f"Unsupported TLP level '{tlp}' for incident reports. "
            f"OPTIX accepts: {valid}.",
            400,
        )

    body: dict[str, Any] = {
        "title": title,
        "query": query,
        "reportType": "tactical",
        "tlpLevel": optix_tlp,
        "contextMode": "optix_only",
    }

    data = await _post(api_key, "/api/intelligence-reports/generate", body)

    report_id = data.get("reportId") or data.get("id")
    if not report_id:
        raise OptixApiError(
            "OPTIX did not return a report ID — the incident may not have been saved",
            502,
        )
    status = data.get("status", "generating")

    return IncidentConfirmation(
        reference_id=int(report_id),
        status=status,
        created_at=datetime.utcnow(),
        title=title,
    )


# ---------------------------------------------------------------------------
# Entity lookup
# ---------------------------------------------------------------------------

async def get_entity(
    api_key: str,
    query: str,
    entity_type: Optional[str] = None,
) -> Entity:
    params: dict[str, Any] = {"q": query, "limit": 5}
    if entity_type:
        params["type"] = entity_type

    search_data = await _get(api_key, "/api/entities/search", params)

    results: list[dict[str, Any]] = []
    if isinstance(search_data, dict):
        results = search_data.get("results", [])
    elif isinstance(search_data, list):
        results = search_data

    if not results:
        try:
            entity_id = int(query)
            ent = await _get(api_key, f"/api/entities/{entity_id}")
            return _map_entity(ent)
        except (ValueError, TypeError):
            raise OptixNotFoundError(
                f"No entity found matching '{query}'" + (f" with type '{entity_type}'" if entity_type else "")
            )

    best = results[0]
    ent = await _get(api_key, f"/api/entities/{best['id']}")
    return _map_entity(ent)


def _map_entity(ent: dict[str, Any]) -> Entity:
    aliases = ent.get("aliases") or []
    if isinstance(aliases, str):
        try:
            import json
            aliases = json.loads(aliases)
        except Exception:
            aliases = []

    metadata = ent.get("metadata") or {}

    ioc_names: list[str] = []
    if isinstance(metadata, dict):
        for key in ("iocType", "infrastructure", "c2Protocol"):
            val = metadata.get(key)
            if val and isinstance(val, str):
                ioc_names.append(val)

    return Entity(
        id=ent["id"],
        name=ent.get("name") or "Unknown",
        type=ent.get("type") or "Unknown",
        description=ent.get("description"),
        confidence=float(ent.get("confidence") or 0.5),
        first_seen=_parse_dt(ent.get("firstSeen") or ent.get("first_seen")),
        last_seen=_parse_dt(ent.get("lastSeen") or ent.get("last_seen")),
        associated_iocs=ioc_names,
        aliases=aliases if isinstance(aliases, list) else [],
        metadata=metadata if isinstance(metadata, dict) else {},
    )


# ---------------------------------------------------------------------------
# Health probe
# ---------------------------------------------------------------------------

async def probe_health(api_key: Optional[str] = None) -> bool:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            resp = await client.get(f"{OPTIX_API_URL}/api/sources", headers=headers)
            return resp.status_code < 500
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Document tools
# ---------------------------------------------------------------------------

def _map_document(doc: dict[str, Any]) -> Document:
    score = float(doc.get("cyberScore") or doc.get("cyber_score") or 0.0)
    entities = doc.get("entities") or []
    ioc_count = len([e for e in entities if isinstance(e, dict) and e.get("type") == "IOC"])
    return Document(
        id=doc["id"],
        title=doc.get("title") or "Untitled",
        url=doc.get("url"),
        publisher=doc.get("publisher"),
        published_at=_parse_dt(doc.get("publishedAt") or doc.get("published_at")),
        ingested_at=_parse_dt(doc.get("ingestedAt") or doc.get("ingested_at")),
        summary=doc.get("summary"),
        cyber_score=score,
        tlp=doc.get("tlp") or doc.get("tlpLevel"),
        severity=_severity_from_score(score),
        content_types=doc.get("contentTypes") or doc.get("content_types") or [],
        accepted=bool(doc.get("accepted")),
        quarantined=bool(doc.get("quarantined")),
        ioc_count=ioc_count,
    )


async def get_document(api_key: str, document_id: int) -> Document:
    data = await _get(api_key, f"/api/documents/{document_id}")
    return _map_document(data)


async def search_documents(
    api_key: str,
    query: str,
    limit: int = 20,
    offset: int = 0,
    publisher: Optional[str] = None,
    content_type: Optional[str] = None,
    since: Optional[str] = None,
) -> DocumentPage:
    params: dict[str, Any] = {
        "q": query,
        "limit": min(limit, 100),
        "offset": offset,
        "sortBy": "date",
        "sortDir": "desc",
    }
    if publisher:
        params["publisher"] = publisher
    if content_type:
        params["contentType"] = content_type
    if since:
        params["publishedAfter"] = since

    data = await _get(api_key, "/api/documents/search", params)

    raw_items: list[dict[str, Any]] = []
    total = 0
    if isinstance(data, dict):
        raw_items = data.get("data", data.get("documents", data.get("results", [])))
        total = data.get("total", len(raw_items))
    elif isinstance(data, list):
        raw_items = data
        total = len(data)

    items = [_map_document(d) for d in raw_items if isinstance(d, dict) and d.get("id")]
    return DocumentPage(items=items, total=total, has_more=(offset + limit) < total)


# ---------------------------------------------------------------------------
# Intelligence reports
# ---------------------------------------------------------------------------

def _map_intel_report(r: dict[str, Any]) -> IntelligenceReport:
    tlp = r.get("tlpLevel") or r.get("tlp")
    if tlp == "TLP:CLEAR":
        tlp = "TLP:WHITE"
    entity_ids = r.get("entityIds") or []
    if not isinstance(entity_ids, list):
        entity_ids = []
    return IntelligenceReport(
        id=r["id"],
        title=r.get("title") or "Untitled",
        report_type=r.get("reportType"),
        status=r.get("status") or "unknown",
        tlp_level=tlp,
        content=r.get("content"),
        summary=r.get("summary"),
        created_at=_parse_dt(r.get("createdAt") or r.get("created_at")),
        entity_ids=[int(e) for e in entity_ids if str(e).isdigit()],
    )


async def list_intelligence_reports(
    api_key: str,
    limit: int = 20,
    report_type: Optional[str] = None,
    tlp_level: Optional[str] = None,
    entity_id: Optional[int] = None,
) -> IntelligenceReportPage:
    params: dict[str, Any] = {"limit": min(limit, 200)}
    if report_type:
        params["reportType"] = report_type
    if tlp_level:
        params["tlpLevel"] = tlp_level
    if entity_id is not None:
        params["entityId"] = entity_id

    data = await _get(api_key, "/api/intelligence-reports", params)

    raw: list[dict[str, Any]] = data if isinstance(data, list) else data.get("reports", [])
    items = [_map_intel_report(r) for r in raw if isinstance(r, dict) and r.get("id")]
    return IntelligenceReportPage(items=items, total=len(items))


async def get_intelligence_report(api_key: str, report_id: int) -> IntelligenceReport:
    data = await _get(api_key, f"/api/intelligence-reports/{report_id}")
    return _map_intel_report(data)


async def generate_report(
    api_key: str,
    title: str,
    query: str,
    report_type: str = "tactical",
    tlp: str = "TLP:GREEN",
) -> IncidentConfirmation:
    optix_tlp = _TLP_MAP.get(tlp.upper(), "TLP:GREEN")
    body: dict[str, Any] = {
        "title": title,
        "query": query,
        "reportType": report_type,
        "tlpLevel": optix_tlp,
        "contextMode": "optix_only",
    }
    data = await _post(api_key, "/api/intelligence-reports/generate", body)
    report_id = data.get("reportId") or data.get("id")
    if not report_id:
        raise OptixApiError("OPTIX did not return a report ID", 502)
    return IncidentConfirmation(
        reference_id=int(report_id),
        status=data.get("status", "generating"),
        created_at=datetime.utcnow(),
        title=title,
    )


# ---------------------------------------------------------------------------
# Attack matrix
# ---------------------------------------------------------------------------

async def get_attack_matrix(
    api_key: str,
    technique_id: Optional[str] = None,
) -> AttackMatrixResult:
    if technique_id:
        data = await _get(api_key, f"/api/attack-matrix/{technique_id}")
        entry = AttackMatrixEntry(
            technique_id=data.get("techniqueId") or technique_id,
            technique_name=data.get("techniqueName") or data.get("name"),
            tactic=data.get("tactic"),
            doc_count=int(data.get("docCount") or data.get("documentCount") or 0),
            has_coverage=bool(data.get("hasCoverage") or data.get("procedureCount", 0) > 0),
        )
        return AttackMatrixResult(
            total_techniques=1,
            covered=1 if entry.has_coverage else 0,
            gaps=0 if entry.has_coverage else 1,
            entries=[entry],
        )

    data = await _get(api_key, "/api/attack-matrix")
    raw_entries: list[dict[str, Any]] = []
    if isinstance(data, list):
        raw_entries = data
    elif isinstance(data, dict):
        raw_entries = data.get("techniques", data.get("entries", []))
        if not raw_entries:
            for tactic_group in data.get("tactics", []):
                raw_entries.extend(tactic_group.get("techniques", []))

    entries: list[AttackMatrixEntry] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        entries.append(AttackMatrixEntry(
            technique_id=item.get("techniqueId") or item.get("id"),
            technique_name=item.get("techniqueName") or item.get("name"),
            tactic=item.get("tactic"),
            doc_count=int(item.get("docCount") or item.get("documentCount") or 0),
            has_coverage=bool(item.get("hasCoverage") or int(item.get("procedureCount") or 0) > 0),
        ))

    covered = sum(1 for e in entries if e.has_coverage)
    return AttackMatrixResult(
        total_techniques=len(entries),
        covered=covered,
        gaps=len(entries) - covered,
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Watchlist
# ---------------------------------------------------------------------------

async def get_watchlist(api_key: str) -> list[WatchlistEntry]:
    data = await _get(api_key, "/api/watchlist")
    if isinstance(data, dict):
        data = data.get("items", [])
    entries: list[WatchlistEntry] = []
    for item in (data or []):
        if not isinstance(item, dict):
            continue
        entity = item.get("entity") or item
        entries.append(WatchlistEntry(
            entity_id=int(entity.get("id") or item.get("entityId") or 0),
            entity_name=entity.get("name") or "Unknown",
            entity_type=entity.get("type") or "Unknown",
            watched_at=_parse_dt(item.get("watchedAt") or item.get("createdAt")),
        ))
    return entries


async def add_to_watchlist(api_key: str, entity_id: int) -> WatchlistAction:
    data = await _post(api_key, f"/api/watchlist/{entity_id}", {})
    watching = bool(data.get("watching", True))
    return WatchlistAction(
        entity_id=entity_id,
        watching=watching,
        message=f"Entity {entity_id} is now on your watchlist.",
    )


async def remove_from_watchlist(api_key: str, entity_id: int) -> WatchlistAction:
    data = await _delete(api_key, f"/api/watchlist/{entity_id}")
    watching = bool(data.get("watching", False))
    return WatchlistAction(
        entity_id=entity_id,
        watching=watching,
        message=f"Entity {entity_id} has been removed from your watchlist.",
    )


# ---------------------------------------------------------------------------
# Headlines
# ---------------------------------------------------------------------------

async def get_headlines(api_key: str) -> HeadlinesResult:
    data = await _get(api_key, "/api/headlines")
    raw_headlines: list[Any] = data.get("headlines") or []
    headlines: list[Headline] = []
    for h in raw_headlines:
        if isinstance(h, dict):
            headlines.append(Headline(
                text=h.get("text") or "",
                entity_names=h.get("entityNames") or [],
            ))
        elif isinstance(h, str):
            headlines.append(Headline(text=h, entity_names=[]))
    return HeadlinesResult(
        headlines=headlines,
        generated_at=data.get("generatedAt"),
        card_count=int(data.get("cardCount") or 0),
        stale=bool(data.get("stale", False)),
    )


# ---------------------------------------------------------------------------
# Threat cards
# ---------------------------------------------------------------------------

async def get_threat_cards(
    api_key: str,
    time_range: str = "7d",
    sector: Optional[str] = None,
) -> list[ThreatCard]:
    params: dict[str, Any] = {"range": time_range}
    if sector:
        params["sector"] = sector

    data = await _get(api_key, "/api/threat-cards", params)

    raw: list[dict[str, Any]] = data if isinstance(data, list) else data.get("cards", [])
    cards: list[ThreatCard] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        entity = item.get("entity") or {}
        score = float(item.get("cyberScore") or item.get("score") or 0.0)
        techniques: list[str] = []
        for t in item.get("techniques") or []:
            if isinstance(t, dict):
                tid = t.get("attackId") or t.get("techniqueId") or t.get("id")
                if tid:
                    techniques.append(str(tid))
            elif isinstance(t, str):
                techniques.append(t)
        sectors: list[str] = []
        for s in item.get("sectors") or item.get("targetSectors") or []:
            sectors.append(s if isinstance(s, str) else str(s))
        cards.append(ThreatCard(
            id=item.get("id"),
            title=item.get("title") or entity.get("name") or "Unknown",
            entity_type=entity.get("type") or item.get("entityType"),
            entity_name=entity.get("name") or item.get("entityName"),
            doc_count=int(item.get("docCount") or item.get("documentCount") or 0),
            severity=_severity_from_score(score) if score else item.get("severity"),
            summary=item.get("summary") or item.get("description"),
            techniques=techniques,
            sectors=sectors,
        ))
    return cards


# ---------------------------------------------------------------------------
# Entity deep research (15 credits)
# ---------------------------------------------------------------------------

async def research_entity(
    api_key: str,
    entity_id: int,
    force_refresh: bool = False,
) -> ResearchJobResult:
    body: dict[str, Any] = {"forceRefresh": force_refresh}
    data = await _post(api_key, f"/api/entities/{entity_id}/deep-research", body)

    ent = await _get(api_key, f"/api/entities/{entity_id}")
    entity_name = ent.get("name") or f"Entity {entity_id}"

    existing = data.get("existingResearch") or data
    summary = existing.get("summary") or data.get("summary")

    return ResearchJobResult(
        research_id=data.get("researchId") or data.get("id"),
        entity_id=entity_id,
        entity_name=entity_name,
        status=data.get("status", "queued"),
        message=data.get("message"),
        summary=summary,
        steps=data.get("steps") or [],
    )


# ---------------------------------------------------------------------------
# Entity query / hunting rule (4 credits)
# ---------------------------------------------------------------------------

async def ask_entity(
    api_key: str,
    entity_id: int,
    language: str,
) -> EntityQueryResult:
    body: dict[str, Any] = {"language": language}
    data = await _post(api_key, f"/api/entities/{entity_id}/generate-entity-query", body)

    ent = await _get(api_key, f"/api/entities/{entity_id}")
    entity_name = ent.get("name") or f"Entity {entity_id}"

    query_text = (
        data.get("query")
        or data.get("huntingQuery")
        or data.get("rule")
        or data.get("content")
        or ""
    )
    notes = data.get("notes") or data.get("falsePositiveGuidance") or data.get("tuningNotes")
    siem_name = data.get("siemName") or data.get("languageName")

    return EntityQueryResult(
        entity_id=entity_id,
        entity_name=entity_name,
        language=language,
        siem_name=siem_name,
        query=query_text,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Detection rule generation (4 credits)
# ---------------------------------------------------------------------------

async def generate_detection_rule(
    api_key: str,
    technique_id: str,
    language: str,
    technique_name: Optional[str] = None,
    document_id: Optional[int] = None,
    entity_id: Optional[int] = None,
    custom_context: Optional[str] = None,
) -> DetectionRule:
    body: dict[str, Any] = {
        "techniqueId": technique_id,
        "language": language,
    }
    if technique_name:
        body["techniqueName"] = technique_name
    if document_id is not None:
        body["documentId"] = document_id
    if entity_id is not None:
        body["originEntityId"] = entity_id
    if custom_context:
        body["customContext"] = custom_context

    data = await _post(api_key, "/api/generate-detection-query", body)

    query_text = (
        data.get("query")
        or data.get("rule")
        or data.get("detection")
        or data.get("content")
        or ""
    )
    siem_name = data.get("siemName") or data.get("languageName")
    rule_name = data.get("ruleName") or data.get("title") or f"{technique_id} Detection ({language})"
    notes = data.get("notes") or data.get("falsePositiveGuidance") or data.get("tuningNotes")

    return DetectionRule(
        language=language,
        siem_name=siem_name,
        query=query_text,
        rule_name=rule_name,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Tradecraft / threat hunting query (4 credits)
# ---------------------------------------------------------------------------

async def generate_tradecraft_query(
    api_key: str,
    language: str,
    entity_name: str,
    entity_type: str,
    entity_id: Optional[int] = None,
    technique_entries: Optional[list[dict[str, Any]]] = None,
) -> TradecraftQueryResult:
    entries = technique_entries or []
    body: dict[str, Any] = {
        "language": language,
        "entries": entries,
        "entityName": entity_name,
        "entityType": entity_type,
    }
    if entity_id is not None:
        body["originEntityId"] = entity_id

    data = await _post(api_key, "/api/generate-tradecraft-query", body)

    query_text = (
        data.get("query")
        or data.get("rule")
        or data.get("content")
        or ""
    )
    siem_name = data.get("siemName") or data.get("languageName")
    notes = data.get("notes") or data.get("falsePositiveGuidance")

    return TradecraftQueryResult(
        language=language,
        siem_name=siem_name,
        query=query_text,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Document coverage-gap analysis (free read)
# ---------------------------------------------------------------------------

async def get_coverage_gaps(api_key: str, document_id: int) -> CoverageGapsResult:
    data = await _get(api_key, f"/api/documents/{document_id}/coverage-gaps")

    raw_techniques: list[dict[str, Any]] = data.get("techniques") or []
    gaps: list[CoverageGap] = []
    for t in raw_techniques:
        if not isinstance(t, dict):
            continue
        entity = t.get("entity") or t
        attack_id: Optional[str] = None
        name = entity.get("name") or t.get("techniqueName") or "Unknown"
        import re
        m = re.search(r"T\d{4}(?:\.\d{3})?", name)
        if m:
            attack_id = m.group(0)
        else:
            attack_id = t.get("attackId") or entity.get("attackId")
        procedure_count = int(t.get("procedureCount") or t.get("coverageCount") or 0)
        gaps.append(CoverageGap(
            technique_name=name,
            attack_id=attack_id,
            covered=procedure_count > 0,
            procedure_count=procedure_count,
        ))

    total = int(data.get("total") or len(gaps))
    gap_count = int(data.get("gapCount") or sum(1 for g in gaps if not g.covered))
    return CoverageGapsResult(
        document_id=document_id,
        gaps=gaps,
        total=total,
        gap_count=gap_count,
    )


# ---------------------------------------------------------------------------
# IOC context enrichment (free read)
# ---------------------------------------------------------------------------

async def get_ioc_context(api_key: str, ioc_id: int) -> IOCContext:
    data = await _get(api_key, f"/api/ioc-triage/{ioc_id}/context")

    entity = data.get("entity") or {}
    meta = entity.get("metadata") or {}
    if isinstance(meta, str):
        try:
            import json
            meta = json.loads(meta)
        except Exception:
            meta = {}

    tally = data.get("tally") or {}
    threat_ctx = data.get("threatContext") or {}

    def _names(lst: list[Any]) -> list[str]:
        return [
            e.get("name") or "" for e in (lst or [])
            if isinstance(e, dict) and e.get("name")
        ]

    tags_raw = data.get("tags") or []
    tag_names: list[str] = []
    for tag in tags_raw:
        if isinstance(tag, dict):
            tag_names.append(tag.get("tag") or tag.get("name") or "")
        elif isinstance(tag, str):
            tag_names.append(tag)
    tag_names = [t for t in tag_names if t]

    source_docs: list[int] = []
    for doc in data.get("entityDocuments") or data.get("sourceDocs") or []:
        if isinstance(doc, dict):
            did = doc.get("id") or doc.get("documentId")
            if did:
                source_docs.append(int(did))
        elif isinstance(doc, int):
            source_docs.append(doc)

    return IOCContext(
        ioc_id=ioc_id,
        ioc_name=entity.get("name") or f"IOC {ioc_id}",
        ioc_type=meta.get("iocType"),
        ioc_status=meta.get("iocStatus"),
        tally_malicious=int(tally.get("malicious") or tally.get("confirmedMalicious") or 0),
        tally_benign=int(tally.get("benign") or tally.get("confirmedBenign") or 0),
        tally_weight=float(tally.get("weight") or tally.get("score") or 0.0),
        related_actors=_names(threat_ctx.get("actors")),
        related_malware=_names(threat_ctx.get("malware")),
        related_techniques=_names(threat_ctx.get("techniques")),
        related_campaigns=_names(threat_ctx.get("campaigns")),
        source_document_ids=source_docs,
        tags=tag_names,
    )


# ---------------------------------------------------------------------------
# AI search (free)
# ---------------------------------------------------------------------------

async def ai_search(
    api_key: str,
    query: str,
    mode: str = "natural",
) -> SearchResponse:
    body: dict[str, Any] = {"query": query, "mode": mode}
    data = await _post(api_key, "/api/search", body)

    raw_docs: list[dict[str, Any]] = data.get("documents") or data.get("hits") or []
    hits: list[SearchHit] = []
    for doc in raw_docs:
        if not isinstance(doc, dict):
            continue
        hits.append(SearchHit(
            id=int(doc.get("id") or 0),
            title=doc.get("title") or "Untitled",
            url=doc.get("url"),
            publisher=doc.get("publisher"),
            snippet=doc.get("snippet") or doc.get("summary"),
            score=float(doc.get("score") or doc.get("cyberScore") or 0.0),
            published_at=_parse_dt(doc.get("publishedAt")),
            source=doc.get("source"),
        ))

    entities: list[dict[str, Any]] = data.get("entities") or []

    return SearchResponse(
        hits=hits,
        entities=entities,
        answer=data.get("answer"),
        confidence=data.get("confidence"),
        query=query,
    )


# ---------------------------------------------------------------------------
# Submit feedback / vote (free write)
# ---------------------------------------------------------------------------

async def submit_feedback(
    api_key: str,
    document_id: int,
    vote: str,
    scope: str = "platform",
) -> VoteResult:
    body: dict[str, Any] = {"vote": vote, "visibilityScope": scope}
    data = await _post(api_key, f"/api/documents/{document_id}/vote", body)
    return VoteResult(
        document_id=document_id,
        user_vote=data.get("userVote") or vote,
        upvotes=int(data.get("upvotes") or data.get("upCount") or 0),
        downvotes=int(data.get("downvotes") or data.get("downCount") or 0),
    )


# ---------------------------------------------------------------------------
# Save feed view (free write)
# ---------------------------------------------------------------------------

async def save_feed_view(
    api_key: str,
    name: str,
    filters: Optional[dict[str, Any]] = None,
) -> SavedView:
    body: dict[str, Any] = {"name": name, "filters": filters or {}}
    data = await _post(api_key, "/api/feed/saved-views", body)
    return SavedView(
        id=int(data.get("id") or 0),
        name=data.get("name") or name,
        filters=data.get("filters") or filters or {},
        created_at=_parse_dt(data.get("createdAt")),
    )


# ---------------------------------------------------------------------------
# IOC triage (free write)
# ---------------------------------------------------------------------------

async def triage_ioc(
    api_key: str,
    entity_ids: list[int],
    status: str,
    scope: str = "platform",
) -> TriageResult:
    body: dict[str, Any] = {
        "entityIds": entity_ids,
        "status": status,
        "visibilityScope": scope,
    }
    data = await _post(api_key, "/api/ioc-triage/bulk-update", body)
    return TriageResult(
        updated=int(data.get("updated") or len(entity_ids)),
        status=status,
        entity_ids=entity_ids,
    )
