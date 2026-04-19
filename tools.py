from __future__ import annotations

import json
from typing import Any

import mcp.types as types
from mcp.server import Server
from pydantic import ValidationError

import client as optix_client
from auth import get_current_api_key, get_current_auth, refresh_auth_balance
from exceptions import OptixApiError, OptixAuthError, OptixCreditError, OptixNotFoundError
from tool_inputs import (
    AddToWatchlistInput,
    AiSearchInput,
    AskEntityInput,
    GenerateDetectionRuleInput,
    GenerateReportInput,
    GenerateTradecraftQueryInput,
    GetAttackMatrixInput,
    GetCoverageGapsInput,
    GetDocumentInput,
    GetEntityInput,
    GetHeadlinesInput,
    GetIOCContextInput,
    GetIntelligenceReportInput,
    GetThreatCardsInput,
    GetThreatFeedInput,
    ListIntelligenceReportsInput,
    RemoveFromWatchlistInput,
    ReportIncidentInput,
    SaveFeedViewInput,
    SearchDocumentsInput,
    SearchIndicatorInput,
    SubmitFeedbackInput,
    TriageIOCInput,
    ResearchEntityInput,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIEM_LANG_CHOICES = (
    "kql, splunk_spl, s1ql_v1, s1ql_v2, crowdstrike, elastic_eql, "
    "exabeam, chronicle_yara_l, sigma, carbon_black, palo_alto_xql"
)


def _validation_error_text(exc: ValidationError) -> str:
    errors = exc.errors(include_url=False)
    messages = [f"{'.'.join(str(l) for l in e['loc'])}: {e['msg']}" for e in errors]
    return "Validation error — " + "; ".join(messages)


def _check_credits(required: int) -> None:
    """Fast-fail pre-flight: raise OptixCreditError when the cached balance is
    known to be insufficient, avoiding an unnecessary upstream round-trip.

    Skipped when the balance is unknown (None) or the account is exempt — in
    those cases OPTIX enforces limits server-side and returns 402 if needed.
    """
    try:
        ctx = get_current_auth()
    except Exception:
        return
    if ctx.is_credit_exempt:
        return
    if ctx.credit_balance is None:
        return
    if ctx.credit_balance < required:
        pool_note = " (shared org pool)" if ctx.is_org_pool else ""
        raise OptixCreditError(balance=ctx.credit_balance, required=required)


async def _refresh_balance(api_key: str) -> None:
    """Re-fetch credit balance after a successful credited operation so the
    cached auth context stays accurate throughout the session."""
    await refresh_auth_balance(api_key)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

def register_tools(server: Server) -> None:

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            # ------------------------------------------------------------------
            # 1. get_threat_feed
            # ------------------------------------------------------------------
            types.Tool(
                name="get_threat_feed",
                description=(
                    "Retrieve the OPTIX threat intelligence feed — a paginated stream of curated, "
                    "scored intelligence documents from all configured sources. Use this tool when "
                    "an analyst asks for recent threat reports, wants to browse new intelligence, "
                    "or needs to filter by severity or TLP classification. Each entry includes a "
                    "severity rating, TLP label, IOC count, publisher, and AI summary."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of entries to return (1–100). Default: 20.",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 100,
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Number of entries to skip for pagination. Default: 0.",
                            "default": 0,
                            "minimum": 0,
                        },
                        "severity_filter": {
                            "type": "string",
                            "description": "Filter by severity level. One of: critical, high, medium, low.",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "tlp_filter": {
                            "type": "string",
                            "description": "Filter by TLP classification. One of: TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED.",
                            "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"],
                        },
                        "since": {
                            "type": "string",
                            "description": "ISO 8601 datetime. Only return documents published after this time.",
                        },
                    },
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 2. search_indicator
            # ------------------------------------------------------------------
            types.Tool(
                name="search_indicator",
                description=(
                    "Search OPTIX for a specific indicator of compromise (IOC) by value or type. "
                    "Use this tool when an analyst provides an IP address, domain name, file hash, "
                    "URL, or email address and wants to know if OPTIX has seen it, with what confidence, "
                    "and which reports reference it."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "The indicator value to search for, e.g. '185.220.101.45', 'malicious-domain.ru'.",
                        },
                        "type_hint": {
                            "type": "string",
                            "description": "Optional entity type to narrow the search. Valid values: IOC, Infrastructure, ThreatActor, MalwareFamily.",
                        },
                    },
                    "required": ["value"],
                },
            ),

            # ------------------------------------------------------------------
            # 3. report_incident  [40 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="report_incident",
                description=(
                    "Submit a structured incident report to OPTIX and generate a tactical intelligence "
                    "report. Provide the incident title, description, severity, TLP, observed indicators, "
                    "and analyst notes. Returns a confirmation with the assigned reference ID. "
                    "NOTE: This operation costs 40 OPTIX credits. Call get_account_status first if "
                    "you are unsure whether the account has sufficient credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Short descriptive title for the incident.",
                            "minLength": 3,
                            "maxLength": 300,
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed narrative of the incident including the attack chain.",
                            "minLength": 10,
                        },
                        "severity": {
                            "type": "string",
                            "description": "Incident severity level.",
                            "enum": ["critical", "high", "medium", "low"],
                        },
                        "tlp": {
                            "type": "string",
                            "description": "TLP classification. Accepts TLP:WHITE, TLP:GREEN, or TLP:AMBER. Default: TLP:GREEN.",
                            "default": "TLP:GREEN",
                            "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"],
                        },
                        "indicators": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of raw indicator values observed during the incident.",
                        },
                        "analyst_notes": {
                            "type": "string",
                            "description": "Additional analyst context, hypotheses, or remediation steps.",
                        },
                    },
                    "required": ["title", "description", "severity"],
                },
            ),

            # ------------------------------------------------------------------
            # 4. get_entity
            # ------------------------------------------------------------------
            types.Tool(
                name="get_entity",
                description=(
                    "Fetch a named threat intelligence entity from OPTIX by name or numeric ID. "
                    "Use this when an analyst asks about a specific threat actor (e.g. 'APT28'), "
                    "malware family (e.g. 'LockBit'), campaign, vulnerability, or tool. "
                    "Returns a structured entity summary including description, confidence, aliases, "
                    "associated IOCs, and MITRE ATT&CK metadata."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Name or numeric ID of the entity. Examples: 'APT28', 'CVE-2023-44487', '42'.",
                            "minLength": 1,
                        },
                        "entity_type": {
                            "type": "string",
                            "description": "Optional type to narrow the search: ThreatActor, MalwareFamily, Tool, Campaign, Vulnerability, Technique, IOC, Infrastructure, Target.",
                        },
                    },
                    "required": ["query"],
                },
            ),

            # ------------------------------------------------------------------
            # 5. get_account_status
            # ------------------------------------------------------------------
            types.Tool(
                name="get_account_status",
                description=(
                    "Retrieve the current OPTIX account credit balance, monthly allocation, usage, "
                    "and account context. Use this before performing credit-consuming operations, "
                    "or when the analyst asks how many credits remain. Returns balance, allocation, "
                    "credits used this month, reset date, and whether the account uses a shared "
                    "organisational credit pool."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 6. get_document
            # ------------------------------------------------------------------
            types.Tool(
                name="get_document",
                description=(
                    "Fetch a specific intelligence document from OPTIX by its numeric ID. "
                    "Returns full document metadata including title, publisher, TLP, severity, "
                    "AI summary, cyber score, and content type tags."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "document_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX document identifier, e.g. 1042.",
                            "minimum": 1,
                        },
                    },
                    "required": ["document_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 7. search_documents
            # ------------------------------------------------------------------
            types.Tool(
                name="search_documents",
                description=(
                    "Full-text search across all OPTIX intelligence documents. Use this tool when an "
                    "analyst wants to find documents by keyword, topic, publisher, or content type. "
                    "Supports filtering by publisher and date range. Returns paginated document summaries."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search string, minimum 2 characters. Examples: 'LockBit', 'supply chain attack', 'CVE-2024-3400'.",
                            "minLength": 2,
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results to return (1–100). Default: 20.",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 100,
                        },
                        "offset": {
                            "type": "integer",
                            "description": "Results to skip for pagination. Default: 0.",
                            "default": 0,
                            "minimum": 0,
                        },
                        "publisher": {
                            "type": "string",
                            "description": "Filter by publisher name, e.g. 'Mandiant', 'CISA'.",
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Filter by content type tag: ThreatResearch, MalwareAnalysis, Vulnerability, etc.",
                        },
                        "since": {
                            "type": "string",
                            "description": "ISO 8601 datetime. Only return documents published after this time.",
                        },
                    },
                    "required": ["query"],
                },
            ),

            # ------------------------------------------------------------------
            # 8. list_intelligence_reports
            # ------------------------------------------------------------------
            types.Tool(
                name="list_intelligence_reports",
                description=(
                    "List intelligence reports stored in OPTIX. These are generated reports (tactical, "
                    "strategic, operational, technical, or RFI) created by analysts or automated "
                    "pipelines. Optionally filter by report type, TLP level, or linked entity."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum reports to return (1–200). Default: 20.",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 200,
                        },
                        "report_type": {
                            "type": "string",
                            "description": "Filter by type: tactical, strategic, technical, operational, rfi.",
                            "enum": ["tactical", "strategic", "technical", "operational", "rfi"],
                        },
                        "tlp_level": {
                            "type": "string",
                            "description": "Filter by TLP level, e.g. 'TLP:GREEN'.",
                        },
                        "entity_id": {
                            "type": "integer",
                            "description": "Filter to reports referencing this entity ID.",
                        },
                    },
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 9. get_intelligence_report
            # ------------------------------------------------------------------
            types.Tool(
                name="get_intelligence_report",
                description=(
                    "Retrieve a specific OPTIX intelligence report by its numeric ID, including "
                    "the full report content, status, TLP classification, and associated entities. "
                    "Use this after list_intelligence_reports to fetch the full text of a report."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "report_id": {
                            "type": "integer",
                            "description": "Numeric intelligence report identifier.",
                            "minimum": 1,
                        },
                    },
                    "required": ["report_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 10. get_attack_matrix
            # ------------------------------------------------------------------
            types.Tool(
                name="get_attack_matrix",
                description=(
                    "Retrieve the OPTIX MITRE ATT&CK coverage matrix showing which techniques "
                    "have been observed in intelligence data and which have existing detection rules. "
                    "Use this to understand detection coverage gaps or to look up a specific technique. "
                    "Returns overall coverage statistics and per-technique detail rows."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "Specific MITRE ATT&CK technique ID to look up, e.g. 'T1566'. Omit to get the full matrix.",
                        },
                    },
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 11. get_watchlist
            # ------------------------------------------------------------------
            types.Tool(
                name="get_watchlist",
                description=(
                    "List all threat actors, malware families, and other entities currently on "
                    "the analyst's OPTIX watchlist. Watchlisted entities trigger notifications when "
                    "new intelligence documents reference them."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 12. add_to_watchlist
            # ------------------------------------------------------------------
            types.Tool(
                name="add_to_watchlist",
                description=(
                    "Add an entity to the analyst's OPTIX watchlist so that new intelligence "
                    "documents mentioning it trigger notifications. Supply the numeric entity ID "
                    "(use get_entity to look up an entity ID from a name)."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX entity identifier to start watching.",
                            "minimum": 1,
                        },
                    },
                    "required": ["entity_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 13. remove_from_watchlist
            # ------------------------------------------------------------------
            types.Tool(
                name="remove_from_watchlist",
                description=(
                    "Remove an entity from the analyst's OPTIX watchlist to stop receiving "
                    "notifications about it. Supply the numeric entity ID."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX entity identifier to stop watching.",
                            "minimum": 1,
                        },
                    },
                    "required": ["entity_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 14. get_headlines
            # ------------------------------------------------------------------
            types.Tool(
                name="get_headlines",
                description=(
                    "Retrieve the current OPTIX threat intelligence headlines — a short list of "
                    "AI-synthesised sentences summarising the most active threats from recent "
                    "intelligence documents. Use when an analyst asks for a quick situational "
                    "awareness briefing or 'what's happening right now?'."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 15. get_threat_cards
            # ------------------------------------------------------------------
            types.Tool(
                name="get_threat_cards",
                description=(
                    "Retrieve profile-matched situational awareness threat cards from OPTIX. "
                    "Each card profiles an active threat actor or malware campaign and shows "
                    "observed MITRE ATT&CK techniques, targeted sectors, document count, and "
                    "a severity assessment. Supports 24h, 7d, and 30d time windows."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "string",
                            "description": "Time window for threat card generation: 24h, 7d, or 30d. Default: 7d.",
                            "enum": ["24h", "7d", "30d"],
                            "default": "7d",
                        },
                        "sector": {
                            "type": "string",
                            "description": "Filter cards to a specific sector, e.g. 'Finance', 'Healthcare'.",
                        },
                    },
                    "required": [],
                },
            ),

            # ------------------------------------------------------------------
            # 16. get_ioc_context
            # ------------------------------------------------------------------
            types.Tool(
                name="get_ioc_context",
                description=(
                    "Retrieve enriched community context for an IOC — including analyst vote tallies "
                    "(malicious vs benign), community-assigned tags, co-occurring threat actors and "
                    "malware families, associated ATT&CK techniques, and source documents. "
                    "Use this to assess an IOC's reputation and threat context."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ioc_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX entity identifier for the IOC. Use search_indicator to find the ID.",
                            "minimum": 1,
                        },
                    },
                    "required": ["ioc_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 17. get_coverage_gaps
            # ------------------------------------------------------------------
            types.Tool(
                name="get_coverage_gaps",
                description=(
                    "Analyse a specific intelligence document to identify MITRE ATT&CK techniques "
                    "it references and determine which lack detection rule coverage. Returns a "
                    "per-technique breakdown showing whether each technique has at least one "
                    "detection procedure, and counts the total coverage gaps."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "document_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX document identifier to analyse.",
                            "minimum": 1,
                        },
                    },
                    "required": ["document_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 18. ai_search
            # ------------------------------------------------------------------
            types.Tool(
                name="ai_search",
                description=(
                    "Natural language threat intelligence search across OPTIX documents and entities. "
                    "Use 'natural' mode to let OPTIX expand the query with AI-inferred synonyms, "
                    "aliases, and related terms before searching. Use 'keyword' mode for literal "
                    "matching. Returns ranked document hits, named entities, and optionally an "
                    "AI-synthesised answer."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=True,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Natural language question or keyword. Examples: 'What TTPs does APT29 use?', 'LockBit ransomware IOCs'.",
                            "minLength": 2,
                        },
                        "mode": {
                            "type": "string",
                            "description": "Search mode: 'natural' for AI-expanded NLP search (default), 'keyword' for literal matching.",
                            "enum": ["natural", "keyword"],
                            "default": "natural",
                        },
                    },
                    "required": ["query"],
                },
            ),

            # ------------------------------------------------------------------
            # 19. research_entity  [15 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="research_entity",
                description=(
                    "Trigger deep AI research on a specific OPTIX entity (threat actor, malware "
                    "family, vulnerability, tool, campaign, or technique). OPTIX crawls authoritative "
                    "sources, enriches the entity's profile with structured intelligence, and returns "
                    "a research summary. Supported entity types: ThreatActor, MalwareFamily, "
                    "Vulnerability, Tool, Campaign, Technique. "
                    "NOTE: This operation costs 15 OPTIX credits. Call get_account_status first if "
                    "you are unsure whether the account has sufficient credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX entity identifier. Use get_entity to find it.",
                            "minimum": 1,
                        },
                        "force_refresh": {
                            "type": "boolean",
                            "description": "Set true to force a new research run even if recent results exist. Default: false.",
                            "default": False,
                        },
                    },
                    "required": ["entity_id"],
                },
            ),

            # ------------------------------------------------------------------
            # 20. ask_entity  [4 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="ask_entity",
                description=(
                    "Generate a SIEM threat hunting query for a specific threat entity. Given an "
                    "entity ID (ThreatActor, MalwareFamily, Tool, or Vulnerability) and a target "
                    "SIEM language, OPTIX generates a comprehensive hunting query informed by the "
                    f"entity's known TTPs, IOCs, and intelligence history. "
                    f"Supported SIEM languages: {_SIEM_LANG_CHOICES}. "
                    "NOTE: This operation costs 4 OPTIX credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX entity identifier (ThreatActor, MalwareFamily, Tool, or Vulnerability).",
                            "minimum": 1,
                        },
                        "language": {
                            "type": "string",
                            "description": f"Target SIEM language. Supported: {_SIEM_LANG_CHOICES}.",
                        },
                    },
                    "required": ["entity_id", "language"],
                },
            ),

            # ------------------------------------------------------------------
            # 21. generate_detection_rule  [4 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="generate_detection_rule",
                description=(
                    "Generate a SIEM detection rule for a specific MITRE ATT&CK technique. "
                    "OPTIX creates a detection query in the requested SIEM language using available "
                    "intelligence context. Optionally enriches the rule with context from a specific "
                    "document or entity. "
                    f"Supported SIEM languages: {_SIEM_LANG_CHOICES}. "
                    "NOTE: This operation costs 4 OPTIX credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "technique_id": {
                            "type": "string",
                            "description": "MITRE ATT&CK technique ID, e.g. 'T1059.001' (PowerShell).",
                        },
                        "language": {
                            "type": "string",
                            "description": f"Target SIEM language. Supported: {_SIEM_LANG_CHOICES}.",
                        },
                        "technique_name": {
                            "type": "string",
                            "description": "Human-readable technique name, e.g. 'PowerShell'. Improves generation quality.",
                        },
                        "document_id": {
                            "type": "integer",
                            "description": "Optional document ID to incorporate document-specific detection context.",
                        },
                        "entity_id": {
                            "type": "integer",
                            "description": "Optional entity ID (ThreatActor or MalwareFamily) to enrich the rule.",
                        },
                        "custom_context": {
                            "type": "string",
                            "description": "Additional analyst context to guide generation, e.g. specific log sources or environment details.",
                        },
                    },
                    "required": ["technique_id", "language"],
                },
            ),

            # ------------------------------------------------------------------
            # 22. generate_tradecraft_query  [4 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="generate_tradecraft_query",
                description=(
                    "Generate a SIEM threat hunting query covering the complete known tradecraft "
                    "(TTPs, tools, behaviours) of a specific threat actor or malware family. "
                    "Unlike generate_detection_rule (which targets a single technique), this tool "
                    "produces a broad multi-technique hunt designed to surface any activity by the "
                    "named adversary. Optionally scope to specific technique entries. "
                    f"Supported SIEM languages: {_SIEM_LANG_CHOICES}. "
                    "NOTE: This operation costs 4 OPTIX credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "language": {
                            "type": "string",
                            "description": f"Target SIEM language. Supported: {_SIEM_LANG_CHOICES}.",
                        },
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the threat actor or malware family, e.g. 'APT29' or 'LockBit'.",
                        },
                        "entity_type": {
                            "type": "string",
                            "description": "Entity type: ThreatActor or MalwareFamily.",
                            "enum": ["ThreatActor", "MalwareFamily"],
                        },
                        "entity_id": {
                            "type": "integer",
                            "description": "Optional OPTIX entity ID to enrich the query with structured intelligence.",
                        },
                        "technique_entries": {
                            "type": "array",
                            "description": "Optional technique scope list. Each item may have techniqueId, techniqueName, description.",
                            "items": {"type": "object"},
                        },
                    },
                    "required": ["language", "entity_name", "entity_type"],
                },
            ),

            # ------------------------------------------------------------------
            # 23. generate_report  [40 credits]
            # ------------------------------------------------------------------
            types.Tool(
                name="generate_report",
                description=(
                    "Generate a strategic, operational, technical, or RFI intelligence report in "
                    "OPTIX using a natural language query. OPTIX searches its document corpus and "
                    "entity knowledge base to produce a structured, cited report. Returns a report "
                    "ID that can be retrieved with get_intelligence_report once generation completes. "
                    "NOTE: This operation costs 40 OPTIX credits. Call get_account_status first if "
                    "you are unsure whether the account has sufficient credits."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=True,
                    idempotentHint=False,
                    openWorldHint=True,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "Report title, e.g. 'Q3 Ransomware Threat Landscape'.",
                            "minLength": 3,
                            "maxLength": 300,
                        },
                        "query": {
                            "type": "string",
                            "description": "Natural language description of what the report should cover.",
                            "minLength": 10,
                        },
                        "report_type": {
                            "type": "string",
                            "description": "Report type: tactical, strategic, technical, operational, or rfi. Default: tactical.",
                            "enum": ["tactical", "strategic", "technical", "operational", "rfi"],
                            "default": "tactical",
                        },
                        "tlp": {
                            "type": "string",
                            "description": "TLP classification for the report. Default: TLP:GREEN.",
                            "enum": ["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"],
                            "default": "TLP:GREEN",
                        },
                    },
                    "required": ["title", "query"],
                },
            ),

            # ------------------------------------------------------------------
            # 24. submit_feedback
            # ------------------------------------------------------------------
            types.Tool(
                name="submit_feedback",
                description=(
                    "Submit a relevance vote (upvote or downvote) on an OPTIX intelligence document. "
                    "Upvotes signal that the document is relevant and valuable; downvotes signal it "
                    "is not relevant to the organisation's threat profile. Community votes improve "
                    "OPTIX scoring and feed personalisation over time."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "document_id": {
                            "type": "integer",
                            "description": "Numeric OPTIX document identifier to vote on.",
                            "minimum": 1,
                        },
                        "vote": {
                            "type": "string",
                            "description": "Vote direction: 'up' for relevant, 'down' for not relevant.",
                            "enum": ["up", "down"],
                        },
                        "scope": {
                            "type": "string",
                            "description": "Vote visibility: 'platform' (all analysts) or 'org' (your organisation only). Default: platform.",
                            "enum": ["platform", "org"],
                            "default": "platform",
                        },
                    },
                    "required": ["document_id", "vote"],
                },
            ),

            # ------------------------------------------------------------------
            # 25. save_feed_view
            # ------------------------------------------------------------------
            types.Tool(
                name="save_feed_view",
                description=(
                    "Save a named feed filter configuration in OPTIX so the analyst can recall it "
                    "later. For example: save a filter for 'critical ransomware last 7 days' with "
                    "severity=critical, contentType=ThreatResearch as a named view. Returns the "
                    "saved view ID and name."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Human-readable name for this saved view, e.g. 'Critical malware last 7 days'.",
                            "minLength": 1,
                            "maxLength": 200,
                        },
                        "filters": {
                            "type": "object",
                            "description": (
                                "Filter configuration to save. Common keys: severity, tlp, contentType, "
                                "publisher, publishedAfter, publishedBefore. Pass an empty object to save "
                                "a default view with no filters."
                            ),
                            "default": {},
                        },
                    },
                    "required": ["name"],
                },
            ),

            # ------------------------------------------------------------------
            # 26. triage_ioc
            # ------------------------------------------------------------------
            types.Tool(
                name="triage_ioc",
                description=(
                    "Apply a triage verdict to one or more IOCs in OPTIX. Triage decisions record "
                    "analyst judgement about whether an IOC is genuinely malicious, a false positive, "
                    "benign, expired, or under monitoring. Supports bulk operations on multiple IOC "
                    "entity IDs at once. Scope as 'platform' to share the decision globally or 'org' "
                    "to keep it within your organisation."
                ),
                annotations=types.ToolAnnotations(
                    readOnlyHint=False,
                    destructiveHint=False,
                    idempotentHint=True,
                    openWorldHint=False,
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "entity_ids": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "List of OPTIX entity IDs (IOCs) to triage. At least one required.",
                            "minItems": 1,
                        },
                        "status": {
                            "type": "string",
                            "description": (
                                "Triage verdict: confirmed (active malicious), false_positive, "
                                "benign (known good), expired (formerly active), monitoring, unresolved."
                            ),
                            "enum": ["confirmed", "false_positive", "expired", "benign", "monitoring", "unresolved"],
                        },
                        "scope": {
                            "type": "string",
                            "description": "Decision scope: 'platform' (global) or 'org' (organisation-only). Default: platform.",
                            "enum": ["platform", "org"],
                            "default": "platform",
                        },
                    },
                    "required": ["entity_ids", "status"],
                },
            ),
        ]

    # ---------------------------------------------------------------------------
    # Tool dispatcher
    # ---------------------------------------------------------------------------

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        try:
            api_key = get_current_api_key()
        except OptixAuthError as exc:
            return [types.TextContent(type="text", text=f"Authentication error: {exc.message}")]

        try:
            # ---- Original 5 tools ----------------------------------------

            if name == "get_threat_feed":
                params = GetThreatFeedInput.model_validate(arguments)
                result = await optix_client.get_threat_feed(
                    api_key=api_key,
                    limit=params.limit,
                    offset=params.offset,
                    severity_filter=params.severity_filter,
                    tlp_filter=params.tlp_filter,
                    since=params.since,
                )
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "search_indicator":
                params = SearchIndicatorInput.model_validate(arguments)
                indicators = await optix_client.search_indicator(
                    api_key=api_key,
                    value=params.value,
                    type_hint=params.type_hint,
                )
                output = json.dumps(
                    [ind.model_dump(mode="json") for ind in indicators],
                    indent=2,
                    default=str,
                )
                return [types.TextContent(type="text", text=output)]

            elif name == "report_incident":
                _check_credits(40)
                params = ReportIncidentInput.model_validate(arguments)
                confirmation = await optix_client.report_incident(
                    api_key=api_key,
                    title=params.title,
                    description=params.description,
                    severity=params.severity,
                    tlp=params.tlp,
                    indicators=params.indicators,
                    analyst_notes=params.analyst_notes,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=confirmation.model_dump_json(indent=2))]

            elif name == "get_entity":
                params = GetEntityInput.model_validate(arguments)
                entity = await optix_client.get_entity(
                    api_key=api_key,
                    query=params.query,
                    entity_type=params.entity_type,
                )
                return [types.TextContent(type="text", text=entity.model_dump_json(indent=2))]

            elif name == "get_account_status":
                account = await optix_client.get_credit_status(api_key=api_key)
                return [types.TextContent(type="text", text=account.model_dump_json(indent=2))]

            # ---- New free read tools ---------------------------------------

            elif name == "get_document":
                params = GetDocumentInput.model_validate(arguments)
                doc = await optix_client.get_document(api_key=api_key, document_id=params.document_id)
                return [types.TextContent(type="text", text=doc.model_dump_json(indent=2))]

            elif name == "search_documents":
                params = SearchDocumentsInput.model_validate(arguments)
                page = await optix_client.search_documents(
                    api_key=api_key,
                    query=params.query,
                    limit=params.limit,
                    offset=params.offset,
                    publisher=params.publisher,
                    content_type=params.content_type,
                    since=params.since,
                )
                return [types.TextContent(type="text", text=page.model_dump_json(indent=2))]

            elif name == "list_intelligence_reports":
                params = ListIntelligenceReportsInput.model_validate(arguments)
                page = await optix_client.list_intelligence_reports(
                    api_key=api_key,
                    limit=params.limit,
                    report_type=params.report_type,
                    tlp_level=params.tlp_level,
                    entity_id=params.entity_id,
                )
                return [types.TextContent(type="text", text=page.model_dump_json(indent=2))]

            elif name == "get_intelligence_report":
                params = GetIntelligenceReportInput.model_validate(arguments)
                report = await optix_client.get_intelligence_report(
                    api_key=api_key, report_id=params.report_id
                )
                return [types.TextContent(type="text", text=report.model_dump_json(indent=2))]

            elif name == "get_attack_matrix":
                params = GetAttackMatrixInput.model_validate(arguments)
                matrix = await optix_client.get_attack_matrix(
                    api_key=api_key, technique_id=params.technique_id
                )
                return [types.TextContent(type="text", text=matrix.model_dump_json(indent=2))]

            elif name == "get_watchlist":
                entries = await optix_client.get_watchlist(api_key=api_key)
                output = json.dumps(
                    [e.model_dump(mode="json") for e in entries], indent=2, default=str
                )
                return [types.TextContent(type="text", text=output)]

            elif name == "get_headlines":
                result = await optix_client.get_headlines(api_key=api_key)
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "get_threat_cards":
                params = GetThreatCardsInput.model_validate(arguments)
                cards = await optix_client.get_threat_cards(
                    api_key=api_key,
                    time_range=params.time_range,
                    sector=params.sector,
                )
                output = json.dumps(
                    [c.model_dump(mode="json") for c in cards], indent=2, default=str
                )
                return [types.TextContent(type="text", text=output)]

            elif name == "get_ioc_context":
                params = GetIOCContextInput.model_validate(arguments)
                ctx = await optix_client.get_ioc_context(api_key=api_key, ioc_id=params.ioc_id)
                return [types.TextContent(type="text", text=ctx.model_dump_json(indent=2))]

            elif name == "get_coverage_gaps":
                params = GetCoverageGapsInput.model_validate(arguments)
                result = await optix_client.get_coverage_gaps(
                    api_key=api_key, document_id=params.document_id
                )
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "ai_search":
                params = AiSearchInput.model_validate(arguments)
                result = await optix_client.ai_search(
                    api_key=api_key, query=params.query, mode=params.mode
                )
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            # ---- New credit-consuming tools --------------------------------

            elif name == "research_entity":
                _check_credits(15)
                params = ResearchEntityInput.model_validate(arguments)
                result = await optix_client.research_entity(
                    api_key=api_key,
                    entity_id=params.entity_id,
                    force_refresh=params.force_refresh,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "ask_entity":
                _check_credits(4)
                params = AskEntityInput.model_validate(arguments)
                result = await optix_client.ask_entity(
                    api_key=api_key,
                    entity_id=params.entity_id,
                    language=params.language,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "generate_detection_rule":
                _check_credits(4)
                params = GenerateDetectionRuleInput.model_validate(arguments)
                rule = await optix_client.generate_detection_rule(
                    api_key=api_key,
                    technique_id=params.technique_id,
                    language=params.language,
                    technique_name=params.technique_name,
                    document_id=params.document_id,
                    entity_id=params.entity_id,
                    custom_context=params.custom_context,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=rule.model_dump_json(indent=2))]

            elif name == "generate_tradecraft_query":
                _check_credits(4)
                params = GenerateTradecraftQueryInput.model_validate(arguments)
                result = await optix_client.generate_tradecraft_query(
                    api_key=api_key,
                    language=params.language,
                    entity_name=params.entity_name,
                    entity_type=params.entity_type,
                    entity_id=params.entity_id,
                    technique_entries=params.technique_entries,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "generate_report":
                _check_credits(40)
                params = GenerateReportInput.model_validate(arguments)
                confirmation = await optix_client.generate_report(
                    api_key=api_key,
                    title=params.title,
                    query=params.query,
                    report_type=params.report_type,
                    tlp=params.tlp,
                )
                await _refresh_balance(api_key)
                return [types.TextContent(type="text", text=confirmation.model_dump_json(indent=2))]

            # ---- New write tools (no credits) ------------------------------

            elif name == "add_to_watchlist":
                params = AddToWatchlistInput.model_validate(arguments)
                action = await optix_client.add_to_watchlist(
                    api_key=api_key, entity_id=params.entity_id
                )
                return [types.TextContent(type="text", text=action.model_dump_json(indent=2))]

            elif name == "remove_from_watchlist":
                params = RemoveFromWatchlistInput.model_validate(arguments)
                action = await optix_client.remove_from_watchlist(
                    api_key=api_key, entity_id=params.entity_id
                )
                return [types.TextContent(type="text", text=action.model_dump_json(indent=2))]

            elif name == "submit_feedback":
                params = SubmitFeedbackInput.model_validate(arguments)
                result = await optix_client.submit_feedback(
                    api_key=api_key,
                    document_id=params.document_id,
                    vote=params.vote,
                    scope=params.scope,
                )
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            elif name == "save_feed_view":
                params = SaveFeedViewInput.model_validate(arguments)
                view = await optix_client.save_feed_view(
                    api_key=api_key, name=params.name, filters=params.filters
                )
                return [types.TextContent(type="text", text=view.model_dump_json(indent=2))]

            elif name == "triage_ioc":
                params = TriageIOCInput.model_validate(arguments)
                result = await optix_client.triage_ioc(
                    api_key=api_key,
                    entity_ids=params.entity_ids,
                    status=params.status,
                    scope=params.scope,
                )
                return [types.TextContent(type="text", text=result.model_dump_json(indent=2))]

            else:
                return [types.TextContent(type="text", text=f"Error: Unknown tool '{name}'")]

        except ValidationError as exc:
            return [types.TextContent(type="text", text=_validation_error_text(exc))]
        except OptixAuthError as exc:
            return [types.TextContent(type="text", text=f"Authentication error: {exc.message}")]
        except OptixCreditError as exc:
            return [types.TextContent(
                type="text",
                text=(
                    f"Insufficient credits: {exc.message}\n\n"
                    "Use get_account_status to see your current balance and reset date."
                ),
            )]
        except OptixNotFoundError as exc:
            return [types.TextContent(type="text", text=f"Not found: {exc.message}")]
        except OptixApiError as exc:
            return [types.TextContent(type="text", text=f"OPTIX API error: {exc.message}")]
        except Exception as exc:
            return [types.TextContent(type="text", text=f"Unexpected error: {exc}")]
