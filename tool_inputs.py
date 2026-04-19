from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class GetThreatFeedInput(BaseModel):
    model_config = ConfigDict(strict=True)

    limit: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of entries to return (1–100).",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Number of entries to skip for pagination.",
    )
    severity_filter: Optional[Literal["critical", "high", "medium", "low"]] = Field(
        default=None,
        description="Filter results to this severity level only.",
    )
    tlp_filter: Optional[
        Literal["TLP:WHITE", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]
    ] = Field(
        default=None,
        description="Filter results to this TLP classification only.",
    )
    since: Optional[str] = Field(
        default=None,
        description="ISO 8601 datetime. Return only documents published after this time.",
    )


class SearchIndicatorInput(BaseModel):
    model_config = ConfigDict(strict=True)

    value: str = Field(
        description=(
            "The indicator value to search for, e.g. '185.220.101.45', "
            "'malicious-domain.ru', 'd41d8cd98f00b204e9800998ecf8427e'."
        )
    )
    type_hint: Optional[str] = Field(
        default=None,
        description=(
            "Optional entity type to narrow the search. "
            "Valid values: IOC, Infrastructure, ThreatActor, MalwareFamily."
        ),
    )


class ReportIncidentInput(BaseModel):
    model_config = ConfigDict(strict=True)

    title: str = Field(
        description="Short descriptive title for the incident, e.g. 'Ransomware deployment via LNK dropper'.",
        min_length=3,
        max_length=300,
    )
    description: str = Field(
        description="Detailed narrative of the incident including the attack chain and analyst observations.",
        min_length=10,
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        description="Incident severity level.",
    )
    tlp: Literal["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"] = Field(
        default="TLP:GREEN",
        description=(
            "TLP classification controlling who may see this report. "
            "Accepts TLP:WHITE, TLP:GREEN, or TLP:AMBER. Defaults to TLP:GREEN."
        ),
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="List of raw indicator values observed during the incident.",
    )
    analyst_notes: Optional[str] = Field(
        default=None,
        description="Additional analyst context, hypotheses, or recommended actions.",
    )


class GetEntityInput(BaseModel):
    model_config = ConfigDict(strict=True)

    query: str = Field(
        description=(
            "Name or numeric ID of the entity to look up. "
            "Examples: 'APT28', 'Cobalt Strike', 'CVE-2023-44487', '42'."
        ),
        min_length=1,
    )
    entity_type: Optional[str] = Field(
        default=None,
        description=(
            "Optional entity type to narrow the search. "
            "Valid values: ThreatActor, MalwareFamily, Tool, Campaign, "
            "Vulnerability, Technique, IOC, Infrastructure, Target."
        ),
    )


# ---------------------------------------------------------------------------
# Document inputs
# ---------------------------------------------------------------------------

class GetDocumentInput(BaseModel):
    model_config = ConfigDict(strict=True)

    document_id: int = Field(
        description="Numeric OPTIX document identifier, e.g. 1042.",
        ge=1,
    )


class SearchDocumentsInput(BaseModel):
    model_config = ConfigDict(strict=True)

    query: str = Field(
        description="Search string. Minimum 2 characters.",
        min_length=2,
    )
    limit: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of results to return.",
    )
    offset: int = Field(
        default=0,
        ge=0,
        description="Number of results to skip for pagination.",
    )
    publisher: Optional[str] = Field(
        default=None,
        description="Filter by publisher or source name, e.g. 'Mandiant'.",
    )
    content_type: Optional[str] = Field(
        default=None,
        description="Filter by content type tag, e.g. 'ThreatResearch', 'MalwareAnalysis', 'Vulnerability'.",
    )
    since: Optional[str] = Field(
        default=None,
        description="ISO 8601 datetime. Only return documents published after this time.",
    )


# ---------------------------------------------------------------------------
# Intelligence report inputs
# ---------------------------------------------------------------------------

class ListIntelligenceReportsInput(BaseModel):
    model_config = ConfigDict(strict=True)

    limit: int = Field(
        default=20,
        ge=1,
        le=200,
        description="Maximum number of reports to return.",
    )
    report_type: Optional[str] = Field(
        default=None,
        description=(
            "Filter by report type. One of: tactical, strategic, technical, operational, rfi."
        ),
    )
    tlp_level: Optional[str] = Field(
        default=None,
        description="Filter by TLP level, e.g. 'TLP:GREEN'.",
    )
    entity_id: Optional[int] = Field(
        default=None,
        description="Filter to reports that reference a specific entity ID.",
    )


class GetIntelligenceReportInput(BaseModel):
    model_config = ConfigDict(strict=True)

    report_id: int = Field(
        description="Numeric intelligence report identifier.",
        ge=1,
    )


class GenerateReportInput(BaseModel):
    model_config = ConfigDict(strict=True)

    title: str = Field(
        description="Report title, e.g. 'Q3 Ransomware Threat Landscape'.",
        min_length=3,
        max_length=300,
    )
    query: str = Field(
        description="Natural language query or description of what the report should cover.",
        min_length=10,
    )
    report_type: Literal["tactical", "strategic", "technical", "operational", "rfi"] = Field(
        default="tactical",
        description="Report type controlling depth and audience.",
    )
    tlp: Literal["TLP:WHITE", "TLP:GREEN", "TLP:AMBER"] = Field(
        default="TLP:GREEN",
        description="TLP classification for the generated report.",
    )


# ---------------------------------------------------------------------------
# Attack matrix input
# ---------------------------------------------------------------------------

class GetAttackMatrixInput(BaseModel):
    model_config = ConfigDict(strict=True)

    technique_id: Optional[str] = Field(
        default=None,
        description="Filter to a specific MITRE ATT&CK technique ID, e.g. 'T1566'. Omit to get the full matrix.",
    )


# ---------------------------------------------------------------------------
# Watchlist inputs
# ---------------------------------------------------------------------------

class AddToWatchlistInput(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(
        description="Numeric OPTIX entity identifier to start watching.",
        ge=1,
    )


class RemoveFromWatchlistInput(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(
        description="Numeric OPTIX entity identifier to stop watching.",
        ge=1,
    )


# ---------------------------------------------------------------------------
# Headlines / threat cards inputs
# ---------------------------------------------------------------------------

class GetHeadlinesInput(BaseModel):
    model_config = ConfigDict(strict=True)

    pass


class GetThreatCardsInput(BaseModel):
    model_config = ConfigDict(strict=True)

    time_range: Literal["24h", "7d", "30d"] = Field(
        default="7d",
        description="Time window for threat card generation: 24h, 7d, or 30d.",
    )
    sector: Optional[str] = Field(
        default=None,
        description="Filter cards to a specific sector, e.g. 'Finance', 'Healthcare'.",
    )


# ---------------------------------------------------------------------------
# Entity research and query inputs
# ---------------------------------------------------------------------------

class ResearchEntityInput(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(
        description="Numeric OPTIX entity identifier to run deep research on.",
        ge=1,
    )
    force_refresh: bool = Field(
        default=False,
        description=(
            "Set true to force a new research run even if a recent result already exists. "
            "Existing completed research is returned immediately unless this is true."
        ),
    )


class AskEntityInput(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(
        description=(
            "Numeric OPTIX entity identifier. Supported types: ThreatActor, MalwareFamily, Tool, Vulnerability."
        ),
        ge=1,
    )
    language: str = Field(
        description=(
            "Target SIEM language for the generated hunting query. "
            "Supported: kql, splunk_spl, s1ql_v1, s1ql_v2, crowdstrike, elastic_eql, "
            "exabeam, chronicle_yara_l, sigma, carbon_black, palo_alto_xql."
        ),
    )


# ---------------------------------------------------------------------------
# Detection rule inputs
# ---------------------------------------------------------------------------

class GenerateDetectionRuleInput(BaseModel):
    model_config = ConfigDict(strict=True)

    technique_id: str = Field(
        description="MITRE ATT&CK technique ID to generate a detection rule for, e.g. 'T1059.001'.",
    )
    technique_name: Optional[str] = Field(
        default=None,
        description="Human-readable technique name, e.g. 'PowerShell'. Improves generation quality when supplied.",
    )
    language: str = Field(
        description=(
            "Target SIEM language. "
            "Supported: kql, splunk_spl, s1ql_v1, s1ql_v2, crowdstrike, elastic_eql, "
            "exabeam, chronicle_yara_l, sigma, carbon_black, palo_alto_xql."
        ),
    )
    document_id: Optional[int] = Field(
        default=None,
        description="Optional document ID to incorporate document-specific detection context.",
    )
    entity_id: Optional[int] = Field(
        default=None,
        description="Optional entity ID (ThreatActor or MalwareFamily) to enrich the generated rule.",
    )
    custom_context: Optional[str] = Field(
        default=None,
        description="Additional analyst context to guide the rule generation, e.g. specific log sources.",
    )


class GenerateTradecraftQueryInput(BaseModel):
    model_config = ConfigDict(strict=True)

    language: str = Field(
        description=(
            "Target SIEM language. "
            "Supported: kql, splunk_spl, s1ql_v1, s1ql_v2, crowdstrike, elastic_eql, "
            "exabeam, chronicle_yara_l, sigma, carbon_black, palo_alto_xql."
        ),
    )
    entity_name: str = Field(
        description="Name of the threat actor or malware family to generate a tradecraft query for.",
    )
    entity_type: Literal["ThreatActor", "MalwareFamily"] = Field(
        description="Entity type: ThreatActor or MalwareFamily.",
    )
    entity_id: Optional[int] = Field(
        default=None,
        description="Optional OPTIX entity ID to enrich the query with structured intelligence.",
    )
    technique_entries: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Optional list of technique entries to focus the query. Each entry may contain "
            "'techniqueId', 'techniqueName', and 'description'. If omitted OPTIX infers from entity context."
        ),
    )


# ---------------------------------------------------------------------------
# Coverage gaps input
# ---------------------------------------------------------------------------

class GetCoverageGapsInput(BaseModel):
    model_config = ConfigDict(strict=True)

    document_id: int = Field(
        description="Numeric OPTIX document identifier to analyse for detection coverage gaps.",
        ge=1,
    )


# ---------------------------------------------------------------------------
# IOC context / enrichment input
# ---------------------------------------------------------------------------

class GetIOCContextInput(BaseModel):
    model_config = ConfigDict(strict=True)

    ioc_id: int = Field(
        description="Numeric OPTIX entity identifier for the IOC (must be of type IOC).",
        ge=1,
    )


# ---------------------------------------------------------------------------
# AI search input
# ---------------------------------------------------------------------------

class AiSearchInput(BaseModel):
    model_config = ConfigDict(strict=True)

    query: str = Field(
        description=(
            "Natural language threat intelligence question, keyword search, or entity name. "
            "Examples: 'What TTPs does APT29 use?', 'LockBit ransomware', 'CVE-2024-3400'."
        ),
        min_length=2,
    )
    mode: Literal["natural", "keyword"] = Field(
        default="natural",
        description="Search mode: 'natural' for AI-expanded NLP search, 'keyword' for literal matching.",
    )


# ---------------------------------------------------------------------------
# Feedback input
# ---------------------------------------------------------------------------

class SubmitFeedbackInput(BaseModel):
    model_config = ConfigDict(strict=True)

    document_id: int = Field(
        description="Numeric OPTIX document identifier to vote on.",
        ge=1,
    )
    vote: Literal["up", "down"] = Field(
        description="Vote direction: 'up' for relevant, 'down' for not relevant.",
    )
    scope: Literal["platform", "org"] = Field(
        default="platform",
        description=(
            "Vote visibility: 'platform' shares the vote with all analysts, "
            "'org' restricts it to your organisation (requires an active org context)."
        ),
    )


# ---------------------------------------------------------------------------
# Saved feed view input
# ---------------------------------------------------------------------------

class SaveFeedViewInput(BaseModel):
    model_config = ConfigDict(strict=True)

    name: str = Field(
        description="Human-readable name for this saved view, e.g. 'Critical malware last 7 days'.",
        min_length=1,
        max_length=200,
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Filter configuration to save. Common keys: severity, tlp, contentType, publisher, "
            "publishedAfter, publishedBefore. Pass an empty dict to save the current default view."
        ),
    )


# ---------------------------------------------------------------------------
# IOC triage input
# ---------------------------------------------------------------------------

class TriageIOCInput(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_ids: list[int] = Field(
        description="List of OPTIX entity IDs (IOCs) to triage. Must contain at least one.",
        min_length=1,
    )
    status: Literal[
        "confirmed", "false_positive", "expired", "benign", "monitoring", "unresolved"
    ] = Field(
        description=(
            "Triage verdict to apply. "
            "confirmed = active malicious IOC; "
            "false_positive = analyst error or benign misclassification; "
            "benign = known good (e.g. CDN, internal range); "
            "expired = formerly active, no longer relevant; "
            "monitoring = under observation; "
            "unresolved = needs further analysis."
        ),
    )
    scope: Literal["platform", "org"] = Field(
        default="platform",
        description=(
            "Triage decision visibility: 'platform' applies the verdict globally, "
            "'org' restricts it to your organisation."
        ),
    )
