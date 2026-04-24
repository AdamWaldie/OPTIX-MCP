from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatFeedEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Unique document identifier")
    title: str = Field(description="Title of the threat intelligence document")
    severity: Optional[str] = Field(
        default=None,
        description="Severity level derived from cyber score: critical (>=0.8), high (>=0.6), medium (>=0.4), low (<0.4)",
    )
    tlp: Optional[str] = Field(
        default=None,
        description="TLP classification (TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED) controlling sharing",
    )
    ioc_count: int = Field(
        default=0,
        description="Number of indicators of compromise extracted from this document",
    )
    published_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the document was originally published by its source",
    )
    ingested_at: datetime = Field(
        description="UTC timestamp when OPTIX ingested this document"
    )
    source: Optional[str] = Field(
        default=None, description="Publisher or source name for this intelligence"
    )
    summary: Optional[str] = Field(
        default=None, description="AI-generated summary of the intelligence document"
    )
    cyber_score: float = Field(
        default=0.0,
        description="OPTIX relevance score from 0.0 (not relevant) to 1.0 (highly relevant CTI)",
    )
    url: Optional[str] = Field(
        default=None, description="Original URL of the source document"
    )
    content_types: list[str] = Field(
        default_factory=list,
        description="Classification tags such as ThreatResearch, MalwareAnalysis, Vulnerability",
    )


class ThreatFeedPage(BaseModel):
    model_config = ConfigDict(strict=True)

    items: list[ThreatFeedEntry] = Field(description="Threat feed entries for this page")
    total: int = Field(description="Total number of matching documents")
    page: int = Field(description="Current page number (1-based)")
    limit: int = Field(description="Maximum items per page")
    has_more: bool = Field(description="Whether additional pages are available")


class Indicator(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Internal OPTIX entity identifier")
    value: str = Field(description="The raw indicator value, e.g. an IP address, domain, or file hash")
    type: str = Field(
        description="Indicator type: IOC, IP, Domain, Hash, URL, Email, or similar"
    )
    confidence: float = Field(
        default=0.5,
        description="Confidence score from 0.0 to 1.0 that this is a genuine malicious indicator",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the earliest sighting in OPTIX data",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the most recent sighting in OPTIX data",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Analyst-assigned or automatically inferred tags, e.g. c2, phishing, dropper",
    )
    tlp: Optional[str] = Field(
        default=None,
        description="TLP classification for this indicator",
    )
    linked_report_ids: list[int] = Field(
        default_factory=list,
        description="IDs of intelligence reports that reference this indicator",
    )
    description: Optional[str] = Field(
        default=None,
        description="Contextual description or notes about this indicator",
    )


class IncidentReport(BaseModel):
    model_config = ConfigDict(strict=True)

    title: str = Field(
        description="Short descriptive title for the incident, e.g. 'Ransomware deployment via LNK dropper'"
    )
    description: str = Field(
        description="Detailed narrative of the incident including the attack chain and analyst observations"
    )
    severity: str = Field(
        description="Incident severity: critical, high, medium, or low",
    )
    tlp: str = Field(
        default="TLP:GREEN",
        description="TLP classification controlling who can see this report. Defaults to TLP:GREEN",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="List of raw indicator values (IPs, domains, hashes) observed during the incident",
    )
    analyst_notes: Optional[str] = Field(
        default=None,
        description="Additional analyst context, hypotheses, or recommended actions",
    )


class IncidentConfirmation(BaseModel):
    model_config = ConfigDict(strict=True)

    reference_id: int = Field(description="OPTIX-assigned intelligence report ID for this incident")
    status: str = Field(description="Current report status: generating, ready, or failed")
    created_at: datetime = Field(description="UTC timestamp when the incident report was created")
    title: str = Field(description="The title of the created incident report")


class Entity(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Internal OPTIX entity identifier")
    name: str = Field(description="Canonical name of the entity, e.g. 'APT28', 'Cobalt Strike', 'CVE-2023-44487'")
    type: str = Field(
        description="Entity classification: ThreatActor, MalwareFamily, Tool, Campaign, Vulnerability, Technique, IOC, Infrastructure, or Target"
    )
    description: Optional[str] = Field(
        default=None,
        description="Narrative summary of this entity including known behaviour, attribution, or impact",
    )
    confidence: float = Field(
        default=0.5,
        description="Confidence score from 0.0 to 1.0 in the entity's classification and attribution",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest date this entity was observed in OPTIX source intelligence",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Most recent date this entity was observed in OPTIX source intelligence",
    )
    associated_iocs: list[str] = Field(
        default_factory=list,
        description="Related indicator values directly linked to this entity",
    )
    aliases: list[str] = Field(
        default_factory=list,
        description="Known alternate names or aliases for this entity",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured metadata such as target sectors, techniques, or campaign details",
    )


class CreditStatus(BaseModel):
    model_config = ConfigDict(strict=True)

    balance: Optional[int] = Field(
        default=None,
        description="Current credit balance. Null when the account is exempt (unlimited).",
    )
    allocation: Optional[int] = Field(
        default=None,
        description="Monthly credit allocation for this account tier.",
    )
    used_this_month: Optional[int] = Field(
        default=None,
        description="Credits consumed in the current billing cycle.",
    )
    is_exempt: bool = Field(
        default=False,
        description="True when this account has unlimited credits (platform admin or active exemption).",
    )
    is_org_pool: bool = Field(
        default=False,
        description="True when the balance shown is a shared organisational pool rather than a personal balance.",
    )
    reset_date: Optional[str] = Field(
        default=None,
        description="ISO 8601 date when credits next reset.",
    )
    tier: Optional[str] = Field(
        default=None,
        description="Account tier: free, individual, team, or enterprise.",
    )


class AccountStatus(BaseModel):
    model_config = ConfigDict(strict=True)

    credits: CreditStatus = Field(description="Current credit balance and usage")
    org_id: Optional[int] = Field(
        default=None,
        description="Active organisation ID, or null for personal workspace.",
    )
    report_cost: int = Field(
        default=40,
        description="Credits consumed by report_incident per submission.",
    )


class HealthStatus(BaseModel):
    model_config = ConfigDict(strict=True)

    status: str = Field(description="Service status: ok or degraded")
    version: str = Field(description="MCP server version string")
    optix_connected: bool = Field(description="Whether the OPTIX backend is reachable")
    optix_url: str = Field(description="OPTIX backend URL this server is configured to use")
    timestamp: datetime = Field(description="UTC timestamp of this health check")
    uptime_seconds: float = Field(default=0.0, description="Seconds elapsed since the MCP server process started")


class AuthContext(BaseModel):
    model_config = ConfigDict(strict=True)

    api_key_id: int
    api_key_name: str
    user_id: Optional[int]
    org_id: Optional[int]
    permissions: list[str]
    credit_balance: Optional[int] = None
    credit_allocation: Optional[int] = None
    is_credit_exempt: bool = False
    credit_reset_date: Optional[str] = None
    is_org_pool: bool = False


# ---------------------------------------------------------------------------
# Document models
# ---------------------------------------------------------------------------

class Document(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Unique OPTIX document identifier")
    title: str = Field(description="Document title")
    url: Optional[str] = Field(default=None, description="Original source URL")
    publisher: Optional[str] = Field(default=None, description="Publisher or source name")
    published_at: Optional[datetime] = Field(default=None, description="Original publication UTC timestamp")
    ingested_at: Optional[datetime] = Field(default=None, description="OPTIX ingestion UTC timestamp")
    summary: Optional[str] = Field(default=None, description="AI-generated document summary")
    cyber_score: float = Field(default=0.0, description="OPTIX cyber relevance score 0–1")
    tlp: Optional[str] = Field(default=None, description="TLP classification")
    severity: Optional[str] = Field(default=None, description="Derived severity: critical, high, medium, low")
    content_types: list[str] = Field(default_factory=list, description="Content type tags")
    accepted: bool = Field(default=False, description="Whether the document has been accepted into the feed")
    quarantined: bool = Field(default=False, description="Whether the document is quarantined")
    ioc_count: int = Field(default=0, description="Number of extracted IOCs")


class DocumentPage(BaseModel):
    model_config = ConfigDict(strict=True)

    items: list[Document] = Field(description="Documents in this result page")
    total: int = Field(description="Total matching document count")
    has_more: bool = Field(description="Whether more pages are available")


# ---------------------------------------------------------------------------
# Intelligence report models
# ---------------------------------------------------------------------------

class IntelligenceReport(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="OPTIX intelligence report identifier")
    title: str = Field(description="Report title")
    report_type: Optional[str] = Field(default=None, description="Report type: tactical, strategic, technical, operational, rfi")
    status: str = Field(description="Report status: generating, ready, or failed")
    tlp_level: Optional[str] = Field(default=None, description="TLP classification of this report")
    content: Optional[str] = Field(default=None, description="Full report markdown content (may be null while generating)")
    summary: Optional[str] = Field(default=None, description="Short executive summary")
    created_at: Optional[datetime] = Field(default=None, description="UTC timestamp when the report was created")
    entity_ids: list[int] = Field(default_factory=list, description="Entity IDs associated with this report")


class IntelligenceReportPage(BaseModel):
    model_config = ConfigDict(strict=True)

    items: list[IntelligenceReport] = Field(description="Intelligence reports")
    total: int = Field(description="Total report count")


# ---------------------------------------------------------------------------
# Attack matrix model
# ---------------------------------------------------------------------------

class AttackMatrixEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID, e.g. T1566.001")
    technique_name: Optional[str] = Field(default=None, description="Technique display name")
    tactic: Optional[str] = Field(default=None, description="ATT&CK tactic this technique belongs to")
    doc_count: int = Field(default=0, description="Number of intelligence documents covering this technique")
    has_coverage: bool = Field(default=False, description="Whether a detection rule exists for this technique")


class AttackMatrixResult(BaseModel):
    model_config = ConfigDict(strict=True)

    total_techniques: int = Field(description="Total MITRE techniques observed in OPTIX data")
    covered: int = Field(description="Techniques with at least one detection rule")
    gaps: int = Field(description="Techniques with no detection coverage")
    entries: list[AttackMatrixEntry] = Field(description="Per-technique detail rows")


# ---------------------------------------------------------------------------
# Watchlist model
# ---------------------------------------------------------------------------

class WatchlistEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(description="OPTIX entity identifier being watched")
    entity_name: str = Field(description="Canonical entity name")
    entity_type: str = Field(description="Entity type, e.g. ThreatActor, MalwareFamily")
    watched_at: Optional[datetime] = Field(default=None, description="UTC timestamp when this entity was added to the watchlist")


class WatchlistAction(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(description="Entity ID acted upon")
    watching: bool = Field(description="True if now watching, False if removed from watchlist")
    message: str = Field(description="Human-readable confirmation message")


# ---------------------------------------------------------------------------
# Headlines model
# ---------------------------------------------------------------------------

class Headline(BaseModel):
    model_config = ConfigDict(strict=True)

    text: str = Field(description="Headline text summarising a threat trend")
    entity_names: list[str] = Field(default_factory=list, description="Named entities referenced in this headline")


class HeadlinesResult(BaseModel):
    model_config = ConfigDict(strict=True)

    headlines: list[Headline] = Field(description="Current threat headlines")
    generated_at: Optional[str] = Field(default=None, description="ISO 8601 timestamp of when these headlines were generated")
    card_count: int = Field(default=0, description="Number of threat cards that contributed to these headlines")
    stale: bool = Field(default=False, description="True if headlines are older than 8 hours and should be regenerated")


# ---------------------------------------------------------------------------
# Threat cards model
# ---------------------------------------------------------------------------

class ThreatCard(BaseModel):
    model_config = ConfigDict(strict=True)

    id: Optional[int] = Field(default=None, description="OPTIX threat card identifier")
    title: str = Field(description="Threat card title")
    entity_type: Optional[str] = Field(default=None, description="Primary entity type for this card")
    entity_name: Optional[str] = Field(default=None, description="Primary entity name, e.g. 'LockBit 3.0'")
    doc_count: int = Field(default=0, description="Number of supporting intelligence documents")
    severity: Optional[str] = Field(default=None, description="Derived severity level")
    summary: Optional[str] = Field(default=None, description="Card summary")
    techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs observed")
    sectors: list[str] = Field(default_factory=list, description="Target sectors mentioned in this card")


# ---------------------------------------------------------------------------
# Detection rule / entity query models
# ---------------------------------------------------------------------------

class DetectionRule(BaseModel):
    model_config = ConfigDict(strict=True)

    language: str = Field(description="SIEM language ID, e.g. kql, splunk_spl, sigma")
    siem_name: Optional[str] = Field(default=None, description="Human-readable SIEM platform name")
    query: str = Field(description="The generated detection query or rule body")
    rule_name: Optional[str] = Field(default=None, description="Suggested rule name or title")
    notes: Optional[str] = Field(default=None, description="Analyst notes, false-positive guidance, or tuning suggestions")


class EntityQueryResult(BaseModel):
    model_config = ConfigDict(strict=True)

    entity_id: int = Field(description="OPTIX entity identifier the query was generated for")
    entity_name: str = Field(description="Entity name")
    language: str = Field(description="SIEM language ID used")
    siem_name: Optional[str] = Field(default=None, description="Human-readable SIEM platform name")
    query: str = Field(description="Generated hunting query")
    notes: Optional[str] = Field(default=None, description="Tuning notes and false-positive guidance")


class TradecraftQueryResult(BaseModel):
    model_config = ConfigDict(strict=True)

    language: str = Field(description="SIEM language ID used")
    siem_name: Optional[str] = Field(default=None, description="Human-readable SIEM platform name")
    query: str = Field(description="Generated tradecraft hunting query covering the supplied TTPs")
    notes: Optional[str] = Field(default=None, description="Detection notes and false-positive considerations")


# ---------------------------------------------------------------------------
# Entity research model
# ---------------------------------------------------------------------------

class ResearchJobResult(BaseModel):
    model_config = ConfigDict(strict=True)

    research_id: Optional[int] = Field(default=None, description="Research job identifier")
    entity_id: int = Field(description="Entity the research was triggered for")
    entity_name: str = Field(description="Entity name")
    status: str = Field(description="Job status: running, completed, queued, or failed")
    message: Optional[str] = Field(default=None, description="Status message or progress detail")
    summary: Optional[str] = Field(default=None, description="Research summary (available when status=completed)")
    steps: list[dict[str, Any]] = Field(default_factory=list, description="Research progress steps")


# ---------------------------------------------------------------------------
# Coverage gaps model
# ---------------------------------------------------------------------------

class CoverageGap(BaseModel):
    model_config = ConfigDict(strict=True)

    technique_name: str = Field(description="MITRE ATT&CK technique name")
    attack_id: Optional[str] = Field(default=None, description="MITRE ATT&CK ID, e.g. T1566.001")
    covered: bool = Field(description="True if a detection rule exists for this technique")
    procedure_count: int = Field(default=0, description="Number of detection procedures covering this technique")


class CoverageGapsResult(BaseModel):
    model_config = ConfigDict(strict=True)

    document_id: int = Field(description="Document the analysis was run on")
    gaps: list[CoverageGap] = Field(description="Per-technique coverage assessment")
    total: int = Field(description="Total techniques found in this document")
    gap_count: int = Field(description="Number of techniques with no detection coverage")


# ---------------------------------------------------------------------------
# IOC context / enrichment model
# ---------------------------------------------------------------------------

class IOCContext(BaseModel):
    model_config = ConfigDict(strict=True)

    ioc_id: int = Field(description="OPTIX entity identifier for this IOC")
    ioc_name: str = Field(description="IOC value, e.g. '185.220.101.45'")
    ioc_type: Optional[str] = Field(default=None, description="IOC type: ip, domain, hash, url, email")
    ioc_status: Optional[str] = Field(default=None, description="Triage status: confirmed, false_positive, benign, monitoring, unresolved")
    tally_malicious: int = Field(default=0, description="Analyst votes classifying this IOC as malicious")
    tally_benign: int = Field(default=0, description="Analyst votes classifying this IOC as benign")
    tally_weight: float = Field(default=0.0, description="Weighted community consensus score")
    related_actors: list[str] = Field(default_factory=list, description="Threat actor names co-occurring with this IOC in source documents")
    related_malware: list[str] = Field(default_factory=list, description="Malware family names linked to this IOC")
    related_techniques: list[str] = Field(default_factory=list, description="ATT&CK technique IDs associated with this IOC")
    related_campaigns: list[str] = Field(default_factory=list, description="Campaign names linked to this IOC")
    source_document_ids: list[int] = Field(default_factory=list, description="IDs of documents that mention this IOC")
    tags: list[str] = Field(default_factory=list, description="Community-assigned tags for this IOC")


# ---------------------------------------------------------------------------
# AI search models
# ---------------------------------------------------------------------------

class SearchHit(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Document identifier")
    title: str = Field(description="Document title")
    url: Optional[str] = Field(default=None, description="Source URL")
    publisher: Optional[str] = Field(default=None, description="Publisher name")
    snippet: Optional[str] = Field(default=None, description="Content excerpt most relevant to the query")
    score: float = Field(default=0.0, description="Relevance score 0–1")
    published_at: Optional[datetime] = Field(default=None, description="Publication UTC timestamp")
    source: Optional[str] = Field(default=None, description="Result origin: database, live-search, or id-lookup")


class SearchResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    hits: list[SearchHit] = Field(description="Matching documents ranked by relevance")
    entities: list[dict[str, Any]] = Field(default_factory=list, description="Named entities relevant to the query")
    answer: Optional[str] = Field(default=None, description="AI-synthesised natural language answer")
    confidence: Optional[float] = Field(default=None, description="Answer confidence 0–1")
    query: str = Field(description="The search query that was executed")


# ---------------------------------------------------------------------------
# Feedback / vote model
# ---------------------------------------------------------------------------

class VoteResult(BaseModel):
    model_config = ConfigDict(strict=True)

    document_id: int = Field(description="Document the vote was cast on")
    user_vote: Optional[str] = Field(default=None, description="The caller's vote: up, down, or null (removed)")
    upvotes: int = Field(default=0, description="Total upvotes for this document")
    downvotes: int = Field(default=0, description="Total downvotes for this document")


# ---------------------------------------------------------------------------
# Feed saved view model
# ---------------------------------------------------------------------------

class SavedView(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Saved view identifier")
    name: str = Field(description="View name chosen by the analyst")
    filters: dict[str, Any] = Field(default_factory=dict, description="Stored filter configuration")
    created_at: Optional[datetime] = Field(default=None, description="UTC timestamp when this view was saved")


# ---------------------------------------------------------------------------
# IOC triage model
# ---------------------------------------------------------------------------

class TriageResult(BaseModel):
    model_config = ConfigDict(strict=True)

    updated: int = Field(description="Number of IOCs whose triage status was updated")
    status: str = Field(description="The triage status that was applied")
    entity_ids: list[int] = Field(description="Entity IDs that were triaged")


# ---------------------------------------------------------------------------
# Threat actor listing model
# ---------------------------------------------------------------------------

class ThreatActorListEntry(BaseModel):
    model_config = ConfigDict(strict=True)

    id: int = Field(description="Internal OPTIX entity identifier")
    name: str = Field(description="Canonical threat actor name, e.g. 'APT28'")
    aliases: list[str] = Field(
        default_factory=list,
        description="Known alternate names or aliases for this actor",
    )
    confidence: float = Field(
        default=0.5,
        description="Confidence score from 0.0 to 1.0 in the entity classification",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest date this actor was observed in OPTIX source intelligence",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Most recent date this actor was observed in OPTIX source intelligence",
    )
    actor_type: Optional[str] = Field(
        default=None,
        description="Actor sub-type when available, e.g. nation-state, cybercriminal, hacktivist",
    )


# ---------------------------------------------------------------------------
# Composite threat actor profile model
# ---------------------------------------------------------------------------

class ThreatActorProfile(BaseModel):
    model_config = ConfigDict(strict=True)

    entity: Entity = Field(description="Resolved entity record for the threat actor")
    alias_resolved: Optional[str] = Field(
        default=None,
        description="Resolution note when the input name was an alias, e.g. \"Resolved 'Fancy Bear' → APT28\"",
    )
    ioc_contexts: list[IOCContext] = Field(
        default_factory=list,
        description="Enriched context for up to 5 IOCs linked to this actor, fetched from the IOC triage context endpoint",
    )
    linked_report_count: int = Field(
        default=0,
        description="Number of OPTIX intelligence reports referencing this actor",
    )
    latest_report_summary: Optional[str] = Field(
        default=None,
        description="Summary from the most recent linked intelligence report, if one exists",
    )
    latest_report_id: Optional[int] = Field(
        default=None,
        description="ID of the most recent linked intelligence report",
    )
    enrichment_notes: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings about partial enrichment failures (e.g. IOC or report fetch errors)",
    )
