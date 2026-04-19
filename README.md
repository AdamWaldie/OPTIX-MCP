# OPTIX MCP Server

A standalone Python/FastAPI server that implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io) for the OPTIX threat intelligence platform. It exposes 26 analyst-friendly tools that AI assistants and programmatic consumers can use to query threat feeds, search documents and indicators, manage watchlists, triage IOCs, generate detection rules, trigger AI research, and produce intelligence reports — without needing to understand OPTIX's internal REST API.

## Requirements

- Python 3.11+
- An active OPTIX installation
- An OPTIX API key (create one in OPTIX Settings → API Keys)

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPTIX_API_URL` | No | `https://optixthreatintelligence.co.uk` | Base URL of the OPTIX backend. Override only when self-hosting. |
| `MCP_HOST` | No | `0.0.0.0` | Host address the MCP server binds to |
| `MCP_PORT` | No | `8090` | Port the MCP server listens on |
| `OPTIX_REQUEST_TIMEOUT` | No | `30` | Seconds before upstream OPTIX calls time out |

Create a `.env` file in the `OPTIX MCP/` directory to set these, or export them as shell variables.

```env
# Only needed if self-hosting OPTIX at a custom URL:
OPTIX_API_URL=https://your-optix-instance.example.com
MCP_PORT=8090
```

## Running Locally

```bash
cd "OPTIX MCP"
cp .env.example .env          # then edit .env with your OPTIX_API_URL
pip install -r requirements.txt
python main.py
```

The server starts on `http://0.0.0.0:8090` by default.

- **Health check:** `GET http://localhost:8090/health`
- **MCP SSE endpoint:** `GET http://localhost:8090/mcp` (requires `X-API-Key` header)

## Authentication

Every request to the MCP endpoint must include your OPTIX API key in the `X-API-Key` header:

```
X-API-Key: optix_your_api_key_here
```

Unauthenticated requests receive a structured `401` response:

```json
{
  "error": "Missing API key",
  "detail": "Provide your OPTIX API key in the X-API-Key request header.",
  "docs": "See README.md for instructions on obtaining an API key."
}
```

## Connecting to Claude Desktop

**Recommended — via Smithery (no local install required):**

Add the following to your Claude Desktop configuration file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "optix": {
      "command": "npx",
      "args": [
        "-y",
        "@smithery/cli@latest",
        "run",
        "@optixcybersecurity/optix-mcp",
        "--",
        "--api-key",
        "optix_your_api_key_here"
      ]
    }
  }
}
```

**Alternative — self-hosted local server:**

```json
{
  "mcpServers": {
    "optix": {
      "command": "python",
      "args": ["/path/to/OPTIX MCP/stdio.py"],
      "env": {
        "OPTIX_API_KEY": "optix_your_api_key_here"
      }
    }
  }
}
```

## Connecting to Cursor

**Recommended — hosted endpoint (no local install required):**

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "optix": {
      "url": "https://optixthreatintelligence.co.uk/mcp",
      "headers": {
        "X-API-Key": "optix_your_api_key_here"
      }
    }
  }
}
```

**Alternative — local server:**

```json
{
  "mcpServers": {
    "optix": {
      "url": "http://localhost:8090/mcp",
      "headers": {
        "X-API-Key": "optix_your_api_key_here"
      }
    }
  }
}
```

---

## Credit System

Several tools consume OPTIX credits. The server enforces a **pre-flight credit check** before making any upstream call: if the cached balance is known to be insufficient, it returns an error immediately without deducting or attempting the operation.

After every successful credit-consuming call the server re-fetches the credit balance so that `get_account_status` always reflects the current state.

| Operation | Cost |
|---|---|
| `report_incident` | 40 credits |
| `generate_report` | 40 credits |
| `research_entity` | 15 credits |
| `ask_entity` | 4 credits |
| `generate_detection_rule` | 4 credits |
| `generate_tradecraft_query` | 4 credits |
| All other tools | Free |

---

## Available Tools

> **Authentication:** All tools authenticate via the `X-API-Key` header set in your MCP client configuration — there is no `api_key` tool parameter. The key is validated against the OPTIX backend on every request.

### Tool Overview

| # | Tool | Category | Cost |
|---|---|---|---|
| 1 | `get_threat_feed` | Read | Free |
| 2 | `search_indicator` | Read | Free |
| 3 | `report_incident` | Write | 40 credits |
| 4 | `get_entity` | Read | Free |
| 5 | `get_account_status` | Read | Free |
| 6 | `get_document` | Read | Free |
| 7 | `search_documents` | Read | Free |
| 8 | `list_intelligence_reports` | Read | Free |
| 9 | `get_intelligence_report` | Read | Free |
| 10 | `get_attack_matrix` | Read | Free |
| 11 | `get_watchlist` | Read | Free |
| 12 | `add_to_watchlist` | Write | Free |
| 13 | `remove_from_watchlist` | Write | Free |
| 14 | `get_headlines` | Read | Free |
| 15 | `get_threat_cards` | Read | Free |
| 16 | `get_ioc_context` | Read | Free |
| 17 | `get_coverage_gaps` | Read | Free |
| 18 | `ai_search` | Read | Free |
| 19 | `research_entity` | AI / Write | 15 credits |
| 20 | `ask_entity` | AI / Write | 4 credits |
| 21 | `generate_detection_rule` | AI / Write | 4 credits |
| 22 | `generate_tradecraft_query` | AI / Write | 4 credits |
| 23 | `generate_report` | AI / Write | 40 credits |
| 24 | `submit_feedback` | Write | Free |
| 25 | `save_feed_view` | Write | Free |
| 26 | `triage_ioc` | Write | Free |

---

### `get_threat_feed`

Returns a paginated stream of curated, scored intelligence documents from all OPTIX sources.

**When to use:** "What are the latest critical threats?" / "Show me recent TLP:AMBER intelligence."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | integer | No | Max entries (1–100, default 20) |
| `offset` | integer | No | Skip N entries for pagination |
| `severity_filter` | string | No | `critical`, `high`, `medium`, or `low` |
| `tlp_filter` | string | No | `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED` |
| `since` | string | No | ISO 8601 datetime — only return documents published after this time |

---

### `search_indicator`

Searches OPTIX for a specific indicator of compromise (IOC) by value.

**When to use:** "Has OPTIX seen 185.220.101.45?" / "What do we know about this hash?"

| Parameter | Type | Required | Description |
|---|---|---|---|
| `value` | string | Yes | IP, domain, hash, URL, or email to search |
| `type_hint` | string | No | `IOC`, `Infrastructure`, `ThreatActor`, `MalwareFamily` |

---

### `report_incident` ⚡ 40 credits

Submits a structured incident report to OPTIX and generates a tactical intelligence report.

**When to use:** An analyst has completed an investigation and wants to create a formal intelligence report.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `title` | string | Yes | Short incident title (3–300 chars) |
| `description` | string | Yes | Full incident narrative |
| `severity` | string | Yes | `critical`, `high`, `medium`, or `low` |
| `tlp` | string | No | TLP classification (default `TLP:GREEN`) |
| `indicators` | string[] | No | Observed IOC values |
| `analyst_notes` | string | No | Additional context or recommended actions |

---

### `get_entity`

Fetches a named threat intelligence entity (threat actor, malware, campaign, CVE, technique) by name or ID.

**When to use:** "Tell me about APT28" / "What do we know about LockBit?"

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | Yes | Entity name or numeric OPTIX ID |
| `entity_type` | string | No | `ThreatActor`, `MalwareFamily`, `Tool`, `Campaign`, `Vulnerability`, `Technique` |

---

### `get_account_status`

Returns your current OPTIX credit balance, monthly allocation, usage, reset date, and account context.

**When to use:** Before any credit-consuming operation, or when the analyst asks "how many credits do I have?"

No parameters required.

---

### `get_document`

Fetches a specific intelligence document by its numeric OPTIX ID.

**When to use:** When you have a document ID from another tool and need full metadata and summary.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `document_id` | integer | Yes | Numeric document ID (e.g. 1042) |

---

### `search_documents`

Full-text search across all OPTIX intelligence documents.

**When to use:** "Find documents about supply chain attacks" / "Show me Mandiant reports from this week."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | Yes | Search string (min 2 chars) |
| `limit` | integer | No | Max results (1–100, default 20) |
| `offset` | integer | No | Results to skip for pagination |
| `publisher` | string | No | Filter by publisher name |
| `content_type` | string | No | Filter by content type: `ThreatResearch`, `MalwareAnalysis`, `Vulnerability`, etc. |
| `since` | string | No | ISO 8601 datetime — only return documents published after this time |

---

### `list_intelligence_reports`

Lists generated intelligence reports (tactical, strategic, operational, technical, RFI) stored in OPTIX.

**When to use:** "What intelligence reports have we produced?" / "Show me all RFI reports."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `limit` | integer | No | Max reports (1–200, default 20) |
| `report_type` | string | No | `tactical`, `strategic`, `technical`, `operational`, `rfi` |
| `tlp_level` | string | No | Filter by TLP level |
| `entity_id` | integer | No | Filter to reports referencing this entity |

---

### `get_intelligence_report`

Retrieves the full content of a specific intelligence report.

**When to use:** After `list_intelligence_reports` to fetch the full text of a report.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `report_id` | integer | Yes | Numeric report identifier |

---

### `get_attack_matrix`

Retrieves the OPTIX MITRE ATT&CK coverage matrix — which techniques have been observed in intelligence data and which have detection rules.

**When to use:** "What ATT&CK techniques are we seeing?" / "Do we have detection coverage for T1566?"

| Parameter | Type | Required | Description |
|---|---|---|---|
| `technique_id` | string | No | Specific ATT&CK ID (e.g. `T1566`). Omit for the full matrix. |

---

### `get_watchlist`

Lists all entities on the analyst's OPTIX watchlist.

**When to use:** "What entities am I watching?" / "Show my watchlist."

No parameters required.

---

### `add_to_watchlist`

Adds an entity to the analyst's watchlist to receive notifications when new intelligence mentions it.

**When to use:** "Start watching APT29" (get the entity ID first with `get_entity`).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `entity_id` | integer | Yes | Numeric OPTIX entity ID |

---

### `remove_from_watchlist`

Removes an entity from the analyst's watchlist.

**When to use:** "Stop watching LockBit."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `entity_id` | integer | Yes | Numeric OPTIX entity ID |

---

### `get_headlines`

Returns AI-synthesised threat intelligence headlines summarising the most active current threats.

**When to use:** "What's happening in the threat landscape right now?" / "Give me a briefing."

No parameters required.

---

### `get_threat_cards`

Returns profile-matched situational awareness threat cards showing active threats with observed TTPs and targeted sectors.

**When to use:** "What threats are most relevant to us?" / "Show me the threat cards for the last 30 days."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `time_range` | string | No | `24h`, `7d` (default), or `30d` |
| `sector` | string | No | Filter by sector, e.g. `Finance`, `Healthcare` |

---

### `get_ioc_context`

Returns enriched community context for an IOC including analyst vote tallies, co-occurring threat actors and malware, ATT&CK techniques, and source documents.

**When to use:** "What do analysts think about this IP?" / "Is this domain confirmed malicious?"

| Parameter | Type | Required | Description |
|---|---|---|---|
| `ioc_id` | integer | Yes | Numeric OPTIX entity ID for the IOC (find it with `search_indicator`) |

---

### `get_coverage_gaps`

Analyses an intelligence document to identify MITRE ATT&CK techniques it references and determines which lack detection coverage.

**When to use:** "Does our detection stack cover the techniques in this report?" / "What are our coverage gaps from this document?"

| Parameter | Type | Required | Description |
|---|---|---|---|
| `document_id` | integer | Yes | Numeric OPTIX document ID |

---

### `ai_search`

Natural language or keyword search across OPTIX documents and entities with optional AI query expansion.

**When to use:** "Find everything about LockBit's recent TTPs" / "Search for Volt Typhoon."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `query` | string | Yes | Natural language question or keyword (min 2 chars) |
| `mode` | string | No | `natural` (AI-expanded, default) or `keyword` (literal) |

---

### `research_entity` ⚡ 15 credits

Triggers deep AI research on an entity — OPTIX crawls authoritative sources and enriches the entity's profile with structured intelligence.

**When to use:** "Do a deep dive on APT29" / "Research the latest on LockBit."

Supported entity types: `ThreatActor`, `MalwareFamily`, `Vulnerability`, `Tool`, `Campaign`, `Technique`.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `entity_id` | integer | Yes | Numeric OPTIX entity ID |
| `force_refresh` | boolean | No | Force new research even if recent results exist (default `false`) |

---

### `ask_entity` ⚡ 4 credits

Generates a SIEM threat hunting query for a specific entity using its known TTPs, IOCs, and intelligence history.

**When to use:** "Generate a KQL hunt for APT28" / "Write a Sigma rule to detect LockBit."

Supported entity types: `ThreatActor`, `MalwareFamily`, `Tool`, `Vulnerability`.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `entity_id` | integer | Yes | Numeric OPTIX entity ID |
| `language` | string | Yes | SIEM language: `kql`, `splunk_spl`, `s1ql_v1`, `s1ql_v2`, `crowdstrike`, `elastic_eql`, `exabeam`, `chronicle_yara_l`, `sigma`, `carbon_black`, `palo_alto_xql` |

---

### `generate_detection_rule` ⚡ 4 credits

Generates a SIEM detection rule for a specific MITRE ATT&CK technique.

**When to use:** "Write a Splunk detection for T1059.001" / "Create a KQL rule for PowerShell abuse."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `technique_id` | string | Yes | MITRE ATT&CK technique ID, e.g. `T1059.001` |
| `language` | string | Yes | Target SIEM language (see list above) |
| `technique_name` | string | No | Human-readable name, e.g. `PowerShell` |
| `document_id` | integer | No | Enrich rule with context from a specific document |
| `entity_id` | integer | No | Enrich rule with context from a specific entity |
| `custom_context` | string | No | Additional analyst context (log sources, environment) |

---

### `generate_tradecraft_query` ⚡ 4 credits

Generates a broad SIEM hunting query covering the complete known tradecraft of a threat actor or malware family.

**When to use:** "Generate a multi-technique hunt for APT29 in Sentinel" / "Write a comprehensive Sigma rule set for Volt Typhoon."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `language` | string | Yes | Target SIEM language (see list above) |
| `entity_name` | string | Yes | Threat actor or malware name, e.g. `APT29` |
| `entity_type` | string | Yes | `ThreatActor` or `MalwareFamily` |
| `entity_id` | integer | No | OPTIX entity ID to enrich the query |
| `technique_entries` | array | No | Optional list of `{techniqueId, techniqueName, description}` to scope the hunt |

---

### `generate_report` ⚡ 40 credits

Generates a strategic, operational, technical, or RFI intelligence report using OPTIX's document and entity corpus.

**When to use:** "Write a strategic report on the ransomware threat landscape" / "Generate an RFI on APT40."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `title` | string | Yes | Report title (3–300 chars) |
| `query` | string | Yes | Natural language description of the report topic |
| `report_type` | string | No | `tactical` (default), `strategic`, `technical`, `operational`, `rfi` |
| `tlp` | string | No | TLP classification (default `TLP:GREEN`) |

---

### `submit_feedback`

Submits a relevance vote (upvote or downvote) on an OPTIX intelligence document. Community votes improve OPTIX scoring and feed personalisation.

**When to use:** "Upvote this document — it's very relevant" / "Downvote this, it's not applicable to us."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `document_id` | integer | Yes | Numeric OPTIX document ID |
| `vote` | string | Yes | `up` or `down` |
| `scope` | string | No | `platform` (all analysts, default) or `org` (your org only) |

---

### `save_feed_view`

Saves a named feed filter configuration so the analyst can recall it later.

**When to use:** "Save this filter as 'Critical malware this week'" / "Bookmark my current view."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `name` | string | Yes | View name (1–200 chars) |
| `filters` | object | No | Filter configuration. Common keys: `severity`, `tlp`, `contentType`, `publisher`, `publishedAfter` |

---

### `triage_ioc`

Applies a triage verdict to one or more IOCs, recording analyst judgement about their disposition.

**When to use:** "Mark these IPs as confirmed malicious" / "Flag this domain as a false positive."

| Parameter | Type | Required | Description |
|---|---|---|---|
| `entity_ids` | integer[] | Yes | List of OPTIX IOC entity IDs (find with `search_indicator`) |
| `status` | string | Yes | `confirmed`, `false_positive`, `benign`, `expired`, `monitoring`, or `unresolved` |
| `scope` | string | No | `platform` (global decision, default) or `org` (organisation-scoped) |

---

## Health Endpoint

`GET /health` returns service status without requiring authentication:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "optix_connected": true,
  "optix_url": "https://your-optix-instance.example.com",
  "timestamp": "2024-04-19T12:00:00Z"
}
```

If `optix_connected` is `false`, status will be `degraded` and tool calls will fail until the OPTIX backend is reachable.

---

## Error Handling

All tools return structured error messages rather than raising exceptions to the AI client:

| Error type | Cause | Response |
|---|---|---|
| `Authentication error` | Invalid or missing API key | Prompt the user to check their OPTIX API key |
| `Insufficient credits` | Balance below the operation cost | Call `get_account_status` and wait for the reset date |
| `Not found` | Entity, document, or report does not exist | Verify the ID or name and try again |
| `OPTIX API error` | Backend error or validation failure | Includes the original OPTIX error message for diagnosis |
| `Validation error` | Invalid tool parameters | Includes field-level detail to correct the call |
