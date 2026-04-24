from __future__ import annotations

import mcp.types as types
from mcp.server import Server


def register_prompts(server: Server) -> None:

    @server.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        return [
            types.Prompt(
                name="threat-brief",
                description=(
                    "Generate a structured threat intelligence brief for a named entity. "
                    "Pulls available OPTIX intelligence and produces a concise analyst-ready summary "
                    "covering attribution, TTPs, recent activity, and recommended actions."
                ),
                arguments=[
                    types.PromptArgument(
                        name="entity_name",
                        description="Name of the threat actor, malware family, or campaign to brief (e.g. 'APT29', 'LockBit').",
                        required=True,
                    ),
                ],
            ),
            types.Prompt(
                name="ioc-triage",
                description=(
                    "Run a structured triage workflow for a suspicious indicator of compromise. "
                    "Guides the analyst through context gathering, confidence scoring, and a final "
                    "triage verdict using OPTIX community intelligence."
                ),
                arguments=[
                    types.PromptArgument(
                        name="indicator",
                        description="The indicator value to triage, e.g. '185.220.101.45', 'malicious-domain.ru', or a file hash.",
                        required=True,
                    ),
                ],
            ),
        ]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        args = arguments or {}

        if name == "threat-brief":
            entity_name = args.get("entity_name", "<entity>")
            return types.GetPromptResult(
                description=f"Threat intelligence brief for {entity_name}",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=(
                                f"Please produce a structured threat intelligence brief for **{entity_name}** "
                                f"using available OPTIX data.\n\n"
                                f"Steps:\n"
                                f"1. Use `entity.get` to look up {entity_name} and retrieve its OPTIX profile.\n"
                                f"2. Use `search.documents` to find recent intelligence documents mentioning {entity_name}.\n"
                                f"3. Use `feed.headlines` to check whether {entity_name} appears in current headlines.\n"
                                f"4. Synthesise the findings into the following sections:\n\n"
                                f"   **Attribution & Overview** — Who is {entity_name}? Sponsorship, origin, motivation.\n"
                                f"   **Recent Activity** — Latest observed campaigns or incidents (past 90 days).\n"
                                f"   **TTPs** — Key MITRE ATT&CK techniques and tools used.\n"
                                f"   **Targeted Sectors & Regions** — Primary victim industries and geographies.\n"
                                f"   **Indicators of Compromise** — Notable IOCs if available.\n"
                                f"   **Recommended Actions** — Detection priorities, hunting queries, and defensive mitigations.\n\n"
                                f"Use TLP:GREEN as the default classification unless OPTIX data indicates otherwise."
                            ),
                        ),
                    ),
                ],
            )

        if name == "ioc-triage":
            indicator = args.get("indicator", "<indicator>")
            return types.GetPromptResult(
                description=f"IOC triage workflow for {indicator}",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(
                            type="text",
                            text=(
                                f"Please run a structured triage workflow for the indicator: **{indicator}**\n\n"
                                f"Follow these steps in order:\n\n"
                                f"1. **Search** — Use `search.indicator` with value='{indicator}' to check if OPTIX has seen this indicator and retrieve its entity ID.\n"
                                f"2. **Enrich** — If an entity ID is found, use `ioc.context` to retrieve community votes, co-occurring threat actors, and source documents.\n"
                                f"3. **Document context** — Use `search.documents` to find any intelligence reports that mention '{indicator}'.\n"
                                f"4. **Confidence assessment** — Based on the above, rate confidence that the indicator is malicious: High / Medium / Low / Unknown.\n"
                                f"5. **Verdict** — Choose one of: confirmed | false_positive | benign | expired | monitoring | unresolved.\n"
                                f"6. **Record verdict** — Use `ioc.triage` to apply the verdict to the IOC entity (use the entity ID from step 1).\n"
                                f"7. **Summary** — Provide a brief triage summary including: indicator value, type, verdict, confidence, key evidence, and recommended next steps.\n\n"
                                f"If `search.indicator` returns no results, report that the indicator is not in the OPTIX database and suggest submitting it via `incident.report` if it was observed in an active incident."
                            ),
                        ),
                    ),
                ],
            )

        raise ValueError(f"Unknown prompt: {name!r}")
