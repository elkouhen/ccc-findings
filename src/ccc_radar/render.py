import math
from pathlib import Path
from typing import TypedDict
from xml.sax.saxutils import quoteattr

from ccc_radar.ccc_bridge import CodeHitWithFindings
from ccc_radar.flow import FlowResult
from ccc_radar.graph import Cycle, GraphEdge, Hotspot, OutboundCallInConsumer
from ccc_radar.models import MessageEndpoint
from ccc_radar.search import SearchHit, Summary, get_context
from ccc_radar.workspace import DiscoveredService, FederationResult


class FindingHit(TypedDict):
    """Shape returned by `cccr search --json` and the `search_findings` MCP tool."""

    id: str
    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int
    score: float
    fix: str | None
    cwe: list[str]
    owasp: list[str]
    context: str | None
    context_error: str | None


class RuleCount(TypedDict):
    rule_id: str
    count: int


class FindingsSummary(TypedDict):
    """Shape returned by `cccr summary --json` and the `findings_summary` MCP tool."""

    by_severity: dict[str, int]
    top_rules: list[RuleCount]
    by_top_level_dir: dict[str, int]


def render_search_text(hits: list[SearchHit], repo_root: Path, include_context: bool) -> str:
    lines = []
    for i, hit in enumerate(hits, start=1):
        finding = hit.finding
        lines.append(
            f"{i}. [{finding.severity}] {finding.rule_id}  "
            f"{finding.path}:{finding.start_line}-{finding.end_line}  ({hit.score:.2f})"
        )
        lines.append(f"   {finding.message}")
        if include_context:
            try:
                context = get_context(repo_root, finding)
            except OSError as exc:
                lines.append(f"   contexte indisponible : {exc}")
            else:
                for context_line in context.splitlines():
                    lines.append(f"   {context_line}")
    return "\n".join(lines)


def render_search_json(
    hits: list[SearchHit], repo_root: Path, include_context: bool
) -> list[FindingHit]:
    results: list[FindingHit] = []
    for hit in hits:
        finding = hit.finding
        context: str | None = None
        context_error: str | None = None
        if include_context:
            try:
                context = get_context(repo_root, finding)
            except OSError as exc:
                context_error = str(exc)
        results.append(
            FindingHit(
                id=finding.id,
                rule_id=finding.rule_id,
                severity=finding.severity,
                message=finding.message,
                path=finding.path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                score=hit.score,
                fix=finding.fix,
                cwe=finding.cwe,
                owasp=finding.owasp,
                context=context,
                context_error=context_error,
            )
        )
    return results


def render_code_search_text(
    hits: list[CodeHitWithFindings], warning: str | None = None
) -> str:
    """Rendu texte de `cccr search` : même format que `ccc search`
    (`--- Result N (score) --- / File: ...`), chaque résultat suivi d'un bloc
    des findings Semgrep qui le chevauchent — un utilisateur de `ccc` garde
    ses repères, `cccr` ajoute la couche findings.
    """
    lines: list[str] = []
    if warning:
        lines.append(f"⚠ {warning}")
        lines.append("")
    for i, hit in enumerate(hits, start=1):
        if i > 1:
            lines.append("")
        lines.append(f"--- Result {i} (score: {hit['score']:.3f}) ---")
        lines.append(
            f"File: {hit['path']}:{hit['start_line']}-{hit['end_line']} [{hit['language']}]"
        )
        lines.append(hit["content"])
        if hit["findings"]:
            lines.append("")
            lines.append(f"  ⚠ findings (max: {hit['max_severity']}):")
            for finding in hit["findings"]:
                lines.append(
                    f"  [{finding['severity']}] {finding['rule_id']}  "
                    f"{finding['path']}:{finding['start_line']}-{finding['end_line']}"
                )
                lines.append(f"    {finding['message']}")
    return "\n".join(lines)


def render_fallback_findings_text(fallback: list[FindingHit]) -> str:
    """Rendu texte du repli findings-only de `cccr search` quand ccc est
    indisponible — même style numéroté que `cccr findings`."""
    lines: list[str] = []
    for i, hit in enumerate(fallback, start=1):
        lines.append(
            f"{i}. [{hit['severity']}] {hit['rule_id']}  "
            f"{hit['path']}:{hit['start_line']}-{hit['end_line']}  ({hit['score']:.2f})"
        )
        lines.append(f"   {hit['message']}")
    return "\n".join(lines)


def render_summary_text(result: Summary) -> str:
    severities = " | ".join(f"{sev} {count}" for sev, count in result.by_severity.items())
    top_rules = ", ".join(f"{rule} ({count})" for rule, count in result.top_rules)
    top_dirs = ", ".join(f"{d} ({count})" for d, count in result.by_top_level_dir.items())
    return "\n".join(
        [
            severities,
            f"top règles : {top_rules}",
            f"top répertoires : {top_dirs}",
        ]
    )


def render_summary_json(result: Summary) -> FindingsSummary:
    return FindingsSummary(
        by_severity=result.by_severity,
        top_rules=[RuleCount(rule_id=r, count=c) for r, c in result.top_rules],
        by_top_level_dir=result.by_top_level_dir,
    )


class GraphSite(TypedDict):
    path: str
    start_line: int
    end_line: int
    topic: str


class OutboundCallHit(TypedDict):
    """Un appel REST détecté à l'intérieur d'un handler de consommation
    Kafka (BACKLOG-10 K12)."""

    consumer: GraphSite
    call: GraphSite


class CycleEdgeInfo(TypedDict):
    kind: str  # "rest" | "kafka"
    from_service: str
    to_service: str
    from_site: GraphSite
    to_site: GraphSite


class CycleInfo(TypedDict):
    services: list[str]
    edges: list[CycleEdgeInfo]
    has_synchronous_rest: bool


class HotspotInfo(TypedDict):
    service: str
    site: GraphSite
    finding_rule_id: str
    finding_severity: str


class GraphResult(TypedDict):
    """Shape returned by `cccr graph --json` et le tool MCP `graph`.

    `cycles`/`hotspots` restent vides tant qu'aucune donnée inter-module
    n'est disponible : ni fédération explicite (`--workspace`/
    `workspace_root`, BACKLOG-11 A2), ni endpoints/findings attribués à un
    module Maven par l'indexation d'un répertoire parent multi-modules
    (BACKLOG-13 M1/M2/M3) — voir `note`.
    """

    outbound_calls_in_consumers: list[OutboundCallHit]
    cycles: list[CycleInfo]
    hotspots: list[HotspotInfo]
    note: str


_NO_CROSS_MODULE_DATA_NOTE = (
    "Cycles et hotspots inter-services nécessitent soit un répertoire multi-services "
    "fédéré (--workspace/workspace_root, BACKLOG-11 A2), soit des endpoints/findings "
    "attribués à un module Maven par une indexation multi-modules (BACKLOG-13) — "
    "seuls les appels REST détectés dans un handler Kafka de ce projet sont remontés "
    "pour l'instant."
)


def _endpoint_to_site(endpoint: MessageEndpoint) -> GraphSite:
    return GraphSite(
        path=endpoint.path,
        start_line=endpoint.start_line,
        end_line=endpoint.end_line,
        topic=endpoint.topic,
    )


def _cycle_to_info(cycle: Cycle) -> CycleInfo:
    return CycleInfo(
        services=list(cycle.services),
        edges=[
            CycleEdgeInfo(
                kind=edge.kind,
                from_service=edge.from_service,
                to_service=edge.to_service,
                from_site=_endpoint_to_site(edge.from_endpoint),
                to_site=_endpoint_to_site(edge.to_endpoint),
            )
            for edge in cycle.edges
        ],
        has_synchronous_rest=cycle.has_synchronous_rest,
    )


def _hotspot_to_info(hotspot: Hotspot) -> HotspotInfo:
    return HotspotInfo(
        service=hotspot.service,
        site=_endpoint_to_site(hotspot.endpoint),
        finding_rule_id=hotspot.finding.rule_id,
        finding_severity=hotspot.finding.severity,
    )


def render_graph_json(
    outbound_calls: list[OutboundCallInConsumer],
    cycles: list[Cycle] | None = None,
    hotspots: list[Hotspot] | None = None,
    warnings: list[str] | None = None,
    cross_module_data_available: bool = False,
) -> GraphResult:
    cycles = cycles or []
    hotspots = hotspots or []
    if cross_module_data_available:
        note = " ".join(f"⚠ {w}" for w in (warnings or []))
    else:
        note = _NO_CROSS_MODULE_DATA_NOTE
    return GraphResult(
        outbound_calls_in_consumers=[
            OutboundCallHit(
                consumer=_endpoint_to_site(hit.consumer), call=_endpoint_to_site(hit.call)
            )
            for hit in outbound_calls
        ],
        cycles=[_cycle_to_info(c) for c in cycles],
        hotspots=[_hotspot_to_info(h) for h in hotspots],
        note=note,
    )


def render_graph_text(result: GraphResult) -> str:
    calls = result["outbound_calls_in_consumers"]
    lines: list[str] = []
    if calls:
        lines.append(f"Appels REST dans un handler Kafka ({len(calls)}) :")
        for hit in calls:
            call, consumer = hit["call"], hit["consumer"]
            lines.append(
                f"  {call['path']}:{call['start_line']} {call['topic']}  "
                f"(dans le handler {consumer['topic']}, "
                f"{consumer['path']}:{consumer['start_line']}-{consumer['end_line']})"
            )
    else:
        lines.append("Aucun appel REST détecté dans un handler Kafka.")

    cycles = result["cycles"]
    if cycles:
        lines.append(f"Cycles inter-services ({len(cycles)}) :")
        for cycle in cycles:
            chain = " -> ".join(cycle["services"])
            sync_marker = " [synchrone]" if cycle["has_synchronous_rest"] else ""
            lines.append(f"  {chain}{sync_marker}")
            for edge in cycle["edges"]:
                lines.append(
                    f"    [{edge['kind']}] {edge['from_service']} "
                    f"({edge['from_site']['path']}:{edge['from_site']['start_line']}) -> "
                    f"{edge['to_service']} "
                    f"({edge['to_site']['path']}:{edge['to_site']['start_line']})"
                )

    hotspots = result["hotspots"]
    if hotspots:
        lines.append(f"Hotspots ({len(hotspots)}, classés par sévérité) :")
        for hotspot in hotspots:
            site = hotspot["site"]
            lines.append(
                f"  [{hotspot['finding_severity']}] {hotspot['service']} "
                f"{site['path']}:{site['start_line']} — {hotspot['finding_rule_id']}"
            )

    if result["note"]:
        lines.append(result["note"])
    return "\n".join(lines)


def render_graph_drawio(
    services: list[str], edges: list[GraphEdge], cycles: list[Cycle]
) -> str:
    """Rend le graphe d'interactions services <-> services (BACKLOG-14 G1)
    en XML mxGraph (format natif diagrams.net/drawio) : un nœud par service
    (y compris sans arête), une arête par `GraphEdge` — REST en trait
    plein, Kafka en pointillé, libellé = route/topic. Les arêtes d'un cycle
    `has_synchronous_rest=True` sont mises en évidence en rouge (même
    signal que le cycle « synchrone » du rendu JSON/texte). Layout initial
    en grille — diagrams.net réorganise à la demande, ce n'est pas un rendu
    figé. Toute valeur dérivée du code source (nom de service, route,
    topic) est échappée XML via `quoteattr` — jamais interpolée brute."""
    synchronous_edge_ids = {
        id(edge) for cycle in cycles if cycle.has_synchronous_rest for edge in cycle.edges
    }

    ordered_services = sorted(services)
    node_ids = {name: f"node-{i}" for i, name in enumerate(ordered_services)}
    columns = max(1, math.ceil(math.sqrt(len(ordered_services)))) if ordered_services else 1

    cells: list[str] = []
    for i, name in enumerate(ordered_services):
        x = 40 + (i % columns) * 220
        y = 40 + (i // columns) * 120
        cells.append(
            f'<mxCell id="{node_ids[name]}" value={quoteattr(name)} '
            'style="rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;" '
            f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="160" height="50" '
            'as="geometry" /></mxCell>'
        )

    for i, edge in enumerate(edges):
        source_id = node_ids.get(edge.from_service)
        target_id = node_ids.get(edge.to_service)
        if source_id is None or target_id is None:
            continue
        style = "edgeStyle=orthogonalEdgeStyle;html=1;"
        style += "dashed=1;" if edge.kind == "kafka" else ""
        style += (
            "strokeColor=#d32f2f;fontColor=#d32f2f;"
            if id(edge) in synchronous_edge_ids
            else "strokeColor=#666666;"
        )
        cells.append(
            f'<mxCell id="edge-{i}" value={quoteattr(edge.to_endpoint.topic)} style={quoteattr(style)} '
            f'edge="1" parent="1" source="{source_id}" target="{target_id}">'
            '<mxGeometry relative="1" as="geometry" /></mxCell>'
        )

    body = "\n        ".join(cells)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="cccr">\n'
        '  <diagram name="cccr graph" id="cccr-graph">\n'
        '    <mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" '
        'pageHeight="1100" math="0" shadow="0">\n'
        "      <root>\n"
        '        <mxCell id="0" />\n'
        '        <mxCell id="1" parent="0" />\n'
        f"        {body}\n"
        "      </root>\n"
        "    </mxGraphModel>\n"
        "  </diagram>\n"
        "</mxfile>\n"
    )


class EndpointHit(TypedDict):
    """Shape returned by `cccr endpoints --json` and the `list_endpoints`
    MCP tool (BACKLOG-11 A1)."""

    id: str
    role: str
    system: str
    topic: str
    topic_dynamic: bool
    source: str
    framework: str | None
    path: str
    start_line: int
    end_line: int
    module: str | None
    qualified_name: str | None


def render_endpoints_json(endpoints: list[MessageEndpoint]) -> list[EndpointHit]:
    return [
        EndpointHit(
            id=e.id,
            role=e.role,
            system=e.system,
            topic=e.topic,
            topic_dynamic=e.topic_dynamic,
            source=e.source,
            framework=e.framework,
            path=e.path,
            start_line=e.start_line,
            end_line=e.end_line,
            module=e.module,
            qualified_name=e.qualified_name,
        )
        for e in endpoints
    ]


def render_endpoints_text(endpoints: list[MessageEndpoint]) -> str:
    if not endpoints:
        return "Aucun endpoint indexé."
    lines = []
    for e in endpoints:
        dynamic_marker = " (dynamique)" if e.topic_dynamic else ""
        module_marker = f" [{e.module}]" if e.module else ""
        lines.append(
            f"[{e.system}/{e.role}] {e.topic}{dynamic_marker}{module_marker}  "
            f"{e.path}:{e.start_line}-{e.end_line}"
        )
    return "\n".join(lines)


class WorkspaceServiceInfo(TypedDict):
    name: str
    path: str
    kind: str
    indexed: bool
    endpoint_count: int
    finding_count: int


class WorkspaceResult(TypedDict):
    """Shape returned by `cccr workspace <root> --json` and the
    `list_workspace_services` MCP tool (BACKLOG-11 A2)."""

    services: list[WorkspaceServiceInfo]
    warnings: list[str]


def render_workspace_json(
    services: list[DiscoveredService], federation: FederationResult
) -> WorkspaceResult:
    return WorkspaceResult(
        services=[
            WorkspaceServiceInfo(
                name=s.name,
                path=str(s.path),
                kind=s.kind,
                indexed=s.indexed,
                endpoint_count=len(federation.endpoints_by_service.get(s.name, [])),
                finding_count=len(federation.findings_by_service.get(s.name, [])),
            )
            for s in services
        ],
        warnings=federation.warnings,
    )


def render_workspace_text(result: WorkspaceResult) -> str:
    if not result["services"]:
        return "Aucun module Maven découvert (pom.xml introuvable)."
    lines = []
    for info in result["services"]:
        status = "indexé" if info["indexed"] else "non indexé"
        lines.append(
            f"[{info['kind']}] {info['name']} ({status})  "
            f"endpoints={info['endpoint_count']} findings={info['finding_count']}  "
            f"{info['path']}"
        )
    for warning in result["warnings"]:
        lines.append(f"⚠ {warning}")
    return "\n".join(lines)


class FlowSiteInfo(TypedDict):
    service: str | None  # None hors fédération (projet courant seul)
    role: str
    system: str
    framework: str | None
    path: str
    start_line: int
    end_line: int
    topic_dynamic: bool
    finding_rule_ids: list[str]


class FlowResultInfo(TypedDict):
    """Shape returned by `cccr flow <query> --json` and the
    `trace_message_flow` MCP tool (BACKLOG-10 K5/K6)."""

    query: str
    resolved_topic: str
    sites: list[FlowSiteInfo]
    warnings: list[str]


def render_flow_json(result: FlowResult) -> FlowResultInfo:
    return FlowResultInfo(
        query=result.query,
        resolved_topic=result.resolved_topic,
        sites=[
            FlowSiteInfo(
                service=site.service,
                role=site.endpoint.role,
                system=site.endpoint.system,
                framework=site.endpoint.framework,
                path=site.endpoint.path,
                start_line=site.endpoint.start_line,
                end_line=site.endpoint.end_line,
                topic_dynamic=site.endpoint.topic_dynamic,
                finding_rule_ids=[f.rule_id for f in site.findings],
            )
            for site in result.sites
        ],
        warnings=result.warnings,
    )


def render_flow_text(result: FlowResultInfo) -> str:
    lines = [f"Topic/route résolu : {result['resolved_topic']}"]
    if not result["sites"]:
        lines.append("Aucun site (producteur/consommateur/serveur/appelant) trouvé.")
        return "\n".join(lines)
    for site in result["sites"]:
        service_marker = f"[{site['service']}] " if site["service"] else ""
        framework_marker = f" ({site['framework']})" if site["framework"] else ""
        dynamic_marker = " (dynamique)" if site["topic_dynamic"] else ""
        lines.append(
            f"  {service_marker}{site['role']}/{site['system']}{framework_marker}"
            f"{dynamic_marker}  {site['path']}:{site['start_line']}-{site['end_line']}"
        )
        for rule_id in site["finding_rule_ids"]:
            lines.append(f"    ⚠ finding: {rule_id}")
    for warning in result["warnings"]:
        lines.append(f"⚠ {warning}")
    return "\n".join(lines)
