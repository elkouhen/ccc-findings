import math
import subprocess
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


class GraphNodeInfo(TypedDict):
    name: str
    kind: str  # "microservice" | "kafka_topic"


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


class GraphEdgeInfo(TypedDict):
    kind: str  # "rest" | "kafka_produce" | "kafka_consume"
    from_node: str
    from_kind: str  # "microservice" | "kafka_topic"
    to_node: str
    to_kind: str  # "microservice" | "kafka_topic"
    label: str
    from_site: GraphSite | None
    to_site: GraphSite | None


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

    `services`/`nodes`/`edges`/`cycles`/`hotspots` restent vides tant qu'aucune
    donnée inter-module n'est disponible : ni fédération explicite
    (`--workspace`/`workspace_root`, BACKLOG-11 A2), ni endpoints/findings
    attribués à un module Maven par l'indexation d'un répertoire parent
    multi-modules (BACKLOG-13 M1/M2/M3) — voir `note`.
    """

    services: list[str]
    nodes: list[GraphNodeInfo]
    edges: list[GraphEdgeInfo]
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


def _graph_nodes(services: list[str], edges: list[GraphEdge]) -> list[GraphNodeInfo]:
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    return [GraphNodeInfo(name=service, kind="microservice") for service in services] + [
        GraphNodeInfo(name=topic, kind="kafka_topic") for topic in kafka_topics
    ]


def _graph_edges(edges: list[GraphEdge]) -> list[GraphEdgeInfo]:
    rendered_edges: list[GraphEdgeInfo] = []
    for edge in edges:
        if edge.kind == "rest":
            rendered_edges.append(
                GraphEdgeInfo(
                    kind="rest",
                    from_node=edge.from_service,
                    from_kind="microservice",
                    to_node=edge.to_service,
                    to_kind="microservice",
                    label=edge.from_endpoint.topic,
                    from_site=_endpoint_to_site(edge.from_endpoint),
                    to_site=_endpoint_to_site(edge.to_endpoint),
                )
            )
            continue

        topic = edge.from_endpoint.topic
        rendered_edges.append(
            GraphEdgeInfo(
                kind="kafka_produce",
                from_node=edge.from_service,
                from_kind="microservice",
                to_node=topic,
                to_kind="kafka_topic",
                label=topic,
                from_site=_endpoint_to_site(edge.from_endpoint),
                to_site=None,
            )
        )
        rendered_edges.append(
            GraphEdgeInfo(
                kind="kafka_consume",
                from_node=topic,
                from_kind="kafka_topic",
                to_node=edge.to_service,
                to_kind="microservice",
                label=topic,
                from_site=None,
                to_site=_endpoint_to_site(edge.to_endpoint),
            )
        )
    return rendered_edges


def _hotspot_to_info(hotspot: Hotspot) -> HotspotInfo:
    return HotspotInfo(
        service=hotspot.service,
        site=_endpoint_to_site(hotspot.endpoint),
        finding_rule_id=hotspot.finding.rule_id,
        finding_severity=hotspot.finding.severity,
    )


def render_graph_json(
    services: list[str],
    edges: list[GraphEdge],
    outbound_calls: list[OutboundCallInConsumer],
    cycles: list[Cycle] | None = None,
    hotspots: list[Hotspot] | None = None,
    warnings: list[str] | None = None,
    cross_module_data_available: bool = False,
) -> GraphResult:
    cycles = cycles or []
    hotspots = hotspots or []
    warning_note = " ".join(f"⚠ {w}" for w in (warnings or []))
    if cross_module_data_available:
        note = warning_note
    elif warning_note:
        note = f"{_NO_CROSS_MODULE_DATA_NOTE} {warning_note}"
    else:
        note = _NO_CROSS_MODULE_DATA_NOTE
    return GraphResult(
        services=services,
        nodes=_graph_nodes(services, edges),
        edges=_graph_edges(edges),
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
    lines: list[str] = []
    services = result["services"]
    nodes = result["nodes"]
    edges = result["edges"]
    if services:
        lines.append(f"Services ({len(services)}) : {', '.join(services)}")
    else:
        lines.append("Aucun service inter-module disponible pour construire le graphe.")

    kafka_topics = [node["name"] for node in nodes if node["kind"] == "kafka_topic"]
    if kafka_topics:
        lines.append(f"Topics Kafka ({len(kafka_topics)}) : {', '.join(kafka_topics)}")
    else:
        lines.append("Aucun topic Kafka inter-service détecté.")

    if edges:
        lines.append(f"Arêtes du graphe ({len(edges)}) :")
        for edge in edges:
            from_site = (
                f" ({edge['from_site']['path']}:{edge['from_site']['start_line']})"
                if edge["from_site"] is not None
                else ""
            )
            to_site = (
                f" ({edge['to_site']['path']}:{edge['to_site']['start_line']})"
                if edge["to_site"] is not None
                else ""
            )
            lines.append(
                f"  [{edge['kind']}] {edge['from_node']}{from_site} --{edge['label']}--> "
                f"{edge['to_node']}{to_site}"
            )
    else:
        lines.append("Aucune arête inter-service détectée.")

    calls = result["outbound_calls_in_consumers"]
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
    endpoints_by_service: dict[str, list[MessageEndpoint]], edges: list[GraphEdge], cycles: list[Cycle]
) -> str:
    """Rend le graphe d'interactions en XML mxGraph (format natif
    diagrams.net/drawio) : un nœud par microservice, plus un nœud par topic
    Kafka inter-service. Les arêtes REST vont de l'appelant vers l'appelé ;
    les arêtes Kafka sont dépliées en microservice -> topic (production) puis
    topic -> microservice (consommation). Les nœuds microservices et topics
    portent des couleurs distinctes. Les arêtes d'un cycle
    `has_synchronous_rest=True` sont mises en évidence en rouge (même signal
    que le cycle « synchrone » du rendu JSON/texte). Layout initial en grille
    — diagrams.net réorganise à la demande, ce n'est pas un rendu figé. Toute
    valeur dérivée du code source (nom de service, route, topic) est échappée
    XML via `quoteattr` — jamais interpolée brute."""
    synchronous_edge_ids = {
        id(edge) for cycle in cycles if cycle.has_synchronous_rest for edge in cycle.edges
    }
    node_width = 220
    node_height = 60

    ordered_services = sorted(endpoints_by_service)
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    ordered_nodes = [("microservice", name) for name in ordered_services] + [
        ("kafka_topic", name) for name in kafka_topics
    ]
    node_ids = {name: f"node-{i}" for i, (_, name) in enumerate(ordered_nodes)}
    positions = _graphviz_node_positions(
        ordered_services,
        kafka_topics,
        edges,
        node_width=node_width,
        node_height=node_height,
    ) or _fallback_drawio_positions(
        ordered_services,
        kafka_topics,
        node_width=node_width,
        node_height=node_height,
    )

    cells: list[str] = []
    for node_kind, name in ordered_nodes:
        if node_kind == "microservice":
            label = f"<b>{name}</b>"
            width = node_width
            height = node_height
            style = (
                "rounded=1;whiteSpace=wrap;html=1;"
                "fillColor=#dae8fc;strokeColor=#6c8ebf;"
            )
        else:
            label = f"<b>{name}</b>"
            width = node_width
            height = node_height
            style = (
                "rounded=1;whiteSpace=wrap;html=1;"
                "fillColor=#ffe6cc;strokeColor=#d79b00;"
            )
        x, y = positions[name]
        cells.append(
            f'<mxCell id="{node_ids[name]}" value={quoteattr(label)} '
            f'style={quoteattr(style)} '
            f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{width}" height="{height}" '
            'as="geometry" /></mxCell>'
        )

    visual_edge_index = 0
    for source_name, target_name, label, kind, highlighted in _visual_graph_edges(
        edges, synchronous_edge_ids
    ):
        source_id = node_ids.get(source_name)
        target_id = node_ids.get(target_name)
        if source_id is None or target_id is None:
            continue
        style = "edgeStyle=orthogonalEdgeStyle;html=1;"
        style += "dashed=1;" if kind == "kafka" else ""
        style += (
            "strokeColor=#d32f2f;fontColor=#d32f2f;"
            if highlighted
            else "strokeColor=#666666;"
        )
        cells.append(
            f'<mxCell id="edge-{visual_edge_index}" value={quoteattr(label)} style={quoteattr(style)} '
            f'edge="1" parent="1" source="{source_id}" target="{target_id}">'
            '<mxGeometry relative="1" as="geometry" /></mxCell>'
        )
        visual_edge_index += 1

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


def _d2_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _rest_resources_served(endpoints: list[MessageEndpoint]) -> list[str]:
    return sorted(
        {
            endpoint.topic
            for endpoint in endpoints
            if endpoint.system == "rest" and endpoint.role == "serve"
        }
    )


def _d2_markdown_block(lines: list[str], indent: str = "  ") -> list[str]:
    return (
        [f"{indent}label: |md"]
        + [f"{indent}  {line}" for line in lines]
        + [f"{indent}|"]
    )


def _visual_graph_edges(
    edges: list[GraphEdge], synchronous_edge_ids: set[int]
) -> list[tuple[str, str, str, str, bool]]:
    """Projette les `GraphEdge` vers les arêtes réellement dessinées, en
    supprimant les doublons ayant la même source, destination et label.

    Retourne `(source, target, label, kind, highlighted)` où `kind` vaut
    `"rest"` ou `"kafka"`. Si plusieurs arêtes physiques se projettent vers la
    même arête visuelle, `highlighted` est conservé dès qu'au moins une de ces
    arêtes appartient à un cycle synchrone."""
    projected: dict[tuple[str, str, str], tuple[str, bool]] = {}
    order: list[tuple[str, str, str]] = []
    for edge in edges:
        visual_edges: list[tuple[str, str, str]] = []
        if edge.kind == "rest":
            visual_edges.append((edge.from_service, edge.to_service, edge.from_endpoint.topic))
        else:
            topic = edge.from_endpoint.topic
            visual_edges.append((edge.from_service, topic, topic))
            visual_edges.append((topic, edge.to_service, topic))

        for source_name, target_name, label in visual_edges:
            key = (source_name, target_name, label)
            highlighted = id(edge) in synchronous_edge_ids
            if key not in projected:
                projected[key] = (edge.kind, highlighted)
                order.append(key)
                continue
            kind, existing_highlighted = projected[key]
            projected[key] = (kind, existing_highlighted or highlighted)

    return [
        (source_name, target_name, label, *projected[(source_name, target_name, label)])
        for source_name, target_name, label in order
    ]


def render_graph_d2(
    endpoints_by_service: dict[str, list[MessageEndpoint]], edges: list[GraphEdge], cycles: list[Cycle]
) -> str:
    """Rend le graphe en source D2 pour bénéficier du moteur d'agencement
    natif de D2. Les nœuds restent microservices + topics Kafka, les arêtes
    REST vont de l'appelant vers l'appelé et les arêtes Kafka sont dépliées
    en production puis consommation. Les cycles synchrones sont marqués en
    rouge, Kafka en pointillé."""
    synchronous_edge_ids = {
        id(edge) for cycle in cycles if cycle.has_synchronous_rest for edge in cycle.edges
    }
    ordered_services = sorted(endpoints_by_service)
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    service_ids = {name: f"svc_{i}" for i, name in enumerate(ordered_services)}
    topic_ids = {name: f"topic_{i}" for i, name in enumerate(kafka_topics)}

    lines = [
        "direction: down",
        "",
    ]
    for name in ordered_services:
        node_id = service_ids[name]
        served_resources = _rest_resources_served(endpoints_by_service.get(name, []))
        label_lines = [f"**{name}**"]
        if served_resources:
            label_lines.extend([f"- `{resource}`" for resource in served_resources])
        lines.extend(
            [
                f"{node_id}: {{",
                "  shape: rectangle",
                '  style.fill: "#dae8fc"',
                '  style.stroke: "#6c8ebf"',
            ]
        )
        lines.extend(_d2_markdown_block(label_lines))
        lines.extend(
            [
                "}",
                "",
            ]
        )
    for name in kafka_topics:
        node_id = topic_ids[name]
        lines.extend(
            [
                f"{node_id}: {{",
                f'  label: "{_d2_escape(name)}"',
                "  shape: rectangle",
                '  style.fill: "#ffe6cc"',
                '  style.stroke: "#d79b00"',
                "}",
                "",
            ]
        )

    for source_name, target_name, label, kind, highlighted in _visual_graph_edges(
        edges, synchronous_edge_ids
    ):
        source_id = service_ids.get(source_name, topic_ids.get(source_name))
        target_id = service_ids.get(target_name, topic_ids.get(target_name))
        if source_id is None or target_id is None:
            continue
        lines.append(f'{source_id} -> {target_id}: "{_d2_escape(label)}" {{')
        if kind == "kafka":
            lines.append("  style.stroke-dash: 3")
        if highlighted:
            lines.append('  style.stroke: "#d32f2f"')
        lines.append("}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_graph_d2(output_path: Path, source: str, layout: str = "elk") -> None:
    """Écrit soit la source D2 (`.d2`), soit un rendu généré par la CLI D2
    (`.svg`, `.png`, etc.)."""
    if output_path.suffix.lower() == ".d2":
        output_path.write_text(source, encoding="utf-8")
        return

    try:
        proc = subprocess.run(
            ["d2", "--layout", layout, "-", str(output_path)],
            input=source,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "CLI 'd2' introuvable. Installez D2 ou utilisez une sortie .d2 pour écrire la source."
        ) from exc

    if proc.returncode != 0:
        details = proc.stderr.strip() or proc.stdout.strip() or f"code {proc.returncode}"
        raise RuntimeError(f"d2 a échoué: {details}")


def _fallback_drawio_positions(
    ordered_services: list[str],
    kafka_topics: list[str],
    *,
    node_width: int,
    node_height: int,
) -> dict[str, tuple[int, int]]:
    top_margin = 24
    left_margin = 24
    horizontal_gap = 48
    vertical_gap = 72
    band_gap = 84

    def grid_columns(count: int) -> int:
        return max(1, math.ceil(math.sqrt(count))) if count else 1

    def band_width(count: int, columns: int) -> int:
        if count == 0:
            return 0
        items_in_row = min(count, columns)
        return items_in_row * node_width + max(0, items_in_row - 1) * horizontal_gap

    def layout_band(
        names: list[str], start_y: int, columns: int, content_width: int
    ) -> tuple[dict[str, tuple[int, int]], int]:
        positions: dict[str, tuple[int, int]] = {}
        if not names:
            return positions, start_y

        row_step = node_height + vertical_gap
        for row_index in range(math.ceil(len(names) / columns)):
            row_items = names[row_index * columns : (row_index + 1) * columns]
            row_width = len(row_items) * node_width + max(0, len(row_items) - 1) * horizontal_gap
            row_x = left_margin + max(0, (content_width - row_width) // 2)
            y = start_y + row_index * row_step
            for column_index, name in enumerate(row_items):
                x = row_x + column_index * (node_width + horizontal_gap)
                positions[name] = (x, y)

        last_row_index = math.ceil(len(names) / columns) - 1
        next_y = start_y + (last_row_index + 1) * row_step
        return positions, next_y

    service_columns = grid_columns(len(ordered_services))
    topic_columns = grid_columns(len(kafka_topics))
    content_width = max(
        band_width(len(ordered_services), service_columns),
        band_width(len(kafka_topics), topic_columns),
    )
    service_positions, next_y = layout_band(
        ordered_services, top_margin, service_columns, content_width
    )
    topic_positions, _ = layout_band(
        kafka_topics,
        next_y + (band_gap if kafka_topics and ordered_services else 0),
        topic_columns,
        content_width,
    )
    return service_positions | topic_positions


def _graphviz_escape(label: str) -> str:
    return label.replace("\\", "\\\\").replace('"', '\\"')


def _graphviz_node_positions(
    ordered_services: list[str],
    kafka_topics: list[str],
    edges: list[GraphEdge],
    *,
    node_width: int,
    node_height: int,
) -> dict[str, tuple[int, int]] | None:
    if not ordered_services and not kafka_topics:
        return {}

    all_nodes = ordered_services + kafka_topics
    engine = "neato" if len(all_nodes) <= 12 else "sfdp"
    graphviz_ids = {name: f"n{i}" for i, name in enumerate(all_nodes)}
    edge_specs: list[tuple[str, str]] = []
    for edge in edges:
        if edge.kind == "rest":
            edge_specs.append((edge.from_service, edge.to_service))
        else:
            topic = edge.from_endpoint.topic
            edge_specs.append((edge.from_service, topic))
            edge_specs.append((topic, edge.to_service))

    dot_lines = [
        "digraph G {",
        (
            "  graph [overlap=prism0, sep=\"+4\", splines=true, "
            "outputorder=edgesfirst, pack=true, pad=0.08];"
        ),
        (
            "  node [shape=box, fixedsize=true, width="
            f"{node_width / 72:.3f}, height={node_height / 72:.3f}];"
        ),
    ]
    if engine == "neato":
        dot_lines.append("  graph [mode=ipsep, model=shortpath];")
    else:
        dot_lines.append("  graph [K=0.45, repulsiveforce=0.8];")

    for name in ordered_services:
        dot_lines.append(f'  {graphviz_ids[name]} [label="{_graphviz_escape(name)}"];')
    for name in kafka_topics:
        dot_lines.append(f'  {graphviz_ids[name]} [label="{_graphviz_escape(name)}"];')

    for source_name, target_name in edge_specs:
        dot_lines.append(f"  {graphviz_ids[source_name]} -> {graphviz_ids[target_name]};")
    dot_lines.append("}")

    try:
        proc = subprocess.run(
            [engine, "-Tplain"],
            input="\n".join(dot_lines),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    return _parse_graphviz_plain_output(
        proc.stdout,
        graphviz_ids,
        node_width=node_width,
        node_height=node_height,
    )


def _parse_graphviz_plain_output(
    plain_output: str,
    graphviz_ids: dict[str, str],
    *,
    node_width: int,
    node_height: int,
) -> dict[str, tuple[int, int]] | None:
    node_centers: dict[str, tuple[float, float]] = {}
    for raw_line in plain_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if parts[0] == "node" and len(parts) >= 4:
            node_centers[parts[1]] = (float(parts[2]), float(parts[3]))

    if not node_centers:
        return None

    reverse_ids = {graphviz_id: name for name, graphviz_id in graphviz_ids.items()}
    pixels_per_inch = 72.0
    left_margin = 24
    top_margin = 24
    positions: dict[str, tuple[int, int]] = {}
    node_width_in = node_width / pixels_per_inch
    node_height_in = node_height / pixels_per_inch
    min_left_in = min(x_in - node_width_in / 2 for x_in, _ in node_centers.values())
    max_top_in = max(y_in + node_height_in / 2 for _, y_in in node_centers.values())
    for graphviz_id, (x_in, y_in) in node_centers.items():
        name = reverse_ids.get(graphviz_id)
        if name is None:
            continue
        node_left_in = x_in - node_width_in / 2
        node_top_in = y_in + node_height_in / 2
        x = int(round(left_margin + (node_left_in - min_left_in) * pixels_per_inch))
        y = int(round(top_margin + (max_top_in - node_top_in) * pixels_per_inch))
        positions[name] = (x, y)
    return positions if len(positions) == len(graphviz_ids) else None


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


def render_endpoints_text(endpoints: list[MessageEndpoint], warnings: list[str] | None = None) -> str:
    if not endpoints:
        lines = ["Aucun endpoint indexé."]
        for warning in warnings or []:
            lines.append(f"⚠ {warning}")
        return "\n".join(lines)
    lines = []
    for e in endpoints:
        dynamic_marker = " (dynamique)" if e.topic_dynamic else ""
        module_marker = f" [{e.module}]" if e.module else ""
        lines.append(
            f"[{e.system}/{e.role}] {e.topic}{dynamic_marker}{module_marker}  "
            f"{e.path}:{e.start_line}-{e.end_line}"
        )
    for warning in warnings or []:
        lines.append(f"⚠ {warning}")
    return "\n".join(lines)


class WorkspaceServiceInfo(TypedDict):
    name: str
    path: str
    kind: str
    indexed: bool
    endpoint_count: int
    finding_count: int


class WorkspaceResult(TypedDict):
    """Shape returned by `cccr microservices [root] --json` and the
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
