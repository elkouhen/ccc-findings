import math
import re
import subprocess
from html import escape as html_escape
from pathlib import Path
from typing import TypedDict
from xml.sax.saxutils import quoteattr

from ccc_radar.ccc_bridge import CodeHitWithFindings
from ccc_radar.configuration import service_configuration_example
from ccc_radar.flow import FlowResult
from ccc_radar.graph import GraphEdge, OutboundCallInConsumer
from ccc_radar.models import MessageEndpoint
from ccc_radar.modules import DiscoveredModule
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


class GraphEdgeInfo(TypedDict):
    kind: str  # "rest" | "kafka_produce" | "kafka_consume"
    from_node: str
    from_kind: str  # "microservice" | "kafka_topic"
    to_node: str
    to_kind: str  # "microservice" | "kafka_topic"
    label: str
    from_site: GraphSite | None
    to_site: GraphSite | None


class GraphResult(TypedDict):
    """Shape returned by `cccr graph --json` et le tool MCP `graph`.

    `services`/`nodes`/`edges` restent vides tant qu'aucune donnée
    inter-module n'est disponible : ni fédération explicite
    (`--workspace`/`workspace_root`, BACKLOG-11 A2), ni endpoints attribués à
    un module Maven par l'indexation d'un répertoire parent multi-modules
    (BACKLOG-13 M1/M2/M3) — voir `note`.
    """

    services: list[str]
    nodes: list[GraphNodeInfo]
    edges: list[GraphEdgeInfo]
    outbound_calls_in_consumers: list[OutboundCallHit]
    note: str


_NO_CROSS_MODULE_DATA_NOTE = (
    "La topologie inter-services nécessite soit un répertoire multi-services "
    "fédéré (--workspace/workspace_root, BACKLOG-11 A2), soit des endpoints "
    "attribués à un module Maven par une indexation multi-modules (BACKLOG-13) — "
    "seuls les appels REST détectés dans un handler Kafka de ce projet sont "
    "remontés pour l'instant."
)


def _endpoint_to_site(endpoint: MessageEndpoint) -> GraphSite:
    return GraphSite(
        path=endpoint.path,
        start_line=endpoint.start_line,
        end_line=endpoint.end_line,
        topic=endpoint.topic,
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


def render_graph_json(
    services: list[str],
    edges: list[GraphEdge],
    outbound_calls: list[OutboundCallInConsumer],
    warnings: list[str] | None = None,
    cross_module_data_available: bool = False,
) -> GraphResult:
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

    if result["note"]:
        lines.append(result["note"])
    return "\n".join(lines)


def render_graph_drawio(
    endpoints_by_service: dict[str, list[MessageEndpoint]], edges: list[GraphEdge]
) -> str:
    """Rend le graphe d'interactions en XML mxGraph (format natif
    diagrams.net/drawio) : un nœud par microservice, plus un nœud par topic
    Kafka inter-service. Les arêtes REST vont de l'appelant vers l'appelé ;
    les arêtes Kafka sont dépliées en microservice -> topic (production) puis
    topic -> microservice (consommation). Les nœuds microservices et topics
    portent des couleurs et des formes distinctes. Le fichier ne porte pas de
    contraintes de couche ou de tri topologique : un layout élastique
    déterministe rapproche les topics des services qui les utilisent et repousse
    les nœuds non liés. Toute valeur dérivée du code source (nom de service,
    route, topic) est échappée XML via `quoteattr` — jamais interpolée brute."""
    node_width = 320

    ordered_services = sorted(endpoints_by_service)
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    service_resources = {
        name: _rest_resources_served(endpoints_by_service.get(name, [])) for name in ordered_services
    }
    ordered_nodes = [("microservice", name) for name in ordered_services] + [
        ("kafka_topic", name) for name in kafka_topics
    ]
    node_ids = {node: f"node-{i}" for i, node in enumerate(ordered_nodes)}
    node_dimensions = {
        ("microservice", name): (node_width, _drawio_service_height(service_resources[name]))
        for name in ordered_services
    } | {("kafka_topic", name): (220, 60) for name in kafka_topics}
    # The graph model remains detailed, but the visual export bundles calls
    # sharing the same endpoints. This removes parallel strokes and keeps their
    # individual routes as a multi-line label on the single connector.
    visual_edges = _drawio_visual_graph_edges(edges)
    positions = _drawio_initial_positions(ordered_nodes, visual_edges, node_dimensions)

    cells: list[str] = []
    for node_kind, name in ordered_nodes:
        if node_kind == "microservice":
            label = _drawio_service_label(name, service_resources[name])
            width, height = node_dimensions[(node_kind, name)]
            style = (
                "rounded=1;arcSize=14;whiteSpace=wrap;html=1;"
                "fillColor=#eaf2ff;strokeColor=#4f79b5;strokeWidth=2;"
                "fontColor=#183b66;fontSize=14;fontStyle=1;shadow=1;"
                "spacingLeft=12;spacingRight=12;"
            )
        else:
            label = f"<b>{html_escape(name)}</b>"
            width, height = node_dimensions[(node_kind, name)]
            style = (
                "shape=cylinder3;boundedLbl=1;whiteSpace=wrap;html=1;"
                "fillColor=#fff3df;strokeColor=#d18b20;strokeWidth=2;"
                "fontColor=#744a0b;fontSize=13;"
            )
        x, y = positions[(node_kind, name)]
        cells.append(
                f'<mxCell id="{node_ids[(node_kind, name)]}" value={quoteattr(label)} '
            f'style={quoteattr(style)} '
            f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{width}" height="{height}" '
            'as="geometry" /></mxCell>'
        )

    for visual_edge_index, (source_kind, source_name, target_kind, target_name, label, kind) in enumerate(
        visual_edges
    ):
        source_id = node_ids.get((source_kind, source_name))
        target_id = node_ids.get((target_kind, target_name))
        if source_id is None or target_id is None:
            continue
        style = (
            "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;"
            "html=1;endArrow=block;endFill=1;strokeWidth=2;"
            "labelBackgroundColor=#ffffff;fontSize=11;spacing=4;"
        )
        if kind == "kafka":
            style += "dashed=1;dashPattern=6 4;strokeColor=#d18b20;fontColor=#744a0b;"
        else:
            style += "strokeColor=#4f79b5;fontColor=#183b66;"
        cells.append(
            f'<mxCell id="edge-{visual_edge_index}" value={quoteattr(label)} style={quoteattr(style)} '
            f'edge="1" parent="1" source="{source_id}" target="{target_id}">'
            '<mxGeometry relative="1" as="geometry" /></mxCell>'
        )

    body = "\n        ".join(cells)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="cccr">\n'
        '  <diagram name="cccr graph" id="cccr-graph">\n'
        '    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" '
        'connect="1" arrows="1" fold="1" page="0" pageScale="1" pageWidth="1169" '
        'pageHeight="827" background="#fafbfc" math="0" shadow="0">\n'
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


def _drawio_service_height(resources: list[str]) -> int:
    """Height of a service card, including its resource header and rows."""
    return 82 + 22 * max(1, len(resources))


def _drawio_service_label(name: str, resources: list[str]) -> str:
    """HTML label shared by Draw.io service cards.

    Resource names come from source code and must be HTML-escaped separately:
    XML attribute escaping alone would otherwise let a route containing markup
    alter the card's label.
    """
    title = html_escape(name)
    if resources:
        count = f"{len(resources)} ressource{'s' if len(resources) > 1 else ''} exposée{'s' if len(resources) > 1 else ''}"
        rows = "".join(_drawio_resource_row(resource) for resource in resources)
    else:
        count = "Aucune ressource exposée"
        rows = (
            '<tr><td colspan="2" style="padding:6px 4px;color:#6b7280;">'
            'Aucune ressource HTTP détectée</td></tr>'
        )
    return (
        '<div style="text-align:left;line-height:1.25;">'
        f'<div style="text-align:center;font-size:14px;color:#183b66;"><b>{title}</b></div>'
        '<div style="margin-top:7px;padding:4px 5px;background-color:#dbeafe;'
        'color:#315f9b;font-size:10px;font-weight:bold;border-radius:4px;">'
        f'{count}</div>'
        '<table style="width:100%;margin-top:3px;font-size:10px;border-collapse:collapse;">'
        f"{rows}</table></div>"
    )


def _drawio_resource_row(resource: str) -> str:
    method, separator, path = resource.partition(" ")
    if not separator:
        method, path = "HTTP", resource
    colors = {
        "GET": ("#dbeafe", "#1d4ed8"),
        "POST": ("#dcfce7", "#15803d"),
        "PUT": ("#f3e8ff", "#7e22ce"),
        "PATCH": ("#fef3c7", "#b45309"),
        "DELETE": ("#fee2e2", "#b91c1c"),
        "ANY": ("#e5e7eb", "#4b5563"),
    }
    background, foreground = colors.get(method, ("#e5e7eb", "#4b5563"))
    return (
        '<tr><td style="padding:2px 5px 2px 0;width:47px;">'
        f'<span style="background-color:{background};color:{foreground};font-weight:bold;'
        f'font-size:9px;padding:2px 4px;border-radius:3px;">{html_escape(method)}</span></td>'
        f'<td style="padding:2px 0;color:#183b66;">{html_escape(path)}</td></tr>'
    )


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
    edges: list[GraphEdge],
) -> list[tuple[str, str, str, str, str, str]]:
    """Projette les `GraphEdge` vers les arêtes réellement dessinées, en
    supprimant les doublons ayant la même source, destination et label.

    Retourne `(source_kind, source, target_kind, target, label, kind)`, où les
    types de nœuds évitent toute ambiguïté quand un service porte le même nom
    qu'un topic Kafka."""
    projected: dict[tuple[str, str, str, str, str], str] = {}
    order: list[tuple[str, str, str, str, str]] = []
    for edge in edges:
        visual_edges: list[tuple[str, str, str, str, str]] = []
        if edge.kind == "rest":
            label = edge.from_endpoint.topic
            if edge.from_endpoint.framework == "spring-cloud-gateway":
                match = re.search(r"Path=([^;]+)", edge.from_endpoint.snippet)
                if match is not None:
                    label = f"ANY {match.group(1)}"
            visual_edges.append(
                ("microservice", edge.from_service, "microservice", edge.to_service, label)
            )
        else:
            topic = edge.from_endpoint.topic
            visual_edges.append(("microservice", edge.from_service, "kafka_topic", topic, topic))
            visual_edges.append(("kafka_topic", topic, "microservice", edge.to_service, topic))

        for source_kind, source_name, target_kind, target_name, label in visual_edges:
            key = (source_kind, source_name, target_kind, target_name, label)
            if key not in projected:
                projected[key] = edge.kind
                order.append(key)

    return [
        (*key, projected[key])
        for key in order
    ]


def _drawio_visual_graph_edges(
    edges: list[GraphEdge],
) -> list[tuple[str, str, str, str, str, str]]:
    """Bundle detailed relations by endpoints for a readable Draw.io export.

    This is deliberately Draw.io-specific: JSON and D2 retain one relation per
    route. The generated label contains each route, in stable discovery order.
    """
    bundled: dict[tuple[str, str, str, str, str], list[str]] = {}
    order: list[tuple[str, str, str, str, str]] = []
    for source_kind, source_name, target_kind, target_name, label, kind in _visual_graph_edges(edges):
        key = (source_kind, source_name, target_kind, target_name, kind)
        if key not in bundled:
            bundled[key] = []
            order.append(key)
        if label not in bundled[key]:
            bundled[key].append(label)
    return [
        (source_kind, source_name, target_kind, target_name, "<br/>".join(bundled[key]), kind)
        for key in order
        for source_kind, source_name, target_kind, target_name, kind in [key]
    ]


def render_graph_d2(
    endpoints_by_service: dict[str, list[MessageEndpoint]], edges: list[GraphEdge]
) -> str:
    """Rend le graphe en source D2 pour bénéficier du moteur d'agencement
    natif de D2. Les nœuds restent microservices + topics Kafka, les arêtes
    REST vont de l'appelant vers l'appelé et les arêtes Kafka sont dépliées
    en production puis consommation. Kafka reste en pointillé."""
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

    for source_kind, source_name, target_kind, target_name, label, kind in _visual_graph_edges(edges):
        source_id = (service_ids if source_kind == "microservice" else topic_ids).get(source_name)
        target_id = (service_ids if target_kind == "microservice" else topic_ids).get(target_name)
        if source_id is None or target_id is None:
            continue
        lines.append(f'{source_id} -> {target_id}: "{_d2_escape(label)}" {{')
        if kind == "kafka":
            lines.append("  style.stroke-dash: 3")
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


def _drawio_initial_positions(
    ordered_nodes: list[tuple[str, str]],
    visual_edges: list[tuple[str, str, str, str, str, str]],
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
) -> dict[tuple[str, str], tuple[int, int]]:
    """Elastic seed positions by service/topic affinity.

    This is a deterministic force-directed layout: graph edges pull related
    nodes together, every node repels every other node, and disconnected
    components receive a mild horizontal offset. It writes ordinary Draw.io
    coordinates only; no ports, waypoints, ranks, or layer constraints are
    encoded in the XML.
    """
    left_margin = 24
    top_margin = 24
    if not ordered_nodes:
        return {}

    # The simulation is intentionally more patient than an interactive D3
    # layout. Graph exports are generated off-line, so spending a few seconds
    # finding a stable placement is preferable to exporting a dense, unreadable
    # diagram. Distances are measured between rectangle borders, not centers.
    linked_node_gap = 60.0
    repulsion_strength = 44_000.0
    center_strength = 0.016
    alpha = 1.0
    alpha_min = 0.002
    alpha_decay = 1 - alpha_min ** (1 / 5_000)
    velocity_decay = 0.65
    max_velocity = 36.0
    max_iterations = 6_000
    node_margin = 44.0
    order_index = {node: index for index, node in enumerate(ordered_nodes)}
    node_set = set(ordered_nodes)
    adjacency: dict[tuple[str, str], set[tuple[str, str]]] = {node: set() for node in ordered_nodes}
    edge_pairs: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for source_kind, source_name, target_kind, target_name, _label, _kind in visual_edges:
        source = (source_kind, source_name)
        target = (target_kind, target_name)
        if source not in node_set or target not in node_set or source == target:
            continue
        edge = (source, target) if order_index[source] < order_index[target] else (target, source)
        if edge not in edge_pairs:
            edge_pairs.append(edge)
        adjacency[source].add(target)
        adjacency[target].add(source)

    components: list[list[tuple[str, str]]] = []
    seen: set[tuple[str, str]] = set()
    for node in ordered_nodes:
        if node in seen:
            continue
        stack = [node]
        component: list[tuple[str, str]] = []
        seen.add(node)
        while stack:
            current = stack.pop()
            component.append(current)
            for neighbor in sorted(adjacency[current], key=lambda item: order_index[item]):
                if neighbor in seen:
                    continue
                seen.add(neighbor)
                stack.append(neighbor)
        component.sort(key=lambda item: order_index[item])
        components.append(component)

    # Isolated services carry no structural information for the force solver.
    # Letting them participate only expands the main graph, so they are packed
    # after the connected components have settled.
    isolated_nodes = [
        component[0]
        for component in components
        if len(component) == 1 and not adjacency[component[0]]
    ]
    simulated_nodes = [node for node in ordered_nodes if node not in set(isolated_nodes)]

    positions_f: dict[tuple[str, str], tuple[float, float]] = {}
    component_centers: dict[tuple[str, str], tuple[float, float]] = {}
    x_offset = 0.0
    golden_angle = math.pi * (3 - math.sqrt(5))
    for component in components:
        if component[0] in isolated_nodes:
            continue
        component_span = max(720.0, math.sqrt(len(component)) * 460.0)
        center_x = x_offset + component_span / 2
        center_y = component_span / 2
        for slot, node in enumerate(component):
            angle = slot * golden_angle
            radius = 120.0 * math.sqrt(slot + 1)
            kind_bias = -0.18 if node[0] == "microservice" else 0.18
            positions_f[node] = (
                center_x + math.cos(angle + kind_bias) * radius,
                center_y + math.sin(angle + kind_bias) * radius,
            )
            component_centers[node] = (center_x, center_y)
        x_offset += component_span + 260.0

    # Isolated nodes are packed afterwards and deliberately do not consume
    # force-simulation space.
    positions_f.update({node: (0.0, 0.0) for node in isolated_nodes})
    velocities = {node: (0.0, 0.0) for node in simulated_nodes}
    degrees = {node: max(1, len(adjacency[node])) for node in ordered_nodes}
    for iteration in range(max_iterations):
        if alpha < alpha_min:
            break

        for source, target in edge_pairs:
            sx, sy = positions_f[source]
            tx, ty = positions_f[target]
            dx = tx - sx
            dy = ty - sy
            distance = max(1.0, math.hypot(dx, dy))
            desired = _drawio_link_distance(
                source, target, dx, dy, node_dimensions, gap=linked_node_gap
            )
            # A high-degree topic must not turn into a massive rigid hub. The
            # spring contribution is shared across its incident edges.
            strength = alpha * 0.35 / math.sqrt(degrees[source] * degrees[target])
            force = (distance - desired) / distance * strength
            fx = dx * force
            fy = dy * force
            svx, svy = velocities[source]
            tvx, tvy = velocities[target]
            velocities[source] = (svx + fx, svy + fy)
            velocities[target] = (tvx - fx, tvy - fy)

        for i, source in enumerate(simulated_nodes):
            sx, sy = positions_f[source]
            for target in simulated_nodes[i + 1 :]:
                tx, ty = positions_f[target]
                dx = sx - tx
                dy = sy - ty
                distance = max(1.0, math.hypot(dx, dy))
                # `dx` points from target to source, therefore a positive force
                # pushes the two nodes apart. The former implementation used a
                # negative value here, which made the supposed charge attractive.
                # Connected endpoints already have a spring to keep them
                # separate. Reducing their electrical repulsion lets related
                # services/topics form readable neighbourhoods instead of
                # inflating the whole connected component.
                pair_repulsion = (
                    repulsion_strength * 0.18 if target in adjacency[source] else repulsion_strength
                )
                force = pair_repulsion * alpha / (distance * distance + 2_500.0)
                fx = dx / distance * force
                fy = dy / distance * force
                svx, svy = velocities[source]
                tvx, tvy = velocities[target]
                velocities[source] = (svx + fx, svy + fy)
                velocities[target] = (tvx - fx, tvy - fy)

        for node in simulated_nodes:
            vx, vy = velocities[node]
            x, y = positions_f[node]
            cx, cy = component_centers[node]
            vx += (cx - x) * center_strength * alpha
            vy += (cy - y) * center_strength * alpha
            vx *= 1 - velocity_decay
            vy *= 1 - velocity_decay
            speed = math.hypot(vx, vy)
            if speed > max_velocity:
                scale = max_velocity / speed
                vx *= scale
                vy *= scale
            x, y = positions_f[node]
            positions_f[node] = (x + vx, y + vy)
            velocities[node] = (vx, vy)

        # Rectangle collision is enforced throughout the cooling process. This
        # is stricter than circular collision and guarantees that the Draw.io
        # boxes cannot overlap when the simulation settles.
        _separate_overlapping_drawio_nodes(
            simulated_nodes,
            positions_f,
            node_dimensions,
            margin=node_margin,
            max_passes=2 if iteration < max_iterations - 600 else 6,
        )
        alpha += (0.0 - alpha) * alpha_decay

    _separate_overlapping_drawio_nodes(
        simulated_nodes, positions_f, node_dimensions, margin=node_margin, max_passes=1_000
    )
    _reduce_drawio_edge_crossings(
        simulated_nodes, edge_pairs, positions_f, node_dimensions, margin=node_margin
    )
    _separate_overlapping_drawio_nodes(
        simulated_nodes, positions_f, node_dimensions, margin=node_margin, max_passes=1_000
    )
    _pack_isolated_drawio_nodes(
        isolated_nodes, positions_f, node_dimensions, margin=node_margin
    )

    min_x = min(x - node_dimensions[node][0] / 2 for node, (x, _y) in positions_f.items())
    min_y = min(y - node_dimensions[node][1] / 2 for node, (_x, y) in positions_f.items())
    return {
        node: (
            int(round(x - node_dimensions[node][0] / 2 - min_x + left_margin)),
            int(round(y - node_dimensions[node][1] / 2 - min_y + top_margin)),
        )
        for node, (x, y) in positions_f.items()
    }


def _pack_isolated_drawio_nodes(
    isolated_nodes: list[tuple[str, str]],
    positions: dict[tuple[str, str], tuple[float, float]],
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
    *,
    margin: float,
) -> None:
    """Place disconnected nodes in a compact grid below the connected graph."""
    if not isolated_nodes:
        return

    connected_nodes = [node for node in positions if node not in set(isolated_nodes)]
    max_width = max(node_dimensions[node][0] for node in isolated_nodes)
    max_height = max(node_dimensions[node][1] for node in isolated_nodes)
    columns = math.ceil(math.sqrt(len(isolated_nodes)))
    if connected_nodes:
        left = min(
            positions[node][0] - node_dimensions[node][0] / 2 for node in connected_nodes
        )
        bottom = max(
            positions[node][1] + node_dimensions[node][1] / 2 for node in connected_nodes
        )
        start_x = left
        start_y = bottom + max_height / 2 + margin * 4
    else:
        start_x = 0.0
        start_y = max_height / 2

    for index, node in enumerate(isolated_nodes):
        column = index % columns
        row = index // columns
        width, height = node_dimensions[node]
        positions[node] = (
            start_x + column * (max_width + margin) + width / 2,
            start_y + row * (max_height + margin) + height / 2,
        )


def _reduce_drawio_edge_crossings(
    ordered_nodes: list[tuple[str, str]],
    edge_pairs: list[tuple[tuple[str, str], tuple[str, str]]],
    positions: dict[tuple[str, str], tuple[float, float]],
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
    *,
    margin: float,
) -> None:
    """Use deterministic local swaps to remove crossings left by the springs.

    The force simulation optimises proximity but does not know that two drawn
    connectors cross. For larger graphs, this bounded refinement considers a
    handful of positions near each node's neighbour barycentre and keeps a swap
    only when it improves crossing count without sacrificing local affinity.
    """
    if len(ordered_nodes) < 40 or len(edge_pairs) < 40:
        return

    edges_by_node: dict[tuple[str, str], list[int]] = {node: [] for node in ordered_nodes}
    for index, (source, target) in enumerate(edge_pairs):
        edges_by_node[source].append(index)
        edges_by_node[target].append(index)

    for _pass in range(3):
        improved = False
        for source in ordered_nodes:
            source_edges = edges_by_node[source]
            if not source_edges:
                continue
            neighbors = [
                edge_pairs[index][1] if edge_pairs[index][0] == source else edge_pairs[index][0]
                for index in source_edges
            ]
            barycenter = (
                sum(positions[node][0] for node in neighbors) / len(neighbors),
                sum(positions[node][1] for node in neighbors) / len(neighbors),
            )
            candidates = sorted(
                (
                    node
                    for node in ordered_nodes
                    if node > source and node[0] == source[0] and edges_by_node[node]
                ),
                key=lambda node: math.dist(positions[node], barycenter),
            )[:6]
            for target in candidates:
                if not _drawio_swap_is_clear(
                    source, target, ordered_nodes, positions, node_dimensions, margin=margin
                ):
                    continue
                affected_edges = set(source_edges) | set(edges_by_node[target])
                before = _drawio_swap_cost(affected_edges, edge_pairs, positions)
                positions[source], positions[target] = positions[target], positions[source]
                after = _drawio_swap_cost(affected_edges, edge_pairs, positions)
                if after < before:
                    improved = True
                    break
                positions[source], positions[target] = positions[target], positions[source]
        if not improved:
            break


def _drawio_swap_is_clear(
    source: tuple[str, str],
    target: tuple[str, str],
    ordered_nodes: list[tuple[str, str]],
    positions: dict[tuple[str, str], tuple[float, float]],
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
    *,
    margin: float,
) -> bool:
    """Return whether swapping two boxes keeps both target positions clear."""
    source_position = positions[source]
    target_position = positions[target]
    positions[source], positions[target] = target_position, source_position
    try:
        source_width, source_height = node_dimensions[source]
        target_width, target_height = node_dimensions[target]
        if (
            abs(positions[source][0] - positions[target][0]) < (source_width + target_width) / 2 + margin
            and abs(positions[source][1] - positions[target][1])
            < (source_height + target_height) / 2 + margin
        ):
            return False
        for node in (source, target):
            nx, ny = positions[node]
            nw, nh = node_dimensions[node]
            for other in ordered_nodes:
                if other == node or other in {source, target}:
                    continue
                ox, oy = positions[other]
                ow, oh = node_dimensions[other]
                if abs(nx - ox) < (nw + ow) / 2 + margin and abs(ny - oy) < (nh + oh) / 2 + margin:
                    return False
        return True
    finally:
        positions[source], positions[target] = source_position, target_position


def _drawio_swap_cost(
    affected_edges: set[int],
    edge_pairs: list[tuple[tuple[str, str], tuple[str, str]]],
    positions: dict[tuple[str, str], tuple[float, float]],
) -> float:
    """Score the local edge lengths and crossings affected by a position swap."""
    edge_length = 0.0
    crossings = 0
    for edge_index in affected_edges:
        source, target = edge_pairs[edge_index]
        edge_length += math.dist(positions[source], positions[target])
        for other_index, (other_source, other_target) in enumerate(edge_pairs):
            if other_index == edge_index or {source, target} & {other_source, other_target}:
                continue
            if _drawio_segments_cross(
                positions[source], positions[target], positions[other_source], positions[other_target]
            ):
                crossings += 1
    return edge_length + crossings * 2_500.0


def _drawio_segments_cross(
    start: tuple[float, float],
    end: tuple[float, float],
    other_start: tuple[float, float],
    other_end: tuple[float, float],
) -> bool:
    """Return whether two non-collinear line segments cross in their interiors."""
    def orientation(
        first: tuple[float, float], second: tuple[float, float], third: tuple[float, float]
    ) -> float:
        return (second[0] - first[0]) * (third[1] - first[1]) - (
            second[1] - first[1]
        ) * (third[0] - first[0])

    start_side = orientation(start, end, other_start)
    end_side = orientation(start, end, other_end)
    other_start_side = orientation(other_start, other_end, start)
    other_end_side = orientation(other_start, other_end, end)
    return start_side * end_side < 0 and other_start_side * other_end_side < 0


def _drawio_link_distance(
    source: tuple[str, str],
    target: tuple[str, str],
    dx: float,
    dy: float,
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
    *,
    gap: float,
) -> float:
    """Return the desired center distance for a spring between two boxes."""
    distance = math.hypot(dx, dy)
    if distance < 0.001:
        # The exact direction does not matter for a coincident pair: collision
        # resolution will immediately make it non-coincident.
        return sum(node_dimensions[source]) / 2 + sum(node_dimensions[target]) / 2 + gap

    ux = abs(dx) / distance
    uy = abs(dy) / distance
    source_width, source_height = node_dimensions[source]
    target_width, target_height = node_dimensions[target]
    source_extent = source_width / 2 * ux + source_height / 2 * uy
    target_extent = target_width / 2 * ux + target_height / 2 * uy
    return source_extent + target_extent + gap


def _separate_overlapping_drawio_nodes(
    ordered_nodes: list[tuple[str, str]],
    positions: dict[tuple[str, str], tuple[float, float]],
    node_dimensions: dict[tuple[str, str], tuple[int, int]],
    *,
    margin: float,
    max_passes: int = 160,
) -> None:
    """Resolve rectangle overlaps in-place after the elastic solver settles."""
    for _pass in range(max_passes):
        moved = False
        for i, source in enumerate(ordered_nodes):
            sx, sy = positions[source]
            sw, sh = node_dimensions[source]
            for target in ordered_nodes[i + 1 :]:
                tx, ty = positions[target]
                tw, th = node_dimensions[target]
                dx = tx - sx
                dy = ty - sy
                overlap_x = (sw + tw) / 2 + margin - abs(dx)
                overlap_y = (sh + th) / 2 + margin - abs(dy)
                if overlap_x <= 0 or overlap_y <= 0:
                    continue

                moved = True
                # Resolve on the axis requiring the smallest translation.
                # Forcing same-kind nodes (notably many Kafka topics around a
                # hub) horizontally creates a long, unreadable strip.
                if overlap_x < overlap_y:
                    direction = 1.0 if dx >= 0 else -1.0
                    shift = overlap_x / 2
                    sx -= direction * shift
                    tx += direction * shift
                else:
                    direction = 1.0 if dy >= 0 else -1.0
                    shift = overlap_y / 2
                    sy -= direction * shift
                    ty += direction * shift
                positions[source] = (sx, sy)
                positions[target] = (tx, ty)
        if not moved:
            break


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
    starts_application: bool
    indexed: bool
    endpoint_count: int
    finding_count: int


class ModuleSummary(TypedDict):
    name: str
    path: str
    build_system: str
    version: str | None
    kind: str
    mongo_collections: list[str]
    mongo_method_count: int
    kafka_method_count: int
    blocking_point_count: int
    openapi_files: list[str]


class ModuleDetail(ModuleSummary):
    configuration_example: str
    mongo_methods: list[dict[str, object]]
    kafka_methods: list[dict[str, object]]
    blocking_points: list[dict[str, object]]


class WorkspaceResult(TypedDict):
    """Shape returned by `cccr microservices [root] --json` and the
    `list_workspace_services` MCP tool (BACKLOG-11 A2)."""

    services: list[WorkspaceServiceInfo]
    configuration_examples: dict[str, str]
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
        configuration_examples={
            service.name: service_configuration_example(service.path)
            for service in services
            if service.kind == "microservice"
        },
        warnings=federation.warnings,
    )


def render_workspace_text(result: WorkspaceResult) -> str:
    if not result["services"]:
        return "Aucun service workspace découvert (ni module Maven runtime, ni microservice Gradle Spring Boot)."
    lines = []
    for info in result["services"]:
        status = "indexé" if info["indexed"] else "non indexé"
        lines.append(
            f"[{info['kind']}] {info['name']} ({status})  "
            f"endpoints={info['endpoint_count']} findings={info['finding_count']}  "
            f"{info['path']}"
        )
        example = result["configuration_examples"].get(info["name"])
        if example is not None:
            lines.append("  Configuration Spring (exemple YAML) :")
            lines.extend(f"    {line}" if line else "" for line in example.rstrip().splitlines())
    for warning in result["warnings"]:
        lines.append(f"⚠ {warning}")
    return "\n".join(lines)


def render_modules_list_json(modules: list[DiscoveredModule]) -> list[ModuleSummary]:
    return [
        ModuleSummary(
            name=module.name,
            path=str(module.path),
            build_system=module.build_system,
            version=module.version,
            kind=module.kind,
            starts_application=module.starts_application,
            mongo_collections=list(module.mongo_collections),
            mongo_method_count=len(module.mongo_methods),
            kafka_method_count=len(module.kafka_methods),
            blocking_point_count=len(module.blocking_points),
            openapi_files=list(module.openapi_files),
        )
        for module in modules
    ]


def render_modules_list_text(modules: list[ModuleSummary]) -> str:
    if not modules:
        return "Aucun module Maven ou Gradle découvert."
    lines: list[str] = []
    for module in modules:
        version = module["version"] or "inconnue"
        lines.append(
            f"[{module['build_system']}/{module['kind']}] {module['name']} "
            f"version={version} mongo={len(module['mongo_collections'])} "
            f"mongo_ops={module['mongo_method_count']} kafka_ops={module['kafka_method_count']} "
            f"blocking={module['blocking_point_count']} app={module['starts_application']} "
            f"openapi={len(module['openapi_files'])}  {module['path']}"
        )
    return "\n".join(lines)


def render_module_detail_json(module: DiscoveredModule) -> ModuleDetail:
    return ModuleDetail(
        name=module.name,
        path=str(module.path),
        build_system=module.build_system,
        version=module.version,
        kind=module.kind,
        starts_application=module.starts_application,
        application_entrypoint=(
            module.application_entrypoint.__dict__ if module.application_entrypoint else None
        ),
        configuration_example=module.configuration_example,
        mongo_collections=list(module.mongo_collections),
        mongo_method_count=len(module.mongo_methods),
        kafka_method_count=len(module.kafka_methods),
        blocking_point_count=len(module.blocking_points),
        openapi_files=list(module.openapi_files),
        mongo_methods=[
            {
                "operation": method.operation,
                "receiver": method.receiver,
                "path": method.path,
                "line": method.line,
                "collection": method.collection,
                "evidence": method.evidence.__dict__ if method.evidence else None,
            }
            for method in module.mongo_methods
        ],
        kafka_methods=[
            {
                "role": method.role,
                "mechanism": method.mechanism,
                "method": method.method,
                "path": method.path,
                "line": method.line,
                "topic": method.topic,
                "evidence": method.evidence.__dict__ if method.evidence else None,
            }
            for method in module.kafka_methods
        ],
        blocking_points=[
            {
                "mechanism": point.mechanism,
                "method": point.method,
                "path": point.path,
                "line": point.line,
                "detail": point.detail,
                "evidence": point.evidence.__dict__ if point.evidence else None,
            }
            for point in module.blocking_points
        ],
    )


def render_module_detail_text(module: ModuleDetail) -> str:
    version = module["version"] or "inconnue"
    return (
        f"[{module['build_system']}/{module['kind']}] {module['name']}\n"
        f"version={version}\nchemin={module['path']}\n"
        f"démarre l'application={module['starts_application']}\n"
        f"collections Mongo={', '.join(module['mongo_collections']) or 'aucune'}\n"
        f"opérations Mongo={module['mongo_method_count']}\n"
        f"opérations Kafka={module['kafka_method_count']}\n"
        f"points bloquants={module['blocking_point_count']}\n"
        f"OpenAPI={', '.join(module['openapi_files']) or 'aucun'}"
    )


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
