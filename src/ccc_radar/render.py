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

    ideal_edge = 230.0
    repulsion = 36000.0
    spring_strength = 0.09
    damping = 0.82
    max_step = 42.0
    min_iterations = 80
    max_iterations = 800
    convergence_epsilon = 0.08
    stable_iterations_required = 12
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

    positions_f: dict[tuple[str, str], tuple[float, float]] = {}
    x_offset = 0.0
    for component in components:
        radius = max(ideal_edge, len(component) * 56.0)
        center_x = x_offset + radius
        center_y = radius
        for slot, node in enumerate(component):
            angle = 2 * math.pi * slot / max(1, len(component))
            kind_bias = -0.35 if node[0] == "microservice" else 0.35
            positions_f[node] = (
                center_x + math.cos(angle + kind_bias) * radius,
                center_y + math.sin(angle + kind_bias) * radius,
            )
        x_offset += radius * 2 + ideal_edge * 1.8

    velocities = {node: (0.0, 0.0) for node in ordered_nodes}
    stable_iterations = 0
    for iteration in range(max_iterations):
        forces = {node: (0.0, 0.0) for node in ordered_nodes}
        temperature = max(2.0, max_step * (1.0 - iteration / max_iterations))

        for i, source in enumerate(ordered_nodes):
            sx, sy = positions_f[source]
            sw, sh = node_dimensions[source]
            for target in ordered_nodes[i + 1 :]:
                tx, ty = positions_f[target]
                tw, th = node_dimensions[target]
                dx = sx - tx
                dy = sy - ty
                distance = max(20.0, math.hypot(dx, dy))
                min_distance = (sw + tw + sh + th) / 4 + 40.0
                strength = repulsion / (distance * distance)
                if distance < min_distance:
                    strength *= 2.5
                fx = dx / distance * strength
                fy = dy / distance * strength
                sfx, sfy = forces[source]
                tfx, tfy = forces[target]
                forces[source] = (sfx + fx, sfy + fy)
                forces[target] = (tfx - fx, tfy - fy)

        for source, target in edge_pairs:
            sx, sy = positions_f[source]
            tx, ty = positions_f[target]
            dx = tx - sx
            dy = ty - sy
            distance = max(1.0, math.hypot(dx, dy))
            desired = ideal_edge
            edge_strength = spring_strength
            if source[0] != target[0]:
                desired -= 55.0
                edge_strength *= 1.8
            strength = (distance - desired) * edge_strength
            fx = dx / distance * strength
            fy = dy / distance * strength
            sfx, sfy = forces[source]
            tfx, tfy = forces[target]
            forces[source] = (sfx + fx, sfy + fy)
            forces[target] = (tfx - fx, tfy - fy)

        total_step = 0.0
        max_displacement = 0.0
        for node in ordered_nodes:
            vx, vy = velocities[node]
            fx, fy = forces[node]
            vx = (vx + fx) * damping
            vy = (vy + fy) * damping
            speed = max(1.0, math.hypot(vx, vy))
            step = min(speed, temperature)
            vx = vx / speed * step
            vy = vy / speed * step
            x, y = positions_f[node]
            positions_f[node] = (x + vx, y + vy)
            velocities[node] = (vx, vy)
            displacement = math.hypot(vx, vy)
            total_step += displacement
            max_displacement = max(max_displacement, displacement)

        mean_displacement = total_step / len(ordered_nodes)
        if iteration >= min_iterations and mean_displacement < convergence_epsilon and max_displacement < convergence_epsilon * 4:
            stable_iterations += 1
            if stable_iterations >= stable_iterations_required:
                break
        else:
            stable_iterations = 0

    min_x = min(x for x, _y in positions_f.values())
    min_y = min(y for _x, y in positions_f.values())
    return {
        node: (
            int(round(x - min_x + left_margin)),
            int(round(y - min_y + top_margin)),
        )
        for node, (x, y) in positions_f.items()
    }


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
