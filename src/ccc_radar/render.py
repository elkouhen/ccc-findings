import math
import json
import re
import subprocess
from html import escape as html_escape
from pathlib import Path
from typing import TypedDict
from xml.sax.saxutils import quoteattr

from ccc_radar.ccc_bridge import CodeHitWithFindings
from ccc_radar.flow import FlowResult
from ccc_radar.graph import GraphEdge, OutboundCallInConsumer, graph_edge_rest_resource
from ccc_radar.models import Finding, MessageEndpoint
from ccc_radar.modules import DiscoveredModule, ModuleDependency
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
    """Shape returned by `cccr export microservices --json` and the MCP `graph` tool.

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
                    label=graph_edge_rest_resource(edge),
                    from_site=_endpoint_to_site(edge.from_endpoint),
                    to_site=(
                        _endpoint_to_site(edge.to_endpoint)
                        if edge.to_endpoint is not None
                        else None
                    ),
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
    endpoints_by_service: dict[str, list[MessageEndpoint]],
    edges: list[GraphEdge],
    collections_by_service: dict[str, list[str]] | None = None,
) -> str:
    """Rend le graphe d'interactions en XML mxGraph (format natif
    diagrams.net/drawio) : un nœud par microservice, plus un nœud par topic
    Kafka inter-service, et optionnellement un nœud par collection MongoDB
    indexée dans chaque microservice. Les arêtes REST vont de l'appelant vers l'appelé ;
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
    mongo_collections = _mongodb_collection_nodes(collections_by_service)
    service_resources = {
        name: _rest_resources_served(endpoints_by_service.get(name, [])) for name in ordered_services
    }
    ordered_nodes = [("microservice", name) for name in ordered_services] + [
        ("kafka_topic", name) for name in kafka_topics
    ] + [
        ("mongodb_collection", identity) for _service, _collection, identity in mongo_collections
    ]
    mongo_labels = {identity: collection for _service, collection, identity in mongo_collections}
    node_ids = {node: f"node-{i}" for i, node in enumerate(ordered_nodes)}
    node_dimensions = {
        ("microservice", name): (node_width, _drawio_service_height(service_resources[name]))
        for name in ordered_services
    } | {("kafka_topic", name): (220, 60) for name in kafka_topics} | {
        ("mongodb_collection", identity): (220, 60) for identity in mongo_labels
    }
    # The graph model remains detailed, but the visual export bundles calls
    # sharing the same endpoints. This removes parallel strokes and keeps their
    # individual routes as a multi-line label on the single connector.
    visual_edges = [
        *_drawio_visual_graph_edges(edges),
        *_mongodb_visual_graph_edges(collections_by_service),
    ]
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
        elif node_kind == "kafka_topic":
            label = f"<b>{html_escape(name)}</b>"
            width, height = node_dimensions[(node_kind, name)]
            style = (
                "shape=cylinder3;boundedLbl=1;whiteSpace=wrap;html=1;"
                "fillColor=#fff3df;strokeColor=#d18b20;strokeWidth=2;"
                "fontColor=#744a0b;fontSize=13;"
            )
        else:
            label = (
                f"<b>{html_escape(mongo_labels[name])}</b><br/>"
                '<span style="font-size:10px;color:#276749;">MongoDB</span>'
            )
            width, height = node_dimensions[(node_kind, name)]
            style = (
                "shape=cylinder3;boundedLbl=1;whiteSpace=wrap;html=1;"
                "fillColor=#e6ffed;strokeColor=#2f855a;strokeWidth=2;"
                "fontColor=#276749;fontSize=13;"
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
        elif kind == "mongodb":
            style += "dashed=1;dashPattern=3 3;strokeColor=#2f855a;fontColor=#276749;"
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


def render_graph_html(
    endpoints_by_service: dict[str, list[MessageEndpoint]],
    edges: list[GraphEdge],
    collections_by_service: dict[str, list[str]] | None = None,
    modules_by_service: dict[str, DiscoveredModule] | None = None,
) -> str:
    """Render an interactive Sigma.js graph as a self-contained HTML document.

    Sigma.js and Graphology are loaded from their CDNs at viewing time; graph
    data is embedded locally and safely serialized so the generated file
    contains no application data in executable JavaScript.
    """
    ordered_services = sorted(endpoints_by_service)
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    topic_message_types: dict[str, dict[str, set[str]]] = {
        topic: {"produce": set(), "consume": set()} for topic in kafka_topics
    }
    published_message_types_by_relation: dict[tuple[str, str], set[str]] = {}
    for service, endpoints in endpoints_by_service.items():
        for endpoint in endpoints:
            if (
                endpoint.system == "kafka"
                and endpoint.topic in topic_message_types
                and endpoint.message_type
            ):
                topic_message_types[endpoint.topic][endpoint.role].add(endpoint.message_type)
                if endpoint.role == "produce":
                    published_message_types_by_relation.setdefault((service, endpoint.topic), set()).add(
                        endpoint.message_type
                    )
    module_details = modules_by_service or {}
    nodes = []
    for name in ordered_services:
        resources = _rest_resources_served(endpoints_by_service.get(name, []))
        module = module_details.get(name)
        shown_resources = resources[:4]
        if len(resources) > len(shown_resources):
            shown_resources.append(f"+ {len(resources) - len(shown_resources)} API")
        nodes.append(
            {
                "id": f"microservice:{name}",
                "kind": "microservice",
                "name": name,
                "resources": resources,
                "openapi_files": list(module.openapi_files) if module else [],
                "label": "\n".join([name, *shown_resources])
                if shown_resources
                else f"{name}\nAucune API exposée",
                "width": 320,
                "height": 76 + 18 * max(1, len(shown_resources)),
            }
        )
    nodes += [
        {
            "id": f"kafka_topic:{name}",
            "kind": "kafka_topic",
            "name": name,
            "label": name,
            "published_message_types": sorted(topic_message_types[name]["produce"]),
            "consumed_message_types": sorted(topic_message_types[name]["consume"]),
            "width": 190,
            "height": 42,
        }
        for name in kafka_topics
    ]
    nodes += [
        {
            "id": f"mongodb_collection:{identity}",
            "kind": "mongodb_collection",
            "name": collection,
            "owner": service,
            "label": collection,
            "width": 190,
            "height": 42,
        }
        for service, collection, identity in _mongodb_collection_nodes(collections_by_service)
    ]
    links = []
    for source_kind, source_name, target_kind, target_name, label, kind in _drawio_visual_graph_edges(edges):
        link = {
            "source": f"{source_kind}:{source_name}",
            "target": f"{target_kind}:{target_name}",
            "kind": kind,
            "direction": "outgoing" if kind == "rest" or source_kind == "microservice" else "incoming",
            "label": label.replace("<br/>", "\\n"),
        }
        if kind == "kafka" and source_kind == "microservice" and target_kind == "kafka_topic":
            link["published_message_types"] = sorted(
                published_message_types_by_relation.get((source_name, target_name), set())
            )
        links.append(link)
    links += [
        {
            "source": f"{source_kind}:{source_name}",
            "target": f"{target_kind}:{target_name}",
            "kind": kind,
            "direction": "data_access",
            "label": label,
        }
        for source_kind, source_name, target_kind, target_name, label, kind in _mongodb_visual_graph_edges(
            collections_by_service
        )
    ]
    complexity_relations = [
        (f"{source_kind}:{source_name}", f"{target_kind}:{target_name}")
        for source_kind, source_name, target_kind, target_name, _label, _kind in _visual_graph_edges(edges)
    ] + [
        (f"{source_kind}:{source_name}", f"{target_kind}:{target_name}")
        for source_kind, source_name, target_kind, target_name, _label, _kind in _mongodb_visual_graph_edges(
            collections_by_service
        )
    ]
    relation_counts = {node["id"]: 0 for node in nodes}
    for source, target in complexity_relations:
        relation_counts[source] += 1
        relation_counts[target] += 1
    microservice_counts = {
        node["id"]: relation_counts[node["id"]]
        for node in nodes
        if node["kind"] == "microservice"
    }
    complexity_levels = _complexity_levels(microservice_counts)
    for node in nodes:
        base_size = 17 if node["kind"] == "microservice" else 14 if node["kind"] == "mongodb_collection" else 13
        if node["kind"] != "microservice":
            node["color"] = "#64748b"
            node["size"] = base_size
            continue
        score = relation_counts[node["id"]]
        level = complexity_levels[node["id"]]
        node["complexity"] = {
            "score": score,
            "level": level,
            "relations": relation_counts[node["id"]],
        }
        node["color"] = {"low": "#2563eb", "medium": "#d97706", "high": "#dc2626"}[level]
        node["size"] = base_size + {"low": 0, "medium": 2, "high": 4}[level]
    graph_data = json.dumps({"nodes": nodes, "links": links}, ensure_ascii=False).replace("</", "<\\/")
    return _SIGMA_GRAPH_HTML_TEMPLATE.replace("__GRAPH_DATA__", graph_data)


def _likec4_identifier_map(prefix: str, names: list[str]) -> dict[str, str]:
    """Create deterministic LikeC4 identifiers while keeping source names as titles."""
    identifiers: dict[str, str] = {}
    used: set[str] = set()
    for name in sorted(names):
        normalized = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_")
        base = f"{prefix}_{normalized or 'item'}"
        if base[0].isdigit():
            base = f"{prefix}_{base}"
        candidate = base
        suffix = 2
        while candidate in used:
            candidate = f"{base}_{suffix}"
            suffix += 1
        used.add(candidate)
        identifiers[name] = candidate
    return identifiers


def _likec4_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ")


_MONGO_WRITE_OPERATIONS = frozenset({
    "bulkOps", "findAndModify", "findAndReplace", "insert", "remove", "save",
    "updateFirst", "updateMulti", "upsert",
})


def _complexity_levels(relation_counts: dict[str, int]) -> dict[str, str]:
    """Répartit les microservices en trois tiers de complexité équilibrés.

    Le score est le degré du nœud dans le graphe de dépendances : HTTP,
    Kafka et MongoDB sont donc tous pris en compte. Les égalités de score sont
    départagées par l'identifiant afin que l'export reste déterministe.
    """
    ranked_nodes = sorted(relation_counts, key=lambda node_id: (relation_counts[node_id], node_id))
    size, remainder = divmod(len(ranked_nodes), 3)
    group_sizes = [size, size, size]
    # Les éventuels services restants complètent d'abord les groupes les moins
    # complexes ; les tailles des tiers ne diffèrent jamais de plus d'un.
    for index in range(remainder):
        group_sizes[index] += 1

    levels: dict[str, str] = {}
    offset = 0
    for level, group_size in zip(("low", "medium", "high"), group_sizes):
        for node_id in ranked_nodes[offset:offset + group_size]:
            levels[node_id] = level
        offset += group_size
    return levels


def _likec4_complexity(
    service_ids: dict[str, str],
    topic_ids: dict[str, str],
    collection_ids: dict[str, str],
    external_api_ids: dict[str, str],
    relations: set[tuple[str, str, str, str]],
    findings_by_service: dict[str, list[Finding]],
) -> dict[str, tuple[str | None, str]]:
    """Build a microservice-only complexity signal while retaining finding details."""
    relation_counts = {
        node_id: 0
        for node_id in (*service_ids.values(), *topic_ids.values(), *collection_ids.values(), *external_api_ids.values())
    }
    for _, source, target, _ in relations:
        relation_counts[source] += 1
        relation_counts[target] += 1
    complexity_levels = _complexity_levels(
        {service_id: relation_counts[service_id] for service_id in service_ids.values()}
    )

    severities = ("ERROR", "WARNING", "INFO")
    details: dict[str, tuple[str | None, str]] = {}
    for service, service_id in service_ids.items():
        findings = findings_by_service.get(service, [])
        severity_counts = {
            severity: sum(1 for finding in findings if finding.severity == severity)
            for severity in severities
        }
        score = relation_counts[service_id]
        color = f"complexity_{complexity_levels[service_id]}"
        finding_summary = ", ".join(
            f"{severity}={count}" for severity, count in severity_counts.items() if count
        ) or "none"
        details[service_id] = (
            color,
            f"Complexity score {score}: {relation_counts[service_id]} relations; "
            f"{len(findings)} findings ({finding_summary})",
        )
    for node_id in (*topic_ids.values(), *collection_ids.values(), *external_api_ids.values()):
        score = relation_counts[node_id]
        details[node_id] = (None, f"{score} direct relations")
    return details


def render_graph_likec4(
    endpoints_by_service: dict[str, list[MessageEndpoint]],
    edges: list[GraphEdge],
    collections_by_service: dict[str, list[str]] | None = None,
    findings_by_service: dict[str, list[Finding]] | None = None,
    modules_by_service: dict[str, DiscoveredModule] | None = None,
) -> str:
    """Render the inferred runtime graph as a standalone LikeC4 model.

    Services, Kafka topics, MongoDB collections and external HTTP APIs are peers in one generated
    system boundary. The source inventory is static, so relations carry the
    protocol semantics but never claim to be runtime traces. Only microservice
    complexity is derived from graph degree; findings remain informational details.
    """
    services = sorted(endpoints_by_service)
    topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    collection_nodes = _mongodb_collection_nodes(collections_by_service)
    collection_names = {identity: collection for _service, collection, identity in collection_nodes}
    collection_services = {identity: service for service, _collection, identity in collection_nodes}
    matched_internal_call_ids = {edge.from_endpoint.id for edge in edges if edge.kind == "rest"}
    external_calls = sorted(
        [
            (service, endpoint)
            for service, endpoints in endpoints_by_service.items()
            for endpoint in endpoints
            if endpoint.system == "rest"
            and endpoint.role == "call"
            and endpoint.id not in matched_internal_call_ids
        ],
        key=lambda item: (item[0], item[1].topic, item[1].path, item[1].start_line),
    )
    external_apis = sorted({endpoint.topic for _service, endpoint in external_calls})
    module_details = modules_by_service or {}
    service_ids = _likec4_identifier_map("service", services)
    topic_ids = _likec4_identifier_map("topic", topics)
    collection_ids = _likec4_identifier_map("collection", sorted(collection_names))
    external_api_ids = _likec4_identifier_map("external_api", external_apis)

    relations: set[tuple[str, str, str, str]] = set()
    for edge in edges:
        if edge.kind == "rest":
            relations.add((
                "http",
                service_ids[edge.from_service],
                service_ids[edge.to_service],
                graph_edge_rest_resource(edge),
            ))
            continue
        topic_id = topic_ids[edge.from_endpoint.topic]
        produced_type = edge.from_endpoint.message_type
        consumed_type = edge.to_endpoint.message_type
        relations.add((
            "publishes", service_ids[edge.from_service], topic_id,
            f"publishes {produced_type}" if produced_type else "publishes",
        ))
        relations.add((
            "consumes", topic_id, service_ids[edge.to_service],
            f"consumes {consumed_type}" if consumed_type else "consumes",
        ))
    for service, endpoint in external_calls:
        relations.add(("calls_external", service_ids[service], external_api_ids[endpoint.topic], endpoint.topic))
    for service, collection, identity in collection_nodes:
        if service not in service_ids:
            continue
        module = module_details.get(service)
        operations = {
            "writes_data" if method.operation in _MONGO_WRITE_OPERATIONS else "reads_data"
            for method in (module.mongo_methods if module else ())
            if method.collection == collection
        }
        if not operations:
            operations = {"uses_data"}
        for operation in operations:
            label = {"reads_data": "reads", "writes_data": "writes", "uses_data": "uses"}[operation]
            relations.add((operation, service_ids[service], collection_ids[identity], label))
    complexities = _likec4_complexity(
        service_ids, topic_ids, collection_ids, external_api_ids, relations, findings_by_service or {}
    )

    lines = [
        "// Generated by cccr export microservices --c4. Do not edit generated identifiers.",
        "specification {",
        "  color complexity_low #2563EB",
        "  color complexity_medium #D97706",
        "  color complexity_high #DC2626",
        "  color outgoing #0F766E",
        "  color incoming #D97706",
        "  color data_access #2563EB",
        "  element system",
        "  element microservice {",
        "    notation 'Microservice'",
        "    style { shape component }",
        "  }",
        "  element kafka_topic {",
        "    notation 'Kafka topic'",
        "    style { shape queue }",
        "  }",
        "  element mongodb_collection {",
        "    notation 'MongoDB collection'",
        "    style { shape cylinder }",
        "  }",
        "  element external_api {",
        "    notation 'External HTTP API'",
        "    style { shape browser }",
        "  }",
        "  relationship http {",
        "    color outgoing",
        "    line solid",
        "    head vee",
        "    multiple true",
        "  }",
        "  relationship publishes {",
        "    color outgoing",
        "    line solid",
        "    head vee",
        "    multiple true",
        "  }",
        "  relationship consumes {",
        "    color incoming",
        "    line dotted",
        "    head vee",
        "    multiple true",
        "  }",
        "  relationship uses_data {",
        "    color data_access",
        "    line solid",
        "    head diamond",
        "    multiple true",
        "  }",
        "  relationship reads_data {",
        "    color data_access",
        "    line dotted",
        "    head vee",
        "    multiple true",
        "  }",
        "  relationship writes_data {",
        "    color outgoing",
        "    line solid",
        "    head vee",
        "    multiple true",
        "  }",
        "  relationship calls_external {",
        "    color outgoing",
        "    line dashed",
        "    head vee",
        "    multiple true",
        "  }",
        "}",
        "",
        "model {",
        "  radar = system 'Indexed microservice architecture' {",
    ]
    for service in services:
        color, description = complexities[service_ids[service]]
        openapi_files = module_details.get(service).openapi_files if service in module_details else ()
        if openapi_files:
            description = f"{description}; OpenAPI contracts: {', '.join(openapi_files)}"
        lines.extend(
            [
                f"    {service_ids[service]} = microservice '{_likec4_string(service)}' {{",
                "      technology 'Spring Boot'",
                f"      description '{_likec4_string(description)}'",
                f"      style {{ color {color} }}",
                "    }",
            ]
        )
    for topic in topics:
        color, description = complexities[topic_ids[topic]]
        lines.extend([
            f"    {topic_ids[topic]} = kafka_topic '{_likec4_string(topic)}' {{",
            "      technology 'Kafka'",
            f"      description '{_likec4_string(description)}'",
            *([f"      style {{ color {color} }}"] if color else []),
            "    }",
        ])
    for identity in sorted(collection_names):
        color, description = complexities[collection_ids[identity]]
        collection = collection_names[identity]
        service = collection_services[identity]
        lines.extend(
            [
                f"    {collection_ids[identity]} = mongodb_collection '{_likec4_string(collection)} ({_likec4_string(service)})' {{",
                "      technology 'MongoDB'",
                f"      description '{_likec4_string(description)}'",
                *([f"      style {{ color {color} }}"] if color else []),
                "    }",
            ]
        )
    for external_api in external_apis:
        color, description = complexities[external_api_ids[external_api]]
        lines.extend(
            [
                f"    {external_api_ids[external_api]} = external_api '{_likec4_string(external_api)}' {{",
                "      technology 'HTTP'",
                f"      description '{_likec4_string(description)}'",
                *([f"      style {{ color {color} }}"] if color else []),
                "    }",
            ]
        )
    for kind, source, target, label in sorted(relations):
        lines.append(f"    {source} -[{kind}]-> {target} '{_likec4_string(label)}'")
    lines.extend(
        [
            "  }",
            "}",
            "",
            "views {",
            "  view dependencies {",
            "    title 'Microservice, Kafka and MongoDB dependencies and complexity'",
            "    include radar.**",
            "  }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


_SIGMA_GRAPH_HTML_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CCC Radar graph</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js"></script>
  <style>
    :root { color: #172033; background: #f5f7fb; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; overflow: hidden; }
    #graph { width: 100vw; height: 100vh; background: #f8fafc; touch-action: none; }
    .toolbar { position: fixed; z-index: 2; top: 16px; left: 16px; display: grid; gap: 10px; width: min(390px, calc(100vw - 32px)); padding: 12px; border: 1px solid #d7dee9; border-radius: 10px; background: rgba(255, 255, 255, .96); box-shadow: 0 4px 20px rgba(15, 23, 42, .12); }
    .toolbar-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .toolbar strong { color: #172033; font-size: 15px; white-space: nowrap; }
    .toolbar input:not([type="checkbox"]) { height: 34px; padding: 0 10px; border: 1px solid #b9c5d6; border-radius: 6px; color: #172033; background: #fff; font: inherit; font-size: 13px; }
    .toolbar-tabs { display: flex; gap: 4px; padding: 3px; border-radius: 8px; background: #edf2f7; }
    .toolbar-tab { flex: 1; height: 30px !important; width: auto !important; padding: 0 9px; border: 0 !important; border-radius: 6px !important; color: #52616b !important; background: transparent !important; font-size: 12px !important; font-weight: 700; }
    .toolbar-tab:hover { background: rgba(255, 255, 255, .65) !important; }
    .toolbar-tab.is-active { color: #1d4f91 !important; background: #fff !important; box-shadow: 0 1px 3px rgba(15, 23, 42, .12); }
    .toolbar-panel { display: grid; gap: 10px; }
    .toolbar-panel[hidden] { display: none; }
    #search, #path-query { width: 100%; }
    .graph-actions { display: flex; gap: 4px; }
    .toolbar button { width: 34px; height: 34px; border: 1px solid #b9c5d6; border-radius: 6px; color: #315f9b; background: #fff; font-size: 19px; line-height: 1; cursor: pointer; }
    .toolbar button:hover { background: #eaf2ff; }
    .relation-filters { display: flex; flex-wrap: wrap; gap: 6px; margin: 0; padding: 0; border: 0; }
    .relation-filters legend { width: 100%; margin-bottom: 2px; color: #59708d; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .relation-filter { display: inline-flex; align-items: center; gap: 5px; height: 30px; padding: 0 8px; border: 1px solid #cdd7e5; border-radius: 999px; color: #315f9b; background: #fff; font-size: 12px; white-space: nowrap; cursor: pointer; }
    .relation-filter input, .path-lock input { width: 14px; height: 14px; margin: 0; padding: 0; border: 0; accent-color: #315f9b; }
    .path-controls { border-top: 1px solid #e2e8f0; padding-top: 8px; }
    .path-controls summary, .legend summary { color: #315f9b; font-size: 12px; font-weight: 600; cursor: pointer; }
    .path-controls[open] summary { margin-bottom: 8px; }
    .path-row { display: grid; grid-template-columns: 1fr auto; gap: 6px; align-items: center; }
    .path-actions { display: flex; align-items: center; gap: 6px; grid-column: 1 / -1; }
    .path-lock { display: inline-flex; align-items: center; gap: 5px; height: 30px; padding: 0 8px; border: 1px solid #cdd7e5; border-radius: 6px; color: #315f9b; background: #fff; font-size: 12px; white-space: nowrap; cursor: pointer; }
    #show-path { width: auto; padding: 0 10px; font-size: 12px; font-weight: 600; }
    .path-history { gap: 10px; }
    .path-history-header { padding: 2px 2px 6px; }
    .path-history-kicker { margin: 0 0 2px; color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
    .path-history-title { margin: 0; color: #172033; font-size: 15px; line-height: 1.2; }
    .path-history-description, .path-history-empty { margin: 5px 0 0; color: #64748b; font-size: 12px; line-height: 1.4; }
    .path-history-list { display: grid; gap: 7px; max-height: 360px; margin: 0; padding: 0; overflow: auto; list-style: none; }
    .path-history-item { display: grid; grid-template-columns: minmax(0, 1fr) 30px; gap: 6px; }
    .path-history-replay { width: auto !important; min-width: 0; height: auto !important; min-height: 42px; padding: 8px 10px; border-color: #dbeafe !important; color: #1e429f !important; background: linear-gradient(135deg, #f8fbff, #eff6ff) !important; font-size: 12px !important; font-weight: 600; text-align: left; overflow-wrap: anywhere; }
    .path-history-replay:hover { border-color: #93c5fd !important; background: #dbeafe !important; }
    .path-history-delete { align-self: center; width: 30px !important; height: 30px !important; color: #a53f3f !important; font-size: 16px !important; }
    #details { position: fixed; z-index: 2; right: 16px; bottom: 16px; width: min(400px, calc(100vw - 32px)); max-height: min(68vh, 560px); overflow: auto; border: 1px solid #d7dee9; border-radius: 14px; background: rgba(255, 255, 255, .97); color: #475569; font-size: 13px; line-height: 1.45; box-shadow: 0 12px 32px rgba(15, 23, 42, .16); }
    .details-header { padding: 16px; border-bottom: 1px solid #e2e8f0; background: linear-gradient(135deg, #f8fafc, #eef5ff); }
    .details-header.is-low { border-left: 4px solid #2563eb; }
    .details-header.is-medium { border-left: 4px solid #d97706; }
    .details-header.is-high { border-left: 4px solid #dc2626; }
    .details-kicker { margin: 0 0 3px; color: #64748b; font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .details-title { margin: 0; overflow-wrap: anywhere; color: #172033; font-size: 18px; line-height: 1.2; }
    .details-meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 12px; }
    .detail-badge { display: inline-flex; align-items: center; min-height: 24px; padding: 3px 8px; border: 1px solid #cbd5e1; border-radius: 999px; color: #475569; background: #fff; font-size: 11px; font-weight: 600; }
    .detail-badge.complexity { border-color: currentColor; }
    .detail-badge.complexity.low { color: #2563eb; background: #eff6ff; }
    .detail-badge.complexity.medium { color: #b45309; background: #fffbeb; }
    .detail-badge.complexity.high { color: #dc2626; background: #fef2f2; }
    .details-section { padding: 12px 16px; border-bottom: 1px solid #edf2f7; }
    .details-section:last-child { border-bottom: 0; }
    .details-section h2 { margin: 0 0 7px; color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .details-section ul { display: grid; gap: 5px; margin: 0; padding: 0; list-style: none; }
    .details-section li { padding: 6px 8px; border-radius: 6px; color: #334155; background: #f8fafc; overflow-wrap: anywhere; }
    .details-section li.relation-item { padding: 0; background: transparent; }
    .relation-link { display: block; width: 100%; padding: 7px 8px; border: 1px solid #e2e8f0; border-radius: 6px; color: #1d4f91; background: #f8fafc; font: inherit; text-align: left; cursor: pointer; overflow-wrap: anywhere; }
    .relation-link:hover, .relation-link:focus-visible { border-color: #93c5fd; background: #eff6ff; outline: none; }
    .details-empty { padding: 18px; color: #64748b; text-align: center; }
    .path-details-header { padding: 16px; border-bottom: 1px solid #dbeafe; background: linear-gradient(135deg, #eff6ff, #f8fafc 60%, #f0fdf4); }
    .path-details-kicker { margin: 0 0 3px; color: #1d4f91; font-size: 10px; font-weight: 800; letter-spacing: .09em; text-transform: uppercase; }
    .path-details-title { margin: 0; color: #172033; font-size: 18px; line-height: 1.25; }
    .path-details-summary { margin: 8px 0 0; color: #52616b; font-size: 12px; }
    .path-overview { display: grid; gap: 6px; margin: 0; padding: 0; list-style: none; }
    .path-overview-item { position: relative; padding: 7px 9px 7px 31px !important; border: 1px solid #e2e8f0; background: #fff !important; }
    .path-overview-item::before { position: absolute; top: 8px; left: 9px; color: #94a3b8; content: "→"; }
    .path-overview-item:first-child::before { color: #2563eb; content: "●"; font-size: 9px; }
    .path-overview-item:last-child::before { color: #16a34a; content: "●"; font-size: 9px; }
    .path-overview-item.is-topic { border-style: dashed; color: #475569; background: #f8fafc !important; }
    .path-step { border-left: 3px solid #94a3b8; }
    .path-step.is-rest { border-left-color: #D55E00; }
    .path-step.is-kafka-publish { border-left-color: #009E73; }
    .path-step.is-kafka-consume { border-left-color: #0072B2; }
    .path-step.is-mongodb { border-left-color: #CC79A7; }
    .path-step-label { margin: 0; color: #64748b; font-size: 10px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    .legend { position: fixed; z-index: 2; left: 16px; bottom: 16px; width: 210px; padding: 9px 11px; border: 1px solid #d7dee9; border-radius: 8px; background: rgba(255, 255, 255, .95); color: #475569; font-size: 11px; box-shadow: 0 2px 12px rgba(15, 23, 42, .10); }
    .legend[open] summary { margin-bottom: 8px; }
    .legend-content { display: grid; gap: 5px; }
    .legend-row { display: flex; align-items: center; gap: 6px; }
    .legend-mark { display: inline-block; width: 10px; height: 10px; border-radius: 50%; }
    .legend-line { width: 18px; height: 2px; }
  </style>
</head>
<body>
  <div class="toolbar">
    <div class="toolbar-header">
      <strong>CCC Radar</strong>
      <div class="graph-actions" aria-label="Navigation du graphe">
        <button id="zoom-out" type="button" aria-label="Dezoomer" title="Dezoomer">-</button>
        <button id="zoom-in" type="button" aria-label="Zoomer" title="Zoomer">+</button>
        <button id="fit-view" type="button" aria-label="Ajuster a l'ecran" title="Ajuster a l'ecran">o</button>
        <button id="reset" type="button" aria-label="Reinitialiser la selection" title="Reinitialiser">x</button>
      </div>
    </div>
    <div class="toolbar-tabs" role="tablist" aria-label="Outils du graphe">
      <button id="graph-tab" class="toolbar-tab is-active" type="button" role="tab" aria-selected="true" aria-controls="graph-panel">Graphe</button>
      <button id="paths-tab" class="toolbar-tab" type="button" role="tab" aria-selected="false" aria-controls="paths-panel">Chemins analyses</button>
    </div>
    <div id="graph-panel" class="toolbar-panel" role="tabpanel" aria-labelledby="graph-tab">
      <input id="search" type="search" placeholder="Rechercher un noeud" autocomplete="off" aria-label="Rechercher un noeud">
      <fieldset class="relation-filters">
        <legend>Relations affichees</legend>
        <label class="relation-filter" title="Afficher les appels HTTP"><input id="relation-http" type="checkbox" checked aria-label="Afficher les relations HTTP">HTTP</label>
        <label class="relation-filter" title="Afficher les publications et consommations Kafka"><input id="relation-kafka" type="checkbox" checked aria-label="Afficher les relations Kafka">Kafka</label>
        <label class="relation-filter" title="Afficher les acces aux collections MongoDB"><input id="relation-mongodb" type="checkbox" checked aria-label="Afficher les relations MongoDB">MongoDB</label>
      </fieldset>
      <details class="path-controls">
        <summary>Explorer un chemin</summary>
        <div class="path-row">
          <input id="path-query" type="text" placeholder="service-a -> topic-1 -> service-b" autocomplete="off" aria-label="Chemin avec des noms de services ou topics">
          <button id="show-path" type="button" aria-label="Afficher le plus court chemin" title="Afficher le plus court chemin">Afficher</button>
          <div class="path-actions"><label class="path-lock" title="Conserver le chemin lors de la selection d'un noeud"><input id="path-lock" type="checkbox" aria-label="Verrouiller le chemin">Verrouiller</label></div>
        </div>
      </details>
    </div>
    <div id="paths-panel" class="toolbar-panel path-history" role="tabpanel" aria-labelledby="paths-tab" hidden>
      <div class="path-history-header">
        <p class="path-history-kicker">Navigation architecture</p>
        <h2 class="path-history-title">Chemins analyses</h2>
        <p class="path-history-description">Rejouez un parcours ou retirez-le de cette liste locale.</p>
      </div>
      <ul id="analyzed-paths" class="path-history-list" aria-label="Chemins analyses"></ul>
      <p id="analyzed-paths-empty" class="path-history-empty">Aucun chemin analyse pour le moment.</p>
    </div>
  </div>
  <details class="legend" aria-label="Legende du graphe">
    <summary>Legende</summary>
    <div class="legend-content">
      <div class="legend-row"><span class="legend-mark" style="background:#2563eb"></span>Complexite faible (tiers inferieur)</div>
      <div class="legend-row"><span class="legend-mark" style="background:#d97706"></span>Complexite moyenne (tiers central)</div>
      <div class="legend-row"><span class="legend-mark" style="background:#dc2626"></span>Complexite elevee (tiers superieur)</div>
      <div class="legend-row"><span class="legend-mark" style="background:#64748b;clip-path:polygon(25% 7%,75% 7%,100% 50%,75% 93%,25% 93%,0 50%)"></span>Microservice</div>
      <div class="legend-row"><span class="legend-mark" style="background:#64748b"></span>Topic Kafka</div>
      <div class="legend-row"><span class="legend-mark" style="border-radius:1px;background:#64748b"></span>Collection MongoDB</div>
      <div class="legend-row"><span class="legend-line" style="background:#D55E00"></span>Appel HTTP</div>
      <div class="legend-row"><span class="legend-line" style="background:#009E73"></span>Publication Kafka</div>
      <div class="legend-row"><span class="legend-line" style="background:#0072B2"></span>Consommation Kafka</div>
      <div class="legend-row"><span class="legend-line" style="background:#CC79A7"></span>Acces MongoDB</div>
    </div>
  </details>
  <div id="details"><div class="details-empty">Selectionnez un noeud pour isoler ses relations et afficher ses APIs.</div></div>
  <div id="graph" aria-label="Graphe des interactions"></div>
  <script id="graph-data" type="application/json">__GRAPH_DATA__</script>
  <script>
    const graphData = JSON.parse(document.getElementById("graph-data").textContent);
    const nodeDataById = new Map(graphData.nodes.map(node => [node.id, node]));
    const layoutNodes = graphData.nodes.map((node, index) => {
      const angle = (Math.PI * 2 * index) / Math.max(1, graphData.nodes.length);
      return { ...node, x: Math.cos(angle), y: Math.sin(angle), vx: 0, vy: 0 };
    });
    const layoutById = new Map(layoutNodes.map(node => [node.id, node]));

    // A deterministic spring layout keeps connected services and topics close
    // before Sigma uploads the resulting graph to WebGL.
    for (let iteration = 0; iteration < 720; iteration += 1) {
      const cooling = .14 * (1 - iteration / 720) + .015;
      for (let i = 0; i < layoutNodes.length; i += 1) {
        for (let j = i + 1; j < layoutNodes.length; j += 1) {
          const a = layoutNodes[i], b = layoutNodes[j];
          const dx = b.x - a.x || (i < j ? .001 : -.001);
          const dy = b.y - a.y || .001;
          const distance2 = dx * dx + dy * dy + .012;
          const strength = 1.25 / distance2;
          a.vx -= dx * strength; a.vy -= dy * strength;
          b.vx += dx * strength; b.vy += dy * strength;
        }
      }
      graphData.links.forEach(link => {
        const source = layoutById.get(link.source), target = layoutById.get(link.target);
        if (!source || !target) return;
        const dx = target.x - source.x, dy = target.y - source.y;
        const distance = Math.hypot(dx, dy) || .001;
        const desired = link.kind === "kafka" ? 1.05 : link.kind === "mongodb" ? .68 : .82;
        const pull = (distance - desired) * .035;
        const ux = dx / distance, uy = dy / distance;
        source.vx += ux * pull; source.vy += uy * pull;
        target.vx -= ux * pull; target.vy -= uy * pull;
      });
      layoutNodes.forEach(node => {
        node.vx += -node.x * .008; node.vy += -node.y * .008;
        node.x += node.vx * cooling; node.y += node.vy * cooling;
        node.vx *= .72; node.vy *= .72;
      });
    }

    const RELATION_COLORS = Object.freeze({
      http: "#D55E00",
      kafkaPublish: "#009E73",
      kafkaConsume: "#0072B2",
      mongodb: "#CC79A7",
    });
    function relationColor(link) {
      if (link.kind === "rest") return RELATION_COLORS.http;
      if (link.direction === "incoming") return RELATION_COLORS.kafkaConsume;
      if (link.direction === "data_access") return RELATION_COLORS.mongodb;
      return RELATION_COLORS.kafkaPublish;
    }
    const network = new graphology.MultiDirectedGraph();
    layoutNodes.forEach(node => network.addNode(node.id, {
      label: node.name,
      x: node.x,
      y: node.y,
      size: node.size,
      color: node.color,
      type: node.kind,
    }));
    graphData.links.forEach((link, index) => network.addEdgeWithKey(`edge-${index}`, link.source, link.target, {
      label: link.label,
      size: 1.2,
      color: relationColor(link),
      kind: link.kind,
      type: "arrow",
    }));

    let selectedId = null;
    let relatedNodes = null;
    let relatedEdges = null;
    let pathMicroserviceOrder = new Map();
    // Sigma invokes reducers while it is constructed, so these controls must
    // exist before creating the renderer.
    const relationHttp = document.getElementById("relation-http");
    const relationKafka = document.getElementById("relation-kafka");
    const relationMongodb = document.getElementById("relation-mongodb");
    function isVisibleRelation(kind) {
      return (kind !== "rest" || relationHttp.checked)
        && (kind !== "kafka" || relationKafka.checked)
        && (kind !== "mongodb" || relationMongodb.checked);
    }
    const NODE_VERTEX_SHADER = `
      attribute vec2 a_position;
      attribute float a_size;
      attribute vec4 a_color;
      uniform float u_ratio;
      uniform float u_scale;
      uniform mat3 u_matrix;
      varying vec4 v_color;
      void main() {
        gl_Position = vec4((u_matrix * vec3(a_position, 1.0)).xy, 0.0, 1.0);
        gl_PointSize = a_size * u_ratio * u_scale * 2.0;
        v_color = a_color;
      }
    `;
    const MICROSERVICE_FRAGMENT_SHADER = `
      precision mediump float;
      varying vec4 v_color;
      void main() {
        vec2 point = gl_PointCoord - vec2(.5);
        float shape = max(abs(point.x) * .866025 + abs(point.y) * .5, abs(point.y));
        float distance = shape - .43;
        float alpha = 1.0 - smoothstep(-.014, .014, distance);
        if (alpha < .01) discard;
        float border = smoothstep(.33, .42, shape);
        vec3 fill = vec3(.98, .99, 1.0);
        gl_FragColor = vec4(mix(fill, v_color.rgb, border), v_color.a * alpha);
      }
    `;
    const KAFKA_TOPIC_FRAGMENT_SHADER = `
      precision mediump float;
      varying vec4 v_color;
      void main() {
        vec2 point = gl_PointCoord - vec2(.5);
        float shape = length(point);
        float distance = shape - .43;
        float alpha = 1.0 - smoothstep(-.014, .014, distance);
        if (alpha < .01) discard;
        float border = smoothstep(.34, .42, shape);
        vec3 fill = vec3(.98, .99, 1.0);
        gl_FragColor = vec4(mix(fill, v_color.rgb, border), v_color.a * alpha);
      }
    `;
    const MONGODB_COLLECTION_FRAGMENT_SHADER = `
      precision mediump float;
      varying vec4 v_color;
      void main() {
        vec2 point = gl_PointCoord - vec2(.5);
        float shape = max(abs(point.x), abs(point.y));
        float distance = shape - .42;
        float alpha = 1.0 - smoothstep(-.014, .014, distance);
        if (alpha < .01) discard;
        float border = smoothstep(.32, .41, shape);
        vec3 fill = vec3(.98, .99, 1.0);
        gl_FragColor = vec4(mix(fill, v_color.rgb, border), v_color.a * alpha);
      }
    `;
    const packedColorBuffer = new ArrayBuffer(4);
    const packedColorBytes = new Uint8Array(packedColorBuffer);
    const packedColorFloat = new Float32Array(packedColorBuffer);
    function packColor(color) {
      const value = color.startsWith("#") ? color.slice(1) : color;
      packedColorBytes[0] = parseInt(value.slice(0, 2), 16) || 0;
      packedColorBytes[1] = parseInt(value.slice(2, 4), 16) || 0;
      packedColorBytes[2] = parseInt(value.slice(4, 6), 16) || 0;
      packedColorBytes[3] = 254;
      return packedColorFloat[0];
    }
    function compileShader(gl, type, source) {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        throw new Error(`Impossible de compiler le shader WebGL: ${gl.getShaderInfoLog(shader)}`);
      }
      return shader;
    }
    function createNodeProgram(fragmentShader) {
      return class ShapeNodeProgram {
        constructor(gl) {
          this.gl = gl;
          this.array = new Float32Array();
          this.buffer = gl.createBuffer();
          const vertexShader = compileShader(gl, gl.VERTEX_SHADER, NODE_VERTEX_SHADER);
          const pixelShader = compileShader(gl, gl.FRAGMENT_SHADER, fragmentShader);
          this.program = gl.createProgram();
          gl.attachShader(this.program, vertexShader);
          gl.attachShader(this.program, pixelShader);
          gl.linkProgram(this.program);
          if (!gl.getProgramParameter(this.program, gl.LINK_STATUS)) {
            throw new Error(`Impossible d'associer le shader WebGL: ${gl.getProgramInfoLog(this.program)}`);
          }
          this.positionLocation = gl.getAttribLocation(this.program, "a_position");
          this.sizeLocation = gl.getAttribLocation(this.program, "a_size");
          this.colorLocation = gl.getAttribLocation(this.program, "a_color");
          this.matrixLocation = gl.getUniformLocation(this.program, "u_matrix");
          this.ratioLocation = gl.getUniformLocation(this.program, "u_ratio");
          this.scaleLocation = gl.getUniformLocation(this.program, "u_scale");
          this.bind();
        }
        allocate(capacity) { this.array = new Float32Array(capacity * 4); }
        process(data, hidden, offset) {
          const index = offset * 4;
          if (hidden) {
            this.array.fill(0, index, index + 4);
            return;
          }
          this.array[index] = data.x;
          this.array[index + 1] = data.y;
          this.array[index + 2] = data.size;
          this.array[index + 3] = packColor(data.color);
        }
        bind() {
          const gl = this.gl;
          gl.bindBuffer(gl.ARRAY_BUFFER, this.buffer);
          gl.enableVertexAttribArray(this.positionLocation);
          gl.enableVertexAttribArray(this.sizeLocation);
          gl.enableVertexAttribArray(this.colorLocation);
          gl.vertexAttribPointer(this.positionLocation, 2, gl.FLOAT, false, 16, 0);
          gl.vertexAttribPointer(this.sizeLocation, 1, gl.FLOAT, false, 16, 8);
          gl.vertexAttribPointer(this.colorLocation, 4, gl.UNSIGNED_BYTE, true, 16, 12);
        }
        bufferData() { this.gl.bufferData(this.gl.ARRAY_BUFFER, this.array, this.gl.DYNAMIC_DRAW); }
        render(params) {
          if (!this.array.length) return;
          const gl = this.gl;
          gl.useProgram(this.program);
          gl.uniform1f(this.ratioLocation, 1 / Math.sqrt(params.ratio));
          gl.uniform1f(this.scaleLocation, params.scalingRatio);
          gl.uniformMatrix3fv(this.matrixLocation, false, params.matrix);
          gl.drawArrays(gl.POINTS, 0, this.array.length / 4);
        }
      };
    }
    const renderer = new Sigma(network, document.getElementById("graph"), {
      nodeProgramClasses: {
        microservice: createNodeProgram(MICROSERVICE_FRAGMENT_SHADER),
        kafka_topic: createNodeProgram(KAFKA_TOPIC_FRAGMENT_SHADER),
        mongodb_collection: createNodeProgram(MONGODB_COLLECTION_FRAGMENT_SHADER),
      },
      renderEdgeLabels: false,
      labelDensity: .08,
      labelGridCellSize: 110,
      labelRenderedSizeThreshold: 8,
      nodeReducer: (node, data) => {
        if (!selectedId || relatedNodes.has(node)) {
          const order = pathMicroserviceOrder.get(node);
          return order ? { ...data, label: `${order}. ${data.label}` } : data;
        }
        return { ...data, color: "#d8e0ea", label: "" };
      },
      edgeReducer: (edge, data) => {
        if (!isVisibleRelation(data.kind)) return { ...data, hidden: true };
        if (!selectedId || relatedEdges.has(edge)) return data;
        return { ...data, color: "#e5eaf0", size: .35 };
      },
    });
    const details = document.getElementById("details");
    const search = document.getElementById("search");
    const pathQuery = document.getElementById("path-query");
    const pathLock = document.getElementById("path-lock");
    const graphTab = document.getElementById("graph-tab");
    const pathsTab = document.getElementById("paths-tab");
    const graphPanel = document.getElementById("graph-panel");
    const pathsPanel = document.getElementById("paths-panel");
    const analyzedPathsList = document.getElementById("analyzed-paths");
    const analyzedPathsEmpty = document.getElementById("analyzed-paths-empty");
    const pathStops = [];
    const analyzedPaths = [];
    const nodesByNormalizedName = new Map();
    function normalizeNodeName(name) {
      return name.trim().replace(/\\s+/g, " ").toLocaleLowerCase();
    }
    graphData.nodes.forEach(node => {
      const key = normalizeNodeName(node.name);
      nodesByNormalizedName.set(key, [...(nodesByNormalizedName.get(key) || []), node]);
    });
    const pathHistoryStorageKey = (() => {
      const signature = [
        ...graphData.nodes.map(node => node.id),
        ...graphData.links.map(link => `${link.source}->${link.target}:${link.kind}`),
      ].sort().join("|");
      let hash = 2166136261;
      for (let index = 0; index < signature.length; index += 1) {
        hash = Math.imul(hash ^ signature.charCodeAt(index), 16777619);
      }
      return `cccr:analyzed-paths:${hash >>> 0}`;
    })();

    function isValidPathStops(stops) {
      if (!Array.isArray(stops) || stops.length < 2 || new Set(stops).size !== stops.length) return false;
      if (!stops.every(id => nodeDataById.has(id))) return false;
      const source = nodeDataById.get(stops[0]);
      const target = nodeDataById.get(stops[stops.length - 1]);
      return source.kind === "microservice"
        && target.kind === "microservice"
        && stops.slice(1, -1).every(id => ["microservice", "kafka_topic"].includes(nodeDataById.get(id).kind));
    }
    function loadAnalyzedPaths() {
      try {
        const stored = JSON.parse(localStorage.getItem(pathHistoryStorageKey) || "[]");
        if (!Array.isArray(stored)) return;
        stored.filter(isValidPathStops).forEach(stops => analyzedPaths.push(stops));
      } catch (_error) {
        // The export remains usable when browser storage is unavailable or stale.
      }
    }
    function persistAnalyzedPaths() {
      try {
        localStorage.setItem(pathHistoryStorageKey, JSON.stringify(analyzedPaths));
      } catch (_error) {
        // Saving the optional history must never prevent graph exploration.
      }
    }
    function setToolbarTab(tab) {
      const showingPaths = tab === "paths";
      graphTab.classList.toggle("is-active", !showingPaths);
      graphTab.setAttribute("aria-selected", String(!showingPaths));
      pathsTab.classList.toggle("is-active", showingPaths);
      pathsTab.setAttribute("aria-selected", String(showingPaths));
      graphPanel.hidden = showingPaths;
      pathsPanel.hidden = !showingPaths;
    }
    function renderAnalyzedPaths() {
      analyzedPathsList.replaceChildren();
      analyzedPathsEmpty.hidden = analyzedPaths.length > 0;
      analyzedPaths.forEach((stops, index) => {
        const item = document.createElement("li");
        item.className = "path-history-item";
        const replay = document.createElement("button");
        replay.className = "path-history-replay";
        replay.type = "button";
        replay.textContent = stops.map(id => nodeDataById.get(id).name).join(" -> ");
        replay.title = "Reanalyser ce chemin";
        replay.addEventListener("click", () => replayAnalyzedPath(stops));
        const remove = document.createElement("button");
        remove.className = "path-history-delete";
        remove.type = "button";
        remove.textContent = "×";
        remove.title = "Supprimer ce chemin analyse";
        remove.setAttribute("aria-label", `Supprimer le chemin ${replay.textContent}`);
        remove.addEventListener("click", () => {
          analyzedPaths.splice(index, 1);
          persistAnalyzedPaths();
          renderAnalyzedPaths();
        });
        item.append(replay, remove);
        analyzedPathsList.append(item);
      });
    }
    function rememberAnalyzedPath(stops) {
      const path = [...stops];
      const key = path.join("|");
      const existingIndex = analyzedPaths.findIndex(item => item.join("|") === key);
      if (existingIndex >= 0) analyzedPaths.splice(existingIndex, 1);
      analyzedPaths.unshift(path);
      persistAnalyzedPaths();
      renderAnalyzedPaths();
    }
    function replayAnalyzedPath(stops) {
      pathStops.splice(0, pathStops.length, ...stops);
      renderPathQuery();
      setToolbarTab("graph");
      showShortestPath();
    }
    loadAnalyzedPaths();

    function appendList(title, values) {
      if (!values.length) return;
      const section = document.createElement("section");
      section.className = "details-section";
      const heading = document.createElement("h2");
      heading.textContent = title;
      const list = document.createElement("ul");
      values.forEach(value => { const item = document.createElement("li"); item.textContent = value; list.append(item); });
      section.append(heading, list);
      details.append(section);
    }
    function appendRelationList(title, links, currentId, labelForLink) {
      const seen = new Set();
      const entries = links.flatMap(link => {
        const targetId = link.source === currentId ? link.target : link.source;
        const label = labelForLink(link);
        const key = `${targetId}::${label}`;
        if (seen.has(key)) return [];
        seen.add(key);
        return [{ targetId, label }];
      });
      if (!entries.length) return;
      const section = document.createElement("section");
      section.className = "details-section";
      const heading = document.createElement("h2");
      heading.textContent = title;
      const list = document.createElement("ul");
      entries.forEach(({ targetId, label }) => {
        const item = document.createElement("li");
        item.className = "relation-item";
        const button = document.createElement("button");
        button.className = "relation-link";
        button.type = "button";
        button.textContent = label;
        button.title = "Selectionner ce noeud dans le graphe";
        button.addEventListener("click", () => selectNode(targetId));
        item.append(button);
        list.append(item);
      });
      section.append(heading, list);
      details.append(section);
    }
    function setDetailsEmpty(message) {
      details.replaceChildren();
      const empty = document.createElement("div");
      empty.className = "details-empty";
      empty.textContent = message;
      details.append(empty);
    }
    function persistState() {
      const params = new URLSearchParams();
      if (pathStops.length) params.set("from", pathStops[0]);
      if (pathStops.length > 1) params.set("to", pathStops[pathStops.length - 1]);
      pathStops.slice(1, -1).forEach(id => params.append("via", id));
      if (pathLock.checked) params.set("lock", "1");
      if (!pathStops.length && selectedId) {
        params.set("selected", selectedId);
      }
      const fragment = params.toString();
      try {
        history.replaceState(null, "", fragment ? `#${fragment}` : location.pathname);
      } catch (_error) {
        location.hash = fragment;
      }
    }
    function clearPathControls() {
      pathQuery.value = "";
      pathStops.splice(0, pathStops.length);
    }
    function restResourceLabel(link, target) {
      const servicePrefix = `${target.name}: `;
      if (link.label === `${target.name}: API`) return "";
      return link.label.startsWith(servicePrefix) ? link.label.slice(servicePrefix.length) : link.label;
    }
    function relationText(link) {
      const source = nodeDataById.get(link.source);
      const target = nodeDataById.get(link.target);
      if (link.kind === "rest") {
        const resource = restResourceLabel(link, target);
        return resource
          ? `HTTP · ${source.name} appelle ${target.name} (${resource})`
          : `HTTP · ${source.name} appelle ${target.name} (contrat non indexe)`;
      }
      if (link.kind === "mongodb") return `MongoDB · ${source.name} stocke dans ${target.name}`;
      if (source.kind === "microservice") {
        const types = link.published_message_types || [];
        return `Kafka · ${source.name} publie${types.length ? ` <${types.join(", ")}>` : ""} sur ${target.name}`;
      }
      return `Kafka · ${target.name} consomme ${source.name}`;
    }
    function shortestPath(sourceId, targetId) {
      const outgoing = new Map();
      graphData.links.forEach((link, index) => {
        if (!isVisibleRelation(link.kind)) return;
        if (!outgoing.has(link.source)) outgoing.set(link.source, []);
        outgoing.get(link.source).push({ target: link.target, edge: `edge-${index}`, link });
      });
      const queue = [sourceId];
      const previous = new Map([[sourceId, null]]);
      for (let cursor = 0; cursor < queue.length; cursor += 1) {
        const current = queue[cursor];
        if (current === targetId) break;
        for (const step of outgoing.get(current) || []) {
          if (previous.has(step.target)) continue;
          previous.set(step.target, { node: current, edge: step.edge, link: step.link });
          queue.push(step.target);
        }
      }
      if (!previous.has(targetId)) return null;
      const nodes = [];
      const edges = [];
      for (let current = targetId; current !== null;) {
        nodes.unshift(current);
        const step = previous.get(current);
        if (step === null) break;
        edges.unshift(step);
        current = step.node;
      }
      return { nodes, edges };
    }
    function shortestPathThrough(stops) {
      const path = { nodes: [], edges: [] };
      for (let index = 0; index < stops.length - 1; index += 1) {
        const segment = shortestPath(stops[index], stops[index + 1]);
        if (segment === null) return null;
        path.nodes.push(...(index === 0 ? segment.nodes : segment.nodes.slice(1)));
        path.edges.push(...segment.edges);
      }
      return path;
    }
    function parsePathQuery() {
      const names = pathQuery.value.split("->").map(name => name.trim()).filter(Boolean);
      if (names.length < 2) return { error: "Saisissez au moins un service source et un service cible separes par ->." };
      const stops = [];
      for (const name of names) {
        const candidates = nodesByNormalizedName.get(normalizeNodeName(name)) || [];
        if (!candidates.length) return { error: `Noeud introuvable : ${name}.` };
        if (candidates.length > 1) return { error: `Nom ambigu : ${name}.` };
        stops.push(candidates[0].id);
      }
      const source = nodeDataById.get(stops[0]);
      const target = nodeDataById.get(stops[stops.length - 1]);
      if (source.kind !== "microservice" || target.kind !== "microservice") {
        return { error: "Le premier et le dernier noeud doivent etre des microservices." };
      }
      if (stops.slice(1, -1).some(id => !["microservice", "kafka_topic"].includes(nodeDataById.get(id).kind))) {
        return { error: "Les noeuds intermediaires doivent etre des microservices ou des topics Kafka." };
      }
      if (new Set(stops).size !== stops.length) {
        return { error: "Les noeuds du chemin doivent etre distincts." };
      }
      return { stops };
    }
    function renderPathQuery() {
      pathQuery.value = pathStops.map(id => nodeDataById.get(id).name).join(" -> ");
    }
    function setPathMicroserviceOrder(path) {
      pathMicroserviceOrder = new Map();
      let order = 1;
      path.nodes.forEach(id => {
        if (nodeDataById.get(id).kind !== "microservice") return;
        pathMicroserviceOrder.set(id, order);
        order += 1;
      });
    }
    function renderPathDetails(path) {
      details.replaceChildren();
      const pathNodeLabel = (id, index) => {
        const node = nodeDataById.get(id);
        const order = pathMicroserviceOrder.get(id);
        if (order) return `${order}. ${node.name}`;
        if (node.kind !== "kafka_topic") return node.name;
        const precedingLink = path.edges[index - 1]?.link;
        const publishedTypes = precedingLink?.published_message_types || node.published_message_types || [];
        const types = publishedTypes.length ? publishedTypes : node.consumed_message_types || [];
        return types.length ? `${node.name} (${types.join(", ")})` : `${node.name} (type Java non indexe)`;
      };
      const header = document.createElement("header");
      header.className = "path-details-header";
      const kicker = document.createElement("p");
      kicker.className = "path-details-kicker";
      kicker.textContent = "Analyse de flux";
      const title = document.createElement("h1");
      title.className = "path-details-title";
      title.textContent = pathStops.length > 2 ? "Chemin avec noeuds intermediaires" : "Chemin le plus court";
      const summary = document.createElement("p");
      summary.className = "path-details-summary";
      const serviceCount = path.nodes.filter(id => nodeDataById.get(id).kind === "microservice").length;
      summary.textContent = `${serviceCount} microservice${serviceCount > 1 ? "s" : ""} · ${path.edges.length} etape${path.edges.length > 1 ? "s" : ""}`;
      header.append(kicker, title, summary);
      details.append(header);
      const overview = document.createElement("section");
      overview.className = "details-section";
      const overviewTitle = document.createElement("h2");
      overviewTitle.textContent = "Parcours";
      const overviewList = document.createElement("ol");
      overviewList.className = "path-overview";
      path.nodes.forEach((id, index) => {
        const item = document.createElement("li");
        item.className = "path-overview-item";
        if (nodeDataById.get(id).kind === "kafka_topic") item.classList.add("is-topic");
        item.textContent = pathNodeLabel(id, index);
        overviewList.append(item);
      });
      overview.append(overviewTitle, overviewList);
      details.append(overview);
      const pathStepTitle = link => {
        if (link.kind === "rest") return "Appel HTTP";
        if (link.kind === "mongodb") return "Acces MongoDB";
        return nodeDataById.get(link.source).kind === "microservice"
          ? "Publication Kafka" : "Consommation Kafka";
      };
      path.edges.forEach((step, index) => {
        const section = document.createElement("section");
        const pathStepClass = step.link.kind === "kafka"
          ? (nodeDataById.get(step.link.source).kind === "microservice" ? "is-kafka-publish" : "is-kafka-consume")
          : `is-${step.link.kind}`;
        section.className = `details-section path-step ${pathStepClass}`;
        const label = document.createElement("p");
        label.className = "path-step-label";
        label.textContent = `Etape ${index + 1} · ${pathStepTitle(step.link)}`;
        section.append(label);
        details.append(section);
      });
    }
    function showShortestPath() {
      const parsed = parsePathQuery();
      if (parsed.error) {
        selectedId = null; relatedNodes = null; relatedEdges = null; pathMicroserviceOrder = new Map();
        renderer.refresh();
        setDetailsEmpty(parsed.error);
        pathStops.splice(0, pathStops.length);
        persistState();
        return;
      }
      const stops = parsed.stops;
      pathStops.splice(0, pathStops.length, ...stops);
      const path = shortestPathThrough(stops);
      if (path === null) {
        selectedId = null; relatedNodes = null; relatedEdges = null; pathMicroserviceOrder = new Map();
        renderer.refresh();
        setDetailsEmpty("Aucun chemin oriente entre les deux microservices.");
        persistState();
        return;
      }
      selectedId = stops[0];
      relatedNodes = new Set(path.nodes);
      relatedEdges = new Set(path.edges.map(step => step.edge));
      setPathMicroserviceOrder(path);
      rememberAnalyzedPath(pathStops);
      renderer.refresh();
      renderPathDetails(path);
      renderer.getCamera().animatedReset({ duration: 220 });
      persistState();
    }
    function renderDetails(id) {
      const node = nodeDataById.get(id);
      const edges = graphData.links.filter(
        link => isVisibleRelation(link.kind) && (link.source === id || link.target === id)
      );
      details.replaceChildren();
      const kindLabel = node.kind === "kafka_topic" ? "Topic Kafka" : node.kind === "mongodb_collection" ? "Collection MongoDB" : "Microservice";
      const complexity = node.complexity;
      const header = document.createElement("header");
      header.className = "details-header";
      if (complexity) header.classList.add(`is-${complexity.level}`);
      const kicker = document.createElement("p");
      kicker.className = "details-kicker";
      kicker.textContent = kindLabel;
      const title = document.createElement("h1");
      title.className = "details-title";
      title.textContent = node.name;
      const meta = document.createElement("div");
      meta.className = "details-meta";
      const relationBadge = document.createElement("span");
      relationBadge.className = "detail-badge";
      relationBadge.textContent = `Relations visibles : ${edges.length}`;
      meta.append(relationBadge);
      if (complexity) {
        const scoreBadge = document.createElement("span");
        scoreBadge.className = `detail-badge complexity ${complexity.level}`;
        scoreBadge.textContent = `Connectivite : ${complexity.level} (${complexity.score})`;
        meta.append(scoreBadge);
      }
      header.append(kicker, title, meta);
      details.append(header);
      if (node.kind === "microservice") {
        const httpCalls = edges.filter(link => link.kind === "rest" && link.source === id);
        const httpClients = edges.filter(link => link.kind === "rest" && link.target === id);
        const kafkaPublications = edges.filter(link => link.kind === "kafka" && link.source === id);
        const kafkaConsumptions = edges.filter(link => link.kind === "kafka" && link.target === id);
        const mongoCollections = edges.filter(link => link.kind === "mongodb" && link.source === id);
        appendList("APIs HTTP exposees", node.resources);
        appendList("Contrats OpenAPI detectes", node.openapi_files || []);
        appendRelationList("Services HTTP consommes", httpCalls, id, link => {
          const target = nodeDataById.get(link.target);
          const resource = restResourceLabel(link, target);
          return resource ? `${target.name} · ${resource}` : `${target.name} · contrat non indexe`;
        });
        appendRelationList("Clients HTTP detectes", httpClients, id, link => {
          const source = nodeDataById.get(link.source);
          const resource = restResourceLabel(link, node);
          return resource ? `${source.name} · ${resource}` : `${source.name} · contrat non indexe`;
        });
        appendRelationList("Evenements Kafka publies", kafkaPublications, id, link => {
          const topic = nodeDataById.get(link.target);
          const types = link.published_message_types || [];
          return types.length ? `${topic.name} · ${types.join(", ")}` : topic.name;
        });
        appendRelationList("Evenements Kafka consommes", kafkaConsumptions, id, link => {
          const topic = nodeDataById.get(link.source);
          return topic.name;
        });
        appendRelationList("Collections MongoDB utilisees", mongoCollections, id, link => (
          nodeDataById.get(link.target).name
        ));
      }
      if (node.kind === "kafka_topic") {
        appendList("Types publies", node.published_message_types);
        appendList("Types consommes", node.consumed_message_types);
        appendRelationList("Services producteurs", edges.filter(link => link.kind === "kafka" && link.target === id), id,
          link => nodeDataById.get(link.source).name);
        appendRelationList("Services consommateurs", edges.filter(link => link.kind === "kafka" && link.source === id), id,
          link => nodeDataById.get(link.target).name);
      }
      if (node.kind === "mongodb_collection") {
        appendList("Stockee par", [node.owner]);
        appendRelationList("Services utilisant cette collection", edges.filter(link => link.kind === "mongodb" && link.target === id), id,
          link => nodeDataById.get(link.source).name);
      }
    }
    function selectNode(id) {
      if (!pathLock.checked) clearPathControls();
      pathMicroserviceOrder = new Map();
      selectedId = id;
      relatedNodes = new Set([id]);
      relatedEdges = new Set();
      network.forEachEdge((edge, attributes, source, target) => {
        if (!isVisibleRelation(attributes.kind)) return;
        if (source === id || target === id) {
          relatedEdges.add(edge); relatedNodes.add(source); relatedNodes.add(target);
        }
      });
      renderer.refresh();
      renderDetails(id);
      const position = renderer.getNodeDisplayData(id);
      if (position) renderer.getCamera().animate({ x: position.x, y: position.y, ratio: .55 }, { duration: 260 });
      persistState();
    }
    function reset() {
      selectedId = null; relatedNodes = null; relatedEdges = null; pathMicroserviceOrder = new Map();
      renderer.refresh();
      setDetailsEmpty("Selectionnez un noeud pour isoler ses relations et afficher ses APIs.");
      search.value = "";
      clearPathControls();
      persistState();
    }
    function restoreState() {
      const params = new URLSearchParams(location.hash.slice(1));
      const sourceId = params.get("from");
      const targetId = params.get("to");
      pathLock.checked = params.get("lock") === "1";
      const restoredStops = [sourceId, ...params.getAll("via"), targetId];
      if (
        sourceId
        && targetId
        && nodeDataById.get(sourceId)?.kind === "microservice"
        && nodeDataById.get(targetId)?.kind === "microservice"
        && restoredStops.every(id => nodeDataById.has(id))
      ) {
        pathStops.push(...restoredStops);
        renderPathQuery();
        showShortestPath();
        return;
      }
      const selectedIdFromUrl = params.get("selected");
      if (selectedIdFromUrl && nodeDataById.has(selectedIdFromUrl)) selectNode(selectedIdFromUrl);
    }
    renderer.on("clickNode", ({ node }) => selectNode(node));
    renderer.on("clickStage", reset);
    document.getElementById("zoom-in").addEventListener("click", () => renderer.getCamera().animatedZoom({ duration: 180 }));
    document.getElementById("zoom-out").addEventListener("click", () => renderer.getCamera().animatedUnzoom({ duration: 180 }));
    document.getElementById("fit-view").addEventListener("click", () => renderer.getCamera().animatedReset({ duration: 220 }));
    document.getElementById("reset").addEventListener("click", reset);
    document.getElementById("show-path").addEventListener("click", showShortestPath);
    graphTab.addEventListener("click", () => setToolbarTab("graph"));
    pathsTab.addEventListener("click", () => setToolbarTab("paths"));
    [relationHttp, relationKafka, relationMongodb].forEach(control => control.addEventListener("change", reset));
    pathLock.addEventListener("change", persistState);
    pathQuery.addEventListener("keydown", event => {
      if (event.key === "Enter") showShortestPath();
    });
    renderAnalyzedPaths();
    restoreState();
    search.addEventListener("input", event => {
      const query = event.target.value.trim().toLocaleLowerCase();
      const node = graphData.nodes.find(
        item => item.name.toLocaleLowerCase().includes(query)
      );
      if (node) selectNode(node.id); else if (!query) reset();
    });
    window.addEventListener("resize", () => renderer.refresh());
  </script>
</body>
</html>
"""


_SIGMA_MODULE_GRAPH_HTML_TEMPLATE = """<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CCC Radar module dependencies</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js"></script>
  <style>
    :root { color: #172033; background: #f5f7fb; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; overflow: hidden; }
    #graph { width: 100vw; height: 100vh; background: #f8fafc; touch-action: none; }
    .toolbar { position: fixed; z-index: 2; top: 16px; left: 16px; display: flex; align-items: center; gap: 8px; padding: 8px; border: 1px solid #d7dee9; border-radius: 6px; background: rgba(255, 255, 255, .95); box-shadow: 0 2px 12px rgba(15, 23, 42, .10); }
    .toolbar strong { padding: 0 6px; font-size: 14px; white-space: nowrap; }
    .toolbar input { width: 220px; height: 32px; padding: 0 9px; border: 1px solid #b9c5d6; border-radius: 4px; color: #172033; background: #fff; font: inherit; font-size: 13px; }
    .toolbar button { width: 32px; height: 32px; border: 1px solid #b9c5d6; border-radius: 4px; color: #315f9b; background: #fff; font-size: 19px; line-height: 1; cursor: pointer; }
    .toolbar button:hover { background: #eaf2ff; }
    #details { position: fixed; z-index: 2; right: 16px; bottom: 16px; width: min(340px, calc(100vw - 32px)); max-height: min(56vh, 440px); overflow: auto; padding: 10px 12px; border: 1px solid #d7dee9; border-radius: 6px; background: rgba(255, 255, 255, .95); color: #475569; font-size: 13px; line-height: 1.4; box-shadow: 0 2px 12px rgba(15, 23, 42, .10); }
    #details strong { display: block; color: #172033; font-size: 14px; }
    #details h2 { margin: 10px 0 4px; color: #59708d; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    #details ul { margin: 0; padding-left: 18px; }
  </style>
</head>
<body>
  <div class="toolbar">
    <strong>Modules</strong>
    <input id="search" type="search" placeholder="Rechercher un module" autocomplete="off" aria-label="Rechercher un module">
    <button id="zoom-out" type="button" aria-label="Dezoomer" title="Dezoomer">-</button>
    <button id="zoom-in" type="button" aria-label="Zoomer" title="Zoomer">+</button>
    <button id="fit-view" type="button" aria-label="Ajuster a l'ecran" title="Ajuster a l'ecran">o</button>
    <button id="reset" type="button" aria-label="Reinitialiser la selection" title="Reinitialiser">x</button>
  </div>
  <div id="details">Selectionnez un module pour explorer ses dependances directes.</div>
  <div id="graph" aria-label="Graphe des dependances de modules"></div>
  <script id="module-graph-data" type="application/json">__MODULE_GRAPH_DATA__</script>
  <script>
    const graphData = JSON.parse(document.getElementById("module-graph-data").textContent);
    const nodeById = new Map(graphData.nodes.map(node => [node.id, node]));
    const network = new graphology.MultiDirectedGraph();
    graphData.nodes.forEach(node => network.addNode(node.id, {
      label: node.name, x: node.x, y: node.y, size: node.kind === "microservice" ? 13 : 10,
      color: node.kind === "microservice" ? "#4f79b5" : "#718096",
    }));
    graphData.links.forEach((link, index) => network.addEdgeWithKey(`dependency-${index}`, link.source, link.target, {
      size: 1.4, color: "#52616b",
    }));
    let selectedId = null;
    let relatedNodes = null;
    let relatedEdges = null;
    const renderer = new Sigma(network, document.getElementById("graph"), {
      labelDensity: .1, labelGridCellSize: 120, labelRenderedSizeThreshold: 7,
      nodeReducer: (node, data) => !selectedId || relatedNodes.has(node)
        ? data : { ...data, color: "#d8e0ea", label: "" },
      edgeReducer: (edge, data) => !selectedId || relatedEdges.has(edge)
        ? data : { ...data, color: "#e5eaf0", size: .35 },
    });
    const details = document.getElementById("details");
    const search = document.getElementById("search");
    function appendList(title, values) {
      if (!values.length) return;
      const heading = document.createElement("h2"); heading.textContent = title;
      const list = document.createElement("ul");
      values.forEach(value => { const item = document.createElement("li"); item.textContent = value; list.append(item); });
      details.append(heading, list);
    }
    function selectModule(id) {
      selectedId = id; relatedNodes = new Set([id]); relatedEdges = new Set();
      const dependencies = [];
      const dependents = [];
      network.forEachEdge((edge, attributes, source, target) => {
        if (source === id || target === id) {
          relatedEdges.add(edge); relatedNodes.add(source); relatedNodes.add(target);
          if (source === id) dependencies.push(nodeById.get(target).name);
          else dependents.push(nodeById.get(source).name);
        }
      });
      renderer.refresh();
      const node = nodeById.get(id);
      details.replaceChildren();
      const title = document.createElement("strong"); title.textContent = node.name;
      details.append(title, document.createTextNode(`${node.kind} - ${relatedEdges.size} dependance${relatedEdges.size > 1 ? "s" : ""}`));
      appendList("APIs exposees", node.httpApisExposed);
      appendList("Topics publies", node.kafkaTopicsPublished);
      appendList("Topics consommes", node.kafkaTopicsConsumed);
      appendList("Depend de", dependencies);
      appendList("Utilise par", dependents);
      const position = renderer.getNodeDisplayData(id);
      if (position) renderer.getCamera().animate({ x: position.x, y: position.y, ratio: .55 }, { duration: 260 });
    }
    function reset() {
      selectedId = null; relatedNodes = null; relatedEdges = null; renderer.refresh();
      details.textContent = "Selectionnez un module pour explorer ses dependances directes.";
      search.value = "";
    }
    renderer.on("clickNode", ({ node }) => selectModule(node));
    renderer.on("clickStage", reset);
    document.getElementById("zoom-in").addEventListener("click", () => renderer.getCamera().animatedZoom({ duration: 180 }));
    document.getElementById("zoom-out").addEventListener("click", () => renderer.getCamera().animatedUnzoom({ duration: 180 }));
    document.getElementById("fit-view").addEventListener("click", () => renderer.getCamera().animatedReset({ duration: 220 }));
    document.getElementById("reset").addEventListener("click", reset);
    search.addEventListener("input", event => {
      const query = event.target.value.trim().toLocaleLowerCase();
      const node = graphData.nodes.find(item => item.name.toLocaleLowerCase().includes(query));
      if (node) selectModule(node.id); else if (!query) reset();
    });
    window.addEventListener("resize", () => renderer.refresh());
  </script>
</body>
</html>
"""


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


def _mongodb_collection_nodes(
    collections_by_service: dict[str, list[str]] | None,
) -> list[tuple[str, str, str]]:
    """Returns a distinct graph identity for each service/collection pair.

    Collection names alone are not globally unique: two microservices can both
    use `orders` in independent Mongo databases. Keeping the service in the
    node identity prevents the visual graph from inventing a shared store.
    """
    return [
        (service, collection, f"{service}:{collection}")
        for service in sorted(collections_by_service or {})
        for collection in sorted(set((collections_by_service or {})[service]))
        if collection
    ]


def _mongodb_visual_graph_edges(
    collections_by_service: dict[str, list[str]] | None,
) -> list[tuple[str, str, str, str, str, str]]:
    return [
        ("microservice", service, "mongodb_collection", identity, "stocke", "mongodb")
        for service, _collection, identity in _mongodb_collection_nodes(collections_by_service)
    ]


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
            label = graph_edge_rest_resource(edge)
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
    endpoints_by_service: dict[str, list[MessageEndpoint]],
    edges: list[GraphEdge],
    collections_by_service: dict[str, list[str]] | None = None,
) -> str:
    """Rend le graphe en source D2 pour bénéficier du moteur d'agencement
    natif de D2. Les nœuds restent microservices + topics Kafka, les arêtes
    REST vont de l'appelant vers l'appelé et les arêtes Kafka sont dépliées
    en production puis consommation. Kafka et les liens vers MongoDB restent
    en pointillé."""
    ordered_services = sorted(endpoints_by_service)
    kafka_topics = sorted({edge.from_endpoint.topic for edge in edges if edge.kind == "kafka"})
    mongo_collections = _mongodb_collection_nodes(collections_by_service)
    service_ids = {name: f"svc_{i}" for i, name in enumerate(ordered_services)}
    topic_ids = {name: f"topic_{i}" for i, name in enumerate(kafka_topics)}
    collection_ids = {identity: f"mongo_{i}" for i, (_service, _collection, identity) in enumerate(mongo_collections)}

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
    for _service, collection, identity in mongo_collections:
        node_id = collection_ids[identity]
        lines.extend(
            [
                f"{node_id}: {{",
                f'  label: "{_d2_escape(collection)}"',
                "  shape: cylinder",
                '  style.fill: "#e6ffed"',
                '  style.stroke: "#2f855a"',
                "}",
                "",
            ]
        )

    ids_by_kind = {
        "microservice": service_ids,
        "kafka_topic": topic_ids,
        "mongodb_collection": collection_ids,
    }
    visual_edges = [*_visual_graph_edges(edges), *_mongodb_visual_graph_edges(collections_by_service)]
    for source_kind, source_name, target_kind, target_name, label, kind in visual_edges:
        source_id = ids_by_kind[source_kind].get(source_name)
        target_id = ids_by_kind[target_kind].get(target_name)
        if source_id is None or target_id is None:
            continue
        lines.append(f'{source_id} -> {target_id}: "{_d2_escape(label)}" {{')
        if kind == "kafka":
            lines.append("  style.stroke-dash: 3")
        elif kind == "mongodb":
            lines.append('  style.stroke: "#2f855a"')
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

    # The simulation is intentionally more patient than an interactive browser
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
    """Shape returned by the `list_endpoints` MCP tool and module inventory views."""

    id: str
    role: str
    system: str
    topic: str
    topic_dynamic: bool
    source: str
    framework: str | None
    message_type: str | None
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
            message_type=e.message_type,
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
        lines = ["Aucune intégration détectée."]
        for warning in warnings or []:
            lines.append(f"⚠ {warning}")
        return "\n".join(lines)
    lines = []
    for e in endpoints:
        dynamic_marker = " (dynamique)" if e.topic_dynamic else ""
        module_marker = f" [{e.module}]" if e.module else ""
        type_marker = f" <{e.message_type}>" if e.message_type else ""
        lines.append(
            f"[{e.system}/{e.role}] {e.topic}{type_marker}{dynamic_marker}{module_marker}  "
            f"{e.path}:{e.start_line}-{e.end_line}"
        )
    for warning in warnings or []:
        lines.append(f"⚠ {warning}")
    return "\n".join(lines)


class WorkspaceServiceInfo(TypedDict):
    name: str
    kind: str
    starts_application: bool
    indexed: bool
    integration_count: int
    finding_count: int
    exposes_http_api: bool
    http_apis_exposed: list[str]
    http_apis_consumed: list[str]
    kafka_topics_published: list[str]
    kafka_topics_consumed: list[str]
    kafka_message_types_published: dict[str, list[str]]
    kafka_message_types_consumed: dict[str, list[str]]
    mongo_collections: list[str]
    openapi_files: list[str]


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
    rest_controllers: list[str]
    openapi_generated_clients: list[str]


class ModuleDetail(ModuleSummary):
    configuration_example: str
    mongo_methods: list[dict[str, object]]
    kafka_methods: list[dict[str, object]]
    blocking_points: list[dict[str, object]]


class WorkspaceResult(TypedDict):
    """Shape returned by `cccr microservices [--root ROOT] --json` and the
    `list_workspace_services` MCP tool (BACKLOG-11 A2)."""

    services: list[WorkspaceServiceInfo]
    warnings: list[str]


def render_workspace_json(
    services: list[DiscoveredService], federation: FederationResult
) -> WorkspaceResult:
    return WorkspaceResult(
        services=[_workspace_service_info(service, federation) for service in services],
        warnings=federation.warnings,
    )


def _workspace_service_info(
    service: DiscoveredService, federation: FederationResult
) -> WorkspaceServiceInfo:
    endpoints = federation.endpoints_by_service.get(service.name, [])
    module = federation.modules_by_service.get(service.name)
    http_apis_exposed = sorted({
        endpoint.topic for endpoint in endpoints
        if endpoint.system == "rest" and endpoint.role == "serve"
    })
    kafka_message_types_published = _workspace_kafka_message_types(endpoints, "produce")
    kafka_message_types_consumed = _workspace_kafka_message_types(endpoints, "consume")
    return WorkspaceServiceInfo(
        name=service.name,
        kind=service.kind,
        starts_application=True,
        indexed=service.indexed,
        integration_count=len(endpoints),
        finding_count=len(federation.findings_by_service.get(service.name, [])),
        exposes_http_api=bool(http_apis_exposed),
        http_apis_exposed=http_apis_exposed,
        http_apis_consumed=sorted({
            endpoint.topic for endpoint in endpoints
            if endpoint.system == "rest" and endpoint.role == "call"
        }),
        kafka_topics_published=sorted({
            endpoint.topic for endpoint in endpoints
            if endpoint.system == "kafka" and endpoint.role == "produce"
        }),
        kafka_topics_consumed=sorted({
            endpoint.topic for endpoint in endpoints
            if endpoint.system == "kafka" and endpoint.role == "consume"
        }),
        kafka_message_types_published=kafka_message_types_published,
        kafka_message_types_consumed=kafka_message_types_consumed,
        mongo_collections=list(module.mongo_collections) if module else [],
        openapi_files=list(module.openapi_files) if module else [],
    )


def _workspace_kafka_message_types(
    endpoints: list[MessageEndpoint], role: str
) -> dict[str, list[str]]:
    message_types: dict[str, set[str]] = {}
    for endpoint in endpoints:
        if endpoint.system != "kafka" or endpoint.role != role or not endpoint.message_type:
            continue
        message_types.setdefault(endpoint.topic, set()).add(endpoint.message_type)
    return {topic: sorted(values) for topic, values in sorted(message_types.items())}


def render_workspace_text(result: WorkspaceResult) -> str:
    if not result["services"]:
        return "Aucun service workspace découvert (ni module Maven runtime, ni microservice Gradle Spring Boot)."
    lines = []
    for info in result["services"]:
        status = "indexé" if info["indexed"] else "non indexé"
        lines.append(
            f"[{info['kind']}] {info['name']} ({status})  "
            f"integrations={info['integration_count']} findings={info['finding_count']}"
        )
        lines.append(
            f"  HTTP exposées: {', '.join(info['http_apis_exposed']) or '-'} | "
            f"HTTP consommées: {', '.join(info['http_apis_consumed']) or '-'}"
        )
        lines.append(
            f"  Kafka publiés: {', '.join(info['kafka_topics_published']) or '-'} | "
            f"Kafka consommés: {', '.join(info['kafka_topics_consumed']) or '-'} | "
            f"Mongo: {', '.join(info['mongo_collections']) or '-'}"
        )
        if info["openapi_files"]:
            lines.append(f"  OpenAPI: {', '.join(info['openapi_files'])}")
        if info["kafka_message_types_published"] or info["kafka_message_types_consumed"]:
            lines.append(
                f"  Types Kafka publiés: {info['kafka_message_types_published'] or '-'} | "
                f"Types Kafka consommés: {info['kafka_message_types_consumed'] or '-'}"
            )
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
            rest_controllers=list(module.rest_controllers),
            openapi_generated_clients=list(module.openapi_generated_clients),
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
            f"openapi={len(module['openapi_files'])} "
            f"rest_controllers={len(module['rest_controllers'])} "
            f"generated_clients={len(module['openapi_generated_clients'])}  {module['path']}"
        )
    return "\n".join(lines)


class ModuleGraphDependency(TypedDict):
    source: str
    target: str


class ModuleGraphResult(TypedDict):
    modules: list[str]
    dependencies: list[ModuleGraphDependency]


def render_module_graph_json(
    modules: list[DiscoveredModule], dependencies: list[ModuleDependency]
) -> ModuleGraphResult:
    return ModuleGraphResult(
        modules=[module.name for module in modules],
        dependencies=[
            ModuleGraphDependency(source=dependency.source, target=dependency.target)
            for dependency in dependencies
        ],
    )


def render_module_graph_text(result: ModuleGraphResult) -> str:
    if not result["modules"]:
        return "Aucun module indexé."
    lines = [f"Modules ({len(result['modules'])}) : {', '.join(result['modules'])}"]
    if not result["dependencies"]:
        lines.append("Aucune dépendance interne déclarée.")
    else:
        lines.extend(
            f"{dependency['source']} --> {dependency['target']}"
            for dependency in result["dependencies"]
        )
    return "\n".join(lines)


def _module_dependency_layout(
    modules: list[DiscoveredModule], dependencies: list[ModuleDependency]
) -> dict[str, tuple[float, float]]:
    """Positionne les dépendances locales en niveaux, de l'appelant vers sa cible.

    Les graphes de dépendances sont le plus souvent des DAG. Les rares cycles
    sont conservés dans une dernière couche plutôt que de bloquer le rendu.
    """
    names = sorted(module.name for module in modules)
    known = set(names)
    outgoing = {name: [] for name in names}
    incoming = {name: [] for name in names}
    for dependency in dependencies:
        if dependency.source not in known or dependency.target not in known:
            continue
        outgoing[dependency.source].append(dependency.target)
        incoming[dependency.target].append(dependency.source)
    indegree = {name: len(incoming[name]) for name in names}
    levels = {name: 0 for name in names if indegree[name] == 0}
    pending = sorted(levels)
    cursor = 0
    while cursor < len(pending):
        source = pending[cursor]
        cursor += 1
        for target in sorted(outgoing[source]):
            levels[target] = max(levels.get(target, 0), levels[source] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    unresolved = [name for name in names if name not in levels]
    if unresolved:
        cycle_level = max(levels.values(), default=-1) + 1
        levels.update({name: cycle_level for name in unresolved})

    layers: dict[int, list[str]] = {}
    for name, level in levels.items():
        layers.setdefault(level, []).append(name)
    order = {name: index for index, name in enumerate(names)}
    for level in sorted(layers):
        layers[level].sort(
            key=lambda name: (
                sum(order[parent] for parent in incoming[name] if parent in order)
                / max(1, sum(parent in order for parent in incoming[name])),
                name,
            )
        )
        order.update({name: index for index, name in enumerate(layers[level])})

    widest = max((len(layer) for layer in layers.values()), default=1)
    positions: dict[str, tuple[float, float]] = {}
    for level, layer in layers.items():
        offset = (widest - len(layer)) * 0.5
        for index, name in enumerate(layer):
            positions[name] = (offset + index, level)
    return positions


def render_module_graph_drawio(
    modules: list[DiscoveredModule], dependencies: list[ModuleDependency]
) -> str:
    """Rend le graphe des dépendances de build dans un diagramme Draw.io.

    Ce rendu est délibérément autonome par rapport à ``render_graph_drawio`` :
    il ne contient ni topic Kafka ni relation REST.
    """
    ordered_modules = sorted(modules, key=lambda module: module.name)
    node_ids = {module.name: f"module-{index}" for index, module in enumerate(ordered_modules)}
    positions = _module_dependency_layout(modules, dependencies)
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for module in ordered_modules:
        horizontal, level = positions.get(module.name, (0, 0))
        x = 80 + horizontal * 260
        y = 80 + level * 150
        kind = "microservice" if module.starts_application else module.kind
        label = f"<b>{html_escape(module.name)}</b><br/><font color=\"#5f6b7a\">{html_escape(kind)}</font>"
        style = (
            "rounded=1;arcSize=8;whiteSpace=wrap;html=1;"
            "fillColor=#e8f1fb;strokeColor=#4f79b5;fontColor=#172033;"
            "fontSize=14;align=center;verticalAlign=middle;"
        )
        cells.append(
            f'<mxCell id="{node_ids[module.name]}" value={quoteattr(label)} style={quoteattr(style)} '
            f'vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="200" height="74" '
            'as="geometry"/></mxCell>'
        )
    for index, dependency in enumerate(dependencies):
        if dependency.source not in node_ids or dependency.target not in node_ids:
            continue
        style = (
            "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;"
            "html=1;endArrow=block;endFill=1;strokeColor=#52616b;"
        )
        cells.append(
            f'<mxCell id="dependency-{index}" value="" style={quoteattr(style)} edge="1" '
            f'parent="1" source="{node_ids[dependency.source]}" target="{node_ids[dependency.target]}">'
            '<mxGeometry relative="1" as="geometry"/></mxCell>'
        )
    return (
        '<mxfile host="app.diagrams.net"><diagram name="Module dependencies">'
        '<mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" page="1" pageWidth="1169" '
        'pageHeight="827" math="0" shadow="0"><root>'
        + "".join(cells)
        + "</root></mxGraphModel></diagram></mxfile>"
    )


def render_module_graph_html(
    modules: list[DiscoveredModule],
    dependencies: list[ModuleDependency],
    endpoints: list[MessageEndpoint],
) -> str:
    """Rend les dépendances de build dans une vue Sigma.js hiérarchique."""
    positions = _module_dependency_layout(modules, dependencies)
    endpoints_by_module = {
        module.name: [endpoint for endpoint in endpoints if endpoint.module == module.name]
        for module in modules
    }
    nodes = [
        {
            "id": module.name,
            "name": module.name,
            "kind": "microservice" if module.starts_application else module.kind,
            "x": positions.get(module.name, (0, 0))[0],
            "y": -positions.get(module.name, (0, 0))[1],
            "httpApisExposed": sorted({
                endpoint.topic
                for endpoint in endpoints_by_module[module.name]
                if endpoint.system == "rest" and endpoint.role == "serve"
            }),
            "kafkaTopicsPublished": sorted({
                endpoint.topic
                for endpoint in endpoints_by_module[module.name]
                if endpoint.system == "kafka" and endpoint.role == "produce"
            }),
            "kafkaTopicsConsumed": sorted({
                endpoint.topic
                for endpoint in endpoints_by_module[module.name]
                if endpoint.system == "kafka" and endpoint.role == "consume"
            }),
        }
        for module in sorted(modules, key=lambda item: item.name)
    ]
    links = [
        {"source": dependency.source, "target": dependency.target}
        for dependency in dependencies
        if dependency.source in positions and dependency.target in positions
    ]
    graph_data = json.dumps({"nodes": nodes, "links": links}, ensure_ascii=False).replace("</", "<\\/")
    return _SIGMA_MODULE_GRAPH_HTML_TEMPLATE.replace("__MODULE_GRAPH_DATA__", graph_data)


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
        rest_controllers=list(module.rest_controllers),
        openapi_generated_clients=list(module.openapi_generated_clients),
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
        f"OpenAPI={', '.join(module['openapi_files']) or 'aucun'}\n"
        f"Contrôleurs REST ({len(module['rest_controllers'])})={', '.join(module['rest_controllers']) or 'aucun'}\n"
        f"Clients OpenAPI générés ({len(module['openapi_generated_clients'])})={', '.join(module['openapi_generated_clients']) or 'aucun'}"
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
    """Shape returned by the `trace_message_flow` MCP tool (BACKLOG-10 K5/K6)."""

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
