"""Graphe d'interactions entre services et détection de points de blocage
(BACKLOG-10 K12). Tout est dérivé à la requête à partir d'endpoints déjà
indexés (K1) — aucune table de graphe en base (ADR-27).
"""

from dataclasses import dataclass

from cccf.models import Finding, MessageEndpoint

_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}


@dataclass(frozen=True)
class GraphEdge:
    kind: str  # "rest" | "kafka"
    from_service: str
    to_service: str
    from_endpoint: MessageEndpoint  # site d'appel (call) ou de production (produce)
    to_endpoint: MessageEndpoint  # site exposé (serve) ou de consommation (consume)


@dataclass(frozen=True)
class Cycle:
    services: tuple[str, ...]  # ordre du parcours, dernier == premier
    edges: tuple[GraphEdge, ...]
    has_synchronous_rest: bool


@dataclass(frozen=True)
class OutboundCallInConsumer:
    consumer: MessageEndpoint
    call: MessageEndpoint


@dataclass(frozen=True)
class Hotspot:
    service: str
    endpoint: MessageEndpoint
    cycle: Cycle
    finding: Finding


def _split_path(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def _is_template_segment(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _segment_matches(call_segment: str, serve_segment: str) -> bool:
    if call_segment == serve_segment:
        return True
    return _is_template_segment(serve_segment) or _is_template_segment(call_segment)


def paths_match(call_topic: str, serve_topic: str) -> bool:
    """Best-effort : même méthode HTTP, et les segments de chemin du call
    (littéral ↔ template `{param}`) préfixent ou couvrent ceux de la route
    exposée. Un call sans aucun littéral exploitable (`<dynamic>`) ne
    matche jamais — mieux vaut une arête absente qu'une fausse arête
    (BACKLOG-10 K12 CA4)."""
    call_method, _, call_path = call_topic.partition(" ")
    serve_method, _, serve_path = serve_topic.partition(" ")
    if call_method != serve_method or call_path == "<dynamic>":
        return False

    call_segments = _split_path(call_path)
    serve_segments = _split_path(serve_path)
    if not call_segments or len(call_segments) > len(serve_segments):
        return False
    return all(
        _segment_matches(call_seg, serve_seg)
        for call_seg, serve_seg in zip(call_segments, serve_segments)
    )


def build_graph(endpoints_by_service: dict[str, list[MessageEndpoint]]) -> list[GraphEdge]:
    """Construit les arêtes REST (call -> serve, appariement de chemin) et
    Kafka (produce -> consume, même topic) entre services distincts. Pas
    d'auto-arête : un service qui s'appelle lui-même n'entre pas dans le
    graphe inter-services."""
    all_endpoints = [
        (service, endpoint)
        for service, endpoints in endpoints_by_service.items()
        for endpoint in endpoints
    ]
    calls = [(s, e) for s, e in all_endpoints if e.system == "rest" and e.role == "call"]
    serves = [(s, e) for s, e in all_endpoints if e.system == "rest" and e.role == "serve"]
    produces = [(s, e) for s, e in all_endpoints if e.system == "kafka" and e.role == "produce"]
    consumes = [(s, e) for s, e in all_endpoints if e.system == "kafka" and e.role == "consume"]

    edges: list[GraphEdge] = []
    for call_service, call in calls:
        for serve_service, serve in serves:
            if call_service == serve_service:
                continue
            if paths_match(call.topic, serve.topic):
                edges.append(GraphEdge("rest", call_service, serve_service, call, serve))

    for produce_service, produce in produces:
        for consume_service, consume in consumes:
            if produce_service == consume_service:
                continue
            if produce.topic == consume.topic:
                edges.append(GraphEdge("kafka", produce_service, consume_service, produce, consume))

    return edges


def find_cycles(edges: list[GraphEdge]) -> list[Cycle]:
    """Cycles simples (chaque service visité au plus une fois) sur le
    graphe services -> services induit par `edges`. Dérivé à la requête,
    jamais persisté (ADR-27)."""
    adjacency: dict[str, list[GraphEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_service, []).append(edge)

    cycles: list[Cycle] = []
    seen: set[frozenset[int]] = set()

    def dfs(
        start: str,
        current: str,
        path_edges: list[GraphEdge],
        visited: list[str],
    ) -> None:
        for edge in adjacency.get(current, []):
            if edge.to_service == start and path_edges:
                cycle_edges = tuple(path_edges + [edge])
                key = frozenset(id(e) for e in cycle_edges)
                if key in seen:
                    continue
                seen.add(key)
                cycles.append(
                    Cycle(
                        services=tuple(visited + [start]),
                        edges=cycle_edges,
                        has_synchronous_rest=any(e.kind == "rest" for e in cycle_edges),
                    )
                )
                continue
            if edge.to_service in visited:
                continue
            dfs(start, edge.to_service, path_edges + [edge], visited + [edge.to_service])

    for service in adjacency:
        dfs(service, service, [], [service])

    return cycles


def find_outbound_calls_in_consumers(
    endpoints: list[MessageEndpoint],
) -> list[OutboundCallInConsumer]:
    """Un appel REST (`call`) dont le site tombe dans la plage de lignes
    d'un handler de consommation Kafka (`consume`) du même fichier — même
    signal que les règles liveness K8, mais dérivé des endpoints plutôt que
    d'une règle Semgrep dédiée. `endpoints` doit venir d'un seul service :
    fichier et lignes ne sont comparables qu'au sein d'un même repo."""
    consumers = [e for e in endpoints if e.system == "kafka" and e.role == "consume"]
    calls = [e for e in endpoints if e.system == "rest" and e.role == "call"]

    results: list[OutboundCallInConsumer] = []
    for consumer in consumers:
        for call in calls:
            if call.path != consumer.path:
                continue
            if consumer.start_line <= call.start_line <= consumer.end_line:
                results.append(OutboundCallInConsumer(consumer, call))
    return results


def find_hotspots(
    cycles: list[Cycle], findings_by_service: dict[str, list[Finding]]
) -> list[Hotspot]:
    """Sites qui sont à la fois sur un cycle et recouverts par un finding
    (fichier + lignes qui se chevauchent — même jointure qu'ADR-19) : les
    candidats les plus probables au blocage observé."""
    hotspots: list[Hotspot] = []
    for cycle in cycles:
        for edge in cycle.edges:
            for service, endpoint in (
                (edge.from_service, edge.from_endpoint),
                (edge.to_service, edge.to_endpoint),
            ):
                for finding in findings_by_service.get(service, []):
                    if finding.path != endpoint.path:
                        continue
                    if finding.start_line <= endpoint.end_line and finding.end_line >= endpoint.start_line:
                        hotspots.append(Hotspot(service, endpoint, cycle, finding))
    return hotspots


def rank_hotspots(hotspots: list[Hotspot]) -> list[Hotspot]:
    """Classement pondéré par sévérité du finding recouvrant (esprit
    ADR-19), ordre stable en cas d'égalité."""
    return sorted(hotspots, key=lambda h: _SEVERITY_RANK[h.finding.severity], reverse=True)
