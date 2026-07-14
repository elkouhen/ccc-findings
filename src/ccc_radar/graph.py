"""Graphe d'interactions entre services dérivé à la requête à partir
d'endpoints déjà indexés — aucune table de graphe en base (ADR-27)."""

from dataclasses import dataclass
import re

from ccc_radar.models import MessageEndpoint


@dataclass(frozen=True)
class GraphEdge:
    kind: str  # "rest" | "kafka"
    from_service: str
    to_service: str
    from_endpoint: MessageEndpoint  # site d'appel (call) ou de production (produce)
    to_endpoint: MessageEndpoint  # site exposé (serve) ou de consommation (consume)


@dataclass(frozen=True)
class OutboundCallInConsumer:
    consumer: MessageEndpoint
    call: MessageEndpoint


def group_endpoints_by_module(
    endpoints: list[MessageEndpoint],
) -> dict[str, list[MessageEndpoint]]:
    """Regroupe des endpoints par module Maven (`endpoint.module`).

    La forme du dictionnaire est la même que celle produite par
    `workspace.load_federation`, et peut donc alimenter directement
    `build_graph`. Un endpoint sans module (`None` — repo non-Maven, ou fichier
    hors arborescence Maven) est ignoré : sans nom stable, il ne peut jamais
    former une arête inter-service fiable.
    """

    grouped: dict[str, list[MessageEndpoint]] = {}
    for endpoint in endpoints:
        if endpoint.module is None:
            continue
        grouped.setdefault(endpoint.module, []).append(endpoint)
    return grouped


def _split_path(path: str) -> list[str]:
    return [segment for segment in path.partition("?")[0].split("/") if segment]


def _matches_wildcard_path(pattern_segments: list[str], concrete_segments: list[str]) -> bool:
    if not pattern_segments or pattern_segments[-1] != "**":
        return False
    prefix = pattern_segments[:-1]
    if len(concrete_segments) <= len(prefix):
        return False
    return all(
        _segment_matches(pattern_seg, concrete_seg)
        for pattern_seg, concrete_seg in zip(prefix, concrete_segments)
    )


def _is_template_segment(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def _segment_matches(call_segment: str, serve_segment: str) -> bool:
    if call_segment == serve_segment:
        return True
    return _is_template_segment(serve_segment) or _is_template_segment(call_segment)


_SERVICE_URL_GETTER_RE = re.compile(r"\.get([A-Z][A-Za-z0-9]*)ServiceUrl\(")
_SERVICE_URL_HOST_RE = re.compile(r'https?://([a-z0-9-]+(?:-[a-z0-9-]+)*-service)\b', re.IGNORECASE)


def _camel_to_kebab(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


def _rest_target_service_hint(call: MessageEndpoint) -> str | None:
    getter_match = _SERVICE_URL_GETTER_RE.search(call.snippet)
    if getter_match is not None:
        return f"{_camel_to_kebab(getter_match.group(1))}-service"
    host_match = _SERVICE_URL_HOST_RE.search(call.snippet)
    if host_match is not None:
        return host_match.group(1).lower()
    return None


def _service_matches_hint(service_name: str, hint: str | None) -> bool:
    if hint is None:
        return True
    normalized = service_name.lower()
    return normalized == hint or normalized.endswith(f"-{hint}") or hint in normalized


def paths_match(call_topic: str, serve_topic: str) -> bool:
    """Best-effort : même méthode HTTP, et les segments de chemin du call
    (littéral ↔ template `{param}`) préfixent ou couvrent ceux de la route
    exposée. Un call sans aucun littéral exploitable (`<dynamic>`) ne matche
    jamais — mieux vaut une arête absente qu'une fausse arête."""

    call_method, _, call_path = call_topic.partition(" ")
    serve_method, _, serve_path = serve_topic.partition(" ")
    if call_method != serve_method or call_path == "<dynamic>":
        return False

    call_segments = _split_path(call_path)
    serve_segments = _split_path(serve_path)
    if not call_segments:
        return False
    if len(call_segments) == len(serve_segments):
        return all(
            _segment_matches(call_seg, serve_seg)
            for call_seg, serve_seg in zip(call_segments, serve_segments)
        )
    if _matches_wildcard_path(call_segments, serve_segments):
        return True
    if _matches_wildcard_path(serve_segments, call_segments):
        return True
    return False


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
    seen: set[tuple[str, str, str, str, str]] = set()
    for call_service, call in calls:
        for serve_service, serve in serves:
            if call_service == serve_service:
                continue
            if not _service_matches_hint(serve_service, _rest_target_service_hint(call)):
                continue
            if paths_match(call.topic, serve.topic):
                key = ("rest", call_service, serve_service, call.id, serve.id)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(GraphEdge("rest", call_service, serve_service, call, serve))

    for produce_service, produce in produces:
        for consume_service, consume in consumes:
            if produce_service == consume_service:
                continue
            if produce.topic == consume.topic:
                key = ("kafka", produce_service, consume_service, produce.id, consume.id)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(GraphEdge("kafka", produce_service, consume_service, produce, consume))

    return edges


def find_outbound_calls_in_consumers(
    endpoints: list[MessageEndpoint],
) -> list[OutboundCallInConsumer]:
    """Un appel REST (`call`) dont le site tombe dans la plage de lignes
    d'un handler de consommation Kafka (`consume`) du même fichier. `endpoints`
    doit venir d'un seul service : fichier et lignes ne sont comparables qu'au
    sein d'un même repo."""

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
