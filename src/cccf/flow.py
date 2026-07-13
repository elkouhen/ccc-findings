"""Traçage d'un flux de messages Kafka ou d'une route REST à travers les
endpoints indexés (BACKLOG-10 K5). Résout une requête (nom de topic/route
exact, sinon correspondance approximative sur le texte du topic) vers tous
ses sites — producteurs/consommateurs Kafka, ou serveurs/appelants REST —
avec les findings Semgrep qui recouvrent chaque site (même jointure
fichier + lignes que `graph.find_hotspots`, esprit ADR-19).

Résolution purement textuelle pour l'instant (égalité exacte, puis
sous-chaîne insensible à la casse si le résultat est non ambigu) : la
similarité vectorielle sur les endpoints arrive avec K3 (BACKLOG-10) et
prendra le relais quand la résolution textuelle ne trouve aucun candidat
unique, sans changer ce contrat.
"""

from dataclasses import dataclass

from cccf.models import Finding, MessageEndpoint


class FlowError(Exception):
    """Aucun topic/route ne correspond à la requête parmi les endpoints
    indexés (ou plusieurs correspondent de façon ambiguë)."""


@dataclass(frozen=True)
class FlowSite:
    service: str | None  # None hors fédération (projet courant seul)
    endpoint: MessageEndpoint
    findings: list[Finding]


@dataclass(frozen=True)
class FlowResult:
    query: str
    resolved_topic: str
    sites: list[FlowSite]
    warnings: list[str]


def _overlaps(finding: Finding, endpoint: MessageEndpoint) -> bool:
    return (
        finding.path == endpoint.path
        and finding.start_line <= endpoint.end_line
        and finding.end_line >= endpoint.start_line
    )


def resolve_topic(query: str, all_topics: set[str]) -> str | None:
    """Nom exact d'abord ; sinon sous-chaîne insensible à la casse, mais
    seulement si elle désigne un unique topic/route — une correspondance
    ambiguë ne doit jamais choisir arbitrairement."""
    if query in all_topics:
        return query
    query_lower = query.lower()
    matches = sorted({topic for topic in all_topics if query_lower in topic.lower()})
    if len(matches) == 1:
        return matches[0]
    return None


def trace_flow(
    query: str,
    endpoints_by_service: dict[str | None, list[MessageEndpoint]],
    findings_by_service: dict[str | None, list[Finding]],
    warnings: list[str] | None = None,
) -> FlowResult:
    """`warnings` : avertissements de fédération (service non indexé/
    incompatible, K7 CA2) déjà émis par `load_federation` — reportés tels
    quels, jamais absorbés silencieusement : un site manquant à cause d'un
    service non fédéré doit rester visible, pas confondu avec une absence
    réelle de producteur/consommateur."""
    all_topics = {e.topic for endpoints in endpoints_by_service.values() for e in endpoints}
    resolved = resolve_topic(query, all_topics)
    if resolved is None:
        raise FlowError(
            f"Aucun topic/route ne correspond à {query!r} parmi les endpoints indexés."
        )

    sites: list[FlowSite] = []
    for service, endpoints in endpoints_by_service.items():
        for endpoint in endpoints:
            if endpoint.topic != resolved:
                continue
            findings = [
                f for f in findings_by_service.get(service, []) if _overlaps(f, endpoint)
            ]
            sites.append(FlowSite(service=service, endpoint=endpoint, findings=findings))

    return FlowResult(
        query=query, resolved_topic=resolved, sites=sites, warnings=list(warnings or [])
    )
