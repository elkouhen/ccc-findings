"""High-confidence architecture risks derived from the indexed inventory."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from ccc_radar.graph import GraphEdge
from ccc_radar.models import MessageEndpoint
from ccc_radar.modules import DiscoveredModule


_MONGO_WRITE_OPERATIONS = frozenset({
    "bulkOps", "findAndModify", "findAndReplace", "insert", "remove", "save",
    "updateFirst", "updateMulti", "upsert",
})


@dataclass(frozen=True)
class ArchitectureRisk:
    id: str
    severity: str
    title: str
    evidence: str
    services: tuple[str, ...]
    confidence: str = "high"


def assess_architecture(
    endpoints_by_service: dict[str, list[MessageEndpoint]],
    edges: list[GraphEdge],
    *,
    modules: list[DiscoveredModule] | None = None,
    endpoints_by_module: dict[str, list[MessageEndpoint]] | None = None,
) -> list[ArchitectureRisk]:
    risks: list[ArchitectureRisk] = []
    edge_keys = {(edge.kind, edge.from_service, edge.to_service, edge.from_endpoint.topic) for edge in edges}
    for service, endpoints in sorted(endpoints_by_service.items()):
        for endpoint in endpoints:
            if endpoint.system == "kafka" and endpoint.topic_dynamic:
                risks.append(ArchitectureRisk(
                    "dynamic-kafka-topic", "WARNING", "Topic Kafka dynamique non cartographiable",
                    f"{service}: {endpoint.path}:{endpoint.start_line} utilise un topic dynamique.", (service,), "high",
                ))
            if endpoint.system == "rest" and endpoint.role == "call" and endpoint.topic.endswith(" <dynamic>"):
                risks.append(ArchitectureRisk(
                    "dynamic-http-target", "WARNING", "Cible HTTP dynamique non cartographiable",
                    f"{service}: {endpoint.path}:{endpoint.start_line} construit une route dynamiquement.", (service,), "high",
                ))
            if endpoint.system == "kafka" and endpoint.role == "produce" and not endpoint.topic_dynamic:
                if not any(key[0] == "kafka" and key[1] == service and key[3] == endpoint.topic for key in edge_keys):
                    risks.append(ArchitectureRisk(
                        "orphan-kafka-producer", "WARNING", "Producer Kafka sans consumer détecté",
                        f"{service} publie `{endpoint.topic}` ({endpoint.path}:{endpoint.start_line}) sans consumer inter-service indexé.", (service,),
                    ))
            if endpoint.system == "kafka" and endpoint.role == "consume" and not endpoint.topic_dynamic:
                if not any(key[0] == "kafka" and key[2] == service and key[3] == endpoint.topic for key in edge_keys):
                    risks.append(ArchitectureRisk(
                        "orphan-kafka-consumer", "WARNING", "Consumer Kafka sans producer détecté",
                        f"{service} consomme `{endpoint.topic}` ({endpoint.path}:{endpoint.start_line}) sans producer inter-service indexé.", (service,),
                    ))
    # A two-way synchronous dependency is a concrete coupling signal.
    rest_pairs = {(edge.from_service, edge.to_service) for edge in edges if edge.kind == "rest"}
    for source, target in sorted(rest_pairs):
        if source < target and (target, source) in rest_pairs:
            risks.append(ArchitectureRisk(
                "synchronous-rest-cycle", "ERROR", "Cycle de dépendance HTTP synchrone",
                f"{source} appelle {target} et {target} appelle {source}.", (source, target),
            ))
    for module in sorted(modules or [], key=lambda item: item.name):
        if module.starts_application or module.kind == "aggregator":
            continue
        endpoints = (endpoints_by_module or {}).get(module.name, [])
        risk = _non_runtime_module_activity_risk(module, endpoints)
        if risk is not None:
            risks.append(risk)
    return risks


def _non_runtime_module_activity_risk(
    module: DiscoveredModule, endpoints: list[MessageEndpoint]
) -> ArchitectureRisk | None:
    exposed_apis = sorted({
        endpoint.topic for endpoint in endpoints if endpoint.system == "rest" and endpoint.role == "serve"
    })
    published_topics = sorted({
        endpoint.topic for endpoint in endpoints if endpoint.system == "kafka" and endpoint.role == "produce"
    })
    consumed_topics = sorted({
        endpoint.topic for endpoint in endpoints if endpoint.system == "kafka" and endpoint.role == "consume"
    })
    mongo_reads = sorted({
        method.collection
        for method in module.mongo_methods
        if method.collection and method.operation not in _MONGO_WRITE_OPERATIONS
    })
    mongo_writes = sorted({
        method.collection
        for method in module.mongo_methods
        if method.collection and method.operation in _MONGO_WRITE_OPERATIONS
    })
    responsibilities = [
        ("APIs HTTP exposées", exposed_apis),
        ("topics Kafka publiés", published_topics),
        ("topics Kafka consommés", consumed_topics),
        ("collections MongoDB lues", mongo_reads),
        ("collections MongoDB écrites", mongo_writes),
    ]
    details = [f"{label}: {', '.join(values)}" for label, values in responsibilities if values]
    if not details:
        return None
    return ArchitectureRisk(
        "non-runtime-module-activity",
        "WARNING",
        "Module non microservice avec responsabilités d'exécution",
        f"{module.name} est un module non runtime mais " + "; ".join(details) + ".",
        (module.name,),
    )


def render_audit_text(risks: list[ArchitectureRisk]) -> str:
    if not risks:
        return "Aucun risque d'architecture à forte confiance détecté dans l'inventaire statique."
    return "\n\n".join(
        f"[{risk.severity}] {risk.title}\n{risk.evidence}\nconfiance : {risk.confidence}"
        for risk in risks
    )


def render_audit_json(risks: list[ArchitectureRisk]) -> list[dict[str, object]]:
    return [asdict(risk) for risk in risks]
