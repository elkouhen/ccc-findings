"""Catalogue métier et navigation orientée architecture.

Les fonctions de ce module transforment les inventaires indexés en objets
stables (module, API, topic et collection), sans exposer les fichiers source.
L'accès à une implantation reste une opération explicite de la CLI.
"""

from dataclasses import dataclass

from ccc_radar.graph import GraphEdge, build_graph
from ccc_radar.models import MessageEndpoint
from ccc_radar.modules import DiscoveredModule


_KINDS = {
    "module": "module",
    "modules": "module",
    "microservice": "microservice",
    "microservices": "microservice",
    "topic": "topic",
    "topics": "topic",
    "api": "api",
    "apis": "api",
    "collection": "collection",
    "collections": "collection",
    "endpoint": "endpoint",
    "endpoints": "endpoint",
}


@dataclass(frozen=True)
class ArchitectureCatalog:
    modules: tuple[DiscoveredModule, ...]
    endpoints: tuple[MessageEndpoint, ...]
    edges: tuple[GraphEdge, ...]

    @property
    def modules_by_name(self) -> dict[str, DiscoveredModule]:
        return {module.name: module for module in self.modules}


def normalize_kind(kind: str) -> str | None:
    return _KINDS.get(kind.casefold())


def build_catalog(
    modules: list[DiscoveredModule], endpoints: list[MessageEndpoint]
) -> ArchitectureCatalog:
    endpoints_by_module: dict[str, list[MessageEndpoint]] = {}
    for endpoint in endpoints:
        if endpoint.module is not None:
            endpoints_by_module.setdefault(endpoint.module, []).append(endpoint)
    return ArchitectureCatalog(
        modules=tuple(sorted(modules, key=lambda module: module.name)),
        endpoints=tuple(endpoints),
        edges=tuple(build_graph(endpoints_by_module)),
    )


def module_summary(catalog: ArchitectureCatalog, name: str) -> dict[str, object] | None:
    module = catalog.modules_by_name.get(name)
    if module is None:
        return None
    endpoints = [endpoint for endpoint in catalog.endpoints if endpoint.module == name]
    served = sorted({endpoint.topic for endpoint in endpoints if endpoint.system == "rest" and endpoint.role == "serve"})
    called = sorted({endpoint.topic for endpoint in endpoints if endpoint.system == "rest" and endpoint.role == "call"})
    produced = sorted({endpoint.topic for endpoint in endpoints if endpoint.system == "kafka" and endpoint.role == "produce"})
    consumed = sorted({endpoint.topic for endpoint in endpoints if endpoint.system == "kafka" and endpoint.role == "consume"})
    outgoing = sorted({edge.to_service for edge in catalog.edges if edge.from_service == name})
    incoming = sorted({edge.from_service for edge in catalog.edges if edge.to_service == name})
    matched_call_ids = {edge.from_endpoint.id for edge in catalog.edges if edge.kind == "rest" and edge.from_service == name}
    external_apis = sorted({
        endpoint.topic
        for endpoint in endpoints
        if endpoint.system == "rest" and endpoint.role == "call" and endpoint.id not in matched_call_ids
    })
    technologies = ["Java"]
    if module.starts_application:
        technologies.append("Spring Boot")
    if produced or consumed or module.kafka_methods:
        technologies.append("Kafka")
    if module.mongo_collections or module.mongo_methods:
        technologies.append("MongoDB")
    if module.openapi_files:
        technologies.append("OpenAPI")
    return {
        "kind": "microservice" if module.starts_application else "module",
        "name": module.name,
        "language": "Java",
        "build_tool": module.build_system,
        "version": module.version,
        "exposes_http_api": bool(served),
        "http_apis_exposed": served,
        "http_apis_consumed": called,
        "kafka_topics_published": produced,
        "kafka_topics_consumed": consumed,
        "databases": {"mongodb_collections": list(module.mongo_collections)},
        "technologies": technologies,
        "openapi": bool(module.openapi_files),
        "scheduled_tasks": [],
        "scheduled_tasks_detection": "not_available",
        "dependencies": {"outgoing_modules": outgoing, "incoming_modules": incoming},
        "external_apis": external_apis,
    }


def list_objects(catalog: ArchitectureCatalog, kind: str) -> list[dict[str, object]]:
    if kind == "microservice":
        return [
            summary for module in catalog.modules
            if module.starts_application
            if (summary := module_summary(catalog, module.name)) is not None
        ]
    if kind == "module":
        return [
            summary for module in catalog.modules
            if (summary := module_summary(catalog, module.name)) is not None
        ]
    if kind == "topic":
        topics = sorted({endpoint.topic for endpoint in catalog.endpoints if endpoint.system == "kafka"})
        return [topic_summary(catalog, topic) for topic in topics]
    if kind == "api":
        apis = sorted({endpoint.topic for endpoint in catalog.endpoints if endpoint.system == "rest"})
        return [api_summary(catalog, api) for api in apis]
    if kind == "collection":
        collections = sorted({collection for module in catalog.modules for collection in module.mongo_collections})
        return [collection_summary(catalog, collection) for collection in collections]
    if kind == "endpoint":
        return [endpoint_summary(endpoint) for endpoint in catalog.endpoints]
    return []


def topic_summary(catalog: ArchitectureCatalog, topic: str) -> dict[str, object]:
    endpoints = [endpoint for endpoint in catalog.endpoints if endpoint.system == "kafka" and endpoint.topic == topic]
    return {
        "kind": "topic",
        "name": topic,
        "producers": sorted({endpoint.module for endpoint in endpoints if endpoint.role == "produce" and endpoint.module}),
        "consumers": sorted({endpoint.module for endpoint in endpoints if endpoint.role == "consume" and endpoint.module}),
    }


def api_summary(catalog: ArchitectureCatalog, api: str) -> dict[str, object]:
    endpoints = [endpoint for endpoint in catalog.endpoints if endpoint.system == "rest" and endpoint.topic == api]
    return {
        "kind": "api",
        "name": api,
        "providers": sorted({endpoint.module for endpoint in endpoints if endpoint.role == "serve" and endpoint.module}),
        "consumers": sorted({endpoint.module for endpoint in endpoints if endpoint.role == "call" and endpoint.module}),
    }


def collection_summary(catalog: ArchitectureCatalog, collection: str) -> dict[str, object]:
    modules = [module for module in catalog.modules if collection in module.mongo_collections]
    return {
        "kind": "collection",
        "name": collection,
        "modules": [module.name for module in modules],
        "operations": sum(
            1 for module in modules for method in module.mongo_methods if method.collection == collection
        ),
    }


def endpoint_summary(endpoint: MessageEndpoint) -> dict[str, object]:
    return {
        "kind": "endpoint",
        "id": endpoint.id,
        "name": endpoint.topic,
        "topic": endpoint.topic,
        "role": endpoint.role,
        "system": endpoint.system,
        "module": endpoint.module,
        "framework": endpoint.framework,
        "dynamic": endpoint.topic_dynamic,
    }


def show_object(catalog: ArchitectureCatalog, kind: str, name: str) -> dict[str, object] | None:
    if kind in {"module", "microservice"}:
        summary = module_summary(catalog, name)
        if summary is None or (kind == "microservice" and summary["kind"] != "microservice"):
            return None
        return summary
    if kind == "topic" and any(endpoint.system == "kafka" and endpoint.topic == name for endpoint in catalog.endpoints):
        return topic_summary(catalog, name)
    if kind == "api" and any(endpoint.system == "rest" and endpoint.topic == name for endpoint in catalog.endpoints):
        return api_summary(catalog, name)
    if kind == "collection" and any(name in module.mongo_collections for module in catalog.modules):
        return collection_summary(catalog, name)
    if kind == "endpoint":
        endpoint = next((item for item in catalog.endpoints if item.id == name), None)
        return endpoint_summary(endpoint) if endpoint else None
    return None


def neighbors(catalog: ArchitectureCatalog, kind: str, name: str) -> list[dict[str, str]] | None:
    if show_object(catalog, kind, name) is None:
        return None
    related: set[tuple[str, str, str]] = set()
    if kind in {"module", "microservice"}:
        for endpoint in (endpoint for endpoint in catalog.endpoints if endpoint.module == name):
            object_kind = "topic" if endpoint.system == "kafka" else "api"
            relation = {
                "produce": "publishes",
                "consume": "consumes",
                "serve": "provides",
                "call": "calls",
            }[endpoint.role]
            related.add((object_kind, endpoint.topic, relation))
        module = catalog.modules_by_name[name]
        for collection in module.mongo_collections:
            related.add(("collection", collection, "uses"))
        for edge in catalog.edges:
            if edge.from_service == name:
                related.add(("module", edge.to_service, "depends_on"))
            if edge.to_service == name:
                related.add(("module", edge.from_service, "used_by"))
    elif kind == "topic":
        for endpoint in (endpoint for endpoint in catalog.endpoints if endpoint.system == "kafka" and endpoint.topic == name):
            if endpoint.module:
                related.add(("module", endpoint.module, "producer" if endpoint.role == "produce" else "consumer"))
    elif kind == "api":
        for endpoint in (endpoint for endpoint in catalog.endpoints if endpoint.system == "rest" and endpoint.topic == name):
            if endpoint.module:
                related.add(("module", endpoint.module, "provider" if endpoint.role == "serve" else "consumer"))
    elif kind == "endpoint":
        endpoint = next(item for item in catalog.endpoints if item.id == name)
        if endpoint.module:
            related.add(("module", endpoint.module, "belongs_to"))
        related.add(("topic" if endpoint.system == "kafka" else "api", endpoint.topic, "implements"))
    else:
        for module in catalog.modules:
            if name in module.mongo_collections:
                related.add(("module", module.name, "uses"))
    return [
        {"kind": item_kind, "name": item_name, "relation": relation}
        for item_kind, item_name, relation in sorted(related)
    ]


def analyze(catalog: ArchitectureCatalog, query: str, target: str | None) -> dict[str, object] | None:
    normalized = query.casefold()
    if normalized in {"consumers", "consumer"} and target:
        result = show_object(catalog, "topic", target)
        return {"query": "consumers", "topic": target, "microservices": result["consumers"]} if result else None
    if normalized in {"producers", "producer"} and target:
        result = show_object(catalog, "topic", target)
        return {"query": "producers", "topic": target, "microservices": result["producers"]} if result else None
    if normalized in {"calls", "dependencies"} and target:
        result = show_object(catalog, "module", target)
        return {"query": "calls", "module": target, "dependencies": result["dependencies"]} if result else None
    if normalized in {"external-apis", "external_api"}:
        items = [
            {"module": module.name, "apis": summary["external_apis"]}
            for module in catalog.modules
            if (summary := module_summary(catalog, module.name)) is not None and summary["external_apis"]
        ]
        return {"query": "external-apis", "items": items}
    if normalized in {"orphan-endpoints", "orphans"}:
        results = []
        for topic in list_objects(catalog, "topic"):
            if not topic["producers"] or not topic["consumers"]:
                results.append(topic)
        for api in list_objects(catalog, "api"):
            if not api["providers"] or not api["consumers"]:
                results.append(api)
        return {"query": "orphan-endpoints", "items": results}
    if normalized == "impact" and target:
        for kind in ("module", "topic", "api", "collection"):
            items = neighbors(catalog, kind, target)
            if items is not None:
                return {"query": "impact", "object": {"kind": kind, "name": target}, "neighbors": items}
    return None


def endpoint_implementation(catalog: ArchitectureCatalog, endpoint_id: str) -> dict[str, object] | None:
    endpoint = next((item for item in catalog.endpoints if item.id == endpoint_id), None)
    if endpoint is None:
        return None
    return {
        "kind": "endpoint",
        "id": endpoint.id,
        "name": endpoint.topic,
        "role": endpoint.role,
        "system": endpoint.system,
        "module": endpoint.module,
        "implementation": {
            "path": endpoint.path,
            "start_line": endpoint.start_line,
            "end_line": endpoint.end_line,
            "qualified_name": endpoint.qualified_name,
            "snippet": endpoint.snippet,
        },
    }


def render_text(result: object) -> str:
    if isinstance(result, list):
        if not result:
            return "Aucun objet d'architecture trouvé."
        return "\n".join(_render_item(item) for item in result)
    if isinstance(result, dict):
        return _render_item(result)
    return str(result)


def _render_item(item: dict[str, object]) -> str:
    kind = item.get("kind") or item.get("query", "result")
    name = item.get("name") or item.get("topic") or item.get("module") or ""
    details = []
    for key, value in item.items():
        if key in {"kind", "name", "topic", "module", "query"} or value in (None, [], {}, False):
            continue
        if isinstance(value, dict):
            value = ", ".join(f"{entry}={content}" for entry, content in value.items() if content)
        elif isinstance(value, list):
            value = ", ".join(str(entry) for entry in value)
        details.append(f"{key}={value}")
    return f"[{kind}] {name}" + ("\n  " + "\n  ".join(details) if details else "")
