from pathlib import Path

from ccc_radar.dependency_analysis import build_dependency_graph
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.modules import DiscoveredModule


def make_endpoint(
    role: str,
    topic: str,
    path: str,
    start_line: int = 1,
    end_line: int = 1,
    *,
    module: str | None = None,
    snippet: str = "",
    topic_dynamic: bool = False,
) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, path, start_line, end_line),
        role=role,
        system="rest",
        topic=topic,
        topic_dynamic=topic_dynamic,
        source="code",
        framework=None,
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet=snippet,
        module=module,
    )


def _module(name: str) -> DiscoveredModule:
    return DiscoveredModule(
        name=name,
        path=Path(f"/repo/{name}"),
        build_system="maven",
        version=None,
        kind="microservice",
        starts_application=True,
        configuration_example="",
    )


def _client_calls(edges):
    return [e for e in edges if e["kind"] == "http" and e["label"] == "client API"]


def test_configured_client_relation_emitted_when_host_in_endpoints() -> None:
    caller = make_endpoint(
        "call",
        "ANY <dynamic>",
        "caller/Client.java",
        module="caller-service",
        snippet="annuaireApi.getDirectory()\ncccr-api-domain:annuaire",
        topic_dynamic=True,
    )
    host = make_endpoint("serve", "GET /annuaire", "annuaire/Controller.java", module="annuaire")

    result = build_dependency_graph(
        {"caller-service": [caller], "annuaire": [host]},
        {},
    )

    client_edges = _client_calls(result["edges"])
    assert len(client_edges) == 1
    assert client_edges[0]["source"] == "microservice:caller-service"
    assert client_edges[0]["target"] == "microservice:annuaire"
    assert result["summary"]["configured_client_relations"] == 1
    # Aucune arête par route fabriquée ni de pollution calls_external.
    assert not [e for e in result["edges"] if e["kind"] == "http" and e["label"] != "client API"]
    assert not [e for e in result["edges"] if e["kind"] == "calls_external"]


def test_configured_client_relation_when_host_known_via_modules_only() -> None:
    caller = make_endpoint(
        "call",
        "ANY <dynamic>",
        "caller/Client.java",
        module="caller-service",
        snippet="annuaireApi.get()\ncccr-api-domain:annuaire",
        topic_dynamic=True,
    )

    result = build_dependency_graph(
        {"caller-service": [caller]},
        {"annuaire": _module("annuaire")},
    )

    client_edges = _client_calls(result["edges"])
    assert len(client_edges) == 1
    assert client_edges[0]["target"] == "microservice:annuaire"
    # Le nœud hôte existe même sans aucun endpoint détecté.
    assert any(n["id"] == "microservice:annuaire" for n in result["nodes"])
    assert result["warnings"] == []


def test_unresolved_configured_client_domain_emits_warning() -> None:
    caller = make_endpoint(
        "call",
        "ANY <dynamic>",
        "caller/Client.java",
        module="caller-service",
        snippet="ghostApi.get()\ncccr-api-domain:ghost",
        topic_dynamic=True,
    )

    result = build_dependency_graph({"caller-service": [caller]}, {})

    assert _client_calls(result["edges"]) == []
    assert not [e for e in result["edges"] if e["kind"] == "calls_external"]
    assert any("ghost" in warning for warning in result["warnings"])
    assert result["summary"]["configured_client_relations"] == 0


def test_multiple_configured_call_sites_collapse_to_single_relation() -> None:
    call_a = make_endpoint(
        "call",
        "ANY <dynamic>",
        "caller/A.java",
        5,
        5,
        module="caller-service",
        snippet="annuaireApi.a()\ncccr-api-domain:annuaire",
        topic_dynamic=True,
    )
    call_b = make_endpoint(
        "call",
        "ANY <dynamic>",
        "caller/B.java",
        9,
        9,
        module="caller-service",
        snippet="annuaireApi.b()\ncccr-api-domain:annuaire",
        topic_dynamic=True,
    )
    host = make_endpoint("serve", "GET /annuaire", "annuaire/Controller.java", module="annuaire")

    result = build_dependency_graph(
        {"caller-service": [call_a, call_b], "annuaire": [host]},
        {},
    )

    assert len(_client_calls(result["edges"])) == 1
