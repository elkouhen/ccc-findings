from pathlib import Path

from ccc_radar.graph import (
    build_graph,
    find_cycles,
    find_hotspots,
    find_outbound_calls_in_consumers,
    group_endpoints_by_module,
    group_findings_by_module,
    paths_match,
    rank_hotspots,
)
from ccc_radar.models import Finding, MessageEndpoint, compute_endpoint_id
from ccc_radar.store import Store


def make_endpoint(
    role: str,
    topic: str,
    path: str,
    start_line: int = 1,
    end_line: int = 1,
    system: str = "rest",
    framework: str | None = None,
    module: str | None = None,
) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, path, start_line, end_line),
        role=role,
        system=system,
        topic=topic,
        topic_dynamic=False,
        source="code",
        framework=framework,
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="",
        module=module,
    )


def make_finding(
    path: str, start_line: int, end_line: int, severity: str, module: str | None = None
) -> Finding:
    return Finding(
        id=f"finding-{path}-{start_line}",
        rule_id="cccr.liveness.requests-no-timeout",
        severity=severity,
        message="Appel HTTP sans timeout.",
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="requests.get(...)",
        fix=None,
        cwe=[],
        owasp=[],
        module=module,
    )


# -- paths_match (CA4) --


def test_paths_match_literal_call_against_template_serve() -> None:
    assert paths_match("GET /orders/123", "GET /orders/{id}")


def test_paths_match_requires_same_method() -> None:
    assert not paths_match("POST /orders/123", "GET /orders/{id}")


def test_paths_match_rejects_different_segment_count() -> None:
    assert not paths_match("GET /orders/123/status", "GET /orders/{id}")


def test_paths_match_allows_call_prefix_shorter_than_serve() -> None:
    # concaténation : le call n'a que le préfixe littéral connu
    assert paths_match("GET /orders", "GET /orders/{id}")


def test_paths_match_rejects_fully_dynamic_call() -> None:
    assert not paths_match("GET <dynamic>", "GET /orders/{id}")


def test_paths_match_rejects_unrelated_paths() -> None:
    assert not paths_match("GET /payments/{id}", "GET /orders/{id}")


# -- build_graph + find_cycles (CA1) --


def _three_service_cycle_fixture() -> dict[str, list[MessageEndpoint]]:
    service_a = [
        make_endpoint("serve", "GET /a-status", "a/Controller.java", 10, 10),
        make_endpoint("call", "GET /b-status", "a/Client.java", 5, 5),
    ]
    service_b = [
        make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10),
        make_endpoint("call", "GET /c-status", "b/Client.java", 5, 5),
    ]
    service_c = [
        make_endpoint("serve", "GET /c-status", "c/Controller.java", 10, 10),
        make_endpoint("call", "GET /a-status", "c/Client.java", 5, 5),
    ]
    return {"service-a": service_a, "service-b": service_b, "service-c": service_c}


def test_build_graph_creates_rest_edges_between_distinct_services_only() -> None:
    edges = build_graph(_three_service_cycle_fixture())

    assert len(edges) == 3
    assert {(e.from_service, e.to_service) for e in edges} == {
        ("service-a", "service-b"),
        ("service-b", "service-c"),
        ("service-c", "service-a"),
    }
    assert all(e.kind == "rest" for e in edges)


def test_build_graph_skips_same_service_calls() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("serve", "GET /a-status", "a/Controller.java", 10, 10),
            make_endpoint("call", "GET /a-status", "a/Client.java", 5, 5),
        ]
    }

    assert build_graph(endpoints_by_service) == []


def test_find_cycles_detects_the_three_service_rest_cycle_with_sites() -> None:
    edges = build_graph(_three_service_cycle_fixture())

    cycles = find_cycles(edges)

    assert len(cycles) == 1
    cycle = cycles[0]
    assert set(cycle.services[:-1]) == {"service-a", "service-b", "service-c"}
    assert cycle.services[0] == cycle.services[-1]
    assert cycle.has_synchronous_rest is True
    # chaque arête porte les sites (fichier:lignes) des deux extrémités
    sites = {(e.from_endpoint.path, e.from_endpoint.start_line) for e in cycle.edges}
    sites |= {(e.to_endpoint.path, e.to_endpoint.start_line) for e in cycle.edges}
    assert ("a/Client.java", 5) in sites
    assert ("b/Controller.java", 10) in sites


def test_find_cycles_marks_webclient_only_cycle_as_not_synchronous() -> None:
    # Cycle A -> B -> A, mais les deux appels sont WebClient (réactif) :
    # le cycle existe, mais pas de garantie de blocage de thread synchrone.
    endpoints_by_service = {
        "service-a": [
            make_endpoint("serve", "GET /a-status", "a/Controller.java", 10, 10),
            make_endpoint(
                "call", "GET /b-status", "a/Client.java", 5, 5, framework="webclient"
            ),
        ],
        "service-b": [
            make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10),
            make_endpoint(
                "call", "GET /a-status", "b/Client.java", 5, 5, framework="webclient"
            ),
        ],
    }

    cycles = find_cycles(build_graph(endpoints_by_service))

    assert len(cycles) == 1
    assert cycles[0].has_synchronous_rest is False


def test_find_cycles_marks_mixed_webclient_and_resttemplate_cycle_as_synchronous() -> None:
    # Un seul maillon bloquant (RestTemplate) suffit à qualifier le cycle.
    endpoints_by_service = {
        "service-a": [
            make_endpoint("serve", "GET /a-status", "a/Controller.java", 10, 10),
            make_endpoint(
                "call", "GET /b-status", "a/Client.java", 5, 5, framework="webclient"
            ),
        ],
        "service-b": [
            make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10),
            make_endpoint(
                "call", "GET /a-status", "b/Client.java", 5, 5, framework="resttemplate"
            ),
        ],
    }

    cycles = find_cycles(build_graph(endpoints_by_service))

    assert len(cycles) == 1
    assert cycles[0].has_synchronous_rest is True


def test_find_cycles_returns_nothing_when_graph_is_acyclic() -> None:
    endpoints_by_service = {
        "service-a": [make_endpoint("call", "GET /b-status", "a/Client.java", 5, 5)],
        "service-b": [make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10)],
    }

    edges = build_graph(endpoints_by_service)

    assert find_cycles(edges) == []


def test_build_graph_creates_kafka_edges_on_matching_topic_only() -> None:
    endpoints_by_service = {
        "producer-svc": [
            make_endpoint("produce", "orders.created", "app/producer.py", 1, 1, system="kafka")
        ],
        "consumer-svc": [
            make_endpoint("consume", "orders.created", "app/consumer.py", 1, 1, system="kafka"),
            make_endpoint(
                "consume", "orders.cancelled", "app/other_consumer.py", 1, 1, system="kafka"
            ),
        ],
    }

    edges = build_graph(endpoints_by_service)

    assert len(edges) == 1
    assert edges[0].kind == "kafka"
    assert edges[0].to_endpoint.path == "app/consumer.py"


# -- find_outbound_calls_in_consumers (CA2) --


def test_find_outbound_calls_in_consumers_flags_call_inside_handler_range() -> None:
    endpoints = [
        make_endpoint(
            "consume", "orders.created", "app/OrderConsumer.java", 15, 25, system="kafka"
        ),
        make_endpoint("call", "POST /payments", "app/OrderConsumer.java", 20, 20),
    ]

    results = find_outbound_calls_in_consumers(endpoints)

    assert len(results) == 1
    assert results[0].call.start_line == 20


def test_find_outbound_calls_in_consumers_ignores_calls_outside_handler_or_other_files() -> None:
    endpoints = [
        make_endpoint(
            "consume", "orders.created", "app/OrderConsumer.java", 15, 25, system="kafka"
        ),
        make_endpoint("call", "POST /payments", "app/OrderConsumer.java", 40, 40),  # hors plage
        make_endpoint("call", "POST /payments", "app/OtherFile.java", 20, 20),  # autre fichier
    ]

    assert find_outbound_calls_in_consumers(endpoints) == []


# -- find_hotspots / rank_hotspots (CA3) --


def test_hotspot_on_cycle_with_error_finding_ranks_before_warning_only() -> None:
    edges = build_graph(_three_service_cycle_fixture())
    cycles = find_cycles(edges)

    findings_by_service = {
        # a/Client.java:5 (call GET /b-status) porte un finding WARNING
        "service-a": [make_finding("a/Client.java", 5, 5, "WARNING")],
        # b/Controller.java:10 (serve GET /b-status) porte un finding ERROR
        "service-b": [make_finding("b/Controller.java", 10, 10, "ERROR")],
    }

    hotspots = rank_hotspots(find_hotspots(cycles, findings_by_service))

    assert len(hotspots) == 2
    assert hotspots[0].finding.severity == "ERROR"
    assert hotspots[0].service == "service-b"
    assert hotspots[1].finding.severity == "WARNING"


def test_find_hotspots_ignores_findings_from_a_different_service() -> None:
    edges = build_graph(_three_service_cycle_fixture())
    cycles = find_cycles(edges)

    # même fichier/lignes que a/Client.java:5, mais rattaché à un autre
    # service : ne doit pas matcher (le fichier n'est comparable qu'au sein
    # d'un même repo).
    findings_by_service = {"service-c": [make_finding("a/Client.java", 5, 5, "ERROR")]}

    assert find_hotspots(cycles, findings_by_service) == []


# -- CA5 : aucune table de graphe persistée --


def test_no_graph_table_in_sqlite_schema(tmp_path: Path) -> None:
    with Store(tmp_path) as store:
        tables = {
            row["name"]
            for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    assert not any("graph" in name or "cycle" in name for name in tables)


# -- group_endpoints_by_module / group_findings_by_module (BACKLOG-13 M2) --


def test_group_endpoints_by_module_groups_by_maven_module() -> None:
    order_endpoint = make_endpoint(
        "produce", "orders.created", "order-service/Producer.java", module="order-service"
    )
    payment_endpoint = make_endpoint(
        "consume", "orders.created", "payment-service/Consumer.java", module="payment-service"
    )

    grouped = group_endpoints_by_module([order_endpoint, payment_endpoint])

    assert grouped == {
        "order-service": [order_endpoint],
        "payment-service": [payment_endpoint],
    }


def test_group_endpoints_by_module_ignores_endpoints_without_a_module() -> None:
    unattributed = make_endpoint("serve", "GET /health", "app/Health.java", module=None)

    assert group_endpoints_by_module([unattributed]) == {}


def test_group_findings_by_module_groups_by_maven_module() -> None:
    finding = make_finding("order-service/Producer.java", 10, 10, "ERROR", module="order-service")

    assert group_findings_by_module([finding]) == {"order-service": [finding]}


def test_group_findings_by_module_ignores_findings_without_a_module() -> None:
    finding = make_finding("app/Legacy.java", 1, 1, "WARNING", module=None)

    assert group_findings_by_module([finding]) == {}


def test_build_graph_and_find_cycles_work_from_module_grouped_endpoints() -> None:
    """Preuve de bout en bout (sans fédération A2/K7) : un seul index couvrant
    plusieurs modules Maven, groupé par `module` via `group_endpoints_by_module`,
    alimente `build_graph`/`find_cycles` exactement comme la fédération le
    faisait déjà — même algorithme, deux façons différentes d'obtenir le dict
    `endpoints_by_service` (BACKLOG-13 M2/M3)."""
    endpoints = [
        make_endpoint(
            "produce", "orders.created", "order-service/Producer.java",
            system="kafka", module="order-service",
        ),
        make_endpoint(
            "consume", "orders.created", "payment-service/Consumer.java",
            system="kafka", module="payment-service",
        ),
    ]

    grouped = group_endpoints_by_module(endpoints)
    edges = build_graph(grouped)

    assert len(edges) == 1
    assert edges[0].from_service == "order-service"
    assert edges[0].to_service == "payment-service"
    assert edges[0].kind == "kafka"
