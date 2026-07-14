from pathlib import Path

from ccc_radar.graph import (
    build_graph,
    find_outbound_calls_in_consumers,
    group_endpoints_by_module,
    paths_match,
)
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
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


def _three_service_fixture() -> dict[str, list[MessageEndpoint]]:
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


def test_paths_match_literal_call_against_template_serve() -> None:
    assert paths_match("GET /orders/123", "GET /orders/{id}")


def test_paths_match_requires_same_method() -> None:
    assert not paths_match("POST /orders/123", "GET /orders/{id}")


def test_paths_match_rejects_different_segment_count() -> None:
    assert not paths_match("GET /orders/123/status", "GET /orders/{id}")


def test_paths_match_allows_call_prefix_shorter_than_serve() -> None:
    assert paths_match("GET /orders", "GET /orders/{id}")


def test_paths_match_rejects_fully_dynamic_call() -> None:
    assert not paths_match("GET <dynamic>", "GET /orders/{id}")


def test_paths_match_rejects_unrelated_paths() -> None:
    assert not paths_match("GET /payments/{id}", "GET /orders/{id}")


def test_build_graph_creates_rest_edges_between_distinct_services_only() -> None:
    edges = build_graph(_three_service_fixture())

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


def test_build_graph_deduplicates_duplicate_edges() -> None:
    call = make_endpoint("call", "GET /b-status", "a/Client.java", 5, 5)
    serve = make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10)

    edges = build_graph({"service-a": [call, call], "service-b": [serve, serve]})

    assert len(edges) == 1


def test_find_outbound_calls_in_consumers_flags_call_inside_handler_range() -> None:
    endpoints = [
        make_endpoint("consume", "orders.created", "app/OrderConsumer.java", 15, 25, system="kafka"),
        make_endpoint("call", "POST /payments", "app/OrderConsumer.java", 20, 20),
    ]

    results = find_outbound_calls_in_consumers(endpoints)

    assert len(results) == 1
    assert results[0].call.start_line == 20


def test_find_outbound_calls_in_consumers_ignores_calls_outside_handler_or_other_files() -> None:
    endpoints = [
        make_endpoint("consume", "orders.created", "app/OrderConsumer.java", 15, 25, system="kafka"),
        make_endpoint("call", "POST /payments", "app/OrderConsumer.java", 40, 40),
        make_endpoint("call", "POST /payments", "app/OtherFile.java", 20, 20),
    ]

    assert find_outbound_calls_in_consumers(endpoints) == []


def test_no_graph_table_in_sqlite_schema(tmp_path: Path) -> None:
    with Store(tmp_path) as store:
        tables = {
            row["name"]
            for row in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }

    assert not any("graph" in name or "cycle" in name for name in tables)


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


def test_build_graph_works_from_module_grouped_endpoints() -> None:
    endpoints = [
        make_endpoint(
            "produce",
            "orders.created",
            "order-service/Producer.java",
            system="kafka",
            module="order-service",
        ),
        make_endpoint(
            "consume",
            "orders.created",
            "payment-service/Consumer.java",
            system="kafka",
            module="payment-service",
        ),
    ]

    grouped = group_endpoints_by_module(endpoints)
    edges = build_graph(grouped)

    assert len(edges) == 1
    assert edges[0].from_service == "order-service"
    assert edges[0].to_service == "payment-service"
    assert edges[0].kind == "kafka"
