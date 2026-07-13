from cccf.flow import FlowError, resolve_topic, trace_flow
from cccf.models import Finding, MessageEndpoint, compute_endpoint_id


def make_endpoint(
    role: str,
    system: str,
    topic: str,
    path: str,
    start_line: int = 1,
    end_line: int = 1,
    framework: str | None = None,
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
    )


def make_finding(path: str, start_line: int, end_line: int, rule_id: str = "rule.x") -> Finding:
    return Finding(
        id=f"finding-{path}-{start_line}",
        rule_id=rule_id,
        severity="WARNING",
        message="message",
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="",
        fix=None,
        cwe=[],
        owasp=[],
    )


# -- resolve_topic --


def test_resolve_topic_exact_match() -> None:
    assert resolve_topic("orders.created", {"orders.created", "orders.paid"}) == "orders.created"


def test_resolve_topic_unambiguous_substring_match() -> None:
    assert resolve_topic("orders", {"orders.created", "payments.made"}) == "orders.created"


def test_resolve_topic_ambiguous_substring_returns_none() -> None:
    assert resolve_topic("orders", {"orders.created", "orders.paid"}) is None


def test_resolve_topic_no_match_returns_none() -> None:
    assert resolve_topic("unknown", {"orders.created"}) is None


# -- trace_flow (K5 CA1) --


def test_trace_flow_lists_producer_and_consumer_across_services_with_overlapping_finding() -> None:
    produce = make_endpoint(
        "produce", "kafka", "orders.created", "order-service/Producer.java", 10, 10
    )
    consume = make_endpoint(
        "consume", "kafka", "orders.created", "payment-service/Consumer.java", 5, 7
    )
    overlapping_finding = make_finding("order-service/Producer.java", 10, 10, "rule.fire-and-forget")
    unrelated_finding = make_finding("payment-service/Consumer.java", 20, 20, "rule.unrelated")

    result = trace_flow(
        "orders.created",
        endpoints_by_service={"order-service": [produce], "payment-service": [consume]},
        findings_by_service={
            "order-service": [overlapping_finding],
            "payment-service": [unrelated_finding],
        },
    )

    assert result.resolved_topic == "orders.created"
    by_service = {site.service: site for site in result.sites}
    assert by_service["order-service"].endpoint is produce
    assert [f.rule_id for f in by_service["order-service"].findings] == ["rule.fire-and-forget"]
    assert by_service["payment-service"].endpoint is consume
    assert by_service["payment-service"].findings == []


def test_trace_flow_reports_federation_warnings_verbatim() -> None:
    produce = make_endpoint("produce", "kafka", "orders.created", "a/Producer.java", 1, 1)

    result = trace_flow(
        "orders.created",
        endpoints_by_service={"order-service": [produce]},
        findings_by_service={"order-service": []},
        warnings=["payment-service (path) : non indexé, ignoré (lancez cccf index sur ce projet)."],
    )

    assert result.warnings == [
        "payment-service (path) : non indexé, ignoré (lancez cccf index sur ce projet)."
    ]


def test_trace_flow_single_project_uses_none_service() -> None:
    serve = make_endpoint("serve", "rest", "GET /orders/{id}", "app/Controller.java", 8, 10)

    result = trace_flow(
        "GET /orders/{id}",
        endpoints_by_service={None: [serve]},
        findings_by_service={None: []},
    )

    assert result.sites[0].service is None


def test_trace_flow_unknown_topic_raises_flow_error() -> None:
    try:
        trace_flow("unknown", endpoints_by_service={None: []}, findings_by_service={None: []})
    except FlowError:
        pass
    else:
        raise AssertionError("expected FlowError")


def test_trace_flow_ambiguous_query_raises_flow_error() -> None:
    endpoints = [
        make_endpoint("produce", "kafka", "orders.created", "a.java", 1, 1),
        make_endpoint("produce", "kafka", "orders.paid", "b.java", 2, 2),
    ]
    try:
        trace_flow("orders", endpoints_by_service={None: endpoints}, findings_by_service={None: []})
    except FlowError:
        pass
    else:
        raise AssertionError("expected FlowError")
