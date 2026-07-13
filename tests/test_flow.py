from pathlib import Path

import numpy as np

from cccf.flow import FlowError, resolve_topic, resolve_topic_by_similarity, trace_flow
from cccf.models import Finding, MessageEndpoint, compute_endpoint_id
from cccf.store import Store


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


# -- resolve_topic_by_similarity (K3) --
#
# Vecteurs construits directement (pas de texte via un vrai/faux embedder de
# texte) : la similarité cosinus d'un embedder de texte réel ou basé sur un
# hash n'est pas calibrée pour des chaînes arbitraires (deux textes courts et
# sans rapport peuvent se retrouver à une similarité élevée selon le modèle
# ou la dimension), donc pas fiable pour prouver le comportement du seuil.


class _StubEmbedder:
    def __init__(self, vector: np.ndarray) -> None:
        self._vector = vector

    def embed_query(self, text: str) -> np.ndarray:
        return self._vector


def test_resolve_topic_by_similarity_returns_closest_endpoint_above_threshold(
    tmp_path: Path,
) -> None:
    endpoint = make_endpoint("produce", "kafka", "orders.created", "a.java", 1, 1)

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["a.java"], [endpoint])
        store.set_endpoint_embedding(endpoint.id, np.array([1.0, 0.0], dtype=np.float32))

        embedder = _StubEmbedder(np.array([0.9, 0.1], dtype=np.float32))
        resolved = resolve_topic_by_similarity(store, embedder, "query", [endpoint])

    assert resolved == "orders.created"


def test_resolve_topic_by_similarity_rejects_low_similarity_match(tmp_path: Path) -> None:
    endpoint = make_endpoint("produce", "kafka", "orders.created", "a.java", 1, 1)

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["a.java"], [endpoint])
        store.set_endpoint_embedding(endpoint.id, np.array([1.0, 0.0], dtype=np.float32))

        # orthogonal : score = 1 - 1 = 0, très en dessous du seuil par défaut
        embedder = _StubEmbedder(np.array([0.0, 1.0], dtype=np.float32))
        resolved = resolve_topic_by_similarity(store, embedder, "query", [endpoint])

    assert resolved is None


def test_resolve_topic_by_similarity_returns_none_without_any_embedded_endpoint(
    tmp_path: Path,
) -> None:
    with Store(tmp_path):
        pass

    with Store(tmp_path) as store:
        embedder = _StubEmbedder(np.array([1.0, 0.0], dtype=np.float32))
        resolved = resolve_topic_by_similarity(store, embedder, "query", [])

    assert resolved is None
