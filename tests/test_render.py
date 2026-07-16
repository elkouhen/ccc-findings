import json
import math
import re
import subprocess
import xml.etree.ElementTree as ET

import ccc_radar.render as render_module
from ccc_radar.graph import build_graph
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.render import (
    render_graph_d2,
    render_graph_drawio,
    render_graph_html,
    render_graph_json,
    render_graph_text,
    write_graph_d2,
)


def make_endpoint(
    role: str,
    topic: str,
    path: str,
    start_line: int = 1,
    end_line: int = 1,
    system: str = "rest",
    framework: str | None = None,
    snippet: str = "",
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
        snippet=snippet,
    )


def _fixture() -> dict[str, list[MessageEndpoint]]:
    return {
        "service-a": [
            make_endpoint(
                "call",
                "GET /orders",
                "a/Client.java",
                3,
                3,
                snippet="http://service-b",
            ),
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka"),
        ],
        "service-b": [
            make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10),
            make_endpoint("consume", "orders.created", "b/Listener.java", 12, 12, system="kafka"),
        ],
    }


def _vertex_for_service(root: ET.Element, service: str) -> ET.Element:
    return next(
        cell
        for cell in root.iter("mxCell")
        if cell.get("vertex") == "1" and f"<b>{service}</b>" in (cell.get("value") or "")
    )


def _vertex_rectangles(root: ET.Element) -> list[tuple[int, int, int, int]]:
    rectangles = []
    for cell in root.iter("mxCell"):
        if cell.get("vertex") != "1":
            continue
        geometry = cell.find("mxGeometry")
        assert geometry is not None
        rectangles.append(
            (
                int(float(geometry.get("x", "0"))),
                int(float(geometry.get("y", "0"))),
                int(float(geometry.get("width", "0"))),
                int(float(geometry.get("height", "0"))),
            )
        )
    return rectangles


def _rectangles_overlap(
    first: tuple[int, int, int, int], second: tuple[int, int, int, int]
) -> bool:
    ax, ay, aw, ah = first
    bx, by, bw, bh = second
    return ax < bx + bw and bx < ax + aw and ay < by + bh and by < ay + ah


def _rectangle_gap(first: tuple[int, int, int, int], second: tuple[int, int, int, int]) -> float:
    ax, ay, aw, ah = first
    bx, by, bw, bh = second
    dx = max(bx - (ax + aw), ax - (bx + bw), 0)
    dy = max(by - (ay + ah), ay - (by + bh), 0)
    return math.hypot(dx, dy)


def test_render_graph_json_expands_kafka_edges_via_topic_nodes() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    rendered = render_graph_json(list(endpoints_by_service), edges, [], cross_module_data_available=True)

    assert rendered["nodes"] == [
        {"name": "service-a", "kind": "microservice"},
        {"name": "service-b", "kind": "microservice"},
        {"name": "orders.created", "kind": "kafka_topic"},
    ]
    assert rendered["edges"] == [
        {
            "kind": "rest",
            "from_node": "service-a",
            "from_kind": "microservice",
            "to_node": "service-b",
            "to_kind": "microservice",
            "label": "GET /orders",
            "from_site": {
                "path": "a/Client.java",
                "start_line": 3,
                "end_line": 3,
                "topic": "GET /orders",
            },
            "to_site": {
                "path": "b/Controller.java",
                "start_line": 10,
                "end_line": 10,
                "topic": "GET /orders",
            },
        },
        {
            "kind": "kafka_produce",
            "from_node": "service-a",
            "from_kind": "microservice",
            "to_node": "orders.created",
            "to_kind": "kafka_topic",
            "label": "orders.created",
            "from_site": {
                "path": "a/Producer.java",
                "start_line": 5,
                "end_line": 5,
                "topic": "orders.created",
            },
            "to_site": None,
        },
        {
            "kind": "kafka_consume",
            "from_node": "orders.created",
            "from_kind": "kafka_topic",
            "to_node": "service-b",
            "to_kind": "microservice",
            "label": "orders.created",
            "from_site": None,
            "to_site": {
                "path": "b/Listener.java",
                "start_line": 12,
                "end_line": 12,
                "topic": "orders.created",
            },
        },
    ]


def test_render_graph_json_returns_note_when_cross_module_data_is_missing() -> None:
    rendered = render_graph_json([], [], [], cross_module_data_available=False)

    assert rendered["services"] == []
    assert rendered["edges"] == []
    assert "topologie inter-services" in rendered["note"]


def test_render_graph_text_formats_services_edges_and_outbound_calls() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)
    result = render_graph_json(list(endpoints_by_service), edges, [], cross_module_data_available=True)

    text = render_graph_text(result)

    assert "Services (2) : service-a, service-b" in text
    assert "Topics Kafka (1) : orders.created" in text
    assert "[rest] service-a (a/Client.java:3) --GET /orders--> service-b" in text
    assert "[kafka_produce] service-a" in text
    assert "[kafka_consume] orders.created --orders.created--> service-b" in text


def test_render_graph_drawio_produces_well_formed_xml() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges)

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]

    service_b_label = _vertex_for_service(root, "service-b").get("value") or ""
    assert "1 ressource exposée" in service_b_label
    assert "GET" in service_b_label
    assert "/orders" in service_b_label
    assert "Aucune ressource HTTP détectée" in (_vertex_for_service(root, "service-a").get("value") or "")
    assert any(cell.get("value") == "<b>orders.created</b>" for cell in root.iter("mxCell"))
    assert len(edge_cells) == 3
    assert all("strokeColor=#d32f2f" not in cell.get("style", "") for cell in edge_cells)


def test_graph_renderers_include_mongodb_collections_when_requested() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)
    collections = {"service-a": ["orders"], "service-b": ["payments"]}

    drawio = render_graph_drawio(endpoints_by_service, edges, collections)
    root = ET.fromstring(drawio)
    values = [cell.get("value") or "" for cell in root.iter("mxCell")]
    assert any("orders" in value and "MongoDB" in value for value in values)
    assert any("payments" in value and "MongoDB" in value for value in values)
    assert sum(cell.get("value") == "stocke" for cell in root.iter("mxCell")) == 2

    document = render_graph_html(endpoints_by_service, edges, collections)
    assert '"id": "mongodb_collection:service-a:orders"' in document
    assert '"id": "mongodb_collection:service-b:payments"' in document

    d2 = render_graph_d2(endpoints_by_service, edges, collections)
    assert 'label: "orders"' in d2
    assert 'label: "payments"' in d2
    assert 'svc_0 -> mongo_0: "stocke" {' in d2


def test_render_graph_html_embeds_sigma_and_safe_graph_data() -> None:
    endpoints_by_service = {
        "service-</script>": [
            make_endpoint("produce", "orders.created", "producer/Producer.java", system="kafka")
        ],
        "service-b": [
            make_endpoint("consume", "orders.created", "consumer/Consumer.java", system="kafka")
        ],
    }

    document = render_graph_html(endpoints_by_service, build_graph(endpoints_by_service))

    assert 'src="https://cdnjs.cloudflare.com/ajax/libs/graphology/0.25.4/graphology.umd.min.js"' in document
    assert 'src="https://cdnjs.cloudflare.com/ajax/libs/sigma.js/2.4.0/sigma.min.js"' in document
    assert "new Sigma(network" in document
    assert "new graphology.MultiDirectedGraph" in document
    assert "for (let iteration = 0; iteration < 720; iteration += 1)" in document
    assert "APIs exposees" in document
    assert "renderer.getCamera().animatedZoom" in document
    assert 'id="fit-view"' in document
    assert 'renderer.on("clickNode"' in document
    assert "nodeReducer:" in document
    assert "<\\/script>" in document
    assert "service-</script>" not in document


def test_render_graph_html_renders_rest_and_kafka_relations() -> None:
    document = render_graph_html(_fixture(), build_graph(_fixture()))

    graph_data = json.loads(
        re.search(
            r'<script id="graph-data" type="application/json">(.*)</script>', document
        ).group(1)
    )

    assert [link["kind"] for link in graph_data["links"]] == ["rest", "kafka", "kafka"]


def test_render_graph_drawio_uses_distinct_readable_styles() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    root = ET.fromstring(render_graph_drawio(endpoints_by_service, edges))
    model = next(root.iter("mxGraphModel"))
    edge_styles = {
        cell.get("value"): cell.get("style", "")
        for cell in root.iter("mxCell")
        if cell.get("edge") == "1"
    }

    assert model.get("page") == "0"
    assert "rounded=1" in _vertex_for_service(root, "service-a").get("style", "")
    assert "shape=cylinder3" in next(
        cell.get("style", "")
        for cell in root.iter("mxCell")
        if cell.get("value") == "<b>orders.created</b>"
    )
    assert "strokeColor=#4f79b5" in edge_styles["GET /orders"]
    assert "dashed=1" in edge_styles["orders.created"]
    assert "labelBackgroundColor=#ffffff" in edge_styles["GET /orders"]


def test_render_graph_drawio_deduplicates_duplicate_visual_edges() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint(
                "call", "GET /orders", "a/Client1.java", 5, 5, snippet="http://service-b"
            ),
            make_endpoint(
                "call", "GET /orders", "a/Client2.java", 15, 15, snippet="http://service-b"
            ),
        ],
        "service-b": [make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10)],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges)

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert edge_cells[0].get("value") == "GET /orders"


def test_render_graph_drawio_bundles_parallel_relations_in_a_multiline_label() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint(
                "call", "GET /orders", "a/Client.java", 5, 5, snippet="http://service-b"
            ),
            make_endpoint(
                "call", "POST /orders", "a/Client.java", 10, 10, snippet="http://service-b"
            ),
        ],
        "service-b": [
            make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10),
            make_endpoint("serve", "POST /orders", "b/Controller.java", 20, 20),
        ],
    }

    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]

    assert len(edge_cells) == 1
    assert edge_cells[0].get("value") == "GET /orders<br/>POST /orders"
    assert edge_cells[0].find("mxGeometry/Array[@as='points']") is None


def test_render_graph_drawio_keeps_a_service_and_topic_with_the_same_name_distinct() -> None:
    endpoints_by_service = {
        "orders": [make_endpoint("produce", "orders", "orders/Producer.java", system="kafka")],
        "notifications": [
            make_endpoint("consume", "orders", "notifications/Consumer.java", system="kafka")
        ],
    }

    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))
    vertices = [cell for cell in root.iter("mxCell") if cell.get("vertex") == "1"]
    edges = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    vertex_ids = {cell.get("id") for cell in vertices}

    assert len(vertices) == 3
    assert len(vertex_ids) == 3
    assert len(edges) == 2
    assert all(cell.get("source") in vertex_ids and cell.get("target") in vertex_ids for cell in edges)


def test_render_graph_drawio_uses_affinity_seed_positions_for_kafka_graph() -> None:
    endpoints_by_service = {
        "orders": [make_endpoint("produce", "orders.created", "orders/Producer.java", system="kafka")],
        "payments": [
            make_endpoint("consume", "orders.created", "payments/Listener.java", system="kafka"),
            make_endpoint("produce", "payments.completed", "payments/Producer.java", system="kafka"),
        ],
        "notifications": [
            make_endpoint("consume", "payments.completed", "notifications/Listener.java", system="kafka")
        ],
    }

    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))
    rectangles = {}
    for cell in root.iter("mxCell"):
        if cell.get("vertex") != "1":
            continue
        geometry = cell.find("mxGeometry")
        assert geometry is not None
        value = cell.get("value") or ""
        name = next(
            name
            for name in ("orders", "payments", "notifications", "orders.created", "payments.completed")
            if f"<b>{name}</b>" in value
        )
        rectangles[name] = (
            int(float(geometry.get("x", "0"))),
            int(float(geometry.get("y", "0"))),
            int(float(geometry.get("width", "0"))),
            int(float(geometry.get("height", "0"))),
        )

    assert _rectangle_gap(rectangles["orders.created"], rectangles["orders"]) < 250
    assert _rectangle_gap(rectangles["orders.created"], rectangles["payments"]) < 250
    assert _rectangle_gap(rectangles["payments.completed"], rectangles["payments"]) < 250
    assert _rectangle_gap(rectangles["payments.completed"], rectangles["notifications"]) < 250


def test_render_graph_drawio_separates_overlapping_nodes() -> None:
    endpoints_by_service = {
        "orders": [
            make_endpoint("produce", "orders.created", "orders/Producer.java", system="kafka"),
            make_endpoint("produce", "orders.cancelled", "orders/CancelProducer.java", system="kafka"),
        ],
        "payments": [
            make_endpoint("consume", "orders.created", "payments/Listener.java", system="kafka"),
            make_endpoint("produce", "payments.completed", "payments/Producer.java", system="kafka"),
        ],
        "notifications": [
            make_endpoint("consume", "payments.completed", "notifications/Listener.java", system="kafka"),
            make_endpoint("consume", "orders.cancelled", "notifications/CancelListener.java", system="kafka"),
        ],
        "audit": [
            make_endpoint("consume", "orders.created", "audit/OrdersListener.java", system="kafka"),
            make_endpoint("consume", "payments.completed", "audit/PaymentsListener.java", system="kafka"),
        ],
    }

    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))
    rectangles = _vertex_rectangles(root)

    for i, first in enumerate(rectangles):
        for second in rectangles[i + 1 :]:
            assert not _rectangles_overlap(first, second)


def test_render_graph_drawio_keeps_50_nodes_and_450_edges_separate() -> None:
    endpoints_by_service: dict[str, list[MessageEndpoint]] = {}
    for service_index in range(25):
        service = f"service-{service_index:02d}"
        endpoints = [
            make_endpoint(
                "produce",
                f"topic-{service_index:02d}",
                f"{service}/Producer.java",
                system="kafka",
            )
        ]
        endpoints.extend(
            make_endpoint(
                "consume",
                f"topic-{(service_index + offset) % 25:02d}",
                f"{service}/Listener{offset}.java",
                start_line=offset,
                end_line=offset,
                system="kafka",
            )
            for offset in range(1, 18)
        )
        endpoints_by_service[service] = endpoints

    document = render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service))
    root = ET.fromstring(document)
    rectangles = _vertex_rectangles(root)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]

    assert len(rectangles) == 50
    assert len(edge_cells) == 450
    for i, first in enumerate(rectangles):
        for second in rectangles[i + 1 :]:
            assert not _rectangles_overlap(first, second)


def test_render_graph_drawio_does_not_encode_layer_or_port_constraints() -> None:
    endpoints_by_service = _fixture()
    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))

    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]

    assert edge_cells
    assert all("exitX=" not in (cell.get("style") or "") for cell in edge_cells)
    assert all("exitY=" not in (cell.get("style") or "") for cell in edge_cells)
    assert all("entryX=" not in (cell.get("style") or "") for cell in edge_cells)
    assert all("entryY=" not in (cell.get("style") or "") for cell in edge_cells)
    assert all(cell.find("mxGeometry/Array[@as='points']") is None for cell in edge_cells)


def test_render_graph_drawio_seed_positions_keep_topic_near_related_services() -> None:
    endpoints_by_service = _fixture()
    root = ET.fromstring(render_graph_drawio(endpoints_by_service, build_graph(endpoints_by_service)))

    service_a = _vertex_for_service(root, "service-a")
    service_b = _vertex_for_service(root, "service-b")
    service_a_position = (
        int(float(service_a.find("mxGeometry").get("x", "0"))),  # type: ignore[union-attr]
        int(float(service_a.find("mxGeometry").get("y", "0"))),  # type: ignore[union-attr]
    )
    service_b_position = (
        int(float(service_b.find("mxGeometry").get("x", "0"))),  # type: ignore[union-attr]
        int(float(service_b.find("mxGeometry").get("y", "0"))),  # type: ignore[union-attr]
    )
    topic = next(
        cell
        for cell in root.iter("mxCell")
        if cell.get("vertex") == "1" and cell.get("value") == "<b>orders.created</b>"
    )
    topic_position = (
        int(float(topic.find("mxGeometry").get("x", "0"))),  # type: ignore[union-attr]
        int(float(topic.find("mxGeometry").get("y", "0"))),  # type: ignore[union-attr]
    )

    assert math.dist(topic_position, service_a_position) < 320
    assert math.dist(topic_position, service_b_position) < 320


def test_render_graph_d2_encodes_rest_and_kafka_edges() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    rendered = render_graph_d2(endpoints_by_service, edges)

    assert "direction: down" in rendered
    assert "  **service-a**" in rendered
    assert "  **service-b**" in rendered
    assert "  - `GET /orders`" in rendered
    assert 'label: "orders.created"' in rendered
    assert 'svc_0 -> svc_1: "GET /orders" {' in rendered
    assert 'svc_0 -> topic_0: "orders.created" {' in rendered
    assert 'topic_0 -> svc_1: "orders.created" {' in rendered
    assert "style.stroke-dash: 3" in rendered


def test_render_graph_drawio_uses_deterministic_elastic_seed() -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges)

    root = ET.fromstring(document)
    positions = {}
    for cell in root.iter("mxCell"):
        if cell.get("vertex") != "1":
            continue
        geometry = cell.find("mxGeometry")
        assert geometry is not None
        value = cell.get("value") or ""
        name = next(
            name
            for name in ("service-a", "service-b", "orders.created")
            if f"<b>{name}</b>" in value
        )
        positions[name] = (
            int(float(geometry.get("x", "0"))),
            int(float(geometry.get("y", "0"))),
        )

    assert render_graph_drawio(endpoints_by_service, edges) == document
    assert len(set(positions.values())) == 3


def test_write_graph_d2_writes_raw_source_when_extension_is_d2(tmp_path) -> None:
    out_file = tmp_path / "graph.d2"

    write_graph_d2(out_file, "a -> b\n")

    assert out_file.read_text(encoding="utf-8") == "a -> b\n"


def test_write_graph_d2_renders_via_d2_cli(monkeypatch, tmp_path) -> None:
    out_file = tmp_path / "graph.svg"
    calls = {}

    def fake_run(*args, **kwargs):
        calls["cmd"] = args[0]
        calls["input"] = kwargs["input"]
        out_file.write_text("<svg />", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(render_module.subprocess, "run", fake_run)

    write_graph_d2(out_file, "a -> b\n", layout="elk")

    assert calls["cmd"] == ["d2", "--layout", "elk", "-", str(out_file)]
    assert calls["input"] == "a -> b\n"
    assert out_file.read_text(encoding="utf-8") == "<svg />"
