import subprocess
import xml.etree.ElementTree as ET

import ccc_radar.render as render_module
from ccc_radar.graph import build_graph
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.render import (
    render_graph_d2,
    render_graph_drawio,
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


def _fixture() -> dict[str, list[MessageEndpoint]]:
    return {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client.java", 3, 3),
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka"),
        ],
        "service-b": [
            make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10),
            make_endpoint("consume", "orders.created", "b/Listener.java", 12, 12, system="kafka"),
        ],
    }


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
    vertex_values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]

    assert vertex_values == {"<b>service-a</b>", "<b>service-b</b>", "<b>orders.created</b>"}
    assert len(edge_cells) == 3
    assert all("strokeColor=#d32f2f" not in cell.get("style", "") for cell in edge_cells)


def test_render_graph_drawio_deduplicates_duplicate_visual_edges() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client1.java", 5, 5),
            make_endpoint("call", "GET /orders", "a/Client2.java", 15, 15),
        ],
        "service-b": [make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10)],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges)

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert edge_cells[0].get("value") == "GET /orders"


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


def test_render_graph_drawio_uses_graphviz_positions_when_available(monkeypatch) -> None:
    endpoints_by_service = _fixture()
    edges = build_graph(endpoints_by_service)

    monkeypatch.setattr(
        render_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=(
                "graph 1 8 4\n"
                "node n0 2 3 3.056 0.833 service-a solid box black lightgrey\n"
                "node n1 6 3 3.056 0.833 service-b solid box black lightgrey\n"
                "node n2 4 1 3.056 0.833 orders.created solid box black lightgrey\n"
                "stop\n"
            ),
            stderr="",
        ),
    )

    document = render_graph_drawio(endpoints_by_service, edges)

    root = ET.fromstring(document)
    positions = {}
    for cell in root.iter("mxCell"):
        if cell.get("vertex") != "1":
            continue
        geometry = cell.find("mxGeometry")
        assert geometry is not None
        positions[cell.get("value")] = (
            int(float(geometry.get("x", "0"))),
            int(float(geometry.get("y", "0"))),
        )

    assert positions["<b>service-a</b>"] == (24, 24)
    assert positions["<b>service-b</b>"] == (312, 24)
    assert positions["<b>orders.created</b>"] == (168, 168)


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
