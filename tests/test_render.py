import subprocess
import xml.etree.ElementTree as ET

import ccc_radar.render as render_module
from ccc_radar.graph import build_graph, find_cycles
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


def _three_service_cycle_fixture() -> dict[str, list[MessageEndpoint]]:
    return {
        "service-a": [
            make_endpoint("serve", "GET /a-status", "a/Controller.java", 10, 10),
            make_endpoint("call", "GET /b-status", "a/Client.java", 5, 5),
        ],
        "service-b": [
            make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10),
            make_endpoint("call", "GET /c-status", "b/Client.java", 5, 5),
        ],
        "service-c": [
            make_endpoint("serve", "GET /c-status", "c/Controller.java", 10, 10),
            make_endpoint("call", "GET /a-status", "c/Client.java", 5, 5),
        ],
    }


def test_render_graph_drawio_produces_well_formed_xml_with_a_node_per_service() -> None:
    endpoints_by_service = _three_service_cycle_fixture()
    edges = build_graph(endpoints_by_service)
    cycles = find_cycles(edges)

    document = render_graph_drawio(endpoints_by_service, edges, cycles)

    root = ET.fromstring(document)  # raises if not well-formed
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert len(values) == 3
    assert values == {"<b>service-a</b>", "<b>service-b</b>", "<b>service-c</b>"}


def test_render_graph_drawio_includes_an_edge_per_graph_edge_with_topic_label() -> None:
    endpoints_by_service = _three_service_cycle_fixture()
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 3
    assert {cell.get("value") for cell in edge_cells} == {
        "GET /a-status",
        "GET /b-status",
        "GET /c-status",
    }


def test_render_graph_drawio_marks_synchronous_cycle_edges_in_red() -> None:
    endpoints_by_service = _three_service_cycle_fixture()
    edges = build_graph(endpoints_by_service)
    cycles = find_cycles(edges)
    assert cycles and cycles[0].has_synchronous_rest

    document = render_graph_drawio(endpoints_by_service, edges, cycles)

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert all("strokeColor=#d32f2f" in cell.get("style", "") for cell in edge_cells)


def test_render_graph_drawio_does_not_highlight_edges_outside_any_cycle() -> None:
    endpoints_by_service = {
        "service-a": [make_endpoint("call", "GET /b-status", "a/Client.java", 5, 5)],
        "service-b": [make_endpoint("serve", "GET /b-status", "b/Controller.java", 10, 10)],
    }
    edges = build_graph(endpoints_by_service)
    assert find_cycles(edges) == []

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert "strokeColor=#d32f2f" not in edge_cells[0].get("style", "")


def test_render_graph_drawio_deduplicates_visual_edges_with_same_endpoints_and_label() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client1.java", 5, 5),
            make_endpoint("call", "GET /orders", "a/Client2.java", 15, 15),
        ],
        "service-b": [make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10)],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert edge_cells[0].get("value") == "GET /orders"


def test_render_graph_drawio_styles_kafka_edges_as_dashed() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka")
        ],
        "service-b": [
            make_endpoint("consume", "orders.created", "b/Listener.java", 10, 10, system="kafka")
        ],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    node_cells = [cell for cell in root.iter("mxCell") if cell.get("vertex") == "1"]
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(node_cells) == 3
    assert len(edge_cells) == 2
    assert any(
        cell.get("value") == "<b>orders.created</b>"
        and "fillColor=#ffe6cc" in cell.get("style", "")
        for cell in node_cells
    )
    assert any(cell.get("value") == "<b>service-a</b>" for cell in node_cells)
    assert any(cell.get("value") == "<b>service-b</b>" for cell in node_cells)
    assert "dashed=1" in edge_cells[0].get("style", "")
    assert {cell.get("value") for cell in edge_cells} == {"orders.created"}


def test_render_graph_d2_encodes_rest_and_kafka_edges() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client.java", 3, 3),
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka"),
        ],
        "service-b": [
            make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10),
            make_endpoint("consume", "orders.created", "b/Listener.java", 12, 12, system="kafka"),
        ],
    }
    edges = build_graph(endpoints_by_service)
    cycles = find_cycles(edges)

    rendered = render_graph_d2(endpoints_by_service, edges, cycles)

    assert 'direction: down' in rendered
    assert "label: |md" in rendered
    assert "  **service-a**" in rendered
    assert "  **service-b**" in rendered
    assert "  - `GET /orders`" in rendered
    assert "  |" in rendered
    assert "shape: rectangle" in rendered
    assert 'label: "orders.created"' in rendered
    assert 'svc_0 -> svc_1: "GET /orders" {' in rendered
    assert 'svc_0 -> topic_0: "orders.created" {' in rendered
    assert 'topic_0 -> svc_1: "orders.created" {' in rendered
    assert 'style.stroke-dash: 3' in rendered


def test_render_graph_d2_deduplicates_visual_edges_with_same_endpoints_and_label() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client1.java", 5, 5),
            make_endpoint("call", "GET /orders", "a/Client2.java", 15, 15),
        ],
        "service-b": [make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10)],
    }
    edges = build_graph(endpoints_by_service)

    rendered = render_graph_d2(endpoints_by_service, edges, [])

    assert rendered.count('svc_0 -> svc_1: "GET /orders" {') == 1


def test_render_graph_d2_lists_multiple_rest_resources_in_markdown_label() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("serve", "GET /orders", "a/Controller.java", 3, 3),
            make_endpoint("serve", "POST /orders", "a/Controller.java", 4, 4),
        ]
    }

    rendered = render_graph_d2(endpoints_by_service, [], [])

    assert "  **service-a**" in rendered
    assert "  - `GET /orders`" in rendered
    assert "  - `POST /orders`" in rendered


def test_render_graph_json_expands_kafka_edges_via_a_topic_node() -> None:
    endpoints_by_service = {
        "producer-svc": [
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka")
        ],
        "consumer-svc": [
            make_endpoint("consume", "orders.created", "b/Listener.java", 10, 10, system="kafka")
        ],
    }
    edges = build_graph(endpoints_by_service)

    rendered = render_graph_json(list(endpoints_by_service), edges, [], cycles=[], hotspots=[])

    assert rendered["nodes"] == [
        {"name": "producer-svc", "kind": "microservice"},
        {"name": "consumer-svc", "kind": "microservice"},
        {"name": "orders.created", "kind": "kafka_topic"},
    ]
    assert rendered["edges"] == [
        {
            "kind": "kafka_produce",
            "from_node": "producer-svc",
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
            "to_node": "consumer-svc",
            "to_kind": "microservice",
            "label": "orders.created",
            "from_site": None,
            "to_site": {
                "path": "b/Listener.java",
                "start_line": 10,
                "end_line": 10,
                "topic": "orders.created",
            },
        },
    ]


def test_render_graph_drawio_shows_only_service_names_in_service_nodes() -> None:
    endpoints_by_service = {
        "service-a": [
            make_endpoint("call", "GET /orders", "a/Client.java", 3, 3),
            make_endpoint("produce", "orders.created", "a/Producer.java", 5, 5, system="kafka"),
        ],
        "service-b": [
            make_endpoint("serve", "GET /orders", "b/Controller.java", 10, 10),
            make_endpoint("consume", "orders.created", "b/Listener.java", 12, 12, system="kafka"),
        ],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    node_values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert "<b>service-a</b>" in node_values
    assert "<b>service-b</b>" in node_values
    assert all("[rest/call]" not in value for value in node_values if value is not None)
    assert all("[rest/serve]" not in value for value in node_values if value is not None)
    assert all("[kafka/produce]" not in value for value in node_values if value is not None)
    assert all("[kafka/consume]" not in value for value in node_values if value is not None)


def test_render_graph_drawio_includes_services_without_any_edge() -> None:
    endpoints_by_service = {"service-a": [], "service-b": []}

    document = render_graph_drawio(endpoints_by_service, [], [])

    root = ET.fromstring(document)
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert len(values) == 2
    assert any("service-a" in value for value in values)
    assert any("service-b" in value for value in values)


def test_render_graph_drawio_handles_no_services_or_edges() -> None:
    document = render_graph_drawio({}, [], [])

    root = ET.fromstring(document)  # still well-formed
    assert [cell for cell in root.iter("mxCell") if cell.get("vertex") == "1"] == []
    assert [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"] == []


def test_render_graph_drawio_escapes_xml_special_characters_in_service_name() -> None:
    endpoints_by_service = {'weird<&"name': []}

    document = render_graph_drawio(endpoints_by_service, [], [])

    root = ET.fromstring(document)  # would raise on unescaped `<`/`&`
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert len(values) == 1
    assert 'weird<&"name' in next(iter(values))


def test_render_graph_drawio_positions_nodes_without_overlap() -> None:
    endpoints_by_service = {
        "service-a": [make_endpoint("call", "GET /b", "a/Client.java", 1, 1)],
        "service-b": [
            make_endpoint("serve", "GET /b", "b/Controller.java", 1, 1),
            make_endpoint("produce", "orders.created", "b/Producer.java", 2, 2, system="kafka"),
        ],
        "service-c": [
            make_endpoint("consume", "orders.created", "c/Consumer.java", 3, 3, system="kafka")
        ],
        "service-d": [],
    }
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(endpoints_by_service, edges, [])

    root = ET.fromstring(document)
    rectangles: list[tuple[int, int, int, int]] = []
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

    for i, (x1, y1, w1, h1) in enumerate(rectangles):
        for x2, y2, w2, h2 in rectangles[i + 1 :]:
            overlaps_horizontally = x1 < x2 + w2 and x2 < x1 + w1
            overlaps_vertically = y1 < y2 + h2 and y2 < y1 + h1
            assert not (overlaps_horizontally and overlaps_vertically)


def test_render_graph_drawio_uses_graphviz_positions_when_dot_is_available(
    monkeypatch,
) -> None:
    endpoints_by_service = {
        "service-a": [make_endpoint("produce", "orders.created", "a/Producer.java", 1, 1, system="kafka")],
        "service-b": [make_endpoint("consume", "orders.created", "b/Consumer.java", 1, 1, system="kafka")],
    }
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

    document = render_graph_drawio(endpoints_by_service, edges, [])

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


def test_render_graph_drawio_falls_back_when_dot_is_unavailable(monkeypatch) -> None:
    endpoints_by_service = {"service-a": [], "service-b": []}

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(render_module.subprocess, "run", raise_file_not_found)

    document = render_graph_drawio(endpoints_by_service, [], [])

    root = ET.fromstring(document)
    positions = []
    for cell in root.iter("mxCell"):
        if cell.get("vertex") != "1":
            continue
        geometry = cell.find("mxGeometry")
        assert geometry is not None
        positions.append(
            (
                int(float(geometry.get("x", "0"))),
                int(float(geometry.get("y", "0"))),
            )
        )

    assert sorted(positions) == [(24, 24), (292, 24)]


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


def test_render_graph_drawio_uses_neato_for_small_graphs(monkeypatch) -> None:
    endpoints_by_service = {"service-a": [], "service-b": []}
    called = {}

    def fake_run(*args, **kwargs):
        called["cmd"] = args[0]
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=(
                "graph 1 5 2\n"
                "node n0 1 1 3.056 0.833 service-a solid box black lightgrey\n"
                "node n1 4 1 3.056 0.833 service-b solid box black lightgrey\n"
                "stop\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(render_module.subprocess, "run", fake_run)

    render_graph_drawio(endpoints_by_service, [], [])

    assert called["cmd"] == ["neato", "-Tplain"]


def test_render_graph_drawio_uses_sfdp_for_larger_graphs(monkeypatch) -> None:
    endpoints_by_service = {f"service-{i}": [] for i in range(10)}
    edges = build_graph(endpoints_by_service)
    called = {}

    def fake_run(*args, **kwargs):
        called["cmd"] = args[0]
        node_lines = "\n".join(
            f"node n{i} {i + 1} 1 3.056 0.833 service-{i} solid box black lightgrey"
            for i in range(10)
        )
        topic_lines = "\n".join(
            f"node n{10 + i} {i + 1} 3 3.056 0.833 topic-{i} solid box black lightgrey"
            for i in range(3)
        )
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=f"graph 1 14 4\n{node_lines}\n{topic_lines}\nstop\n",
            stderr="",
        )

    monkeypatch.setattr(render_module.subprocess, "run", fake_run)

    render_module._graphviz_node_positions(
        list(endpoints_by_service),
        [f"topic-{i}" for i in range(3)],
        edges,
        node_width=220,
        node_height=60,
    )

    assert called["cmd"] == ["sfdp", "-Tplain"]


def test_render_graph_text_lists_services_and_edges_before_cycles() -> None:
    endpoints_by_service = _three_service_cycle_fixture()
    edges = build_graph(endpoints_by_service)
    cycles = find_cycles(edges)

    rendered = render_graph_text(
        render_graph_json(list(endpoints_by_service), edges, [], cycles=cycles, hotspots=[])
    )

    assert "Services (3)" in rendered
    assert "Aucun topic Kafka inter-service détecté." in rendered
    assert "Arêtes du graphe (3)" in rendered
    assert "[rest] service-a (a/Client.java:5) --GET /b-status--> service-b (b/Controller.java:10)" in rendered
    assert "Cycles inter-services (1)" in rendered
