import xml.etree.ElementTree as ET

from ccc_radar.graph import build_graph, find_cycles
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.render import render_graph_drawio


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

    document = render_graph_drawio(list(endpoints_by_service), edges, cycles)

    root = ET.fromstring(document)  # raises if not well-formed
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert values == {"service-a", "service-b", "service-c"}


def test_render_graph_drawio_includes_an_edge_per_graph_edge_with_topic_label() -> None:
    endpoints_by_service = _three_service_cycle_fixture()
    edges = build_graph(endpoints_by_service)

    document = render_graph_drawio(list(endpoints_by_service), edges, [])

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

    document = render_graph_drawio(list(endpoints_by_service), edges, cycles)

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

    document = render_graph_drawio(list(endpoints_by_service), edges, [])

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert "strokeColor=#d32f2f" not in edge_cells[0].get("style", "")


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

    document = render_graph_drawio(list(endpoints_by_service), edges, [])

    root = ET.fromstring(document)
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 1
    assert "dashed=1" in edge_cells[0].get("style", "")


def test_render_graph_drawio_includes_services_without_any_edge() -> None:
    endpoints_by_service = {"service-a": [], "service-b": []}

    document = render_graph_drawio(list(endpoints_by_service), [], [])

    root = ET.fromstring(document)
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert values == {"service-a", "service-b"}


def test_render_graph_drawio_handles_no_services_or_edges() -> None:
    document = render_graph_drawio([], [], [])

    root = ET.fromstring(document)  # still well-formed
    assert [cell for cell in root.iter("mxCell") if cell.get("vertex") == "1"] == []
    assert [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"] == []


def test_render_graph_drawio_escapes_xml_special_characters_in_service_name() -> None:
    endpoints_by_service = {'weird<&"name': []}

    document = render_graph_drawio(list(endpoints_by_service), [], [])

    root = ET.fromstring(document)  # would raise on unescaped `<`/`&`
    values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    assert values == {'weird<&"name'}
