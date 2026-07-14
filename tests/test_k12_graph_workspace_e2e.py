"""E2E `cccr graph --workspace` sur un workspace multi-services indexé
séparément : le CLI doit remonter la topologie inter-services fédérée."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_CYCLE_WORKSPACE = FIXTURES_DIR / "rest_cycle_workspace"

runner = CliRunner()


@pytest.fixture
def indexed_cycle_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "rest_cycle_workspace"
    shutil.copytree(REST_CYCLE_WORKSPACE, dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    for service in ("service-x", "service-y", "service-z"):
        monkeypatch.chdir(dest / service)
        init_result = runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
        assert init_result.exit_code == 0
        index_result = runner.invoke(app, ["index"])
        assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_graph_workspace_reports_the_three_service_rest_topology(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-x")

    result = runner.invoke(
        app, ["graph", "--workspace", str(indexed_cycle_workspace), "--json"]
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data["services"]) == {"service-x", "service-y", "service-z"}
    assert len(data["edges"]) == 3
    assert {edge["label"] for edge in data["edges"]} == {
        "GET /x-status",
        "GET /y-status",
        "GET /z-status",
    }
    sites = {(e["from_site"]["path"], e["from_site"]["start_line"]) for e in data["edges"]}
    assert ("app/YClient.java", 13) in sites


@pytest.mark.integration
def test_graph_text_renders_inter_service_topology(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-y")

    result = runner.invoke(app, ["graph", "--workspace", str(indexed_cycle_workspace)])

    assert result.exit_code == 0
    assert "Arêtes du graphe" in result.output
    assert "service-x" in result.output and "service-y" in result.output
    assert "GET /x-status" in result.output


def test_graph_without_workspace_still_reports_the_no_workspace_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ccc_radar.store import Store

    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(app, ["graph", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["services"] == []
    assert data["edges"] == []
    assert "--workspace" in data["note"]


@pytest.mark.integration
def test_graph_drawio_writes_a_valid_mxgraph_file(
    indexed_cycle_workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xml.etree.ElementTree as ET

    monkeypatch.chdir(indexed_cycle_workspace / "service-x")
    out_file = tmp_path / "graph.drawio"

    result = runner.invoke(
        app, ["graph", "--workspace", str(indexed_cycle_workspace), "--drawio", str(out_file)]
    )

    assert result.exit_code == 0, result.output
    assert str(out_file) in result.output
    assert out_file.is_file()

    root = ET.fromstring(out_file.read_text(encoding="utf-8"))
    node_values = {cell.get("value") for cell in root.iter("mxCell") if cell.get("vertex") == "1"}
    # Les nœuds Drawio incluent désormais une table HTML qui récapitule les
    # ressources exposées. Le contrat utile est la présence de chaque service,
    # pas l'ancien libellé HTML minimal.
    assert {name for name in ("service-x", "service-y", "service-z") if any(
        f"<b>{name}</b>" in (value or "") for value in node_values
    )} == {"service-x", "service-y", "service-z"}
    edge_cells = [cell for cell in root.iter("mxCell") if cell.get("edge") == "1"]
    assert len(edge_cells) == 3
    assert all("strokeColor=#d32f2f" not in cell.get("style", "") for cell in edge_cells)


def test_graph_drawio_without_cross_module_data_writes_an_empty_file_and_the_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import xml.etree.ElementTree as ET

    from ccc_radar.store import Store

    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass
    out_file = tmp_path / "graph.drawio"

    result = runner.invoke(app, ["graph", "--drawio", str(out_file)])

    assert result.exit_code == 0
    assert "--workspace" in result.output
    assert out_file.is_file()
    root = ET.fromstring(out_file.read_text(encoding="utf-8"))
    assert [cell for cell in root.iter("mxCell") if cell.get("vertex") == "1"] == []
