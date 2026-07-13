"""BACKLOG-10 K12 — cccf graph --workspace de bout en bout : trois vrais
microservices Maven indexés séparément, avec un cycle d'appels REST
A -> B -> C -> A, et un site sur ce cycle recouvert par un finding liveness
(hotspot). CA1 (cycle rapporté avec les sites des deux extrémités) et CA3
(hotspot = cycle + finding, classé par sévérité) de K12.
"""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_CYCLE_WORKSPACE = FIXTURES_DIR / "rest_cycle_workspace"

runner = CliRunner()


@pytest.fixture
def indexed_cycle_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "rest_cycle_workspace"
    shutil.copytree(REST_CYCLE_WORKSPACE, dest)
    for service in ("service-x", "service-y", "service-z"):
        monkeypatch.chdir(dest / service)
        init_result = runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
        assert init_result.exit_code == 0
        index_result = runner.invoke(app, ["index"])
        assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_graph_workspace_reports_the_three_service_rest_cycle_with_sites(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-x")

    result = runner.invoke(
        app, ["graph", "--workspace", str(indexed_cycle_workspace), "--json"]
    )

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data["cycles"]) == 1
    cycle = data["cycles"][0]
    assert set(cycle["services"][:-1]) == {"service-x", "service-y", "service-z"}
    assert cycle["has_synchronous_rest"] is True
    assert len(cycle["edges"]) == 3
    sites = {(e["from_site"]["path"], e["from_site"]["start_line"]) for e in cycle["edges"]}
    assert ("app/YClient.java", 13) in sites


@pytest.mark.integration
def test_graph_workspace_reports_hotspot_where_finding_overlaps_a_cycle_site(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-x")

    result = runner.invoke(
        app, ["graph", "--workspace", str(indexed_cycle_workspace), "--json"]
    )

    data = json.loads(result.output)
    assert len(data["hotspots"]) >= 1
    hotspot = data["hotspots"][0]
    assert hotspot["service"] == "service-x"
    assert hotspot["site"]["path"] == "app/YClient.java"
    assert hotspot["finding_rule_id"] == "rules.cccf.liveness.java.new-resttemplate-no-timeout"
    assert hotspot["finding_severity"] == "WARNING"


@pytest.mark.integration
def test_graph_text_renders_cycle_and_hotspot(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-y")

    result = runner.invoke(app, ["graph", "--workspace", str(indexed_cycle_workspace)])

    assert result.exit_code == 0
    assert "Cycles inter-services" in result.output
    assert "Hotspots" in result.output
    assert "service-x" in result.output and "service-y" in result.output


def test_graph_without_workspace_still_reports_the_no_workspace_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cccf.store import Store

    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(app, ["graph", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["cycles"] == []
    assert data["hotspots"] == []
    assert "--workspace" in data["note"]
