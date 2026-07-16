"""`cccr export microservices --json`/`cccr topics` sans `--workspace` sur un index parent Maven
multi-modules : attribution correcte des services/modules et topologie réelle."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_CYCLE_WORKSPACE = FIXTURES_DIR / "rest_cycle_workspace"
KAFKA_WORKSPACE = FIXTURES_DIR / "kafka_workspace"

runner = CliRunner()


@pytest.fixture
def single_index_cycle_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "rest_cycle_workspace"
    shutil.copytree(REST_CYCLE_WORKSPACE, dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest)
    init_result = runner.invoke(app, ["init", "--rules", "service-x/rules/java.yaml"])
    assert init_result.exit_code == 0
    index_result = runner.invoke(app, ["index", "--semgrep"])
    assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_export_without_workspace_reports_cross_module_topology_from_single_parent_index(
    single_index_cycle_parent: Path,
) -> None:
    result = runner.invoke(app, ["export", "microservices", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert set(data["services"]) == {"service-x", "service-y", "service-z"}
    assert len(data["edges"]) == 3
    assert {edge["label"] for edge in data["edges"]} == {
        "GET /x-status",
        "GET /y-status",
        "GET /z-status",
    }
    assert data["note"] == ""


@pytest.mark.integration
def test_export_without_workspace_still_reports_the_note_when_no_module_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ccc_radar.store import Store

    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(app, ["export", "microservices", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["services"] == []
    assert data["edges"] == []
    assert "--workspace" in data["note"]


@pytest.fixture
def single_index_kafka_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest)
    init_result = runner.invoke(app, ["init", "--rules", "order-service/rules/java.yaml"])
    assert init_result.exit_code == 0
    index_result = runner.invoke(app, ["index", "--semgrep"])
    assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_topics_show_attributes_producers_and_consumers_from_single_parent_index(
    single_index_kafka_parent: Path,
) -> None:
    result = runner.invoke(app, ["topics", "show", "orders.created", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["name"] == "orders.created"
    assert data["producers"] == ["order-service"]
    assert data["consumers"] == ["payment-service"]
