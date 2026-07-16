"""E2E `cccr export microservices --workspace --json` sur un workspace multi-services indexé
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
def test_export_workspace_reports_the_three_service_rest_topology(
    indexed_cycle_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(indexed_cycle_workspace / "service-x")

    result = runner.invoke(
        app, ["export", "microservices", "--workspace", str(indexed_cycle_workspace), "--json"]
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
def test_export_without_workspace_still_reports_the_no_workspace_note(
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
