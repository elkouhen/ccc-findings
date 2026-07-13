"""BACKLOG-13 M3 — `cccf graph`/`cccf flow` sans `--workspace` détectent de
vrais cycles/hotspots (ou attribuent un site à son module) à partir d'un
**seul** index couvrant un répertoire parent multi-modules Maven — pas de
fédération multi-dépôts (A2/K7) nécessaire. Réutilise la fixture
`rest_cycle_workspace` (déjà utilisée par test_k12_graph_workspace_e2e.py
pour prouver l'équivalent en mode fédéré), mais indexée une seule fois à la
racine plutôt que service par service.
"""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_CYCLE_WORKSPACE = FIXTURES_DIR / "rest_cycle_workspace"
KAFKA_WORKSPACE = FIXTURES_DIR / "kafka_workspace"

runner = CliRunner()


@pytest.fixture
def single_index_cycle_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "rest_cycle_workspace"
    shutil.copytree(REST_CYCLE_WORKSPACE, dest)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest)
    init_result = runner.invoke(app, ["init", "--rules", "service-x/rules/java.yaml"])
    assert init_result.exit_code == 0
    index_result = runner.invoke(app, ["index"])
    assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_graph_without_workspace_reports_cross_module_cycle_from_a_single_parent_index(
    single_index_cycle_parent: Path,
) -> None:
    result = runner.invoke(app, ["graph", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert len(data["cycles"]) == 1
    cycle = data["cycles"][0]
    assert set(cycle["services"][:-1]) == {"service-x", "service-y", "service-z"}
    assert cycle["has_synchronous_rest"] is True
    assert len(data["hotspots"]) >= 1
    assert data["note"] == ""


@pytest.mark.integration
def test_graph_without_workspace_still_reports_the_note_when_no_module_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-régression : un repo sans layout Maven multi-modules continue de
    renvoyer la note explicite (cycles/hotspots vides), même après M1/M2/M3."""
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


@pytest.fixture
def single_index_kafka_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)
    monkeypatch.chdir(dest)
    init_result = runner.invoke(app, ["init", "--rules", "order-service/rules/java.yaml"])
    assert init_result.exit_code == 0
    index_result = runner.invoke(app, ["index"])
    assert index_result.exit_code == 0, index_result.output
    return dest


@pytest.mark.integration
def test_flow_without_workspace_attributes_sites_to_their_module_from_a_single_parent_index(
    single_index_kafka_parent: Path,
) -> None:
    result = runner.invoke(app, ["flow", "orders.created", "--json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["resolved_topic"] == "orders.created"
    sites_by_module = {site["service"]: site for site in data["sites"]}
    assert sites_by_module["order-service"]["role"] == "produce"
    assert sites_by_module["payment-service"]["role"] == "consume"
