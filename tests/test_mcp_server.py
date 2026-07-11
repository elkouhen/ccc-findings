import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app
from cccf.mcp_server import findings_summary, reindex_findings, search_findings

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"

runner = CliRunner()


@pytest.fixture
def indexed_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])
    return dest


@pytest.mark.integration
def test_search_findings_tool_returns_expected_json(indexed_repo: Path) -> None:
    result = json.loads(search_findings("injection sql"))

    assert len(result) == 2
    assert {"id", "rule_id", "severity", "path", "score"} <= set(result[0].keys())


@pytest.mark.integration
def test_findings_summary_tool_returns_expected_json(indexed_repo: Path) -> None:
    result = json.loads(findings_summary())

    assert result["by_severity"] == {"ERROR": 1, "WARNING": 1}


@pytest.mark.integration
def test_reindex_findings_tool_returns_report(indexed_repo: Path) -> None:
    result = json.loads(reindex_findings())

    assert result["scanned"] == 0
    assert "findings_added" in result


def test_search_findings_tool_on_unindexed_repo_returns_error_and_server_stays_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = json.loads(search_findings("injection sql"))
    assert "error" in result

    # le serveur (les fonctions tools) répond toujours ensuite, sans crash
    result_again = json.loads(findings_summary())
    assert "error" in result_again


def test_mcp_help_documents_client_registration_block() -> None:
    result = runner.invoke(app, ["mcp", "--help"])

    assert result.exit_code == 0
    assert '{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}' in result.output
