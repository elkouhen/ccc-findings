import asyncio
import shutil
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from typer.testing import CliRunner

from cccf.cli import app
from cccf.mcp_server import findings_summary, mcp, reindex_findings, search_findings

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
    result = search_findings("injection sql")

    assert len(result) == 4
    assert {"id", "rule_id", "severity", "path", "score"} <= set(result[0].keys())


@pytest.mark.integration
def test_findings_summary_tool_returns_expected_json(indexed_repo: Path) -> None:
    result = findings_summary()

    assert result["by_severity"] == {"ERROR": 2, "WARNING": 2}


@pytest.mark.integration
def test_reindex_findings_tool_returns_report(indexed_repo: Path) -> None:
    result = reindex_findings()

    assert result.scanned == 0
    assert result.findings_added == 0


def test_search_findings_tool_on_unindexed_repo_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(RuntimeError, match="Index absent"):
        search_findings("injection sql")


def test_search_findings_tool_on_unindexed_repo_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Going through the actual MCP dispatch (not the bare Python function): a
    failing tool must raise ToolError, which the protocol layer turns into
    `isError: true` — not a `{"error": ...}` payload disguised as success."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolError, match="Index absent"):
        asyncio.run(mcp.call_tool("search_findings", {"query": "injection sql"}))

    # le serveur reste utilisable ensuite, sans crash
    with pytest.raises(ToolError):
        asyncio.run(mcp.call_tool("findings_summary", {}))


def test_mcp_help_documents_client_registration_block() -> None:
    result = runner.invoke(app, ["mcp", "--help"])

    assert result.exit_code == 0
    assert '{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}' in result.output


@pytest.mark.integration
def test_search_tool_is_exposed_under_the_same_name_as_ccc(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cccf's code-search MCP tool must be named `search`, like ccc's own
    tool — not `search_code_with_findings` — so both take the same name."""
    monkeypatch.chdir(tmp_path)

    result = asyncio.run(mcp.call_tool("search", {"query": "auth"}))

    assert result[1]["results"]
