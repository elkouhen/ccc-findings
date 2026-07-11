import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"

runner = CliRunner()


@pytest.fixture
def repo_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    return dest


def test_init_without_semgrep_config_fails_with_exact_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init"])

    assert result.exit_code != 0
    assert (
        "Aucune config Semgrep détectée. Relancez avec --rules <chemin-ou-pack>."
        in result.output
    )


@pytest.mark.integration
def test_init_with_rules_then_index_reports_correctly(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

    init_result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    assert init_result.exit_code == 0
    assert (repo_copy / ".cccf" / "config.yml").is_file()

    index_result = runner.invoke(app, ["index"])

    assert index_result.exit_code == 0
    assert "scanned=" in index_result.output
    assert "+findings=2" in index_result.output
    assert "-findings=0" in index_result.output


@pytest.mark.integration
def test_index_twice_second_run_scans_nothing(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    second_result = runner.invoke(app, ["index"])

    assert second_result.exit_code == 0
    assert "scanned=0" in second_result.output


def test_search_without_index_fails_with_exact_message_and_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "injection sql"])

    assert result.exit_code == 2
    assert "Index absent. Lancez d'abord: cccf index" in result.output


@pytest.mark.integration
def test_search_json_output_matches_contract(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["search", "injection sql", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert len(hits) == 2
    expected_keys = {
        "id",
        "rule_id",
        "severity",
        "message",
        "path",
        "start_line",
        "end_line",
        "score",
        "fix",
        "cwe",
        "owasp",
    }
    assert expected_keys <= set(hits[0].keys())


@pytest.mark.integration
def test_search_context_includes_offending_source_line(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(
        app, ["search", "injection sql", "--path", "app/db.py", "--context", "--json"]
    )

    hits = json.loads(result.output)
    assert "cursor.execute" in hits[0]["context"]


@pytest.mark.integration
def test_summary_json_has_expected_structure(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["summary", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["by_severity"] == {"ERROR": 1, "WARNING": 1}
