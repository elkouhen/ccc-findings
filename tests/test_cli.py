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


def test_init_without_semgrep_config_falls_back_to_default_registry_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "p/security-audit" in result.output
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert "p/security-audit" in config_content


@pytest.mark.integration
def test_index_with_default_registry_pack_succeeds_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\n\n"
        "def find_user(conn: sqlite3.Connection, name: str):\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        "    return cursor.fetchall()\n"
    )

    init_result = runner.invoke(app, ["init"])
    assert init_result.exit_code == 0

    index_result = runner.invoke(app, ["index"])

    assert index_result.exit_code == 0
    assert "scanned=" in index_result.output


def test_init_with_explicit_rules_takes_priority_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert "rules/rules.yml" in config_content
    assert "p/security-audit" not in config_content


def test_init_detects_local_semgrep_config_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".semgrep.yml").write_text("rules: []\n")

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert ".semgrep.yml" in config_content
    assert "p/security-audit" not in config_content


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
    assert "+findings=4" in index_result.output
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


def test_findings_without_index_fails_with_exact_message_and_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["findings", "injection sql"])

    assert result.exit_code == 2
    assert "Index absent. Lancez d'abord: cccf index" in result.output


@pytest.mark.integration
def test_findings_json_output_matches_contract(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["findings", "injection sql", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert len(hits) == 4
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
def test_findings_context_includes_offending_source_line(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(
        app, ["findings", "injection sql", "--path", "app/db.py", "--context", "--json"]
    )

    hits = json.loads(result.output)
    assert "cursor.execute" in hits[0]["context"]


def test_search_renders_ccc_format_with_findings_blocks(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cccf search` répond « de la même manière » que ccc : même format de
    résultats, enrichi d'un bloc findings sous les résultats concernés, le
    finding ERROR faisant remonter app/db.py devant app/other.py."""
    monkeypatch.chdir(tmp_path)
    from cccf.models import Finding
    from cccf.store import Store

    finding = Finding(
        id="cli-search-finding",
        rule_id="custom.sql-fstring",
        severity="ERROR",
        message="Une requête SQL construite par f-string permet une injection SQL.",
        path="app/db.py",
        start_line=6,
        end_line=6,
        snippet="cursor.execute(query)",
        fix=None,
        cwe=["CWE-89"],
        owasp=[],
    )
    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    result = runner.invoke(app, ["search", "user authentication flow"])

    assert result.exit_code == 0
    # score affiché = score sémantique brut de ccc (0.850) ; le boost ERROR
    # n'affecte que l'ordre, pas la valeur rapportée
    assert "--- Result 1 (score: 0.850) ---" in result.output
    assert "File: app/db.py:6-6 [python]" in result.output
    assert "findings (max: ERROR)" in result.output
    assert "custom.sql-fstring" in result.output
    # le résultat sans finding est rendu sans bloc findings, après le boosté
    assert result.output.index("app/db.py:6-6") < result.output.index("app/other.py:1-1")


def test_search_json_returns_stable_code_search_result_schema(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    from cccf.store import Store

    with Store(tmp_path):
        pass  # index findings vide mais présent

    result = runner.invoke(app, ["search", "auth", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data.keys()) == {"results", "findings_only_fallback", "warning"}
    assert len(data["results"]) == 2
    assert {"path", "start_line", "end_line", "language", "score", "content",
            "findings", "max_severity"} <= set(data["results"][0].keys())


@pytest.mark.integration
def test_search_prefers_experimental_indexed_code_when_available(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    index_result = runner.invoke(app, ["index", "--engine", "cocoindex"])
    assert index_result.exit_code == 0

    result = runner.invoke(app, ["search", "injection sql", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["results"]
    assert data["warning"] is None
    assert "path" in data["results"][0]


def test_search_without_findings_index_warns_but_shows_code_results(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 0
    assert "index findings absent" in result.output
    assert "--- Result 1" in result.output


def test_search_without_ccc_nor_index_fails_with_message_and_code_2(
    no_ccc_on_path: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 2
    assert "Index absent. Lancez d'abord: cccf index" in result.output


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
    assert data["by_severity"] == {"ERROR": 2, "WARNING": 2}
