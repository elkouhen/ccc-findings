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
