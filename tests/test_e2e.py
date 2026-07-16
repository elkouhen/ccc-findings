import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"

runner = CliRunner()


@pytest.mark.integration
def test_full_init_index_search_fix_reindex_summary_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, repo)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")

    init_result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    assert init_result.exit_code == 0, f"cccr init a échoué : {init_result.output}"
    assert (repo / ".cccr" / "config.yml").is_file(), (
        "cccr init n'a pas créé .cccr/config.yml"
    )

    index_result = runner.invoke(app, ["index", "--semgrep"])
    assert index_result.exit_code == 0, f"cccr index a échoué : {index_result.output}"
    assert "+findings=4" in index_result.output, (
        f"cccr index n'a pas trouvé les 4 findings attendus : {index_result.output}"
    )

    search_result = runner.invoke(app, ["findings", "injection sql", "--json"])
    assert search_result.exit_code == 0, (
        f"cccr findings a échoué : {search_result.output}"
    )
    hits = json.loads(search_result.output)
    sql_hit = next((h for h in hits if h["path"] == "app/db.py"), None)
    assert sql_hit is not None, (
        f"le finding SQL de app/db.py est introuvable dans la recherche : {hits}"
    )
    assert sql_hit["severity"] == "ERROR"

    (repo / "app" / "db.py").write_text(
        "import sqlite3\n\n\n"
        "def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:\n"
        "    cursor = conn.cursor()\n"
        '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
        "    return cursor.fetchall()\n"
    )

    reindex_result = runner.invoke(app, ["index", "--semgrep"])
    assert reindex_result.exit_code == 0, (
        f"cccr index (après correction) a échoué : {reindex_result.output}"
    )
    assert "-findings=1" in reindex_result.output, (
        f"la correction de app/db.py n'a pas fait disparaître son finding : "
        f"{reindex_result.output}"
    )

    search_after_fix = runner.invoke(
        app, ["findings", "injection sql", "--path", "app/db.py", "--json"]
    )
    assert search_after_fix.exit_code == 0, (
        f"cccr findings (après correction) a échoué : {search_after_fix.output}"
    )
    hits_after_fix = json.loads(search_after_fix.output)
    assert hits_after_fix == [], (
        f"le finding SQL de app/db.py aurait dû disparaître après correction : "
        f"{hits_after_fix}"
    )

    summary_result = runner.invoke(app, ["summary", "--json"])
    assert summary_result.exit_code == 0, (
        f"cccr summary a échoué : {summary_result.output}"
    )
    summary_data = json.loads(summary_result.output)
    assert summary_data["by_severity"] == {"ERROR": 1, "WARNING": 2}, (
        f"le résumé après correction est incohérent : {summary_data}"
    )
