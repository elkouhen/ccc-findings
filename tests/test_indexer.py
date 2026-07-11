import shutil
from pathlib import Path

import pytest

from cccf.config import Config
from cccf.indexer import index_repo
from cccf.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"


@pytest.fixture
def repo_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    return dest


def make_config() -> Config:
    return Config(rules=["rules/rules.yml"])


@pytest.mark.integration
def test_first_index_run_finds_two_findings_and_scans_all_files(repo_copy: Path) -> None:
    config = make_config()
    total_files = sum(1 for p in repo_copy.rglob("*") if p.is_file())

    with Store(repo_copy) as store:
        report = index_repo(repo_copy, config, store)
        findings = store.all_findings()

    assert report.scanned == total_files
    assert len(findings) == 2


@pytest.mark.integration
def test_second_run_without_changes_scans_nothing(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store)
        report = index_repo(repo_copy, config, store)
        findings = store.all_findings()

    assert report.scanned == 0
    assert len(findings) == 2


@pytest.mark.integration
def test_fixing_db_py_removes_error_finding_keeps_warning(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store)

        (repo_copy / "app" / "db.py").write_text(
            "import sqlite3\n\n\n"
            "def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:\n"
            "    cursor = conn.cursor()\n"
            '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
            "    return cursor.fetchall()\n"
        )

        index_repo(repo_copy, config, store)
        findings = store.all_findings()

    assert [f.severity for f in findings] == ["WARNING"]
    assert findings[0].path == "app/shell.py"


@pytest.mark.integration
def test_deleting_shell_py_removes_its_finding(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store)

        (repo_copy / "app" / "shell.py").unlink()

        report = index_repo(repo_copy, config, store)
        findings = store.all_findings()

    assert report.deleted_files == 1
    assert [f.path for f in findings] == ["app/db.py"]
