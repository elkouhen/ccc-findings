import os
import shutil
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.ccc_bridge import CccUnavailable, CodeHit, annotate_with_findings, search_code
from cccf.cli import app
from cccf.models import Finding
from cccf.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"

runner = CliRunner()

FAKE_CCC_SCRIPT = """#!/bin/sh
cat <<'EOF'

--- Result 1 (score: 0.900) ---
File: app/db.py:6-6 [python]
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
EOF
"""


def make_finding(
    path: str, start_line: int, end_line: int, severity: str = "ERROR", suffix: str = ""
) -> Finding:
    return Finding(
        id=f"finding-{path}-{start_line}-{end_line}{suffix}",
        rule_id="custom.sql-fstring",
        severity=severity,
        message="Une requête SQL construite par f-string permet une injection SQL.",
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="cursor.execute(query)",
        fix=None,
        cwe=["CWE-89"],
        owasp=[],
    )


def test_annotate_with_findings_inclusive_overlap(tmp_path: Path) -> None:
    overlapping_finding = make_finding("app/db.py", 20, 22, suffix="-overlap")
    non_overlapping_finding = make_finding("app/other.py", 20, 22, suffix="-other")

    with Store(tmp_path) as store:
        store.replace_findings_for_files(
            ["app/db.py", "app/other.py"], [overlapping_finding, non_overlapping_finding]
        )

        hits = [
            CodeHit(path="app/db.py", start_line=10, end_line=20, score=0.9, content="c1"),
            CodeHit(path="app/db.py", start_line=10, end_line=19, score=0.8, content="c2"),
        ]
        annotated = annotate_with_findings(hits, store)

    # hit 10-20 chevauche le finding 20-22 (ligne 20 commune)
    assert [f["id"] for f in annotated[0]["findings"]] == [overlapping_finding.id]
    assert annotated[0]["max_severity"] == "ERROR"

    # hit 10-19 ne chevauche pas le finding 20-22
    assert annotated[1]["findings"] == []
    assert annotated[1]["max_severity"] is None


@pytest.fixture
def fake_ccc_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = tmp_path / "fake_bin"
    bin_dir.mkdir()
    script = bin_dir / "ccc"
    script.write_text(FAKE_CCC_SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '')}")
    return bin_dir


def test_search_code_with_fake_ccc_then_annotate(
    fake_ccc_on_path: Path, tmp_path: Path
) -> None:
    finding = make_finding("app/db.py", 6, 6)

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

        hits = search_code(tmp_path, "injection sql", limit=5)
        annotated = annotate_with_findings(hits, store)

    assert len(hits) == 1
    assert hits[0].path == "app/db.py"
    assert hits[0].start_line == 6
    assert hits[0].end_line == 6
    assert hits[0].score == pytest.approx(0.9)
    assert "cursor.execute" in hits[0].content

    assert len(annotated) == 1
    assert [f["id"] for f in annotated[0]["findings"]] == [finding.id]
    assert annotated[0]["max_severity"] == "ERROR"


def test_search_code_without_ccc_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()

    with pytest.raises(CccUnavailable):
        search_code(tmp_path, "injection sql")


@pytest.mark.integration
def test_mcp_tool_falls_back_when_ccc_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    # PATH sans le répertoire de `ccc`, mais conservant celui de `semgrep`
    # (déjà utilisé par l'indexation ci-dessus, donc pas nécessaire ensuite).
    ccc_dir = str(Path(shutil.which("ccc")).parent)
    restricted_path = os.pathsep.join(
        p for p in os.environ.get("PATH", "").split(os.pathsep) if p != ccc_dir
    )
    monkeypatch.setenv("PATH", restricted_path)

    from cccf.mcp_server import search_code_with_findings

    result = search_code_with_findings("injection sql")

    assert result["results"] == []
    assert result["warning"] == "ccc indisponible : recherche restreinte aux findings Semgrep"
    assert isinstance(result["findings_only_fallback"], list)
    assert len(result["findings_only_fallback"]) == 4
