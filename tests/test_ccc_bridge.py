import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.ccc_bridge import (
    CccUnavailable,
    CodeHit,
    annotate_with_findings,
    search_code,
)
from ccc_radar.cli import app
from ccc_radar.models import Finding
from ccc_radar.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"

runner = CliRunner()


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


def test_annotate_with_findings_attaches_all_findings_from_returned_file(tmp_path: Path) -> None:
    overlapping_finding = make_finding("app/db.py", 20, 22, suffix="-overlap")
    non_overlapping_finding = make_finding("app/other.py", 20, 22, suffix="-other")

    with Store(tmp_path) as store:
        store.replace_findings_for_files(
            ["app/db.py", "app/other.py"], [overlapping_finding, non_overlapping_finding]
        )

        hits = [
            CodeHit(
                path="app/db.py", start_line=10, end_line=20,
                language="python", score=0.9, content="c1",
            ),
            CodeHit(
                path="app/db.py", start_line=10, end_line=19,
                language="python", score=0.8, content="c2",
            ),
        ]
        annotated = annotate_with_findings(hits, store)

    # Les deux extraits représentent le même fichier/classe : tous les
    # findings du fichier sont donc ajoutés, indépendamment des lignes du
    # chunk retourné par ccc.
    assert [f["id"] for f in annotated[0]["findings"]] == [overlapping_finding.id]
    assert annotated[0]["max_severity"] == "ERROR"
    assert [f["id"] for f in annotated[1]["findings"]] == [overlapping_finding.id]
    assert annotated[1]["max_severity"] == "ERROR"


def test_annotate_with_findings_only_loads_findings_for_hit_paths() -> None:
    overlapping_finding = make_finding("app/db.py", 20, 22, suffix="-overlap")

    class PathScopedStore:
        def __init__(self) -> None:
            self.requested_paths: list[str] | None = None

        def all_findings_for_paths(self, paths: list[str]) -> list[Finding]:
            self.requested_paths = paths
            return [overlapping_finding]

        def all_findings(self) -> list[Finding]:
            raise AssertionError("annotate_with_findings should not load the whole store")

    store = PathScopedStore()
    hits = [
        CodeHit(
            path="app/db.py",
            start_line=10,
            end_line=20,
            language="python",
            score=0.9,
            content="c1",
        )
    ]

    annotated = annotate_with_findings(hits, store)

    assert store.requested_paths == ["app/db.py"]
    assert [f["id"] for f in annotated[0]["findings"]] == [overlapping_finding.id]


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
    assert hits[0].language == "python"
    assert hits[0].score == pytest.approx(0.9)
    assert "cursor.execute" in hits[0].content

    assert len(annotated) == 1
    assert [f["id"] for f in annotated[0]["findings"]] == [finding.id]
    assert annotated[0]["max_severity"] == "ERROR"


def test_search_code_with_findings_tool_preserves_ccc_order_despite_findings(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings enrich the raw ccc result; they must never re-rank it."""
    monkeypatch.chdir(tmp_path)
    finding = make_finding("app/db.py", 6, 6)

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    from ccc_radar.mcp_server import search

    result = search("injection sql", limit=2)

    assert [hit["path"] for hit in result["results"]] == ["app/other.py", "app/db.py"]
    assert result["results"][1]["max_severity"] == "ERROR"


def test_search_code_passes_offset_lang_path_refresh_to_ccc(
    fake_ccc_args_recording_on_path: Path, tmp_path: Path
) -> None:
    hits = search_code(
        tmp_path, "injection sql", limit=3, offset=2, lang="python", path="app/*", refresh=True
    )

    assert len(hits) == 1
    args = hits[0].content.removeprefix("ARGS:")
    assert args.split() == [
        "search", "injection", "sql", "--limit", "3", "--offset", "2",
        "--lang", "python", "--path", "app/*", "--refresh",
    ]


def test_search_code_omits_default_optional_flags(
    fake_ccc_args_recording_on_path: Path, tmp_path: Path
) -> None:
    hits = search_code(tmp_path, "auth", limit=5)

    args = hits[0].content.removeprefix("ARGS:")
    assert args.split() == ["search", "auth", "--limit", "5"]


def test_search_code_without_ccc_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    (tmp_path / "empty").mkdir()

    with pytest.raises(CccUnavailable):
        search_code(tmp_path, "injection sql")


def test_search_code_without_ccc_index_raises_unavailable(
    fake_ccc_on_path: Path, tmp_path: Path
) -> None:
    (tmp_path / ".cocoindex_code" / "target_sqlite.db").unlink()

    with pytest.raises(CccUnavailable, match="index code ccc absent"):
        search_code(tmp_path, "injection sql")


def test_search_code_timeout_raises_unavailable(
    fake_ccc_hanging_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_CCC_SEARCH_TIMEOUT_S", "1")

    with pytest.raises(CccUnavailable, match="ccc search a expiré après 1s"):
        search_code(tmp_path, "injection sql")


def test_mcp_tool_raises_when_ccc_returns_error(
    fake_ccc_error_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    index_path = dest / ".cocoindex_code" / "target_sqlite.db"
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text("")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    from ccc_radar.mcp_server import search

    with pytest.raises(RuntimeError, match="ccc a échoué.*ccc service failed"):
        search("injection sql")
