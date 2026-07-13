import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.ccc_bridge import (
    CccUnavailable,
    CodeHit,
    CodeHitWithFindings,
    annotate_with_findings,
    overfetch_limit,
    rank_by_severity,
    search_code,
)
from cccf.cli import app
from cccf.models import Finding
from cccf.store import Store

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


def test_annotate_with_findings_inclusive_overlap(tmp_path: Path) -> None:
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

    # hit 10-20 chevauche le finding 20-22 (ligne 20 commune)
    assert [f["id"] for f in annotated[0]["findings"]] == [overlapping_finding.id]
    assert annotated[0]["max_severity"] == "ERROR"

    # hit 10-19 ne chevauche pas le finding 20-22
    assert annotated[1]["findings"] == []
    assert annotated[1]["max_severity"] is None


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


def make_hit(
    path: str, score: float, max_severity: str | None = None
) -> CodeHitWithFindings:
    return CodeHitWithFindings(
        path=path,
        start_line=1,
        end_line=1,
        language="python",
        score=score,
        content="c",
        findings=[],
        max_severity=max_severity,
    )


def test_overfetch_limit_multiplies_then_caps() -> None:
    assert overfetch_limit(5) == 15
    assert overfetch_limit(30) == 50  # capped, 30 * 3 = 90


def test_rank_by_severity_promotes_error_over_higher_score_no_finding() -> None:
    # error.py est légèrement moins pertinent sémantiquement (0.80 vs 0.82)
    # mais porte un finding ERROR : le boost (+0.15) doit le faire remonter.
    hits = [
        make_hit("clean.py", score=0.82, max_severity=None),
        make_hit("error.py", score=0.80, max_severity="ERROR"),
    ]

    ranked = rank_by_severity(hits, limit=5)

    assert [h["path"] for h in ranked] == ["error.py", "clean.py"]


def test_rank_by_severity_does_not_override_a_clearly_more_relevant_result() -> None:
    # un finding lointain ne doit pas faire remonter un résultat très peu
    # pertinent devant un résultat nettement plus pertinent mais sans finding.
    hits = [
        make_hit("clean.py", score=0.90, max_severity=None),
        make_hit("error.py", score=0.40, max_severity="ERROR"),
    ]

    ranked = rank_by_severity(hits, limit=5)

    assert [h["path"] for h in ranked] == ["clean.py", "error.py"]


def test_rank_by_severity_keeps_ccc_order_on_ties() -> None:
    hits = [
        make_hit("first.py", score=0.5, max_severity=None),
        make_hit("second.py", score=0.5, max_severity=None),
    ]

    ranked = rank_by_severity(hits, limit=5)

    assert [h["path"] for h in ranked] == ["first.py", "second.py"]


def test_rank_by_severity_truncates_to_limit() -> None:
    hits = [make_hit(f"f{i}.py", score=1.0 - i * 0.01) for i in range(10)]

    ranked = rank_by_severity(hits, limit=3)

    assert len(ranked) == 3
    assert [h["path"] for h in ranked] == ["f0.py", "f1.py", "f2.py"]


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


def test_search_code_with_findings_tool_promotes_finding_despite_lower_score(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end through the actual MCP tool: ccc ranks app/other.py (0.90,
    no finding) above app/db.py (0.85, ERROR finding) — the ERROR boost
    (+0.15) should flip that order in the tool's final result."""
    monkeypatch.chdir(tmp_path)
    finding = make_finding("app/db.py", 6, 6)

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    from cccf.mcp_server import search

    result = search("injection sql", limit=2)

    assert [hit["path"] for hit in result["results"]] == ["app/db.py", "app/other.py"]
    assert result["results"][0]["max_severity"] == "ERROR"


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


def test_mcp_tool_raises_when_ccc_returns_error(
    fake_ccc_error_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    from cccf.mcp_server import search

    with pytest.raises(RuntimeError, match="ccc a échoué.*ccc service failed"):
        search("injection sql")
