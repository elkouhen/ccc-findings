import hashlib
import re
from pathlib import Path

import numpy as np
import pytest

from ccc_radar.embedder import finding_to_text
from ccc_radar.models import Finding
from ccc_radar.render import render_search_json, render_search_text
from ccc_radar.search import SearchError, SearchHit, get_context, search_findings, summary
from ccc_radar.store import Store


class BagOfWordsFakeEmbedder:
    """Embedder déterministe par sac-de-mots (feature hashing stable), sans ML."""

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _vectorize(self, text: str) -> np.ndarray:
        vector = np.zeros(self.dim, dtype=np.float32)
        for word in re.findall(r"\w+", text.lower()):
            bucket = int(hashlib.md5(word.encode()).hexdigest(), 16) % self.dim
            vector[bucket] += 1.0
        norm = np.linalg.norm(vector)
        return vector / norm if norm > 0 else vector

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        return np.array([self._vectorize(t) for t in texts], dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self._vectorize(text)


SQL_FINDING = Finding(
    id="sql-finding-id",
    rule_id="custom.sql-fstring",
    severity="ERROR",
    message="Une requête SQL construite par f-string permet une injection SQL.",
    path="app/db.py",
    start_line=6,
    end_line=6,
    snippet='cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
    fix=None,
    cwe=["CWE-89"],
    owasp=[],
)

SHELL_FINDING = Finding(
    id="shell-finding-id",
    rule_id="custom.subprocess-shell-true",
    severity="WARNING",
    message="L'appel à subprocess.run avec shell=True peut permettre une injection de commande.",
    path="app/shell.py",
    start_line=6,
    end_line=6,
    snippet='subprocess.run(cmd, shell=True, capture_output=True, text=True)',
    fix=None,
    cwe=["CWE-78"],
    owasp=[],
)


def seed_store(store: Store, embedder: BagOfWordsFakeEmbedder) -> None:
    store.replace_findings_for_files(["app/db.py"], [SQL_FINDING])
    store.replace_findings_for_files(["app/shell.py"], [SHELL_FINDING])
    for finding in (SQL_FINDING, SHELL_FINDING):
        vector = embedder.embed_texts([finding_to_text(finding)])[0]
        store.set_embedding(finding.id, vector)


def test_search_findings_ranks_matching_finding_first(tmp_path: Path) -> None:
    embedder = BagOfWordsFakeEmbedder()

    with Store(tmp_path) as store:
        seed_store(store, embedder)
        hits = search_findings(store, embedder, "injection")

    assert hits[0].finding.id == SQL_FINDING.id
    assert [hit.finding.id for hit in hits] == [SQL_FINDING.id, SHELL_FINDING.id]


def test_search_findings_filters_by_severity_and_path_glob(tmp_path: Path) -> None:
    embedder = BagOfWordsFakeEmbedder()

    with Store(tmp_path) as store:
        seed_store(store, embedder)

        error_only = search_findings(store, embedder, "injection", severity="ERROR")
        shell_only = search_findings(store, embedder, "injection", path_glob="app/shell*")

    assert [hit.finding.id for hit in error_only] == [SQL_FINDING.id]
    assert [hit.finding.id for hit in shell_only] == [SHELL_FINDING.id]


def test_search_findings_matches_exact_rule_id_and_cwe(tmp_path: Path) -> None:
    embedder = BagOfWordsFakeEmbedder()

    with Store(tmp_path) as store:
        seed_store(store, embedder)

        by_rule = search_findings(store, embedder, "custom.subprocess-shell-true")
        by_cwe = search_findings(store, embedder, "CWE-89")

    assert by_rule[0].finding.id == SHELL_FINDING.id
    assert by_cwe[0].finding.id == SQL_FINDING.id


def test_search_findings_can_fall_back_to_keyword_only_when_vectors_are_absent(
    tmp_path: Path,
) -> None:
    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [SQL_FINDING])

        hits = search_findings(store, BagOfWordsFakeEmbedder(), "custom.sql-fstring")

    assert [hit.finding.id for hit in hits] == [SQL_FINDING.id]


def test_summary_has_exact_counts(tmp_path: Path) -> None:
    embedder = BagOfWordsFakeEmbedder()

    with Store(tmp_path) as store:
        seed_store(store, embedder)
        result = summary(store)

    assert result.by_severity == {"ERROR": 1, "WARNING": 1}
    assert dict(result.top_rules) == {
        "custom.sql-fstring": 1,
        "custom.subprocess-shell-true": 1,
    }
    assert result.by_top_level_dir == {"app": 2}


def test_get_context_line_numbers_and_clamping(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    source_lines = [f"line {i}" for i in range(1, 11)]
    (tmp_path / "app" / "db.py").write_text("\n".join(source_lines) + "\n")

    finding = Finding(
        id="x",
        rule_id="r",
        severity="ERROR",
        message="m",
        path="app/db.py",
        start_line=2,
        end_line=9,
        snippet="line 2\n...\nline 9",
        fix=None,
        cwe=[],
        owasp=[],
    )

    context = get_context(tmp_path, finding, before=5, after=5)
    context_lines = context.splitlines()

    # bornes clampées : ligne 1 (pas -3) à ligne 10 (fin de fichier, pas 14)
    assert context_lines[0] == "    1| line 1"
    assert context_lines[-1] == "   10| line 10"
    assert len(context_lines) == 10


def test_get_context_narrow_window(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    source_lines = [f"line {i}" for i in range(1, 21)]
    (tmp_path / "app" / "db.py").write_text("\n".join(source_lines) + "\n")

    finding = Finding(
        id="x",
        rule_id="r",
        severity="ERROR",
        message="m",
        path="app/db.py",
        start_line=10,
        end_line=10,
        snippet="line 10",
        fix=None,
        cwe=[],
        owasp=[],
    )

    context = get_context(tmp_path, finding, before=1, after=1)
    context_lines = context.splitlines()

    assert context_lines == ["    9| line 9", "   10| line 10", "   11| line 11"]


def test_search_findings_does_not_depend_on_embedding_dimensions(tmp_path: Path) -> None:
    indexed_embedder = BagOfWordsFakeEmbedder(dim=8)
    query_embedder = BagOfWordsFakeEmbedder(dim=16)

    with Store(tmp_path) as store:
        seed_store(store, indexed_embedder)

        hits = search_findings(store, query_embedder, "injection sql")

    assert [hit.finding.id for hit in hits] == [SQL_FINDING.id]


def test_search_findings_rejects_invalid_severity(tmp_path: Path) -> None:
    """BACKLOG-16 P4 : `--severity HIGH` (sévérité Semgrep brute, jamais
    stockée telle quelle — voir `scanner._normalize_severity`) doit lever
    une erreur métier propre plutôt qu'un `ValueError` non géré."""
    embedder = BagOfWordsFakeEmbedder(dim=8)
    with Store(tmp_path) as store:
        seed_store(store, embedder)

        with pytest.raises(SearchError, match="HIGH"):
            search_findings(store, embedder, "injection sql", severity="HIGH")


def test_search_findings_does_not_query_vector_index() -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.top_ks: list[int] = []

        def all_findings(
            self,
            severity_at_least: str | None = None,
            rule_id: str | None = None,
            path_glob: str | None = None,
        ) -> list[Finding]:
            return [SQL_FINDING]

    store = RecordingStore()
    hits = search_findings(store, BagOfWordsFakeEmbedder(), "injection sql")

    assert [hit.finding.id for hit in hits] == [SQL_FINDING.id]
    assert store.top_ks == []


def test_render_search_json_degrades_when_context_file_is_missing(tmp_path: Path) -> None:
    hit = SearchHit(finding=SQL_FINDING, score=0.9)

    result = render_search_json([hit], tmp_path, include_context=True)

    assert result[0]["context"] is None
    assert "context_error" in result[0]
    assert result[0]["path"] == "app/db.py"


def test_render_search_text_degrades_when_context_file_is_missing(tmp_path: Path) -> None:
    hit = SearchHit(finding=SQL_FINDING, score=0.9)

    result = render_search_text([hit], tmp_path, include_context=True)

    assert "contexte indisponible" in result
    assert "custom.sql-fstring" in result
