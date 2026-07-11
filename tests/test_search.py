import hashlib
import re
from pathlib import Path

import numpy as np

from cccf.embedder import finding_to_text
from cccf.models import Finding
from cccf.search import get_context, search_findings, summary
from cccf.store import Store


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
        hits = search_findings(store, embedder, "injection sql")

    assert hits[0].finding.id == SQL_FINDING.id
    assert hits[0].score > hits[1].score


def test_search_findings_filters_by_severity_and_path_glob(tmp_path: Path) -> None:
    embedder = BagOfWordsFakeEmbedder()

    with Store(tmp_path) as store:
        seed_store(store, embedder)

        error_only = search_findings(store, embedder, "sécurité", severity="ERROR")
        shell_only = search_findings(store, embedder, "sécurité", path_glob="app/shell*")

    assert [hit.finding.id for hit in error_only] == [SQL_FINDING.id]
    assert [hit.finding.id for hit in shell_only] == [SHELL_FINDING.id]


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
