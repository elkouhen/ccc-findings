import sqlite3
from pathlib import Path

import numpy as np

from cccf.models import Finding
from cccf.store import Store


def make_finding(
    path: str = "app/db.py",
    rule_id: str = "custom.sql-fstring",
    severity: str = "ERROR",
    suffix: str = "",
) -> Finding:
    return Finding(
        id=f"finding-{path}-{rule_id}{suffix}",
        rule_id=rule_id,
        severity=severity,
        message="Une requête SQL construite par f-string.",
        path=path,
        start_line=6,
        end_line=6,
        snippet='cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
        fix=None,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
    )


def test_insert_and_reread_finding_roundtrip(tmp_path: Path) -> None:
    finding = make_finding()

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    with Store(tmp_path) as store:
        results = store.all_findings()

    assert len(results) == 1
    reread = results[0]
    assert reread == finding


def test_replace_findings_for_files_removes_only_targeted_paths(tmp_path: Path) -> None:
    db_finding = make_finding(path="app/db.py", rule_id="custom.sql-fstring", severity="ERROR")
    shell_finding = make_finding(
        path="app/shell.py", rule_id="custom.subprocess-shell-true", severity="WARNING"
    )

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [db_finding])
        store.replace_findings_for_files(["app/shell.py"], [shell_finding])

    with Store(tmp_path) as store:
        # le finding db.py disparaît (corrigé), shell.py doit rester intact
        store.replace_findings_for_files(["app/db.py"], [])

    with Store(tmp_path) as store:
        results = store.all_findings()

    assert [f.path for f in results] == ["app/shell.py"]


def test_set_and_iter_embeddings(tmp_path: Path) -> None:
    finding = make_finding()
    vector = np.array([0.1, 0.2, 0.3], dtype=np.float32)

    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])
        store.set_embedding(finding.id, vector)

    with Store(tmp_path) as store:
        embeddings = dict(store.iter_embeddings())

    assert finding.id in embeddings
    assert np.allclose(embeddings[finding.id], vector)


def test_reopening_existing_database_reads_schema_version(tmp_path: Path) -> None:
    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "3"

    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "3"


def _make_legacy_v1_db(tmp_path: Path) -> None:
    """Simulate a pre-migration store: schema v1, embedding as a BLOB column."""
    db_path = tmp_path / ".cccf" / "findings.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, indexed_at TEXT NOT NULL);
        CREATE TABLE findings (
            id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, message TEXT, path TEXT,
            start_line INTEGER, end_line INTEGER, snippet TEXT, fix TEXT, cwe TEXT,
            owasp TEXT, embedding BLOB
        );
        INSERT INTO meta VALUES ('schema_version', '1');
        INSERT INTO meta VALUES ('embedding_signature', 'sentence-transformers:old-model');
        INSERT INTO meta VALUES ('embedding_dim', '384');
        INSERT INTO findings VALUES
            ('abc123', 'r1', 'ERROR', 'msg', 'app/db.py', 1, 1, 'snip', NULL, '[]', '[]', X'0000');
        """
    )
    conn.commit()
    conn.close()


def test_opening_legacy_v1_database_migrates_to_vec0_and_forces_reembed(
    tmp_path: Path,
) -> None:
    _make_legacy_v1_db(tmp_path)

    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "3"
        # signature/dim cleared -> next `cccf index` re-embeds everything
        assert store.get_meta("embedding_signature") is None
        assert store.get_embedding_dim() is None
        # findings themselves survive the migration
        assert [f.id for f in store.all_findings()] == ["abc123"]
        cols = {row["name"] for row in store.conn.execute("PRAGMA table_info(findings)")}
        assert "embedding" not in cols


def test_replace_code_chunks_for_files_removes_only_targeted_paths(tmp_path: Path) -> None:
    from cccf.store import CodeChunk

    db_chunk = CodeChunk("db", "app/db.py", 1, 3, "python", "db code")
    shell_chunk = CodeChunk("shell", "app/shell.py", 1, 3, "python", "shell code")

    with Store(tmp_path) as store:
        store.replace_code_chunks_for_files(["app/db.py"], [db_chunk])
        store.replace_code_chunks_for_files(["app/shell.py"], [shell_chunk])
        store.replace_code_chunks_for_files(["app/db.py"], [])
        chunks = store.all_code_chunks()

    assert chunks == [shell_chunk]


def test_knn_search_code_chunks_filters_by_language_and_path_and_paginates(
    tmp_path: Path,
) -> None:
    from cccf.store import CodeChunk

    py_chunk = CodeChunk("py", "app/db.py", 1, 3, "python", "python code")
    ts_chunk = CodeChunk("ts", "web/app.ts", 1, 3, "typescript", "ts code")
    other_py_chunk = CodeChunk("py2", "lib/util.py", 1, 3, "python", "more python")

    with Store(tmp_path) as store:
        store.replace_code_chunks_for_files(
            ["app/db.py", "web/app.ts", "lib/util.py"], [py_chunk, ts_chunk, other_py_chunk]
        )
        # scores decreasing in insertion order: py (best) > ts > other_py
        store.set_code_chunk_embedding("py", np.array([1.0, 0.0, 0.0], dtype=np.float32))
        store.set_code_chunk_embedding("ts", np.array([0.9, 0.1, 0.0], dtype=np.float32))
        store.set_code_chunk_embedding("py2", np.array([0.8, 0.2, 0.0], dtype=np.float32))

        query_vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)

        by_lang = store.knn_search_code_chunks(query_vec, top_k=5, language="python")
        assert [chunk.id for chunk, _ in by_lang] == ["py", "py2"]

        by_path = store.knn_search_code_chunks(query_vec, top_k=5, path_glob="web/*")
        assert [chunk.id for chunk, _ in by_path] == ["ts"]

        paginated = store.knn_search_code_chunks(query_vec, top_k=1, offset=1)
        assert [chunk.id for chunk, _ in paginated] == ["ts"]
