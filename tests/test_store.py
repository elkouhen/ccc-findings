import sqlite3
from pathlib import Path

import numpy as np

from cccf.models import Finding, MessageEndpoint, compute_endpoint_id
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
        assert store.get_meta("schema_version") == "4"

    with Store(tmp_path) as store:
        assert store.get_meta("schema_version") == "4"


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
        assert store.get_meta("schema_version") == "4"
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


def make_endpoint(
    role: str = "produce",
    system: str = "kafka",
    topic: str = "orders.created",
    path: str = "app/producer.py",
    start_line: int = 10,
    end_line: int = 10,
    source: str = "code",
    framework: str | None = "kafka-python",
    topic_dynamic: bool = False,
) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, path, start_line, end_line),
        role=role,
        system=system,
        topic=topic,
        topic_dynamic=topic_dynamic,
        source=source,
        framework=framework,
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="producer.send('orders.created', payload)",
    )


def test_insert_and_reread_endpoint_roundtrip(tmp_path: Path) -> None:
    endpoint = make_endpoint()

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/producer.py"], [endpoint])

    with Store(tmp_path) as store:
        results = store.all_endpoints()

    assert results == [endpoint]


def test_replace_endpoints_for_files_removes_only_targeted_paths(tmp_path: Path) -> None:
    producer = make_endpoint(path="app/producer.py", role="produce")
    consumer = make_endpoint(
        path="app/consumer.py", role="consume", framework="kafka-python", start_line=5, end_line=5
    )

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/producer.py"], [producer])
        store.replace_endpoints_for_files(["app/consumer.py"], [consumer])
        # producer.py réindexé sans endpoint (site supprimé du code) : ne
        # doit pas affecter consumer.py
        store.replace_endpoints_for_files(["app/producer.py"], [])

    with Store(tmp_path) as store:
        results = store.all_endpoints()

    assert [e.path for e in results] == ["app/consumer.py"]


def test_endpoint_identity_stable_and_changes_with_topic_or_location() -> None:
    same_again = compute_endpoint_id("produce", "orders.created", "app/producer.py", 10, 10)
    assert compute_endpoint_id("produce", "orders.created", "app/producer.py", 10, 10) == same_again

    different_topic = compute_endpoint_id("produce", "orders.updated", "app/producer.py", 10, 10)
    assert different_topic != same_again

    different_location = compute_endpoint_id("produce", "orders.created", "app/producer.py", 20, 20)
    assert different_location != same_again


def test_code_and_manifest_endpoints_for_same_topic_coexist_without_collision(
    tmp_path: Path,
) -> None:
    from_code = make_endpoint(
        role="produce", topic="orders.created", path="app/producer.py", source="code"
    )
    from_manifest = make_endpoint(
        role="produce",
        topic="orders.created",
        path="TOPICS.md",
        start_line=3,
        end_line=3,
        source="manifest",
        framework=None,
    )

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/producer.py"], [from_code])
        store.replace_endpoints_for_files(["TOPICS.md"], [from_manifest])

    with Store(tmp_path) as store:
        results = store.all_endpoints(topic="orders.created")

    assert {e.id for e in results} == {from_code.id, from_manifest.id}
    assert {e.source for e in results} == {"code", "manifest"}


def test_all_endpoints_filters_by_system_role_topic_and_path(tmp_path: Path) -> None:
    kafka_producer = make_endpoint(
        role="produce", system="kafka", topic="orders.created", path="app/producer.py"
    )
    kafka_consumer = make_endpoint(
        role="consume",
        system="kafka",
        topic="orders.created",
        path="app/consumer.py",
        start_line=5,
        end_line=5,
    )
    rest_call = make_endpoint(
        role="call",
        system="rest",
        topic="GET /orders/{id}",
        path="app/client.py",
        start_line=1,
        end_line=1,
        framework="requests",
    )

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(
            ["app/producer.py", "app/consumer.py", "app/client.py"],
            [kafka_producer, kafka_consumer, rest_call],
        )

    with Store(tmp_path) as store:
        assert {e.id for e in store.all_endpoints(system="rest")} == {rest_call.id}
        assert {e.id for e in store.all_endpoints(role="consume")} == {kafka_consumer.id}
        assert {e.id for e in store.all_endpoints(topic="orders.created")} == {
            kafka_producer.id,
            kafka_consumer.id,
        }
        assert {e.id for e in store.all_endpoints(path_glob="app/producer.*")} == {
            kafka_producer.id
        }


def test_remove_files_purges_endpoints(tmp_path: Path) -> None:
    endpoint = make_endpoint(path="app/producer.py")

    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/producer.py"], [endpoint])
        store.set_file_hash("app/producer.py", "deadbeef")
        store.remove_files(["app/producer.py"])

    with Store(tmp_path) as store:
        assert store.all_endpoints() == []


def test_remove_files_batches_large_path_lists_over_sqlite_bind_limit(tmp_path: Path) -> None:
    paths = [f"app/file_{i}.py" for i in range(1005)]
    findings = [make_finding(path=path, suffix=f"-{i}") for i, path in enumerate(paths)]
    endpoints = [
        make_endpoint(path=path, start_line=i + 1, end_line=i + 1, topic=f"orders.{i}")
        for i, path in enumerate(paths)
    ]

    with Store(tmp_path) as store:
        store.replace_findings_for_files(paths, findings)
        store.replace_endpoints_for_files(paths, endpoints)
        for i, path in enumerate(paths):
            store.set_file_hash(path, f"sha-{i}")
        store.remove_files(paths)

    with Store(tmp_path) as store:
        assert store.all_findings() == []
        assert store.all_endpoints() == []
