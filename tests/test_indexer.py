import hashlib
import shutil
from pathlib import Path

import numpy as np
import pytest

from cccf.config import Config
from cccf.indexer import _is_test_source, index_repo
from cccf.coco_indexer import index_repo_with_cocoindex
from cccf.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"
ENDPOINT_INDEX_REPO = FIXTURES_DIR / "endpoint_index_repo"
TEST_SOURCE_EXCLUSION_REPO = FIXTURES_DIR / "test_source_exclusion_repo"


class FakeEmbedder:
    """Embedder déterministe basé sur un hash du texte, sans dépendance réseau."""

    def __init__(self, dim: int = 8) -> None:
        self.dim = dim
        self.calls = 0

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        self.calls += len(texts)
        vectors = []
        for text in texts:
            digest = hashlib.sha256(text.encode()).digest()
            raw = np.frombuffer(digest[: self.dim], dtype=np.uint8).astype(np.float32)
            norm = np.linalg.norm(raw)
            vectors.append(raw / norm if norm > 0 else raw)
        return np.array(vectors, dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_texts([text])[0]


@pytest.fixture
def repo_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    return dest


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/rules.yml"]}
    defaults.update(overrides)
    return Config(**defaults)


@pytest.mark.integration
def test_first_index_run_finds_all_findings_and_scans_all_files(repo_copy: Path) -> None:
    config = make_config()
    total_files = sum(1 for p in repo_copy.rglob("*") if p.is_file())

    with Store(repo_copy) as store:
        report = index_repo(repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()

    assert report.scanned == total_files
    assert len(findings) == 4


@pytest.mark.integration
def test_default_include_indexes_root_files(repo_copy: Path) -> None:
    (repo_copy / "root_vuln.py").write_text(
        "import sqlite3\n\n"
        "def find_user(conn: sqlite3.Connection, name: str):\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
    )

    with Store(repo_copy) as store:
        index_repo(repo_copy, make_config(), store, FakeEmbedder())
        findings = store.all_findings(path_glob="root_vuln.py")

    assert len(findings) == 1
    assert findings[0].path == "root_vuln.py"


@pytest.mark.integration
def test_second_run_without_changes_scans_nothing(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, FakeEmbedder())
        report = index_repo(repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()

    assert report.scanned == 0
    assert len(findings) == 4


@pytest.mark.integration
def test_fixing_db_py_removes_error_finding_keeps_others(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, FakeEmbedder())

        (repo_copy / "app" / "db.py").write_text(
            "import sqlite3\n\n\n"
            "def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:\n"
            "    cursor = conn.cursor()\n"
            '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
            "    return cursor.fetchall()\n"
        )

        index_repo(repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()

    assert {f.path for f in findings} == {
        "app/shell.py",
        "app/yaml_loader.py",
        "app/weak_random.py",
    }


@pytest.mark.integration
def test_deleting_shell_py_removes_its_finding(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, FakeEmbedder())

        (repo_copy / "app" / "shell.py").unlink()

        report = index_repo(repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()

    assert report.deleted_files == 1
    assert {f.path for f in findings} == {
        "app/db.py",
        "app/yaml_loader.py",
        "app/weak_random.py",
    }


@pytest.mark.integration
def test_index_repo_embeds_all_findings(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, FakeEmbedder())
        embeddings = dict(store.iter_embeddings())
        findings = store.all_findings()

    assert len(embeddings) == len(findings) == 4
    for finding in findings:
        assert finding.id in embeddings
        assert embeddings[finding.id] is not None


@pytest.mark.integration
def test_changing_embedding_model_reembeds_everything(repo_copy: Path) -> None:
    config = make_config(embedding_model="model-a")
    embedder = FakeEmbedder()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, embedder)
        calls_after_first_run = embedder.calls

        other_config = make_config(embedding_model="model-b")
        index_repo(repo_copy, other_config, store, embedder)
        findings = store.all_findings()

    assert calls_after_first_run == 4
    # changement de modèle -> tous les findings sont ré-embeddés, pas seulement les nouveaux
    assert embedder.calls == calls_after_first_run + len(findings)


@pytest.mark.integration
def test_cocoindex_prototype_indexes_findings_and_code_chunks(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        report = index_repo_with_cocoindex(repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()
        chunks = store.all_code_chunks()

    assert report.scanned > 0
    assert len(findings) == 4
    assert {chunk.path for chunk in chunks} >= {
        "app/db.py",
        "app/shell.py",
        "app/yaml_loader.py",
        "app/weak_random.py",
    }


@pytest.mark.integration
def test_cocoindex_prototype_removes_deleted_file_chunks(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo_with_cocoindex(repo_copy, config, store, FakeEmbedder())
        (repo_copy / "app" / "shell.py").unlink()

        report = index_repo_with_cocoindex(repo_copy, config, store, FakeEmbedder())
        chunks = store.all_code_chunks()
        findings = store.all_findings()

    assert report.deleted_files == 1
    assert "app/shell.py" not in {chunk.path for chunk in chunks}
    assert "app/shell.py" not in {finding.path for finding in findings}


@pytest.mark.integration
def test_cocoindex_prototype_backfills_chunks_after_manual_index(repo_copy: Path) -> None:
    config = make_config()

    with Store(repo_copy) as store:
        index_repo(repo_copy, config, store, FakeEmbedder())
        report = index_repo_with_cocoindex(repo_copy, config, store, FakeEmbedder())
        chunks = store.all_code_chunks()

    assert report.scanned == 0
    assert {chunk.path for chunk in chunks} >= {"app/db.py", "app/shell.py"}


# -- BACKLOG-11 A1 : endpoints indexés dans le même passage que les findings --


@pytest.fixture
def endpoint_repo_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "endpoint_index_repo"
    shutil.copytree(ENDPOINT_INDEX_REPO, dest)
    return dest


@pytest.mark.integration
def test_index_repo_populates_endpoints_and_findings_from_the_same_scan(
    endpoint_repo_copy: Path,
) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        report = index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        endpoints = store.all_endpoints()
        findings = store.all_findings()

    # 1 finding (System.out.println) + 2 endpoints (consume Kafka, call REST)
    # issus du même scan Semgrep — aucune fuite d'un type vers l'autre.
    assert report.findings_added == 1
    assert report.endpoints_added == 2
    assert len(findings) == 1
    assert findings[0].rule_id == "rules.custom.system-out-println"
    assert {e.role for e in endpoints} == {"consume", "call"}
    assert {e.system for e in endpoints} == {"kafka", "rest"}


@pytest.mark.integration
def test_index_repo_second_run_without_changes_leaves_endpoints_untouched(
    endpoint_repo_copy: Path,
) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        report = index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        endpoints = store.all_endpoints()

    assert report.scanned == 0
    assert report.endpoints_added == 0
    assert len(endpoints) == 2


@pytest.fixture
def test_source_exclusion_repo_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "test_source_exclusion_repo"
    shutil.copytree(TEST_SOURCE_EXCLUSION_REPO, dest)
    return dest


@pytest.mark.integration
def test_index_repo_excludes_files_under_a_non_main_source_set(
    test_source_exclusion_repo_copy: Path,
) -> None:
    """BACKLOG-15 H2 : `service/src/test/java/OrderConsumerTest.java` porte
    la même règle System.out.println/Kafka listener que
    `service/src/main/java/OrderConsumer.java`, mais ne doit produire ni
    finding ni endpoint — seul `src/main` est scanné (ADR-34)."""
    config = make_config(rules=["rules/rules.yml"])

    with Store(test_source_exclusion_repo_copy) as store:
        report = index_repo(test_source_exclusion_repo_copy, config, store, FakeEmbedder())
        findings = store.all_findings()
        endpoints = store.all_endpoints()

    assert report.findings_added == 1
    assert report.endpoints_added == 1
    assert [f.path for f in findings] == ["service/src/main/java/OrderConsumer.java"]
    assert [e.path for e in endpoints] == ["service/src/main/java/OrderConsumer.java"]


@pytest.mark.parametrize(
    ("rel_path", "expected"),
    [
        # BACKLOG-16 P1 : un layout Python/JS/Rust en `src/<package>` n'est
        # pas un jeu de sources de test Maven/Gradle.
        ("src/cccf/store.py", False),
        ("src/mypkg/api/views.py", False),
        # Maven/Gradle : `main` n'est jamais du test, les variants suivant
        # la convention `test`/`<prefixe>Test` le sont tous.
        ("service/src/main/java/A.java", False),
        ("service/src/test/java/T.java", True),
        ("service/src/componentTest/java/T.java", True),
        ("service/src/contractTest/java/T.java", True),
        ("service/src/endToEndTest/java/T.java", True),
    ],
)
def test_is_test_source(rel_path: str, expected: bool) -> None:
    assert _is_test_source(rel_path) is expected


@pytest.mark.integration
def test_index_repo_removes_endpoints_of_deleted_file(endpoint_repo_copy: Path) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        index_repo(endpoint_repo_copy, config, store, FakeEmbedder())

        (endpoint_repo_copy / "app" / "OrderConsumer.java").unlink()

        report = index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        endpoints = store.all_endpoints()

    assert report.deleted_files == 1
    assert report.endpoints_removed == 2
    assert endpoints == []


# -- BACKLOG-10 K3 : embeddings dédiés pour les endpoints --


@pytest.mark.integration
def test_index_repo_embeds_all_endpoints(endpoint_repo_copy: Path) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        embeddings = dict(store.iter_endpoint_embeddings())
        endpoints = store.all_endpoints()

    assert len(embeddings) == len(endpoints) == 2
    for endpoint in endpoints:
        assert endpoint.id in embeddings


@pytest.mark.integration
def test_index_repo_second_run_does_not_reembed_unchanged_endpoints(
    endpoint_repo_copy: Path,
) -> None:
    config = make_config(rules=["rules/rules.yml"])
    embedder = FakeEmbedder()

    with Store(endpoint_repo_copy) as store:
        index_repo(endpoint_repo_copy, config, store, embedder)
        calls_after_first_run = embedder.calls

        index_repo(endpoint_repo_copy, config, store, embedder)

    assert embedder.calls == calls_after_first_run


@pytest.mark.integration
def test_index_repo_removes_endpoint_embeddings_of_deleted_file(
    endpoint_repo_copy: Path,
) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        index_repo(endpoint_repo_copy, config, store, FakeEmbedder())

        (endpoint_repo_copy / "app" / "OrderConsumer.java").unlink()

        index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        remaining = store.endpoint_embedding_count()

    assert remaining == 0
