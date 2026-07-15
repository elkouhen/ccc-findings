import hashlib
import shutil
from pathlib import Path

import numpy as np
import pytest

from ccc_radar.config import Config
from ccc_radar.indexer import _is_test_source, _list_repo_files, index_repo
from ccc_radar.inventory_freshness import current_endpoint_inventory_signature
from ccc_radar.coco_indexer import index_repo_with_cocoindex
from ccc_radar.store import Store

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
def test_index_repo_reports_progress_messages(repo_copy: Path) -> None:
    messages: list[str] = []

    with Store(repo_copy) as store:
        index_repo(repo_copy, make_config(), store, FakeEmbedder(), progress=messages.append)

    assert any("inventaire des fichiers" in message for message in messages)
    assert any("delta calculé" in message for message in messages)
    assert any("scan Semgrep" in message for message in messages)
    assert any("écriture des résultats" in message for message in messages)
    assert any("embedding" in message for message in messages)


def test_index_repo_can_disable_semgrep_and_properties(repo_copy: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "ccc_radar.indexer.invoke_semgrep_raw",
        lambda *_args, **_kwargs: pytest.fail("Semgrep ne doit pas être invoqué"),
    )
    monkeypatch.setattr(
        "ccc_radar.indexer.discover_modules",
        lambda *_args, **_kwargs: pytest.fail("Les propriétés ne doivent pas être inventoriées"),
    )
    messages: list[str] = []

    with Store(repo_copy) as store:
        report = index_repo(
            repo_copy, make_config(), store, FakeEmbedder(),
            disabled=frozenset({"semgrep", "properties"}), progress=messages.append,
        )
        assert store.all_findings() == []
        assert store.all_modules() == []

    assert report.findings_added == 0
    assert any("Semgrep désactivé" in message for message in messages)
    assert any("propriétés et inventaire" in message for message in messages)


def test_container_root_scans_only_nested_maven_or_gradle_modules(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("workspace only\n")
    (tmp_path / "loose.java").write_text("class Loose {}\n")
    maven = tmp_path / "orders"
    (maven / "src" / "main" / "java").mkdir(parents=True)
    (maven / "pom.xml").write_text("<project><artifactId>orders</artifactId></project>")
    (maven / "src" / "main" / "java" / "Order.java").write_text("class Order {}\n")
    gradle = tmp_path / "payments"
    (gradle / "src" / "main" / "java").mkdir(parents=True)
    (gradle / "build.gradle").write_text("plugins {}\n")
    (gradle / "src" / "main" / "java" / "Payment.java").write_text("class Payment {}\n")

    files = _list_repo_files(tmp_path, Config(rules=[]))

    assert set(files) == {
        "orders/pom.xml", "orders/src/main/java/Order.java",
        "payments/build.gradle", "payments/src/main/java/Payment.java",
    }


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
def test_cocoindex_reembeds_all_chunks_when_embedding_model_changes_at_same_dimension(
    repo_copy: Path,
) -> None:
    """BACKLOG-16 P5 : `_ensure_code_vec_table` ne recrée `vec_code_chunks`
    qu'au changement de *dimension* — un changement de modèle à dimension
    égale (même `FakeEmbedder(dim=8)`, signature différente via
    `config.embedding_model`) laissait silencieusement les anciens
    vecteurs en place puisque aucun fichier n'a changé entre les deux
    indexations (`chunk_paths` vide, l'ancien code sautait tout
    ré-embedding). `code_embedding_signature` doit forcer un ré-embedding
    complet de `store.all_code_chunks()` dans ce cas."""
    config_a = make_config(embedding_model="model-a")
    config_b = make_config(embedding_model="model-b")
    embedder = FakeEmbedder(dim=8)

    with Store(repo_copy) as store:
        index_repo_with_cocoindex(repo_copy, config_a, store, embedder)
        num_findings = len(store.all_findings())
        num_endpoints = len(store.all_endpoints())
        num_chunks = len(store.all_code_chunks())

        embedder.calls = 0
        index_repo_with_cocoindex(repo_copy, config_b, store, embedder)

    # Aucun fichier n'a changé : les seuls appels d'embedding possibles
    # viennent du ré-embedding complet déclenché par le changement de
    # signature (findings + endpoints + chunks).
    assert embedder.calls == num_findings + num_endpoints + num_chunks


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


@pytest.mark.integration
def test_index_repo_rescans_all_files_when_endpoint_inventory_signature_is_stale(
    endpoint_repo_copy: Path,
) -> None:
    config = make_config(rules=["rules/rules.yml"])

    with Store(endpoint_repo_copy) as store:
        first_report = index_repo(endpoint_repo_copy, config, store, FakeEmbedder())
        store.set_meta("endpoint_inventory_signature", "endpoint-inventory-v0")

        report = index_repo(endpoint_repo_copy, config, store, FakeEmbedder())

        assert report.scanned == first_report.scanned
        assert store.get_meta("endpoint_inventory_signature") == current_endpoint_inventory_signature()


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


@pytest.mark.integration
def test_index_repo_reresolves_spring_property_after_application_yml_change(
    tmp_path: Path,
) -> None:
    """BACKLOG-16 P2 : `ValueAnnotatedConsumer.java:24`
    (`@KafkaListener(topics = ordersTopic)`) résout son topic via le champ
    `@Value("${app.kafka.topics.orders}")` puis `application.yml` — dans un
    process long-vivant (serveur MCP), le cache d'analyse
    (`_load_flat_spring_properties`) ne doit pas resservir l'ancienne
    valeur de `application.yml` après modification. `full=True` force le
    Java à être réanalysé (seul `application.yml` change de hash, le
    fichier Java lui-même est intact)."""
    dest = tmp_path / "kafka_repo"
    shutil.copytree(FIXTURES_DIR / "kafka_repo", dest)
    config = make_config(rules=["rules/java.yaml"])

    def _resolved_topic(store: Store) -> str:
        (endpoint,) = [
            e
            for e in store.all_endpoints()
            if e.path == "app/java/ValueAnnotatedConsumer.java" and e.start_line == 24
        ]
        return endpoint.topic

    with Store(dest) as store:
        index_repo(dest, config, store, FakeEmbedder())
        assert _resolved_topic(store) == "orders.created"

    app_yml = dest / "src" / "main" / "resources" / "application.yml"
    app_yml.write_text(app_yml.read_text().replace("orders.created", "orders.created.v2"))

    with Store(dest) as store:
        index_repo(dest, config, store, FakeEmbedder(), full=True)
        assert _resolved_topic(store) == "orders.created.v2"


@pytest.mark.parametrize(
    ("rel_path", "expected"),
    [
        # BACKLOG-16 P1 : un layout Python/JS/Rust en `src/<package>` n'est
        # pas un jeu de sources de test Maven/Gradle.
        ("src/ccc_radar/store.py", False),
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


def test_index_repo_rescans_everything_when_local_rule_changes(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "ccc_radar.indexer.invoke_semgrep_raw", lambda *_args, **_kwargs: '{"results": []}'
    )
    config = make_config()
    with Store(repo_copy) as store:
        first = index_repo(repo_copy, config, store, FakeEmbedder())
        rule_file = repo_copy / "rules" / "rules.yml"
        rule_file.write_text(rule_file.read_text() + "\n# changed rule input\n")
        second = index_repo(repo_copy, config, store, FakeEmbedder())

    assert first.scanned > 0
    assert second.scanned == first.scanned
