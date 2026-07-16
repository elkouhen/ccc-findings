import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import ccc_radar.embedder as embedder_module
import ccc_radar.render as render_module
from ccc_radar.cli import DEFAULT_RULE_PACKS, app
from ccc_radar.indexer import IndexReport
from ccc_radar.models import Finding, MessageEndpoint, compute_endpoint_id
from ccc_radar.modules import DiscoveredModule
from ccc_radar.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"
ENDPOINT_INDEX_REPO = FIXTURES_DIR / "endpoint_index_repo"
MAVEN_WORKSPACE = FIXTURES_DIR / "maven_workspace"

runner = CliRunner()


def test_architecture_command_help_is_short_and_task_oriented() -> None:
    root_help = runner.invoke(app, ["--help"])
    microservices_help = runner.invoke(app, ["microservices", "--help"])
    graph_help = runner.invoke(app, ["graph", "--help"])
    topics_help = runner.invoke(app, ["topics", "--help"])
    apis_help = runner.invoke(app, ["apis", "--help"])
    export_help = runner.invoke(app, ["export", "microservices", "--help"])

    assert root_help.exit_code == 0
    assert "Explorer l'architecture et les constats" in root_help.output
    assert "BACKLOG-" not in root_help.output
    assert "integrations" in root_help.output
    assert "apis" in root_help.output
    assert "export" in root_help.output
    assert "endpoints" not in root_help.output
    assert "resources" not in root_help.output
    assert microservices_help.exit_code == 0
    assert "Lister les microservices ou résumer un microservice." in microservices_help.output
    assert "cccr microservices mongodb orders" in microservices_help.output
    assert graph_help.exit_code == 0
    assert "Afficher les interactions HTTP et Kafka" in graph_help.output
    assert "--drawio" not in graph_help.output
    assert topics_help.exit_code == 0
    assert "Commande : list, show, neighbors" in topics_help.output
    assert apis_help.exit_code == 0
    assert "providers," in apis_help.output
    assert "consumers ou search" in apis_help.output
    assert export_help.exit_code == 0
    assert "--drawio" in export_help.output
    assert "--html" in export_help.output
    assert "--c4" in export_help.output


def install_fake_skill_rules(home: Path, packs: tuple[str, ...] = DEFAULT_RULE_PACKS) -> Path:
    rules_root = home / "ccc-radar-skill" / "skills" / "cccr" / "rules"
    for pack in packs:
        pack_dir = rules_root / pack
        pack_dir.mkdir(parents=True, exist_ok=True)
        (pack_dir / "java.yaml").write_text("rules: []\n")
    return rules_root


@pytest.fixture
def repo_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    return dest


def test_init_without_semgrep_config_falls_back_to_default_registry_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "p/security-audit" in result.output
    config_content = (tmp_path / ".cccr" / "config.yml").read_text()
    assert "p/security-audit" in config_content


def test_index_rejects_an_unknown_disabled_type(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["index", "--disable", "unknown"])

    assert result.exit_code == 2
    assert "Type d'indexation inconnu" in result.output
    assert "module-architecture" in result.output
    assert "module-tree-sitter" in result.output


def test_index_accepts_markdown_manifest_as_positional_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cccr").mkdir()
    (tmp_path / ".cccr" / "config.yml").write_text("rules: ['rules.yml']\n")
    (tmp_path / "TOPICS.md").write_text("### module-a\n")
    captured: dict[str, object] = {}

    def fake_index_repo(*args: object, **kwargs: object) -> IndexReport:
        captured["extra_files"] = kwargs["extra_files"]
        return IndexReport(1, 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr("ccc_radar.cli.resolve_embedding_model", lambda model: (model, None))
    monkeypatch.setattr("ccc_radar.cli.make_embedder", lambda _model: object())
    monkeypatch.setattr("ccc_radar.cli.index_repo", fake_index_repo)

    result = runner.invoke(app, ["index", "TOPICS.md"])

    assert result.exit_code == 0
    assert captured["extra_files"] == ["TOPICS.md"]


def test_index_accepts_markdown_manifest_option(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cccr").mkdir()
    (tmp_path / ".cccr" / "config.yml").write_text("rules: ['rules.yml']\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "topics.md").write_text("### module-a\n")
    captured: dict[str, object] = {}

    def fake_index_repo(*args: object, **kwargs: object) -> IndexReport:
        captured["extra_files"] = kwargs["extra_files"]
        return IndexReport(1, 0, 0, 0, 0, 0, 0)

    monkeypatch.setattr("ccc_radar.cli.resolve_embedding_model", lambda model: (model, None))
    monkeypatch.setattr("ccc_radar.cli.make_embedder", lambda _model: object())
    monkeypatch.setattr("ccc_radar.cli.index_repo", fake_index_repo)

    result = runner.invoke(app, ["index", "--manifest", "docs/topics.md"])

    assert result.exit_code == 0
    assert captured["extra_files"] == ["docs/topics.md"]


def test_init_without_semgrep_config_installs_all_skill_packs_when_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    install_fake_skill_rules(Path.home())

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "default, liveness, rest, kafka, kafka-security" in result.output
    config_content = (tmp_path / ".cccr" / "config.yml").read_text()
    for pack in DEFAULT_RULE_PACKS:
        assert f".cccr/rules/{pack}" in config_content
        assert (tmp_path / ".cccr" / "rules" / pack / "java.yaml").is_file()


def test_init_without_semgrep_config_falls_back_when_skill_packs_are_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    install_fake_skill_rules(Path.home(), packs=("default", "liveness"))

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "p/security-audit" in result.output
    config_content = (tmp_path / ".cccr" / "config.yml").read_text()
    assert "p/security-audit" in config_content


@pytest.mark.integration
def test_index_with_default_registry_pack_succeeds_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    (tmp_path / "app.py").write_text(
        "import sqlite3\n\n\n"
        "def find_user(conn: sqlite3.Connection, name: str):\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        "    return cursor.fetchall()\n"
    )

    init_result = runner.invoke(app, ["init"])
    assert init_result.exit_code == 0

    index_result = runner.invoke(app, ["index"])

    assert index_result.exit_code == 0
    assert "→ Indexation :" in index_result.output
    assert "scanned=" in index_result.output


def test_init_with_explicit_rules_takes_priority_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccr" / "config.yml").read_text()
    assert "rules/rules.yml" in config_content
    assert "p/security-audit" not in config_content


def test_init_detects_local_semgrep_config_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".semgrep.yml").write_text("rules: []\n")

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccr" / "config.yml").read_text()
    assert ".semgrep.yml" in config_content
    assert "p/security-audit" not in config_content


@pytest.mark.integration
def test_init_with_rules_then_index_reports_correctly(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")

    init_result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    assert init_result.exit_code == 0
    assert (repo_copy / ".cccr" / "config.yml").is_file()

    index_result = runner.invoke(app, ["index"])

    assert index_result.exit_code == 0
    assert "→ Indexation :" in index_result.output
    assert "scanned=" in index_result.output
    assert "+findings=4" in index_result.output
    assert "-findings=0" in index_result.output


@pytest.mark.integration
def test_index_twice_second_run_scans_nothing(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    second_result = runner.invoke(app, ["index"])

    assert second_result.exit_code == 0
    assert "scanned=0" in second_result.output


def test_findings_without_index_fails_with_exact_message_and_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["findings", "injection sql"])

    assert result.exit_code == 2
    assert "Index absent. Lancez d'abord: cccr index" in result.output


def test_findings_without_query_lists_indexed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    finding = Finding(
        id="listed-finding", rule_id="custom.listed", severity="ERROR",
        message="Finding de liste", path="app/Main.java", start_line=3, end_line=3,
        snippet="dangerous();", fix=None, cwe=[], owasp=[],
    )
    with Store(tmp_path) as store:
        store.replace_findings_for_files([finding.path], [finding])

    result = runner.invoke(app, ["findings", "--json", "--limit", "10"])

    assert result.exit_code == 0
    assert json.loads(result.output)[0]["rule_id"] == "custom.listed"


@pytest.mark.integration
def test_findings_json_output_matches_contract(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["findings", "injection sql", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    # La recherche findings est précision-first : « injection sql » ne doit
    # pas ramener les findings qui ne couvrent qu'un des deux termes.
    assert len(hits) == 1
    assert hits[0]["rule_id"].endswith("custom.sql-fstring")
    expected_keys = {
        "id",
        "rule_id",
        "severity",
        "message",
        "path",
        "start_line",
        "end_line",
        "score",
        "fix",
        "cwe",
        "owasp",
    }
    assert expected_keys <= set(hits[0].keys())


@pytest.mark.integration
def test_findings_invalid_severity_fails_with_exit_code_2(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-16 P4 : `--severity HIGH` (sévérité Semgrep brute, jamais
    stockée telle quelle) échouait auparavant avec un ValueError brut."""
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["findings", "injection sql", "--severity", "HIGH"])

    assert result.exit_code == 2
    assert "HIGH" in result.output


@pytest.mark.integration
def test_findings_context_includes_offending_source_line(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(
        app, ["findings", "injection sql", "--path", "app/db.py", "--context", "--json"]
    )

    hits = json.loads(result.output)
    assert "cursor.execute" in hits[0]["context"]


@pytest.mark.integration
def test_findings_hybrid_query_can_match_exact_rule_id(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["findings", "custom.subprocess-shell-true", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert hits[0]["rule_id"].endswith("custom.subprocess-shell-true")


def test_search_renders_ccc_format_with_findings_blocks(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cccr search` répond « de la même manière » que ccc : même format de
    résultats, enrichi d'un bloc findings sous les résultats concernés."""
    monkeypatch.chdir(tmp_path)
    from ccc_radar.models import Finding
    from ccc_radar.store import Store

    finding = Finding(
        id="cli-search-finding",
        rule_id="custom.sql-fstring",
        severity="ERROR",
        message="Une requête SQL construite par f-string permet une injection SQL.",
        path="app/db.py",
        start_line=6,
        end_line=6,
        snippet="cursor.execute(query)",
        fix=None,
        cwe=["CWE-89"],
        owasp=[],
    )
    with Store(tmp_path) as store:
        store.replace_findings_for_files(["app/db.py"], [finding])

    result = runner.invoke(app, ["search", "user authentication flow"])

    assert result.exit_code == 0
    assert "--- Result 1 (score: 0.900) ---" in result.output
    assert "File: app/db.py:6-6 [python]" in result.output
    assert "findings (max: ERROR)" in result.output
    assert "custom.sql-fstring" in result.output
    # L'ordre reste celui de ccc : le résultat sans finding n'est pas déplacé.
    assert result.output.index("app/other.py:1-1") < result.output.index("app/db.py:6-6")


def test_search_json_returns_stable_code_search_result_schema(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    from ccc_radar.store import Store

    with Store(tmp_path):
        pass  # index findings vide mais présent

    result = runner.invoke(app, ["search", "auth", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data.keys()) == {"results", "findings_only_fallback", "warning"}
    assert len(data["results"]) == 2
    assert {"path", "start_line", "end_line", "language", "score", "content",
            "findings", "max_severity"} <= set(data["results"][0].keys())


@pytest.mark.integration
def test_search_uses_ccc_even_when_experimental_code_index_is_available(
    fake_ccc_on_path: Path, repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    index_result = runner.invoke(app, ["index", "--engine", "cocoindex"])
    assert index_result.exit_code == 0
    (repo_copy / ".cocoindex_code").mkdir()
    (repo_copy / ".cocoindex_code" / "target_sqlite.db").write_text("")

    result = runner.invoke(app, ["search", "injection sql", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["results"]
    assert data["warning"] is None
    assert "path" in data["results"][0]


def test_search_without_findings_index_warns_but_shows_code_results(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 0
    assert "index findings absent" in result.output
    assert "--- Result 1" in result.output


def test_search_without_ccc_nor_index_fails_with_message_and_code_2(
    no_ccc_on_path: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 2
    assert "ccc introuvable dans le PATH" in result.output


def test_search_without_ccc_code_index_fails_fast(
    fake_ccc_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cocoindex_code" / "target_sqlite.db").unlink()

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 2
    assert "index code ccc absent" in result.output
    assert "ccc index" in result.output


def test_search_forwards_offset_lang_path_refresh_flags_to_ccc(
    fake_ccc_args_recording_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        [
            "search", "auth",
            "--limit", "3", "--offset", "2", "--lang", "python", "--path", "app/*", "--refresh",
        ],
    )

    assert result.exit_code == 0
    # cccr transmet la requête telle quelle et ne modifie pas son jeu de résultats.
    assert "ARGS:search auth --limit 3 --offset 2 --lang python --path app/* --refresh" in result.output


def test_search_returns_error_when_ccc_returns_error(
    fake_ccc_error_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 2
    assert "ccc a échoué (code 42)" in result.output
    assert "ccc service failed" in result.output


def test_search_returns_error_when_ccc_times_out(
    fake_ccc_hanging_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CCCR_CCC_SEARCH_TIMEOUT_S", "1")

    result = runner.invoke(app, ["search", "auth"])

    assert result.exit_code == 2
    assert "ccc search a expiré après 1s" in result.output


@pytest.mark.integration
def test_summary_json_has_expected_structure(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["summary", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["by_severity"] == {"ERROR": 2, "WARNING": 2}


def _make_endpoint(
    role: str,
    topic: str,
    path: str,
    start_line: int,
    end_line: int,
    module: str | None = None,
) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, path, start_line, end_line),
        role=role,
        system="kafka" if role in ("produce", "consume") else "rest",
        topic=topic,
        topic_dynamic=False,
        source="code",
        framework=None,
        path=path,
        start_line=start_line,
        end_line=end_line,
        snippet="",
        module=module,
    )


def test_graph_without_index_exits_with_code_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["graph"])

    assert result.exit_code == 2
    assert "Index absent" in result.output


def test_graph_json_reports_outbound_call_in_kafka_consumer_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    consumer = _make_endpoint(
        "consume", "orders.created", "app/OrderConsumer.java", 15, 25
    )
    call = _make_endpoint("call", "POST /payments", "app/OrderConsumer.java", 20, 20)
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/OrderConsumer.java"], [consumer, call])

    result = runner.invoke(app, ["graph", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["services"] == []
    assert data["edges"] == []
    assert len(data["outbound_calls_in_consumers"]) == 1
    hit = data["outbound_calls_in_consumers"][0]
    assert hit["call"]["topic"] == "POST /payments"
    assert hit["consumer"]["topic"] == "orders.created"
    assert "--workspace" in data["note"]


def test_graph_text_reports_no_outbound_calls_when_none_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass  # crée .cccr/findings.db, vide

    result = runner.invoke(app, ["graph"])

    assert result.exit_code == 0
    assert "Aucun appel REST détecté dans un handler Kafka." in result.output


def test_graph_d2_writes_source_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    produce = _make_endpoint("produce", "orders.created", "order-service/Producer.java", 10, 10, "order-service")
    consume = _make_endpoint(
        "consume", "orders.created", "payment-service/Consumer.java", 5, 7, "payment-service"
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(
            ["order-service/Producer.java", "payment-service/Consumer.java"],
            [produce, consume],
        )
    out_file = tmp_path / "graph.d2"

    result = runner.invoke(app, ["graph", "--d2", str(out_file)])

    assert result.exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "label: |md" in content
    assert "  **order-service**" in content
    assert 'label: "orders.created"' in content


def test_graph_d2_renders_svg_via_d2_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    produce = _make_endpoint("produce", "orders.created", "order-service/Producer.java", 10, 10, "order-service")
    consume = _make_endpoint(
        "consume", "orders.created", "payment-service/Consumer.java", 5, 7, "payment-service"
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(
            ["order-service/Producer.java", "payment-service/Consumer.java"],
            [produce, consume],
        )
    out_file = tmp_path / "graph.svg"

    def fake_run(*args, **kwargs):
        out_file.write_text("<svg />", encoding="utf-8")
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(render_module.subprocess, "run", fake_run)

    result = runner.invoke(app, ["graph", "--d2", str(out_file)])

    assert result.exit_code == 0
    assert out_file.read_text(encoding="utf-8") == "<svg />"


def test_graph_html_writes_interactive_sigma_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    produce = _make_endpoint("produce", "orders.created", "order-service/Producer.java", 10, 10, "order-service")
    consume = _make_endpoint(
        "consume", "orders.created", "payment-service/Consumer.java", 5, 7, "payment-service"
    )
    with Store(tmp_path) as store:
        store.replace_modules(
            [
                DiscoveredModule(
                    name="order-service",
                    path=tmp_path / "order-service",
                    build_system="maven",
                    version=None,
                    kind="library",
                    starts_application=True,
                    configuration_example="",
                    mongo_collections=("orders",),
                ),
                DiscoveredModule(
                    name="payment-service",
                    path=tmp_path / "payment-service",
                    build_system="maven",
                    version=None,
                    kind="library",
                    starts_application=True,
                    configuration_example="",
                ),
            ]
        )
        store.replace_endpoints_for_files(
            ["order-service/Producer.java", "payment-service/Consumer.java"],
            [produce, consume],
        )
    out_file = tmp_path / "graph.html"

    result = runner.invoke(app, ["export", "microservices", "--html", str(out_file)])

    assert result.exit_code == 0
    document = out_file.read_text(encoding="utf-8")
    assert "new Sigma(network" in document
    assert "order-service" in document
    assert "orders.created" in document
    assert "mongodb_collection:order-service:orders" in document

    c4_file = tmp_path / "architecture.c4"
    c4_export = runner.invoke(app, ["export", "microservices", "--c4", str(c4_file)])
    assert c4_export.exit_code == 0
    c4_document = c4_file.read_text(encoding="utf-8")
    assert "element microservice" in c4_document
    assert "element kafka_topic" in c4_document
    assert "element mongodb_collection" in c4_document
    assert "orders.created" in c4_document


def test_graph_rejects_drawio_and_d2_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(
        app,
        ["graph", "--drawio", str(tmp_path / "graph.drawio"), "--d2", str(tmp_path / "graph.d2")],
    )

    assert result.exit_code == 2
    assert "--drawio, --html ou --d2" in result.output


def test_integrations_without_index_exits_with_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["integrations"])

    assert result.exit_code == 2
    assert "Index absent" in result.output


def test_integrations_json_lists_and_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    consume = _make_endpoint("consume", "orders.created", "app/Consumer.java", 7, 9)
    call = _make_endpoint("call", "POST /payments", "app/Consumer.java", 20, 20)
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Consumer.java"], [consume, call])

    result_all = runner.invoke(app, ["integrations", "--json"])
    assert result_all.exit_code == 0
    assert len(json.loads(result_all.output)) == 2

    result_filtered = runner.invoke(app, ["integrations", "--role", "consume", "--json"])
    assert result_filtered.exit_code == 0
    hits = json.loads(result_filtered.output)
    assert len(hits) == 1
    assert hits[0]["topic"] == "orders.created"


def test_integrations_json_filters_by_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    order = _make_endpoint(
        "produce", "orders.created", "order-service/Producer.java", 10, 10, module="order-service"
    )
    payment = _make_endpoint(
        "consume", "orders.created", "payment-service/Consumer.java", 5, 7,
        module="payment-service",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(
            ["order-service/Producer.java", "payment-service/Consumer.java"], [order, payment]
        )

    result = runner.invoke(app, ["integrations", "--module", "order-service", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert len(hits) == 1
    assert hits[0]["module"] == "order-service"
    assert hits[0]["path"] == "order-service/Producer.java"


def test_integrations_text_shows_module_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    endpoint = _make_endpoint(
        "produce", "orders.created", "order-service/Producer.java", 10, 10, module="order-service"
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["order-service/Producer.java"], [endpoint])

    result = runner.invoke(app, ["integrations"])

    assert result.exit_code == 0
    assert "[order-service]" in result.output


def test_integrations_text_reports_none_when_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(app, ["integrations"])

    assert result.exit_code == 0
    assert "Aucune intégration détectée." in result.output


def test_microservices_commands_explore_business_objects_without_source_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    orders = tmp_path / "orders"
    payments = tmp_path / "payments"
    shipping = tmp_path / "shipping"
    orders.mkdir()
    payments.mkdir()
    shipping.mkdir()
    modules = [
        DiscoveredModule(
            name="orders",
            path=orders,
            build_system="maven",
            version="1.0.0",
            kind="library",
            starts_application=True,
            configuration_example="",
            mongo_collections=("orders",),
            openapi_files=("openapi.yml",),
        ),
        DiscoveredModule(
            name="payments",
            path=payments,
            build_system="gradle",
            version=None,
            kind="library",
            starts_application=True,
            configuration_example="",
        ),
        DiscoveredModule(
            name="shipping",
            path=shipping,
            build_system="maven",
            version="1.0.0",
            kind="library",
            starts_application=True,
            configuration_example="",
        ),
    ]

    def endpoint(role: str, system: str, topic: str, module: str, path: str, snippet: str = "") -> MessageEndpoint:
        return MessageEndpoint(
            id=compute_endpoint_id(role, topic, path),
            role=role,
            system=system,
            topic=topic,
            topic_dynamic=False,
            source="code",
            framework="spring",
            path=path,
            start_line=10,
            end_line=10,
            snippet=snippet,
            module=module,
        )

    publish = endpoint("produce", "kafka", "orders.created", "orders", "OrderPublisher.java", "send")
    consume = endpoint("consume", "kafka", "orders.created", "payments", "PaymentConsumer.java", "listen")
    payment_publish = endpoint(
        "produce", "kafka", "payments.accepted", "payments", "PaymentPublisher.java", "send"
    )
    shipping_consume = endpoint(
        "consume", "kafka", "payments.accepted", "shipping", "ShippingConsumer.java", "listen"
    )
    call = endpoint("call", "rest", "POST /payments", "orders", "PaymentClient.java", "http://payments/payments")
    serve = endpoint("serve", "rest", "POST /payments", "payments", "PaymentController.java")
    with Store(tmp_path) as store:
        store.replace_modules(modules)
        store.replace_endpoints_for_files(
            [
                publish.path,
                consume.path,
                payment_publish.path,
                shipping_consume.path,
                call.path,
                serve.path,
            ],
            [publish, consume, payment_publish, shipping_consume, call, serve],
        )

    summary = runner.invoke(app, ["microservices", "show", "orders", "--root", str(tmp_path), "--json"])
    assert summary.exit_code == 0
    summary_payload = json.loads(summary.output)
    assert summary_payload["http_apis_exposed"] == []
    assert summary_payload["http_apis_consumed"] == ["POST /payments"]
    assert summary_payload["kafka_topics_published"] == ["orders.created"]
    assert summary_payload["databases"]["mongodb_collections"] == ["orders"]

    short_summary = runner.invoke(app, ["microservices", "orders", "--json"])
    assert short_summary.exit_code == 0
    assert json.loads(short_summary.output)["name"] == "orders"
    assert json.loads(short_summary.output)["kafka_topics_published"] == ["orders.created"]

    service_topics = runner.invoke(
        app, ["microservices", "topics", "orders", "--root", str(tmp_path), "--json"]
    )
    assert service_topics.exit_code == 0
    assert json.loads(service_topics.output) == {
        "microservice": "orders", "published": ["orders.created"], "consumed": []
    }

    service_resources = runner.invoke(
        app, ["microservices", "apis", "orders", "--root", str(tmp_path), "--json"]
    )
    assert service_resources.exit_code == 0
    assert json.loads(service_resources.output) == {
        "microservice": "orders", "exposed": [], "consumed": ["POST /payments"]
    }

    service_mongodb = runner.invoke(
        app, ["microservices", "mongodb", "orders", "--root", str(tmp_path), "--json"]
    )
    assert service_mongodb.exit_code == 0
    assert json.loads(service_mongodb.output) == {
        "microservice": "orders", "collections": ["orders"]
    }

    mongodb_collections = runner.invoke(app, ["mongodb", "--root", str(tmp_path), "--json"])
    assert mongodb_collections.exit_code == 0
    assert json.loads(mongodb_collections.output) == [
        {"kind": "collection", "name": "orders", "modules": ["orders"], "operations": 0}
    ]

    mongodb_services = runner.invoke(
        app, ["mongodb", "services", "orders", "--root", str(tmp_path), "--json"]
    )
    assert mongodb_services.exit_code == 0
    assert json.loads(mongodb_services.output) == {
        "query": "services", "collection": "orders", "microservices": ["orders"]
    }

    mongodb_search = runner.invoke(
        app, ["mongodb", "search", "ord", "--root", str(tmp_path), "--json"]
    )
    assert mongodb_search.exit_code == 0
    assert json.loads(mongodb_search.output)["resolved"] == "orders"

    topic_neighbors = runner.invoke(
        app, ["topics", "neighbors", "orders.created", "--root", str(tmp_path), "--json"]
    )
    assert topic_neighbors.exit_code == 0
    assert json.loads(topic_neighbors.output) == [
        {"kind": "module", "name": "orders", "relation": "producer"},
        {"kind": "module", "name": "payments", "relation": "consumer"},
    ]

    consumers = runner.invoke(
        app, ["topics", "consumers", "orders.created", "--root", str(tmp_path), "--json"]
    )
    assert consumers.exit_code == 0
    assert json.loads(consumers.output)["microservices"] == ["payments"]

    trace = runner.invoke(
        app, ["topics", "trace", "orders.created", "--root", str(tmp_path), "--json"]
    )
    assert trace.exit_code == 0
    trace_payload = json.loads(trace.output)
    assert trace_payload["kind"] == "potential_topic_flows"
    assert trace_payload["flows"] == [
        {
            "nodes": [
                {"kind": "topic", "name": "orders.created"},
                {"kind": "microservice", "name": "payments"},
                {"kind": "topic", "name": "payments.accepted"},
                {"kind": "microservice", "name": "shipping"},
            ]
        }
    ]
    assert "hypothèses" in trace_payload["caveat"]

    shallow_trace = runner.invoke(
        app,
        [
            "topics",
            "trace",
            "orders.created",
            "--max-depth",
            "1",
            "--root",
            str(tmp_path),
            "--json",
        ],
    )
    assert shallow_trace.exit_code == 0
    assert json.loads(shallow_trace.output)["flows"] == [
        {
            "nodes": [
                {"kind": "topic", "name": "orders.created"},
                {"kind": "microservice", "name": "payments"},
            ]
        }
    ]

    cycle_publish = endpoint(
        "produce", "kafka", "orders.created", "shipping", "ShippingPublisher.java", "send"
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(
            [cycle_publish.path], [cycle_publish]
        )
    cyclic_trace = runner.invoke(
        app, ["topics", "trace", "orders.created", "--root", str(tmp_path), "--json"]
    )
    assert cyclic_trace.exit_code == 0
    assert json.loads(cyclic_trace.output)["flows"] == [
        {
            "nodes": [
                {"kind": "topic", "name": "orders.created"},
                {"kind": "microservice", "name": "payments"},
                {"kind": "topic", "name": "payments.accepted"},
                {"kind": "microservice", "name": "shipping"},
                {"kind": "topic", "name": "orders.created"},
            ],
            "cycle_detected": True,
        }
    ]

    topic_search = runner.invoke(
        app, ["topics", "search", "created", "--root", str(tmp_path), "--json"]
    )
    assert topic_search.exit_code == 0
    assert json.loads(topic_search.output)["resolved"] == "orders.created"

    resource_search = runner.invoke(
        app, ["apis", "search", "payments", "--root", str(tmp_path), "--json"]
    )
    assert resource_search.exit_code == 0
    assert json.loads(resource_search.output)["resolved"] == "POST /payments"

    api_providers = runner.invoke(
        app, ["apis", "providers", "POST /payments", "--root", str(tmp_path), "--json"]
    )
    assert api_providers.exit_code == 0
    assert json.loads(api_providers.output) == {
        "query": "providers", "api": "POST /payments", "microservices": ["payments"]
    }

    monkeypatch.setattr(
        "ccc_radar.cli.load_config", lambda _root: SimpleNamespace(embedding_model="test-model")
    )
    monkeypatch.setattr("ccc_radar.cli.make_embedder", lambda _model: object())
    monkeypatch.setattr(
        "ccc_radar.cli.resolve_topic_by_similarity",
        lambda _store, _embedder, _query, endpoints: endpoints[0].topic,
    )
    semantic_topic_search = runner.invoke(
        app, ["topics", "search", "publication de commande", "--root", str(tmp_path), "--json"]
    )
    assert semantic_topic_search.exit_code == 0
    assert json.loads(semantic_topic_search.output)["resolved"] == "orders.created"

    semantic_resource_search = runner.invoke(
        app, ["apis", "search", "encaissement", "--root", str(tmp_path), "--json"]
    )
    assert semantic_resource_search.exit_code == 0
    assert json.loads(semantic_resource_search.output)["resolved"] == "POST /payments"

    implementation = runner.invoke(
        app, ["microservices", "implementation", "integration", publish.id, "--root", str(tmp_path), "--json"]
    )
    assert implementation.exit_code == 0
    assert json.loads(implementation.output)["implementation"]["snippet"] == "send"


@pytest.mark.integration
def test_graph_and_integrations_reflect_a_real_cccr_index_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-11 A1 CA4 : cccr graph/endpoints reflètent une indexation
    standard (init + index), sans fixture injectée directement dans le
    store — le scénario de OrderConsumer.java (@KafkaListener contenant un
    appel RestTemplate) doit ressortir de bout en bout."""
    dest = tmp_path / "endpoint_index_repo"
    shutil.copytree(ENDPOINT_INDEX_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    index_result = runner.invoke(app, ["index"])
    assert index_result.exit_code == 0

    endpoints_result = runner.invoke(app, ["integrations", "--json"])
    assert endpoints_result.exit_code == 0
    endpoints = json.loads(endpoints_result.output)
    assert {e["role"] for e in endpoints} == {"consume", "call"}

    graph_result = runner.invoke(app, ["graph", "--json"])
    assert graph_result.exit_code == 0
    data = json.loads(graph_result.output)
    assert data["services"] == []
    assert data["edges"] == []
    assert len(data["outbound_calls_in_consumers"]) == 1
    hit = data["outbound_calls_in_consumers"][0]
    assert hit["consumer"]["topic"] == "orders.created"
    assert hit["call"]["topic"] == "POST /charge"

    # le finding "ordinaire" (System.out.println) est bien resté un finding,
    # pas un endpoint fuité dans la table findings (ni l'inverse) : 1 seul
    # finding au total, les 2 résultats endpoint-inventory n'y apparaissent pas.
    summary_result = runner.invoke(app, ["summary", "--json"])
    assert summary_result.exit_code == 0
    assert sum(json.loads(summary_result.output)["by_severity"].values()) == 1


def test_microservices_lists_only_runtime_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "maven_workspace"
    shutil.copytree(MAVEN_WORKSPACE, dest)
    with Store(dest / "service-a"):
        pass  # crée .cccr/findings.db, vide

    result = runner.invoke(app, ["microservices", str(dest), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    # Les modules Maven sans point d'entrée Spring Boot ne sont pas des
    # microservices, même si une base .cccr locale existe.
    assert data == {"services": [], "warnings": []}


def test_microservices_text_reports_no_modules_for_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    result = runner.invoke(app, ["microservices", str(empty)])

    assert result.exit_code == 0
    assert "Aucun service workspace découvert" in result.output


def test_microservices_defaults_to_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "maven_workspace"
    shutil.copytree(MAVEN_WORKSPACE, dest)
    monkeypatch.chdir(dest)
    with Store(dest / "service-a"):
        pass

    result = runner.invoke(app, ["microservices", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data == {"services": [], "warnings": []}


def test_microservices_discovers_gradle_services(tmp_path: Path) -> None:
    project = tmp_path / "billing-service" / "billing-service-main"
    (project / "build.gradle").parent.mkdir(parents=True)
    (project / "build.gradle").write_text("archivesName = 'billing-service'\n")
    service = project / "src" / "main" / "java"
    service.mkdir(parents=True)
    (service / "BillingServiceMain.java").write_text(
        """
import org.springframework.boot.SpringApplication;

public class BillingServiceMain {
    public static void main(String[] args) {
        SpringApplication.run(BillingServiceMain.class, args);
    }
}
""".strip()
    )
    module = DiscoveredModule(
        name="billing-service",
        path=project,
        build_system="gradle",
        version=None,
        kind="library",
        starts_application=True,
        configuration_example="",
        mongo_collections=("invoices",),
    )
    endpoints = [
        MessageEndpoint(
            id="serve", role="serve", system="rest", topic="POST /invoices", topic_dynamic=False,
            source="code", framework="spring", path="InvoiceController.java", start_line=1,
            end_line=1, snippet="", module="billing-service",
        ),
        MessageEndpoint(
            id="publish", role="produce", system="kafka", topic="invoices.created", topic_dynamic=False,
            source="code", framework="spring", path="InvoicePublisher.java", start_line=1,
            end_line=1, snippet="", module="billing-service",
        ),
        MessageEndpoint(
            id="consume", role="consume", system="kafka", topic="payments.received", topic_dynamic=False,
            source="code", framework="spring", path="PaymentConsumer.java", start_line=1,
            end_line=1, snippet="", module="billing-service",
        ),
    ]
    with Store(tmp_path) as store:
        store.replace_modules([module])
        store.replace_endpoints_for_files([endpoint.path for endpoint in endpoints], endpoints)

    result = runner.invoke(app, ["microservices", str(tmp_path), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["services"] == [
        {
            "name": "billing-service",
            "kind": "microservice",
            "starts_application": True,
            "indexed": True,
            "integration_count": 3,
            "finding_count": 0,
            "exposes_http_api": True,
            "http_apis_exposed": ["POST /invoices"],
            "http_apis_consumed": [],
            "kafka_topics_published": ["invoices.created"],
            "kafka_topics_consumed": ["payments.received"],
            "mongo_collections": ["invoices"],
        }
    ]

    text_result = runner.invoke(app, ["microservices", str(tmp_path)])
    assert text_result.exit_code == 0
    assert "HTTP exposées: POST /invoices" in text_result.output
    assert "Kafka publiés: invoices.created" in text_result.output
    assert "Kafka consommés: payments.received" in text_result.output
    assert "Mongo: invoices" in text_result.output


def test_microservices_service_subcommands_render_apis_and_properties(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    service_a = workspace / "service-a"
    service_b = workspace / "service-b"
    for service, artifact, class_name in (
        (service_a, "order-service", "OrderApplication"),
        (service_b, "payment-service", "PaymentApplication"),
    ):
        (service / "src" / "main" / "java").mkdir(parents=True)
        (service / "pom.xml").write_text(
            f"<project><artifactId>{artifact}</artifactId></project>"
        )
        (service / "src" / "main" / "java" / f"{class_name}.java").write_text(
            "import org.springframework.boot.SpringApplication;\n"
            f"class {class_name} {{ static void main(String[] args) {{ "
            f"SpringApplication.run({class_name}.class, args); }} }}\n"
        )
    (service_a / "src" / "main" / "resources").mkdir(parents=True)
    (service_a / "src" / "main" / "resources" / "application.yml").write_text("server:\n  port: 8081\n")
    (service_a / "src" / "main" / "resources" / "openapi.yml").write_text("openapi: 3.0.0\npaths: {}\n")
    call = MessageEndpoint(
        id="call", role="call", system="rest", topic="GET /payments", topic_dynamic=False,
        source="code", framework="resttemplate", path="OrderClient.java", start_line=10,
            end_line=10, snippet="restTemplate.getForObject(\"http://payment-service/payments\")", module="order-service",
    )
    serve = MessageEndpoint(
        id="serve", role="serve", system="rest", topic="GET /payments", topic_dynamic=False,
        source="code", framework="spring", path="PaymentController.java", start_line=5,
        end_line=5, snippet="", module="payment-service",
    )
    with Store(service_a) as store:
        store.replace_endpoints_for_files([call.path], [call])
    with Store(service_b) as store:
        store.replace_endpoints_for_files([serve.path], [serve])

    resources_by_service = runner.invoke(
        app, ["microservices", "apis", "order-service", "--root", str(workspace), "--json"]
    )
    assert resources_by_service.exit_code == 0
    assert json.loads(resources_by_service.output) == {
        "microservice": "order-service", "exposed": [], "consumed": ["GET /payments"]
    }

    api_consumers = runner.invoke(
        app, ["apis", "consumers", "GET /payments", "--root", str(workspace), "--json"]
    )
    assert api_consumers.exit_code == 0
    assert json.loads(api_consumers.output) == {
        "query": "consumers", "api": "GET /payments", "microservices": ["order-service"]
    }

    properties = runner.invoke(app, ["microservices", "properties", "order-service", "--root", str(workspace), "--json"])
    assert properties.exit_code == 0
    assert "Aucune propriété Spring détectée" in json.loads(properties.output)["properties_example"]

    openapi = runner.invoke(app, ["microservices", "openapi", "order-service", "--root", str(workspace), "--json"])
    assert openapi.exit_code == 0
    assert json.loads(openapi.output)["contracts"] == [
        {"path": "src/main/resources/openapi.yml", "content": "openapi: 3.0.0\npaths: {}\n"}
    ]


def test_workspace_command_is_no_longer_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["workspace"])

    assert result.exit_code != 0
    assert "No such command 'workspace'" in result.output


def test_index_falls_back_to_local_default_model_when_config_uses_remote_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "app.py").write_text("print('hello')\n")
    local_model = tmp_path / "local-model"
    local_model.mkdir()
    monkeypatch.setattr(embedder_module, "DEFAULT_EMBEDDING_MODEL", str(local_model))
    (tmp_path / ".cccr").mkdir()
    (tmp_path / ".cccr" / "config.yml").write_text(
        "rules:\n  - rules/rules.yml\nembedding_model: Snowflake/snowflake-arctic-embed-xs\n"
    )
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "rules.yml").write_text("rules: []\n")

    result = runner.invoke(app, ["index"])

    assert result.exit_code == 0
    assert "Snowflake/snowflake-arctic-embed-xs" in result.output
    with Store(tmp_path) as store:
        assert store.get_meta("embedding_model") == str(local_model)


def test_graph_json_reports_stale_endpoint_inventory_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    endpoint = MessageEndpoint(
        id=compute_endpoint_id("consume", "orders.created", "app/Consumer.java", 5, 7),
        role="consume",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework="spring-kafka",
        path="app/Consumer.java",
        start_line=5,
        end_line=7,
        snippet="",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Consumer.java"], [endpoint])
        store.set_meta("endpoint_inventory_signature", "endpoint-inventory-v0")

    result = runner.invoke(app, ["graph", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "inventaire des intégrations potentiellement obsolète" in payload["note"]
