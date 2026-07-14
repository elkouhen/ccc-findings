import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import ccc_radar.embedder as embedder_module
import ccc_radar.render as render_module
from ccc_radar.cli import DEFAULT_RULE_PACKS, app
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"
ENDPOINT_INDEX_REPO = FIXTURES_DIR / "endpoint_index_repo"
MAVEN_WORKSPACE = FIXTURES_DIR / "maven_workspace"

runner = CliRunner()


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
    assert len(hits) == 4
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
    résultats, enrichi d'un bloc findings sous les résultats concernés, le
    finding ERROR faisant remonter app/db.py devant app/other.py."""
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
    # score affiché = score sémantique brut de ccc (0.850) ; le boost ERROR
    # n'affecte que l'ordre, pas la valeur rapportée
    assert "--- Result 1 (score: 0.850) ---" in result.output
    assert "File: app/db.py:6-6 [python]" in result.output
    assert "findings (max: ERROR)" in result.output
    assert "custom.sql-fstring" in result.output
    # le résultat sans finding est rendu sans bloc findings, après le boosté
    assert result.output.index("app/db.py:6-6") < result.output.index("app/other.py:1-1")


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
def test_search_prefers_experimental_indexed_code_when_available(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    index_result = runner.invoke(app, ["index", "--engine", "cocoindex"])
    assert index_result.exit_code == 0

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
    # search_code_with_findings sur-demande à ccc (overfetch_limit(3) == 9) pour
    # le classement par sévérité ; les autres flags sont transmis tels quels.
    assert "ARGS:search auth --limit 9 --offset 2 --lang python --path app/* --refresh" in result.output


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
    assert data["cycles"] == []
    assert data["hotspots"] == []
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
    assert "soit --drawio, soit --d2" in result.output


def test_endpoints_without_index_exits_with_code_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["endpoints"])

    assert result.exit_code == 2
    assert "Index absent" in result.output


def test_endpoints_json_lists_and_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    consume = _make_endpoint("consume", "orders.created", "app/Consumer.java", 7, 9)
    call = _make_endpoint("call", "POST /payments", "app/Consumer.java", 20, 20)
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Consumer.java"], [consume, call])

    result_all = runner.invoke(app, ["endpoints", "--json"])
    assert result_all.exit_code == 0
    assert len(json.loads(result_all.output)) == 2

    result_filtered = runner.invoke(app, ["endpoints", "--role", "consume", "--json"])
    assert result_filtered.exit_code == 0
    hits = json.loads(result_filtered.output)
    assert len(hits) == 1
    assert hits[0]["topic"] == "orders.created"


def test_endpoints_json_filters_by_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    result = runner.invoke(app, ["endpoints", "--module", "order-service", "--json"])

    assert result.exit_code == 0
    hits = json.loads(result.output)
    assert len(hits) == 1
    assert hits[0]["module"] == "order-service"
    assert hits[0]["path"] == "order-service/Producer.java"


def test_endpoints_text_shows_module_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    endpoint = _make_endpoint(
        "produce", "orders.created", "order-service/Producer.java", 10, 10, module="order-service"
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["order-service/Producer.java"], [endpoint])

    result = runner.invoke(app, ["endpoints"])

    assert result.exit_code == 0
    assert "[order-service]" in result.output


def test_endpoints_text_reports_none_when_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    result = runner.invoke(app, ["endpoints"])

    assert result.exit_code == 0
    assert "Aucun endpoint indexé." in result.output


@pytest.mark.integration
def test_graph_and_endpoints_reflect_a_real_cccr_index_run(
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

    endpoints_result = runner.invoke(app, ["endpoints", "--json"])
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


def test_microservices_discovers_maven_modules_and_flags_unindexed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "maven_workspace"
    shutil.copytree(MAVEN_WORKSPACE, dest)
    with Store(dest / "service-a"):
        pass  # crée .cccr/findings.db, vide

    result = runner.invoke(app, ["microservices", str(dest), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    by_name = {s["name"]: s for s in data["services"]}
    assert by_name["order-service"]["kind"] == "microservice"
    assert by_name["order-service"]["indexed"] is True
    assert by_name["common-lib"]["kind"] == "shared-module"
    assert any("payment-service" in w for w in data["warnings"])


def test_microservices_text_reports_no_modules_for_empty_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    result = runner.invoke(app, ["microservices", str(empty)])

    assert result.exit_code == 0
    assert "Aucun module Maven découvert" in result.output


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
    by_name = {s["name"]: s for s in data["services"]}
    assert by_name["order-service"]["kind"] == "microservice"


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
    assert "inventaire d'endpoints potentiellement obsolète" in payload["note"]
