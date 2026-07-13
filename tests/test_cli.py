import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app
from cccf.models import MessageEndpoint, compute_endpoint_id
from cccf.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"
ENDPOINT_INDEX_REPO = FIXTURES_DIR / "endpoint_index_repo"

runner = CliRunner()


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

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "p/security-audit" in result.output
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert "p/security-audit" in config_content


@pytest.mark.integration
def test_index_with_default_registry_pack_succeeds_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
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
    assert "scanned=" in index_result.output


def test_init_with_explicit_rules_takes_priority_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert "rules/rules.yml" in config_content
    assert "p/security-audit" not in config_content


def test_init_detects_local_semgrep_config_over_default_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".semgrep.yml").write_text("rules: []\n")

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    config_content = (tmp_path / ".cccf" / "config.yml").read_text()
    assert ".semgrep.yml" in config_content
    assert "p/security-audit" not in config_content


@pytest.mark.integration
def test_init_with_rules_then_index_reports_correctly(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

    init_result = runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    assert init_result.exit_code == 0
    assert (repo_copy / ".cccf" / "config.yml").is_file()

    index_result = runner.invoke(app, ["index"])

    assert index_result.exit_code == 0
    assert "scanned=" in index_result.output
    assert "+findings=4" in index_result.output
    assert "-findings=0" in index_result.output


@pytest.mark.integration
def test_index_twice_second_run_scans_nothing(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

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
    assert "Index absent. Lancez d'abord: cccf index" in result.output


@pytest.mark.integration
def test_findings_json_output_matches_contract(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
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
def test_findings_context_includes_offending_source_line(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(
        app, ["findings", "injection sql", "--path", "app/db.py", "--context", "--json"]
    )

    hits = json.loads(result.output)
    assert "cursor.execute" in hits[0]["context"]


def test_search_renders_ccc_format_with_findings_blocks(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cccf search` répond « de la même manière » que ccc : même format de
    résultats, enrichi d'un bloc findings sous les résultats concernés, le
    finding ERROR faisant remonter app/db.py devant app/other.py."""
    monkeypatch.chdir(tmp_path)
    from cccf.models import Finding
    from cccf.store import Store

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
    from cccf.store import Store

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
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
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


@pytest.mark.integration
def test_summary_json_has_expected_structure(
    repo_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])

    result = runner.invoke(app, ["summary", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["by_severity"] == {"ERROR": 2, "WARNING": 2}


def _make_endpoint(role: str, topic: str, path: str, start_line: int, end_line: int) -> MessageEndpoint:
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
    assert len(data["outbound_calls_in_consumers"]) == 1
    hit = data["outbound_calls_in_consumers"][0]
    assert hit["call"]["topic"] == "POST /payments"
    assert hit["consumer"]["topic"] == "orders.created"
    assert data["cycles"] == []
    assert data["hotspots"] == []
    assert "K7" in data["note"]


def test_graph_text_reports_no_outbound_calls_when_none_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass  # crée .cccf/findings.db, vide

    result = runner.invoke(app, ["graph"])

    assert result.exit_code == 0
    assert "Aucun appel REST détecté dans un handler Kafka." in result.output


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
def test_graph_and_endpoints_reflect_a_real_cccf_index_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-11 A1 CA4 : cccf graph/endpoints reflètent une indexation
    standard (init + index), sans fixture injectée directement dans le
    store — le scénario de OrderConsumer.java (@KafkaListener contenant un
    appel RestTemplate) doit ressortir de bout en bout."""
    dest = tmp_path / "endpoint_index_repo"
    shutil.copytree(ENDPOINT_INDEX_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")

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
