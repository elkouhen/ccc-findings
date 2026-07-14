import asyncio
import shutil
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from typer.testing import CliRunner

from ccc_radar.cli import app
from ccc_radar.flow import FlowError
from ccc_radar.mcp_server import (
    findings_summary,
    graph,
    list_endpoints,
    list_workspace_services,
    mcp,
    reindex_findings,
    search_findings,
    trace_message_flow,
)
from ccc_radar.models import Finding, MessageEndpoint, compute_endpoint_id
from ccc_radar.inventory_freshness import current_endpoint_inventory_signature
from ccc_radar.store import Store

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULN_REPO = FIXTURES_DIR / "vuln_repo"
MAVEN_WORKSPACE = FIXTURES_DIR / "maven_workspace"

runner = CliRunner()


@pytest.fixture
def indexed_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    dest = tmp_path / "vuln_repo"
    shutil.copytree(VULN_REPO, dest)
    monkeypatch.chdir(dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    runner.invoke(app, ["index"])
    return dest


@pytest.mark.integration
def test_search_findings_tool_returns_expected_json(indexed_repo: Path) -> None:
    result = search_findings("injection sql")

    assert len(result) == 4
    assert {"id", "rule_id", "severity", "path", "score"} <= set(result[0].keys())


@pytest.mark.integration
def test_search_findings_tool_hybrid_matches_exact_rule_id(indexed_repo: Path) -> None:
    result = search_findings("custom.subprocess-shell-true")

    assert result[0]["rule_id"].endswith("custom.subprocess-shell-true")


@pytest.mark.integration
def test_search_findings_tool_rejects_invalid_severity(indexed_repo: Path) -> None:
    """BACKLOG-16 P4 : côté MCP aussi, une sévérité invalide doit lever une
    erreur métier propre (`SearchError`), pas un `ValueError` non géré."""
    from ccc_radar.search import SearchError

    with pytest.raises(SearchError, match="HIGH"):
        search_findings("injection sql", severity="HIGH")


@pytest.mark.integration
def test_findings_summary_tool_returns_expected_json(indexed_repo: Path) -> None:
    result = findings_summary()

    assert result["by_severity"] == {"ERROR": 2, "WARNING": 2}


@pytest.mark.integration
def test_reindex_findings_tool_returns_report(indexed_repo: Path) -> None:
    result = reindex_findings()

    assert result.scanned == 0
    assert result.findings_added == 0


@pytest.mark.integration
def test_reindex_findings_tool_refreshes_code_chunks_on_cocoindex_engine(
    indexed_repo: Path,
) -> None:
    """BACKLOG-16 P3 : un repo indexé avec `--engine cocoindex` doit voir
    ses chunks de code rafraîchis par `reindex_findings` (MCP), pas
    seulement ses findings — sinon `search` (MCP) sert un contenu de chunk
    périmé après modification d'un fichier."""
    reindex_result = runner.invoke(app, ["index", "--engine", "cocoindex"])
    assert reindex_result.exit_code == 0

    db_path = indexed_repo / "app" / "db.py"
    db_path.write_text(db_path.read_text() + "\n\ndef new_marker(): pass\n")

    result = reindex_findings()
    assert result.scanned == 1

    with Store(indexed_repo) as store:
        chunk_contents = "\n".join(
            chunk.content for chunk in store.all_code_chunks() if chunk.path == "app/db.py"
        )
    assert "new_marker" in chunk_contents


def test_search_findings_tool_on_unindexed_repo_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(RuntimeError, match="Index absent"):
        search_findings("injection sql")


def test_search_findings_tool_on_unindexed_repo_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Going through the actual MCP dispatch (not the bare Python function): a
    failing tool must raise ToolError, which the protocol layer turns into
    `isError: true` — not a `{"error": ...}` payload disguised as success."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolError, match="Index absent"):
        asyncio.run(mcp.call_tool("search_findings", {"query": "injection sql"}))

    # le serveur reste utilisable ensuite, sans crash
    with pytest.raises(ToolError):
        asyncio.run(mcp.call_tool("findings_summary", {}))


def test_mcp_help_documents_client_registration_block() -> None:
    result = runner.invoke(app, ["mcp", "--help"])

    assert result.exit_code == 0
    assert '{"mcpServers": {"cccr": {"command": "cccr", "args": ["mcp"]}}}' in result.output


@pytest.mark.integration
def test_search_tool_is_exposed_under_the_same_name_as_ccc(
    fake_ccc_two_results_on_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cccr's code-search MCP tool must be named `search`, like ccc's own
    tool — not `search_code_with_findings` — so both take the same name."""
    monkeypatch.chdir(tmp_path)

    result = asyncio.run(mcp.call_tool("search", {"query": "auth"}))

    assert result[1]["results"]


def test_graph_tool_returns_outbound_calls_in_kafka_consumer_handlers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    consumer = MessageEndpoint(
        id=compute_endpoint_id(
            "consume", "orders.created", "app/OrderConsumer.java", 15, 25
        ),
        role="consume",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework=None,
        path="app/OrderConsumer.java",
        start_line=15,
        end_line=25,
        snippet="",
    )
    call = MessageEndpoint(
        id=compute_endpoint_id(
            "call", "POST /payments", "app/OrderConsumer.java", 20, 20
        ),
        role="call",
        system="rest",
        topic="POST /payments",
        topic_dynamic=False,
        source="code",
        framework="resttemplate",
        path="app/OrderConsumer.java",
        start_line=20,
        end_line=20,
        snippet="",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/OrderConsumer.java"], [consumer, call])

    result = graph()

    assert result["services"] == []
    assert result["edges"] == []
    assert len(result["outbound_calls_in_consumers"]) == 1
    assert result["outbound_calls_in_consumers"][0]["call"]["topic"] == "POST /payments"


def test_graph_tool_on_unindexed_repo_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolError, match="Index absent"):
        asyncio.run(mcp.call_tool("graph", {}))


def test_list_endpoints_tool_filters_by_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    consume = MessageEndpoint(
        id=compute_endpoint_id("consume", "orders.created", "app/Consumer.java", 7, 9),
        role="consume",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework="spring-kafka",
        path="app/Consumer.java",
        start_line=7,
        end_line=9,
        snippet="",
    )
    call = MessageEndpoint(
        id=compute_endpoint_id("call", "POST /payments", "app/Consumer.java", 20, 20),
        role="call",
        system="rest",
        topic="POST /payments",
        topic_dynamic=False,
        source="code",
        framework="resttemplate",
        path="app/Consumer.java",
        start_line=20,
        end_line=20,
        snippet="",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Consumer.java"], [consume, call])

    result = list_endpoints(role="consume")

    assert len(result) == 1
    assert result[0]["topic"] == "orders.created"


def test_list_endpoints_tool_on_unindexed_repo_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolError, match="Index absent"):
        asyncio.run(mcp.call_tool("list_endpoints", {}))


def test_list_workspace_services_tool_discovers_and_flags_unindexed(tmp_path: Path) -> None:
    dest = tmp_path / "maven_workspace"
    shutil.copytree(MAVEN_WORKSPACE, dest)
    with Store(dest / "service-a"):
        pass

    result = list_workspace_services(str(dest))

    by_name = {s["name"]: s for s in result["services"]}
    assert by_name["order-service"]["indexed"] is True
    assert by_name["common-lib"]["kind"] == "shared-module"
    assert any("payment-service" in w for w in result["warnings"])


@pytest.mark.integration
def test_graph_tool_with_workspace_root_reports_a_real_cross_service_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Le graphe MCP fédéré remonte bien la topologie inter-services."""
    from ccc_radar.cli import app as cli_app

    rest_cycle_workspace = FIXTURES_DIR / "rest_cycle_workspace"
    dest = tmp_path / "rest_cycle_workspace"
    shutil.copytree(rest_cycle_workspace, dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    for service in ("service-x", "service-y", "service-z"):
        monkeypatch.chdir(dest / service)
        runner.invoke(cli_app, ["init", "--rules", "rules/java.yaml"])
        index_result = runner.invoke(cli_app, ["index"])
        assert index_result.exit_code == 0

    monkeypatch.chdir(dest / "service-x")
    result = graph(workspace_root=str(dest))

    assert set(result["services"]) == {"service-x", "service-y", "service-z"}
    assert len(result["edges"]) == 3
    assert {edge["label"] for edge in result["edges"]} == {
        "GET /x-status",
        "GET /y-status",
        "GET /z-status",
    }
    assert result["note"] == ""


def test_trace_message_flow_tool_lists_sites_with_overlapping_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    produce = MessageEndpoint(
        id=compute_endpoint_id("produce", "orders.created", "app/Producer.java", 10, 10),
        role="produce",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework="spring-kafka",
        path="app/Producer.java",
        start_line=10,
        end_line=10,
        snippet="",
    )
    consume = MessageEndpoint(
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
    finding = Finding(
        id="finding-1",
        rule_id="cccr.demo.fire-and-forget",
        severity="WARNING",
        message="message",
        path="app/Producer.java",
        start_line=10,
        end_line=10,
        snippet="",
        fix=None,
        cwe=[],
        owasp=[],
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Producer.java", "app/Consumer.java"], [produce, consume])
        store.replace_findings_for_files(["app/Producer.java"], [finding])
        store.set_meta("endpoint_inventory_signature", current_endpoint_inventory_signature())

    result = trace_message_flow("orders.created")

    assert result["resolved_topic"] == "orders.created"
    by_path = {site["path"]: site for site in result["sites"]}
    assert by_path["app/Producer.java"]["finding_rule_ids"] == ["cccr.demo.fire-and-forget"]
    assert by_path["app/Consumer.java"]["finding_rule_ids"] == []
    assert result["warnings"] == []


def test_trace_message_flow_tool_reports_stale_endpoint_inventory_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    produce = MessageEndpoint(
        id=compute_endpoint_id("produce", "orders.created", "app/Producer.java", 10, 10),
        role="produce",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework="spring-kafka",
        path="app/Producer.java",
        start_line=10,
        end_line=10,
        snippet="",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Producer.java"], [produce])
        store.set_meta("endpoint_inventory_signature", "endpoint-inventory-v0")

    result = trace_message_flow("orders.created")

    assert any("inventaire d'endpoints potentiellement obsolète" in w for w in result["warnings"])


def test_trace_message_flow_tool_falls_back_to_similarity_when_textual_resolution_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-10 K3 : substitue `resolve_topic_by_similarity` (déjà testée
    isolément avec des vecteurs contrôlés dans tests/test_flow.py) pour
    vérifier le câblage sans dépendre d'un embedder réel/faux sur du texte
    arbitraire."""
    import ccc_radar.mcp_server as mcp_server_module

    monkeypatch.chdir(tmp_path)
    produce = MessageEndpoint(
        id=compute_endpoint_id("produce", "orders.created", "app/Producer.java", 10, 10),
        role="produce",
        system="kafka",
        topic="orders.created",
        topic_dynamic=False,
        source="code",
        framework="spring-kafka",
        path="app/Producer.java",
        start_line=10,
        end_line=10,
        snippet="",
    )
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/Producer.java"], [produce])

    runner.invoke(app, ["init", "--rules", "rules/rules.yml"])
    monkeypatch.setattr(
        mcp_server_module, "resolve_topic_by_similarity", lambda *a, **kw: "orders.created"
    )

    result = trace_message_flow("who creates an order")

    assert result["resolved_topic"] == "orders.created"


def test_trace_message_flow_tool_unknown_query_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    with pytest.raises(FlowError):
        trace_message_flow("does-not-exist")


def test_trace_message_flow_tool_on_unindexed_repo_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ToolError, match="Index absent"):
        asyncio.run(mcp.call_tool("trace_message_flow", {"query": "orders.created"}))


def test_trace_message_flow_tool_unknown_query_surfaces_as_mcp_tool_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with Store(tmp_path):
        pass

    with pytest.raises(ToolError):
        asyncio.run(mcp.call_tool("trace_message_flow", {"query": "does-not-exist"}))


@pytest.mark.integration
def test_trace_message_flow_tool_with_workspace_root_traces_across_services(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-10 K6 : trace_message_flow(workspace_root=...) relie un
    producteur et un consommateur fédérés depuis deux services indexés
    séparément (même fixture que tests/test_k5_flow_e2e.py, côté CLI)."""
    kafka_workspace = FIXTURES_DIR / "kafka_workspace"
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(kafka_workspace, dest)
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")
    for service in ("order-service", "payment-service"):
        monkeypatch.chdir(dest / service)
        runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
        index_result = runner.invoke(app, ["index"])
        assert index_result.exit_code == 0

    monkeypatch.chdir(dest / "order-service")
    result = trace_message_flow("orders.created", workspace_root=str(dest))

    services = {site["service"] for site in result["sites"]}
    assert services == {"order-service", "payment-service"}
