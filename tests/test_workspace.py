import shutil
from pathlib import Path

import pytest

from cccf.models import Finding, MessageEndpoint, compute_endpoint_id, compute_finding_id
from cccf.store import Store, StoreError
from cccf.workspace import discover_maven_services, load_federation

FIXTURES_DIR = Path(__file__).parent / "fixtures"
MAVEN_WORKSPACE = FIXTURES_DIR / "maven_workspace"


@pytest.fixture
def workspace_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "maven_workspace"
    shutil.copytree(MAVEN_WORKSPACE, dest)
    return dest


def make_endpoint(role: str, system: str, topic: str, path: str) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, path, 1, 1),
        role=role,
        system=system,
        topic=topic,
        topic_dynamic=False,
        source="code",
        framework=None,
        path=path,
        start_line=1,
        end_line=1,
        snippet="",
    )


def make_finding(path: str, severity: str) -> Finding:
    return Finding(
        id=compute_finding_id("custom.rule", path, "snippet", 1, 1),
        rule_id="custom.rule",
        severity=severity,
        message="msg",
        path=path,
        start_line=1,
        end_line=1,
        snippet="snippet",
        fix=None,
        cwe=[],
        owasp=[],
    )


# -- discover_maven_services --


def test_discover_maven_services_names_kinds_and_ignores_non_maven_dirs(
    workspace_copy: Path,
) -> None:
    services = discover_maven_services(workspace_copy)

    by_name = {s.name: s for s in services}
    assert set(by_name) == {"order-service", "payment-service", "common-lib"}
    assert by_name["order-service"].kind == "microservice"
    assert by_name["payment-service"].kind == "microservice"
    assert by_name["common-lib"].kind == "shared-module"
    assert all(not s.indexed for s in services)  # rien n'a encore été indexé


def test_discover_maven_services_detects_indexed_projects(workspace_copy: Path) -> None:
    with Store(workspace_copy / "service-a"):
        pass  # crée .cccf/findings.db

    services = discover_maven_services(workspace_copy)

    by_name = {s.name: s for s in services}
    assert by_name["order-service"].indexed is True
    assert by_name["payment-service"].indexed is False


def test_discover_maven_services_falls_back_to_directory_name_on_broken_pom(
    tmp_path: Path,
) -> None:
    module = tmp_path / "broken-module"
    module.mkdir()
    (module / "pom.xml").write_text("not even xml <<<")

    services = discover_maven_services(tmp_path)

    assert len(services) == 1
    assert services[0].name == "broken-module"
    assert services[0].kind == "shared-module"


# -- load_federation --


def test_load_federation_reads_microservices_and_flags_unindexed(workspace_copy: Path) -> None:
    endpoint = make_endpoint("serve", "rest", "GET /orders", "app/OrderController.java")
    with Store(workspace_copy / "service-a") as store:
        store.replace_endpoints_for_files(["app/OrderController.java"], [endpoint])

    services = discover_maven_services(workspace_copy)
    result = load_federation(services)

    assert [e.topic for e in result.endpoints_by_service["order-service"]] == ["GET /orders"]
    assert "payment-service" not in result.endpoints_by_service
    assert any("payment-service" in w and "non indexé" in w for w in result.warnings)


def test_load_federation_includes_shared_module_findings_but_not_endpoints(
    workspace_copy: Path,
) -> None:
    finding = make_finding("src/main/java/Util.java", "WARNING")
    with Store(workspace_copy / "shared-lib") as store:
        store.replace_findings_for_files(["src/main/java/Util.java"], [finding])

    services = discover_maven_services(workspace_copy)
    result = load_federation(services)

    assert len(result.findings_by_service["common-lib"]) == 1
    # un module partagé n'est jamais une source d'endpoints (A2 CA5), même
    # indexé
    assert "common-lib" not in result.endpoints_by_service


def test_load_federation_reports_incompatible_schema_as_warning_not_crash(
    workspace_copy: Path,
) -> None:
    db_path = workspace_copy / "service-a" / ".cccf" / "findings.db"
    db_path.parent.mkdir(parents=True)
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO meta VALUES ('schema_version', '1')")
    conn.commit()
    conn.close()

    services = discover_maven_services(workspace_copy)
    result = load_federation(services)

    assert "order-service" not in result.endpoints_by_service
    assert any("order-service" in w for w in result.warnings)


# -- Store(readonly=True) --


def test_readonly_store_reads_without_writing(tmp_path: Path) -> None:
    endpoint = make_endpoint("produce", "kafka", "orders.created", "app/P.java")
    with Store(tmp_path) as store:
        store.replace_endpoints_for_files(["app/P.java"], [endpoint])

    with Store(tmp_path, readonly=True) as store:
        endpoints = store.all_endpoints()
        with pytest.raises(Exception):  # sqlite3.OperationalError: readonly database
            store.replace_endpoints_for_files(["app/P.java"], [])

    assert [e.topic for e in endpoints] == ["orders.created"]

    # aucune écriture n'a persisté malgré la tentative
    with Store(tmp_path) as store:
        assert len(store.all_endpoints()) == 1


def test_readonly_store_missing_database_raises_store_error(tmp_path: Path) -> None:
    with pytest.raises(StoreError, match="introuvable"):
        with Store(tmp_path / "does-not-exist", readonly=True):
            pass
