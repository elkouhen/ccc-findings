"""BACKLOG-10 K7 — vérifie de bout en bout, avec la fédération réelle livrée
par A2, l'intention de K7 : deux dépôts indexés séparément (un producteur
Kafka dans l'un, un consommateur dans l'autre) sont fédérés, chaque site
attribué à son propre service, et la relation entre les deux ressort du
graphe. K7 visait initialement `cccf flow --workspace <nom>` (jamais
livré, K5) ; l'adaptation actée (voir `archive/BACKLOG-PRIORITY.md`,
cadrage 2026-07-13) est la découverte automatique d'un répertoire parent
Maven (A2) plutôt qu'un fichier de workspace nommé — ce test valide que
cette adaptation tient la même promesse.
"""

import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app
from cccf.graph import build_graph
from cccf.workspace import discover_maven_services, load_federation

FIXTURES_DIR = Path(__file__).parent / "fixtures"
KAFKA_WORKSPACE = FIXTURES_DIR / "kafka_workspace"

runner = CliRunner()


@pytest.mark.integration
def test_two_independently_indexed_services_federate_with_a_kafka_edge_between_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    # K7 CA1 (adapté) : chaque service est indexé séparément, comme deux
    # dépôts distincts — cccf n'a jamais connaissance de l'autre pendant
    # cccf init/cccf index.
    for service in ("order-service", "payment-service"):
        monkeypatch.chdir(dest / service)
        init_result = runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
        assert init_result.exit_code == 0
        index_result = runner.invoke(app, ["index"])
        assert index_result.exit_code == 0, index_result.output

    services = discover_maven_services(dest)
    assert {s.name for s in services} == {"order-service", "payment-service"}
    assert all(s.indexed for s in services)

    federation = load_federation(services)
    assert federation.warnings == []

    # chaque site est bien attribué à SON service, pas mélangé
    order_endpoints = federation.endpoints_by_service["order-service"]
    payment_endpoints = federation.endpoints_by_service["payment-service"]
    assert [e.role for e in order_endpoints] == ["produce"]
    assert [e.role for e in payment_endpoints] == ["consume"]
    assert order_endpoints[0].topic == payment_endpoints[0].topic == "orders.created"

    # K7 CA1 (adapté) : la relation producteur -> consommateur ressort du
    # graphe inter-services construit sur la fédération.
    edges = build_graph(federation.endpoints_by_service)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind == "kafka"
    assert edge.from_service == "order-service"
    assert edge.to_service == "payment-service"
    assert edge.from_endpoint.path == "app/OrderProducer.java"
    assert edge.to_endpoint.path == "app/OrderConsumer.java"


def test_missing_service_in_workspace_warns_without_failing_federation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K7 CA2 : un repo du workspace non indexé (ou absent) est signalé,
    sans faire échouer la lecture des autres services."""
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest / "order-service")
    runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
    index_result = runner.invoke(app, ["index"])
    assert index_result.exit_code == 0
    # payment-service reste volontairement non indexé

    services = discover_maven_services(dest)
    federation = load_federation(services)

    assert "order-service" in federation.endpoints_by_service
    assert "payment-service" not in federation.endpoints_by_service
    assert any("payment-service" in w and "non indexé" in w for w in federation.warnings)


def test_federation_never_writes_to_the_other_services_databases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K7 CA3 : aucune écriture dans les bases des autres projets."""
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    for service in ("order-service", "payment-service"):
        monkeypatch.chdir(dest / service)
        runner.invoke(app, ["init", "--rules", "rules/java.yaml"])
        runner.invoke(app, ["index"])

    db_paths = [
        dest / service / ".cccf" / "findings.db"
        for service in ("order-service", "payment-service")
    ]
    mtimes_before = [p.stat().st_mtime_ns for p in db_paths]

    services = discover_maven_services(dest)
    load_federation(services)

    mtimes_after = [p.stat().st_mtime_ns for p in db_paths]
    assert mtimes_before == mtimes_after
