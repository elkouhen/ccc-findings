"""BACKLOG-10 K5 — `cccf flow` de bout en bout : deux microservices indexés
séparément (producteur Kafka dans l'un, consommateur dans l'autre), fédérés
via `--workspace` (BACKLOG-11 A2), et un finding qui recouvre le site du
producteur ressort attaché à son endpoint (CA1)."""

import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cccf.cli import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
KAFKA_WORKSPACE = FIXTURES_DIR / "kafka_workspace"

runner = CliRunner()


@pytest.mark.integration
def test_flow_resolves_topic_across_federated_services_with_overlapping_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    for service in ("order-service", "payment-service"):
        monkeypatch.chdir(dest / service)
        assert runner.invoke(app, ["init", "--rules", "rules/java.yaml"]).exit_code == 0
        assert runner.invoke(app, ["index"]).exit_code == 0

    monkeypatch.chdir(dest / "order-service")
    result = runner.invoke(app, ["flow", "orders.created", "--workspace", str(dest), "--json"])
    assert result.exit_code == 0, result.output

    import json

    payload = json.loads(result.output)
    assert payload["resolved_topic"] == "orders.created"

    sites_by_service = {site["service"]: site for site in payload["sites"]}
    producer_site = sites_by_service["order-service"]
    assert producer_site["role"] == "produce"
    assert producer_site["path"] == "app/OrderProducer.java"
    assert producer_site["finding_rule_ids"] == ["rules.cccf.demo.kafka-send-fire-and-forget"]

    consumer_site = sites_by_service["payment-service"]
    assert consumer_site["role"] == "consume"
    assert consumer_site["path"] == "app/OrderConsumer.java"
    assert consumer_site["finding_rule_ids"] == []


@pytest.mark.integration
def test_flow_reports_warning_when_a_federated_service_is_not_indexed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest / "order-service")
    assert runner.invoke(app, ["init", "--rules", "rules/java.yaml"]).exit_code == 0
    assert runner.invoke(app, ["index"]).exit_code == 0
    # payment-service reste volontairement non indexé

    result = runner.invoke(app, ["flow", "orders.created", "--workspace", str(dest), "--json"])
    assert result.exit_code == 0, result.output

    import json

    payload = json.loads(result.output)
    # le producteur order-service ressort quand même : un service manquant
    # n'efface pas les sites des services fédérés avec succès
    assert [s["service"] for s in payload["sites"]] == ["order-service"]
    assert any("payment-service" in w and "non indexé" in w for w in payload["warnings"])


@pytest.mark.integration
def test_flow_falls_back_to_similarity_when_textual_resolution_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG-10 K3 : quand `resolve_topic` échoue, `cccf flow` retente via
    `resolve_topic_by_similarity` — vérifié en substituant cette fonction
    (déjà testée isolément dans tests/test_flow.py avec des vecteurs
    contrôlés) pour ne pas dépendre du comportement d'un embedder réel/faux
    sur du texte arbitraire (non calibré, voir test_flow.py)."""
    import cccf.cli as cli_module

    dest = tmp_path / "kafka_workspace"
    shutil.copytree(KAFKA_WORKSPACE, dest)

    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(dest / "order-service")
    assert runner.invoke(app, ["init", "--rules", "rules/java.yaml"]).exit_code == 0
    assert runner.invoke(app, ["index"]).exit_code == 0

    monkeypatch.setattr(
        cli_module, "resolve_topic_by_similarity", lambda *a, **kw: "orders.created"
    )
    result = runner.invoke(app, ["flow", "who creates an order", "--json"])
    assert result.exit_code == 0, result.output

    import json

    payload = json.loads(result.output)
    assert payload["resolved_topic"] == "orders.created"


@pytest.mark.integration
def test_flow_unresolved_topic_exits_with_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Aucun endpoint indexé (pack de règles vide) : la résolution textuelle
    échoue, et le repli par similarité (K3) échoue lui aussi de façon
    déterministe (aucun endpoint embeddé) — pas de dépendance à un seuil de
    similarité calibré sur un modèle réel."""
    monkeypatch.setenv("CCCF_FAKE_EMBEDDER", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "empty.yaml").write_text("rules: []\n")

    assert runner.invoke(app, ["init", "--rules", "rules/empty.yaml"]).exit_code == 0
    assert runner.invoke(app, ["index"]).exit_code == 0

    result = runner.invoke(app, ["flow", "does-not-exist"])
    assert result.exit_code == 2
    assert "does-not-exist" in result.output
