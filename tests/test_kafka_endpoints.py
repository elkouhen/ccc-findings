from pathlib import Path

import pytest

from cccf.config import Config
from cccf.scanner import resolve_spring_property, run_semgrep_endpoints

# Le pack de règles vit dans le repo skill (ccc-findings-skill/skills/cccf/
# rules/kafka/), pas dans ce repo (ADR-24). Cible d'analyse : Java + Spring
# + Maven uniquement (pas de pack Python/JS).
FIXTURES_DIR = Path(__file__).parent / "fixtures"
KAFKA_REPO = FIXTURES_DIR / "kafka_repo"


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/java.yaml"]}
    defaults.update(overrides)
    return Config(**defaults)


@pytest.mark.integration
def test_kafka_consume_extracts_literal_topic_from_annotation() -> None:
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderConsumer.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    literal = by_line[7]
    assert literal.role == "consume"
    assert literal.system == "kafka"
    assert literal.framework == "spring-kafka"
    assert literal.topic == "orders.created"
    assert literal.topic_dynamic is False


@pytest.mark.integration
def test_kafka_consume_resolves_spring_property_placeholder() -> None:
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderConsumer.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    resolved = by_line[11]  # topics = "${app.kafka.topics.payments}"
    assert resolved.topic == "payments.received"
    assert resolved.topic_dynamic is False


@pytest.mark.integration
def test_kafka_consume_uses_spring_default_when_property_key_missing() -> None:
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderConsumer.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    # topics = "${app.kafka.topics.unknown:orders.fallback}" : clé absente
    # de application.yml, mais un défaut Spring est fourni.
    defaulted = by_line[15]
    assert defaulted.topic == "orders.fallback"
    assert defaulted.topic_dynamic is False


@pytest.mark.integration
def test_kafka_consume_keeps_placeholder_dynamic_when_unresolved() -> None:
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderConsumer.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    # topics = "${app.kafka.topics.missing}" : ni dans application.yml, ni
    # de défaut Spring — jamais résolu au hasard.
    unresolved = by_line[19]
    assert unresolved.topic == "${app.kafka.topics.missing}"
    assert unresolved.topic_dynamic is True


@pytest.mark.integration
def test_kafka_produce_template_and_record_extract_topics() -> None:
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderProducer.java"]
    )

    by_line = {e.start_line: e for e in endpoints}

    literal_send = by_line[15]  # kafkaTemplate.send("orders.created", payload)
    assert literal_send.role == "produce"
    assert literal_send.framework == "spring-kafka"
    assert literal_send.topic == "orders.created"
    assert literal_send.topic_dynamic is False

    placeholder_send = by_line[19]  # send("${app.kafka.topics.payments}", key, payload)
    assert placeholder_send.topic == "payments.received"
    assert placeholder_send.topic_dynamic is False

    producer_record = by_line[23]  # new ProducerRecord("orders.updated", payload)
    assert producer_record.framework == "kafka-clients"
    assert producer_record.topic == "orders.updated"
    assert producer_record.topic_dynamic is False

    dynamic_send = by_line[28]  # send(topic, payload) : variable, aucun littéral
    assert dynamic_send.topic == "<dynamic>"
    assert dynamic_send.topic_dynamic is True


@pytest.mark.integration
def test_kafka_produce_single_arg_send_of_producer_record_is_not_double_counted() -> None:
    """kafkaTemplate.send(record) (1 seul argument, un ProducerRecord déjà
    construit) ne doit pas être capté par produce-template — le topic est
    déjà porté par le new ProducerRecord(...) correspondant, capté à part."""
    endpoints = run_semgrep_endpoints(
        KAFKA_REPO, make_config(), files=["app/java/OrderProducer.java"]
    )

    assert not any(e.snippet.strip().startswith("kafkaTemplate.send(record)") for e in endpoints)
    # 1 seul produce pour le ProducerRecord de la ligne 22-23 (pas 2)
    record_endpoints = [e for e in endpoints if e.framework == "kafka-clients"]
    assert len(record_endpoints) == 1


@pytest.mark.integration
def test_kafka_pack_runs_standalone_without_other_backlog_tasks() -> None:
    endpoints = run_semgrep_endpoints(KAFKA_REPO, make_config())

    assert len(endpoints) == 8  # 4 consume + 4 produce
    assert {e.role for e in endpoints} == {"consume", "produce"}
    assert {e.system for e in endpoints} == {"kafka"}


# -- resolve_spring_property (unitaire, sans Semgrep) --


def test_resolve_spring_property_reads_nested_yaml_key(tmp_path: Path) -> None:
    resources = tmp_path / "src" / "main" / "resources"
    resources.mkdir(parents=True)
    (resources / "application.yml").write_text("app:\n  name: orders-service\n")

    assert resolve_spring_property(tmp_path, "app.name") == "orders-service"


def test_resolve_spring_property_reads_dotted_properties_file(tmp_path: Path) -> None:
    resources = tmp_path / "src" / "main" / "resources"
    resources.mkdir(parents=True)
    (resources / "application.properties").write_text("app.name=orders-service\n")

    assert resolve_spring_property(tmp_path, "app.name") == "orders-service"


def test_resolve_spring_property_uses_default_when_key_absent(tmp_path: Path) -> None:
    assert resolve_spring_property(tmp_path, "app.missing:fallback-value") == "fallback-value"


def test_resolve_spring_property_returns_none_without_default_or_file(tmp_path: Path) -> None:
    assert resolve_spring_property(tmp_path, "app.missing") is None


def test_resolve_spring_property_prefers_yml_over_properties_when_both_exist(
    tmp_path: Path,
) -> None:
    resources = tmp_path / "src" / "main" / "resources"
    resources.mkdir(parents=True)
    (resources / "application.yml").write_text("app:\n  name: from-yaml\n")
    (resources / "application.properties").write_text("app.name=from-properties\n")

    assert resolve_spring_property(tmp_path, "app.name") == "from-yaml"
