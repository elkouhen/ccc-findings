import json
from pathlib import Path

from typer.testing import CliRunner

from ccc_radar.audit import assess_architecture
from ccc_radar.cli import app
from ccc_radar.config import Config
from ccc_radar.doctor import _has_pack
from ccc_radar.models import MessageEndpoint, compute_endpoint_id
from ccc_radar.modules import DiscoveredModule, MongoMethod
from ccc_radar.store import Store


def endpoint(service: str, role: str, system: str, topic: str, dynamic: bool = False) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, f"{service}.java", 1), role=role,
        system=system, topic=topic, topic_dynamic=dynamic, source="code",
        framework=None, path=f"{service}.java", start_line=1, end_line=1, snippet="",
        module=service,
    )


def test_audit_reports_orphan_endpoint_and_dynamic_target() -> None:
    risks = assess_architecture(
        {
            "orders": [
                endpoint("orders", "produce", "kafka", "orders.created"),
                endpoint("orders", "call", "rest", "GET <dynamic>"),
            ],
        },
        [],
    )
    assert {risk.id for risk in risks} == {
        "orphan-kafka-producer", "dynamic-http-target",
    }


def test_audit_reports_non_runtime_module_with_integration_responsibilities(tmp_path: Path) -> None:
    module = DiscoveredModule(
        name="shared-integration",
        path=tmp_path / "shared-integration",
        build_system="maven",
        version=None,
        kind="library",
        starts_application=False,
        configuration_example="",
        mongo_methods=(
            MongoMethod("find", "mongoTemplate", "Store.java", 10, "orders"),
            MongoMethod("save", "mongoTemplate", "Store.java", 11, "audit"),
        ),
    )
    endpoints = [
        endpoint("shared-integration", "serve", "rest", "POST /internal/orders"),
        endpoint("shared-integration", "produce", "kafka", "orders.created"),
        endpoint("shared-integration", "consume", "kafka", "payments.received"),
    ]

    risks = assess_architecture(
        {"shared-integration": endpoints},
        [],
        modules=[module],
        endpoints_by_module={"shared-integration": endpoints},
    )

    risk = next(risk for risk in risks if risk.id == "non-runtime-module-activity")
    assert risk.severity == "WARNING"
    assert "POST /internal/orders" in risk.evidence
    assert "orders.created" in risk.evidence
    assert "payments.received" in risk.evidence
    assert "collections MongoDB lues: orders" in risk.evidence
    assert "collections MongoDB écrites: audit" in risk.evidence


def test_audit_cli_reports_indexed_non_runtime_module_activity(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    module = DiscoveredModule(
        name="shared-integration",
        path=tmp_path / "shared-integration",
        build_system="maven",
        version=None,
        kind="library",
        starts_application=False,
        configuration_example="",
        mongo_methods=(MongoMethod("save", "mongoTemplate", "Store.java", 11, "audit"),),
    )
    produced = endpoint("shared-integration", "produce", "kafka", "orders.created")
    with Store(tmp_path) as store:
        store.replace_modules([module])
        store.replace_endpoints_for_files([produced.path], [produced])

    result = CliRunner().invoke(app, ["audit", "--json"])

    assert result.exit_code == 0
    audit = next(item for item in json.loads(result.output) if item["id"] == "non-runtime-module-activity")
    assert audit["services"] == ["shared-integration"]
    assert "orders.created" in audit["evidence"]
    assert "collections MongoDB écrites: audit" in audit["evidence"]


def test_doctor_reports_missing_configuration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["doctor", "--json"])
    assert result.exit_code == 2
    assert '"name": "configuration"' in result.output


def test_doctor_accepts_pack_directory_paths() -> None:
    config = Config(
        rules=[".cccr/rules/rest", ".cccr/rules/kafka/java.yaml"],
        include=["**/*"], exclude=[], min_severity="INFO", embedding_model="model",
    )

    assert _has_pack(config, "rest")
    assert _has_pack(config, "kafka")
