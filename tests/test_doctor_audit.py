from pathlib import Path

from typer.testing import CliRunner

from ccc_radar.audit import assess_architecture
from ccc_radar.cli import app
from ccc_radar.models import MessageEndpoint, compute_endpoint_id


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


def test_doctor_reports_missing_configuration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["doctor", "--json"])
    assert result.exit_code == 2
    assert '"name": "configuration"' in result.output
