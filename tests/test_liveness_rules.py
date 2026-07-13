from pathlib import Path

import pytest

from cccf.config import Config
from cccf.scanner import run_semgrep

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LIVENESS_REPO = FIXTURES_DIR / "liveness_repo"
SHIPPED_RULES = (
    Path(__file__).parent.parent / "src" / "cccf" / "rules" / "liveness" / "rules.yml"
)
FIXTURE_RULES = LIVENESS_REPO / "rules" / "rules.yml"


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/rules.yml"]}
    defaults.update(overrides)
    return Config(**defaults)


def test_fixture_rules_pack_matches_shipped_pack() -> None:
    """Le fixture est une copie exacte du pack livré (src/cccf/rules/liveness/) ;
    ce test échoue si l'un des deux fichiers est modifié sans l'autre."""
    assert FIXTURE_RULES.read_text() == SHIPPED_RULES.read_text()


@pytest.mark.integration
def test_requests_no_timeout_flags_calls_without_timeout_only() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/http_client.py"])

    hits = [f for f in findings if f.rule_id == "rules.cccf.liveness.requests-no-timeout"]
    assert {f.start_line for f in hits} == {5, 13}


@pytest.mark.integration
def test_thread_join_no_timeout_flags_bare_join_only() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/blocking.py"])

    hits = [f for f in findings if f.rule_id == "rules.cccf.liveness.thread-join-no-timeout"]
    assert [f.start_line for f in hits] == [6]


@pytest.mark.integration
def test_future_result_no_timeout_flags_bare_result_only() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/blocking.py"])

    hits = [f for f in findings if f.rule_id == "rules.cccf.liveness.future-result-no-timeout"]
    assert [f.start_line for f in hits] == [15]


@pytest.mark.integration
def test_http_call_in_kafka_consumer_loop_ignores_ordinary_for_loops() -> None:
    findings = run_semgrep(
        LIVENESS_REPO,
        make_config(),
        files=["app/consumer_bad.py", "app/consumer_good.py"],
    )

    hits = [
        f
        for f in findings
        if f.rule_id == "rules.cccf.liveness.http-call-in-kafka-python-consumer-loop"
    ]
    assert [(f.path, f.start_line) for f in hits] == [("app/consumer_bad.py", 6)]


@pytest.mark.integration
def test_network_call_inside_lock_ignores_calls_made_before_the_lock() -> None:
    findings = run_semgrep(
        LIVENESS_REPO,
        make_config(),
        files=["app/lock_bad.py", "app/lock_good.py"],
    )

    hits = [f for f in findings if f.rule_id == "rules.cccf.liveness.network-call-inside-lock"]
    assert [(f.path, f.start_line) for f in hits] == [("app/lock_bad.py", 10)]


@pytest.mark.integration
def test_liveness_pack_runs_standalone_on_a_plain_project() -> None:
    """K8 CA3 : le pack liveness fonctionne seul, sans dépendre d'aucune
    autre tâche du backlog (endpoints, graphe...) — juste le pipeline
    findings existant (scanner + config)."""
    findings = run_semgrep(LIVENESS_REPO, make_config())

    assert len(findings) == 8
    assert {f.rule_id for f in findings} == {
        "rules.cccf.liveness.requests-no-timeout",
        "rules.cccf.liveness.thread-join-no-timeout",
        "rules.cccf.liveness.future-result-no-timeout",
        "rules.cccf.liveness.http-call-in-kafka-python-consumer-loop",
        "rules.cccf.liveness.network-call-inside-lock",
    }
