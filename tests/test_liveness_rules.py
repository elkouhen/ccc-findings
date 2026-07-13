from pathlib import Path

import pytest

from cccf.config import Config
from cccf.scanner import run_semgrep

# Le pack de règles vit dans le repo skill (ccc-findings-skill/skills/cccf/
# rules/liveness/), pas dans ce repo (ADR-24 : jamais de chemin absolu vers
# un pack livré, il se copie dans le repo cible — le repo skill est déjà ce
# point de copie). Les fixtures ci-dessous sont une copie de test tenue à
# jour manuellement avec cette source ; il n'y a pas de vérification
# automatique inter-repos (ccc-findings-skill n'a pas d'infra de test).
FIXTURES_DIR = Path(__file__).parent / "fixtures"
LIVENESS_REPO = FIXTURES_DIR / "liveness_repo"


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/python.yaml", "rules/java.yaml"]}
    defaults.update(overrides)
    return Config(**defaults)


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
def test_java_new_resttemplate_no_timeout_ignores_builder_configured_client() -> None:
    findings = run_semgrep(
        LIVENESS_REPO, make_config(), files=["app/java/RestClientConfig.java"]
    )

    hits = [
        f for f in findings if f.rule_id == "rules.cccf.liveness.java.new-resttemplate-no-timeout"
    ]
    assert [f.start_line for f in hits] == [11]


@pytest.mark.integration
def test_java_blocking_join_no_timeout_flags_thread_and_completablefuture() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/java/Blocking.java"])

    hits = [
        f for f in findings if f.rule_id == "rules.cccf.liveness.java.blocking-join-no-timeout"
    ]
    assert {f.start_line for f in hits} == {12, 20}


@pytest.mark.integration
def test_java_blocking_future_get_no_timeout_flags_future_and_completablefuture() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/java/Blocking.java"])

    hits = [
        f
        for f in findings
        if f.rule_id == "rules.cccf.liveness.java.blocking-future-get-no-timeout"
    ]
    assert {f.start_line for f in hits} == {25, 37}


@pytest.mark.integration
def test_java_rest_call_in_kafka_listener_ignores_ordinary_methods() -> None:
    findings = run_semgrep(
        LIVENESS_REPO,
        make_config(),
        files=["app/java/OrderConsumer.java", "app/java/OrdinaryService.java"],
    )

    hits = [
        f for f in findings if f.rule_id == "rules.cccf.liveness.java.rest-call-in-kafka-listener"
    ]
    assert [(f.path, f.start_line) for f in hits] == [("app/java/OrderConsumer.java", 18)]


@pytest.mark.integration
def test_java_network_call_inside_synchronized_ignores_calls_made_before_the_block() -> None:
    findings = run_semgrep(LIVENESS_REPO, make_config(), files=["app/java/CacheRefresher.java"])

    hits = [
        f
        for f in findings
        if f.rule_id == "rules.cccf.liveness.java.network-call-inside-synchronized"
    ]
    assert [f.start_line for f in hits] == [19]


@pytest.mark.integration
def test_liveness_pack_runs_standalone_on_a_plain_project() -> None:
    """K8 CA3 : le pack liveness fonctionne seul, sans dépendre d'aucune
    autre tâche du backlog (endpoints, graphe...) — juste le pipeline
    findings existant (scanner + config)."""
    findings = run_semgrep(LIVENESS_REPO, make_config())

    assert len(findings) == 15
    assert {f.rule_id for f in findings} == {
        "rules.cccf.liveness.requests-no-timeout",
        "rules.cccf.liveness.thread-join-no-timeout",
        "rules.cccf.liveness.future-result-no-timeout",
        "rules.cccf.liveness.http-call-in-kafka-python-consumer-loop",
        "rules.cccf.liveness.network-call-inside-lock",
        "rules.cccf.liveness.java.new-resttemplate-no-timeout",
        "rules.cccf.liveness.java.blocking-join-no-timeout",
        "rules.cccf.liveness.java.blocking-future-get-no-timeout",
        "rules.cccf.liveness.java.rest-call-in-kafka-listener",
        "rules.cccf.liveness.java.network-call-inside-synchronized",
    }
