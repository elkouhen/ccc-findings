from pathlib import Path

import pytest

from cccf.config import Config
from cccf.scanner import SemgrepError, parse_semgrep_endpoints, run_semgrep_endpoints

# Le pack de règles vit dans le repo skill (ccc-findings-skill/skills/cccf/
# rules/rest/), pas dans ce repo (ADR-24). Les fixtures ci-dessous sont une
# copie de test tenue à jour manuellement avec cette source.
#
# Cible d'analyse : Java + Spring + Maven uniquement (pas de pack Python).
FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_REPO = FIXTURES_DIR / "rest_repo"


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/java.yaml"]}
    defaults.update(overrides)
    return Config(**defaults)


@pytest.mark.integration
def test_java_server_routes_extract_role_method_and_literal_path() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/OrderController.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    get_route = by_line[8]
    assert get_route.role == "serve"
    assert get_route.system == "rest"
    assert get_route.framework == "spring"
    assert get_route.topic == "GET /orders/{id}"
    assert get_route.topic_dynamic is False
    assert get_route.source == "code"

    assert by_line[13].topic == "POST /orders"
    assert by_line[18].topic == "PUT /orders/{id}"
    assert by_line[23].topic == "DELETE /orders/{id}"
    assert by_line[27].topic == "PATCH /orders/{id}/status"
    # @RequestMapping(value = "...", method = RequestMethod.GET) reconnu
    # comme GET au même titre que @GetMapping
    assert by_line[32].topic == "GET /orders/{id}/summary"
    # @RequestMapping(..., method = RequestMethod.{PUT,DELETE,PATCH}) : mêmes
    # verbes non-GET reconnus au même titre que les annotations dédiées
    assert by_line[37].topic == "PUT /orders/{id}/cancel"
    assert by_line[42].topic == "DELETE /orders/{id}/archive"
    assert by_line[46].topic == "PATCH /orders/{id}/pause"


@pytest.mark.integration
def test_java_client_calls_flag_concatenated_url_as_dynamic() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/OrderClient.java"]
    )

    by_line = {e.start_line: e for e in endpoints}

    concatenated = by_line[14]  # getForObject("http://.../orders/" + id, ...)
    assert concatenated.role == "call"
    assert concatenated.framework == "resttemplate"
    assert concatenated.topic_dynamic is True
    assert concatenated.topic == "GET /orders/"

    literal = by_line[18]  # postForObject("http://.../orders", order, ...)
    assert literal.topic == "POST /orders"
    assert literal.topic_dynamic is False

    # put/delete concatènent aussi l'id : dynamiques, comme getForObject
    assert by_line[22].topic_dynamic is True
    assert by_line[26].topic_dynamic is True


def test_java_client_call_with_variable_base_extracts_literal_suffix_as_dynamic() -> None:
    # getForObject(base + "/orders/" + id, ...) : premier littéral trouvé
    # au milieu de l'expression, toujours marqué dynamique (concaténation).
    raw = """
    {"results": [{
        "check_id": "rules.cccf.rest.java.call-get",
        "path": "app/java/OrderClient.java",
        "start": {"line": 31}, "end": {"line": 31},
        "extra": {"metadata": {"category": "endpoint-inventory",
                                "role": "call", "http_method": "GET",
                                "framework": "resttemplate"}}
    }]}
    """
    endpoints = parse_semgrep_endpoints(raw, REST_REPO)

    assert endpoints[0].topic == "GET /orders/"
    assert endpoints[0].topic_dynamic is True


@pytest.mark.integration
def test_java_feign_client_methods_are_call_sites_not_server_routes() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/PaymentClient.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert len(endpoints) == 3
    for endpoint in endpoints:
        assert endpoint.role == "call"
        assert endpoint.framework == "feign"

    assert by_line[9].topic == "GET /payments/{id}"
    assert by_line[12].topic == "POST /payments"
    # @RequestMapping(..., method = RequestMethod.PUT) sur une interface Feign
    assert by_line[15].topic == "PUT /payments/{id}/cancel"


@pytest.mark.integration
def test_java_webclient_fluent_calls_are_call_sites() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/WebClientCaller.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert len(endpoints) == 3
    for endpoint in endpoints:
        assert endpoint.role == "call"
        assert endpoint.framework == "webclient"

    assert by_line[14].topic == "GET /orders/{id}"
    assert by_line[18].topic == "POST /orders"
    # BACKLOG-10 K13 : `.uri(...)` sur une ligne distincte de `.patch()`.
    assert by_line[22].topic == "PATCH /orders/{id}/cancel"
    assert not by_line[22].topic_dynamic


@pytest.mark.integration
def test_rest_endpoint_pack_runs_standalone_without_other_backlog_tasks() -> None:
    endpoints = run_semgrep_endpoints(REST_REPO, make_config())

    # java : 9 serve (OrderController) + 5 call resttemplate (OrderClient)
    # + 3 call feign (PaymentClient) + 3 call webclient (WebClientCaller)
    assert len(endpoints) == 20
    assert {e.role for e in endpoints} == {"serve", "call"}
    assert {e.system for e in endpoints} == {"rest"}
    assert {e.source for e in endpoints} == {"code"}
    assert {e.framework for e in endpoints} == {"spring", "resttemplate", "feign", "webclient"}


def test_parse_semgrep_endpoints_missing_role_raises_semgrep_error() -> None:
    raw = """
    {"results": [{
        "check_id": "rules.cccf.rest.java.call-get",
        "path": "app/java/OrderClient.java",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"metadata": {"category": "endpoint-inventory",
                                "http_method": "GET"}}
    }]}
    """
    with pytest.raises(SemgrepError):
        parse_semgrep_endpoints(raw, REST_REPO)


def test_parse_semgrep_endpoints_ignores_non_inventory_results() -> None:
    raw = """
    {"results": [{
        "check_id": "rules.custom.sql-fstring",
        "path": "app/java/OrderClient.java",
        "start": {"line": 1}, "end": {"line": 1},
        "extra": {"metadata": {}}
    }]}
    """
    assert parse_semgrep_endpoints(raw, REST_REPO) == []
