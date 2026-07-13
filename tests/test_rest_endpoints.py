from pathlib import Path

import pytest

from cccf.config import Config
from cccf.scanner import SemgrepError, parse_semgrep_endpoints, run_semgrep_endpoints

# Le pack de règles vit dans le repo skill (ccc-findings-skill/skills/cccf/
# rules/rest/), pas dans ce repo (ADR-24). Les fixtures ci-dessous sont une
# copie de test tenue à jour manuellement avec cette source.
FIXTURES_DIR = Path(__file__).parent / "fixtures"
REST_REPO = FIXTURES_DIR / "rest_repo"


def make_config(**overrides: object) -> Config:
    defaults: dict = {"rules": ["rules/java.yaml", "rules/python.yaml"]}
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
    assert concatenated.topic == "GET http://order-service/orders/"

    literal = by_line[18]  # postForObject("http://.../orders", order, ...)
    assert literal.topic == "POST http://order-service/orders"
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
def test_python_fastapi_routes_extract_role_method_and_fstring_placeholder() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/python/routes.py"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert by_line[6].topic == "GET /orders/{order_id}"
    assert by_line[6].topic_dynamic is False
    assert by_line[6].framework == "fastapi"
    assert by_line[11].topic == "POST /orders"
    assert by_line[16].topic == "PUT /orders/{order_id}"
    assert by_line[21].topic == "DELETE /orders/{order_id}"
    assert by_line[26].topic == "PATCH /orders/{order_id}/status"
    # @app.route(...) bare (Flask) reconnu comme GET, même règle que FastAPI
    assert by_line[31].topic == "GET /orders/{order_id}/summary"


@pytest.mark.integration
def test_python_requests_calls_resolve_fstring_but_flag_concatenation_and_bare_var() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/python/client.py"]
    )

    by_line = {e.start_line: e for e in endpoints}

    fstring_call = by_line[5]  # requests.get(f"http://.../orders/{order_id}")
    assert fstring_call.topic == "GET http://order-service/orders/{order_id}"
    assert fstring_call.topic_dynamic is False

    literal_call = by_line[9]  # requests.post("http://.../orders", json=payload)
    assert literal_call.topic == "POST http://order-service/orders"
    assert literal_call.topic_dynamic is False

    concatenated_call = by_line[13]  # requests.put("..." + order_id, ...)
    assert concatenated_call.topic_dynamic is True

    bare_variable_call = by_line[26]  # requests.get(base_url)
    assert bare_variable_call.topic == "GET <dynamic>"
    assert bare_variable_call.topic_dynamic is True


@pytest.mark.integration
def test_rest_endpoint_pack_runs_standalone_without_other_backlog_tasks() -> None:
    endpoints = run_semgrep_endpoints(REST_REPO, make_config())

    # java : 6 serve + 5 call ; python : 6 serve + 6 call
    assert len(endpoints) == 23
    assert {e.role for e in endpoints} == {"serve", "call"}
    assert {e.system for e in endpoints} == {"rest"}
    assert {e.source for e in endpoints} == {"code"}


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
