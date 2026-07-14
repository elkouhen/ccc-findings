from pathlib import Path

import pytest

from ccc_radar.config import Config
from ccc_radar.scanner import SemgrepError, parse_semgrep_endpoints, run_semgrep_endpoints

# Le pack de règles vit dans le repo skill (ccc-radar-skill/skills/cccr/
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


@pytest.mark.integration
def test_java_class_level_request_mapping_prefix_is_merged_into_method_path() -> None:
    # BACKLOG Q24 : @RequestMapping("/owners") sur la classe, fusionné avec
    # le chemin (ou l'absence de chemin) de chaque méthode annotée.
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/OwnerController.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert len(endpoints) == 4

    # @PostMapping seul (pas de valeur explicite) : hérite entièrement du
    # préfixe de classe, ce n'est plus "<dynamic>".
    create = by_line[9]
    assert create.topic == "POST /owners"
    assert create.topic_dynamic is False

    # @GetMapping("/{ownerId}") : préfixe de classe + chemin méthode fusionnés.
    find_one = by_line[14]
    assert find_one.topic == "GET /owners/{ownerId}"
    assert find_one.topic_dynamic is False

    # @GetMapping seul : même cas que create, sur GET.
    find_all = by_line[19]
    assert find_all.topic == "GET /owners"
    assert find_all.topic_dynamic is False

    # @RequestMapping(method = ..., value = "/{ownerId}") : la forme
    # générique avec value= explicite fusionne aussi correctement.
    update = by_line[24]
    assert update.topic == "PUT /owners/{ownerId}"
    assert update.topic_dynamic is False


@pytest.mark.integration
def test_java_generic_request_mapping_without_http_method_is_inferred_as_any() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/RootController.java"]
    )

    assert [endpoint.topic for endpoint in endpoints] == ["ANY /"]
    assert endpoints[0].framework == "spring"
    assert endpoints[0].role == "serve"


@pytest.mark.integration
def test_framework_generated_endpoints_are_inferred() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO,
        make_config(),
        files=[
            "app/java/OrderRepository.java",
            "app/java/SwaggerConfig.java",
            "app/resources/application.properties",
        ],
    )

    topics = {endpoint.topic: endpoint.framework for endpoint in endpoints}
    assert topics["GET /order"] == "spring-data-rest"
    assert topics["POST /order"] == "spring-data-rest"
    assert topics["GET /order/{id}"] == "spring-data-rest"
    assert topics["PUT /order/{id}"] == "spring-data-rest"
    assert topics["PATCH /order/{id}"] == "spring-data-rest"
    assert topics["DELETE /order/{id}"] == "spring-data-rest"
    assert topics["GET /swagger-ui.html"] == "swagger-ui"
    assert topics["GET /actuator/**"] == "spring-actuator"


def test_java_client_call_with_variable_base_extracts_literal_suffix_as_dynamic() -> None:
    # getForObject(base + "/orders/" + id, ...) : premier littéral trouvé
    # au milieu de l'expression, toujours marqué dynamique (concaténation).
    raw = """
    {"results": [{
        "check_id": "rules.cccr.rest.java.call-get",
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
def test_java_feign_client_url_property_is_merged_into_method_routes() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/ResolvedFeignClient.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert len(endpoints) == 2
    assert by_line[14].topic == "GET /api/v1/customers/{customer-id}"
    assert by_line[17].topic == "POST /api/v1/customers"
    for endpoint in endpoints:
        assert endpoint.role == "call"
        assert endpoint.framework == "feign"
        assert endpoint.topic_dynamic is False


@pytest.mark.integration
def test_resttemplate_exchange_resolves_value_annotated_base_urls() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/ExchangeClient.java"]
    )

    by_line = {e.start_line: e for e in endpoints}
    assert len(endpoints) == 2

    purchase = by_line[26]
    assert purchase.role == "call"
    assert purchase.framework == "resttemplate"
    assert purchase.topic == "POST /api/v1/products/purchase"
    assert purchase.topic_dynamic is False

    fetch_one = by_line[36]
    assert fetch_one.topic == "GET /api/v1/products/"
    assert fetch_one.topic_dynamic is True


@pytest.mark.integration
def test_spring_cloud_config_server_properties_resolve_for_feign_and_exchange() -> None:
    feign_endpoints = run_semgrep_endpoints(
        REST_REPO,
        make_config(),
        files=["services/order/src/main/java/com/example/CloudFeignClient.java"],
    )
    feign_by_line = {e.start_line: e for e in feign_endpoints}
    assert feign_by_line[14].topic == "GET /api/v1/customers/{customer-id}"
    assert feign_by_line[17].topic == "POST /api/v1/customers"
    assert all(not endpoint.topic_dynamic for endpoint in feign_endpoints)

    exchange_endpoints = run_semgrep_endpoints(
        REST_REPO,
        make_config(),
        files=["services/order/src/main/java/com/example/CloudExchangeClient.java"],
    )
    assert len(exchange_endpoints) == 1
    assert exchange_endpoints[0].topic == "POST /api/v1/products/purchase"
    assert exchange_endpoints[0].topic_dynamic is False


@pytest.mark.integration
def test_non_resttemplate_put_calls_are_filtered_out() -> None:
    endpoints = run_semgrep_endpoints(
        REST_REPO, make_config(), files=["app/java/HashMapWriter.java"]
    )

    assert endpoints == []


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

    # java : 9 serve (OrderController) + 4 serve (OwnerController, Q24)
    # + 1 serve générique @RequestMapping (RootController)
    # + 6 serve Spring Data REST + 1 Swagger UI + 1 Actuator
    # + 5 call resttemplate (OrderClient) + 2 call exchange (ExchangeClient)
    # + 1 call exchange via config-server (CloudExchangeClient)
    # + 3 call feign (PaymentClient) + 2 call feign résolus (ResolvedFeignClient)
    # + 2 call feign via config-server (CloudFeignClient)
    # + 3 call webclient (WebClientCaller)
    assert len(endpoints) == 40
    assert {e.role for e in endpoints} == {"serve", "call"}
    assert {e.system for e in endpoints} == {"rest"}
    assert {e.source for e in endpoints} == {"code"}
    assert {e.framework for e in endpoints} == {
        "spring",
        "spring-data-rest",
        "spring-actuator",
        "swagger-ui",
        "resttemplate",
        "feign",
        "webclient",
    }


def test_parse_semgrep_endpoints_missing_role_raises_semgrep_error() -> None:
    raw = """
    {"results": [{
        "check_id": "rules.cccr.rest.java.call-get",
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
