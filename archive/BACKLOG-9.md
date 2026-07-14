# BACKLOG-9 — Inventaire REST : bases Feign, `RestTemplate.exchange`, faux positifs `.put`

## [x] N1 : Résoudre les bases d'URL Spring/Feign et filtrer les faux positifs REST

**Files** : `src/ccc_radar/scanner.py`, `tests/test_rest_endpoints.py`,
`tests/fixtures/rest_repo/app/java/ResolvedFeignClient.java`,
`tests/fixtures/rest_repo/app/java/ExchangeClient.java`,
`tests/fixtures/rest_repo/app/java/HashMapWriter.java`,
`tests/fixtures/rest_repo/application.properties`,
`docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`.

**Description** : correct the REST inventory gaps re-verified on
`fully-completed-microservices-Java-Springboot`:
1. `@FeignClient(url = "${...}")` methods were losing the resolved base-path
   prefix and surfacing `/{id}` or `/` instead of `/api/v1/...`;
2. `RestTemplate.exchange(...)` was not inventoried, which missed cases such as
   `productUrl + "/purchase"`, especially when the base URL came from a Spring
   Cloud Config Server file;
3. the generic Semgrep `.put(...)` match also surfaced `Map.put(...)` false
   positives as `rest/call`.

**AC** :
- a `@FeignClient` using `url=` or `path=` resolved from Spring configuration
  produces properly prefixed `rest/call` routes;
- `RestTemplate.exchange(urlExpr, HttpMethod.X, ...)` produces a `rest/call`
  endpoint, with best-effort resolution of `@Value` fields and literal suffix
  concatenation, including Spring Cloud Config Server layouts
  `configurations/<spring.application.name>.*`;
- a `.put(...)` in a file without `RestTemplate` no longer appears as a REST
  endpoint.
