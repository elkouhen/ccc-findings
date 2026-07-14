# BACKLOG-3 — Remediations from the microservices graph audit

## [x] N1 : Detect Spring `@RequestMapping` without an explicit HTTP method

**Files** : `src/ccc_radar/scanner.py`, `tests/test_rest_endpoints.py`,
`tests/fixtures/rest_repo/app/java/RootController.java`.

**Description** : complete the REST inventory so it reports Spring handlers
declared with `@RequestMapping(...)` without `method=...`, especially the root
route `/` seen in `microservices-kafka-mq`, without breaking routes already
detected by Semgrep.

**AC** :
- `cccr endpoints` reports the `/` route on a Spring controller declared via
  `@RequestMapping("/")` without an explicit method;
- detection stays best-effort and does not duplicate routes already extracted
  by existing Semgrep rules;
- REST tests cover this case.

## [x] N2 : Fix Maven service classification and indexing in `workspace`

**Files** : `src/ccc_radar/maven.py`, `src/ccc_radar/workspace.py`,
`tests/test_workspace.py`.

**Description** : detect real Maven microservices more robustly when the Spring
Boot plugin is not declared in the module's own `pom.xml`, and account for
indexing run at the multi-module parent to avoid incorrectly marking submodules
as “not indexed”.

**AC** :
- a Maven module with a Spring Boot `main()` class is classified as a
  `microservice` even without `spring-boot-maven-plugin` textually present in
  its `pom.xml`;
- an indexed aggregator parent can feed endpoints/findings counts for its
  submodules;
- `workspace` warnings no longer incorrectly report submodules already covered
  by the parent index.

## [x] N3 : Infer framework-generated endpoints useful to the graph

**Files** : `src/ccc_radar/scanner.py`, `tests/test_rest_endpoints.py`,
`tests/fixtures/rest_repo/app/java/OrderRepository.java`,
`tests/fixtures/rest_repo/app/java/SwaggerConfig.java`,
`tests/fixtures/rest_repo/app/resources/application.properties`.

**Description** : add best-effort inference for some endpoints not explicit in
application code but structurally useful for system understanding: Spring Data
REST (`@RepositoryRestResource`), Swagger UI, and Actuator.

**AC** :
- `cccr endpoints` reports Spring Data REST endpoints derived from a
  `@RepositoryRestResource(path = "...")`;
- `cccr endpoints` reports at least `/swagger-ui.html` and `/actuator/**` when
  the corresponding framework signals are present;
- inferred endpoints remain identified as such by their `framework` and do not
  collide with explicit application endpoints.
