# BACKLOG — Robustness of microservices/Kafka/REST scanning (2026-07-14)

Robustness review of `cccr` scanning (microservices, Kafka topics,
message production/consumption, HTTP endpoints, HTTP calls) conducted by
actually running the production pipeline (`.cccr/rules/{default,
liveness,rest,kafka,kafka-security}` copied from `ccc-radar-skill`,
`cccr init --rules ... && cccr index --full`, see `SKILL.md` §Default Rules)
on the 7 projects in `../examples/`:

- `booking-microservices-java-spring-boot` (Java/Spring, RabbitMQ+gRPC, no Kafka/REST client)
- `fully-completed-microservices-Java-Springboot` (Java/Spring, 8 services, Kafka + Feign/RestTemplate + Gateway)
- `kafka-microservices` (tutorial mono-repo Java+Kotlin, 14 services, Kafka only)
- `microservices-demo` (Java/Spring, 3 services, Kafka + Feign)
- `microservices-kafka-mq` (Java/Spring, 2 services, Kafka + Spring Data REST)
- `sample-spring-kafka-microservices` (Java/Spring, 4 services, imperative Kafka + Kafka Streams DSL)
- `spring-petclinic-microservices` (Java/Spring Cloud, 8 services, REST + Gateway + Eureka, no Kafka)

For each one, a ground truth was established by directly reading the code
(dedicated agents), then compared with the result of `cccr endpoints`/
`cccr graph`. Convention: same template as the project's history (one task =
one commit `Q<n>: <title>`, DoD = green `uv run pytest` + `uv run ruff check .`,
`Files` scope respected). Processing order: P0 → P1 → P2.

**Two cross-cutting findings before the details**:

1. The default rule pack (`p/security-audit`, used if `cccr init` is run
   without `--rules`) contains **no** endpoint inventory rule —
   `cccr endpoints`/`graph`/`flow` silently return an empty result (exit 0)
   on a first `cccr init` with no arguments. See Q2.
2. Three distinct anomalies (Q3, Q5, Q9) on different repos all point to the
   same structural weakness: literal extraction (`_find_first_literal`) and
   Semgrep rule coverage reason in terms of “first text pattern found in the
   snippet”, not “value of the right named attribute” — silently wrong rather
   than absent.

---

## P0 — Silently wrong or empty data (the scan “succeeds” but lies)

### [ ] Q1 : `cccr index` crashes (raw traceback) on this kind of network — known bug, root cause + workaround identified

**Files** : `src/ccc_radar/embedder.py` (`make_embedder`), `src/ccc_radar/cli.py`
(`index_cmd` — calls `make_embedder` before any Semgrep access), `docs/SPEC-TECH.md`.

**Description** : reproduced identically on all 7 example projects.
`cccr index --full` raises a raw traceback (`httpx._client.RuntimeError:
Cannot send a request, as the client has been closed.`), preceded by
`[SSL: CERTIFICATE_VERIFY_FAILED] ... requesting HEAD
https://huggingface.co/Snowflake/snowflake-arctic-embed-xs/resolve/main/adapter_config.json`.
The embedding model is nevertheless **already present in the local HF cache**
(`~/.cache/huggingface/hub/models--Snowflake--snowflake-arctic-embed-xs`) —
it is only an ancillary HEAD request (checking an LoRA `adapter_config.json`,
unrelated to the base model) that fails on TLS, then the retry logic reuses an
already-closed `httpx` client instead of failing cleanly. Verified workaround:
`HF_HUB_OFFLINE=1 cccr index --full` succeeds immediately (loads the model from
the local cache, no network call). `make_embedder` is also called
**unconditionally** at the start of `index_cmd`, before any Semgrep access — so
`cccr index` fails completely even when the caller only wants findings/endpoints
(no semantic search).

**AC** :
- `make_embedder`/the internal HF client retries only the network operation
  that failed (no reuse of a closed `httpx` client) — no more raw
  `RuntimeError` bubbling up to the user.
- If the model is already fully present in the local cache, failure of an
  ancillary HEAD request (adapter metadata) must not block loading — behavior
  equivalent to `HF_HUB_OFFLINE=1` by default when the cache is complete, with
  network fallback only if absent.
- A test simulates a complete cache + unavailable network →
  `cccr index --full` succeeds (no traceback, no network dependency).
- `cccr index` without semantic-search intent (eventually: a findings/
  endpoints-only mode, or at minimum an actionable error message rather than a
  30-line traceback) — documented in `docs/SPEC-FONC.md` if a flag is added,
  otherwise at minimum the traceback is replaced by a clear message + the
  `HF_HUB_OFFLINE=1` workaround.

### [ ] Q2 : `cccr init` without `--rules` produces an empty, silent index (0 endpoint, 0 useful finding)

**Files** : `src/ccc_radar/cli.py` (`init`), `docs/README.md`, `docs/SPEC-FONC.md`.

**Description** : reproduced on `booking-microservices-java-spring-boot`:
`cccr init` (without `--rules`) detects the absence of a local Semgrep config
and falls back to `p/security-audit` (generic registry pack). `cccr index --full`
then returns `scanned=363 skipped=0 +findings=0 -findings=0 +endpoints=0
-endpoints=0` — exit 0, no warning. The `p/security-audit` pack contains no
`category: endpoint-inventory` rule (those live in the companion
`ccc-radar-skill` repo, never published in `ccc-radar` itself):
`cccr endpoints`/`graph`/`flow` stay empty on **any** repo initialized without
already knowing that 6 specific rule files must be copied from a second repo.
This is a first-use trap: the tool looks like it works (no error) but produces
nothing usable for the flagship use case (microservices/Kafka/REST).

**AC** :
- `cccr init` without `--rules`, when the chosen pack (detected or fallback)
  contains no `category: endpoint-inventory` rule, displays an explicit warning
  (“no endpoint inventory rule active — `cccr endpoints`/`graph`/`flow` will
  stay empty; see `--rules`”).
- `cccr index`/`cccr summary` also report, when `endpoints_added=0` on a scan
  that processed Java/Kotlin files, that this is probably not a real absence of
  endpoints but an insufficient rule pack — not total silence on exit 0.
- Evaluate (ADR to decide) whether the `default/liveness/rest/kafka/
  kafka-security` packs from `ccc-radar-skill` should be vendored/published
  with `ccc-radar` itself (at least `rest`/`kafka`, the product core according
  to `docs/PRD.md`) rather than relying entirely on a second repo/skill for any
  real use.

### [ ] Q3 : `_find_first_literal` captures the first literal of the whole snippet, not the right attribute's one — silently corrupts REST paths and Kafka topics

**Files** : `src/ccc_radar/scanner.py` (`_find_first_literal`,
`_extract_rest_path`, Kafka topic extraction for `@KafkaListener`),
`tests/test_rest_endpoints.py`, `tests/test_kafka_endpoints.py`.

**Description** : three concrete reproductions of the same structural bug —
`_find_first_literal` scans the entire text of the Semgrep match (preceding
annotations + signature + method body) and returns the **first** text literal
found, without tying it to the named attribute it is supposed to represent
(`topics=`, `@GetMapping(...)`, etc.).

1. **Preceding Swagger/OpenAPI annotation overrides an explicit path** —
   `microservices-demo`,
   `image-generation-manager/.../GenerateImageProcessController.java:36-48`:
   ```java
   @Operation(summary = "Retrieve Processes", description = "...")
   @ApiResponses({...})
   @GetMapping("/processes")
   public ResponseEntity<...> getAllProcesses(...)
   ```
   `cccr endpoints` returns `GET /api/Retrieve Processes` instead of
   `GET /api/processes` — the literal `"Retrieve Processes"` from `@Operation`
   (which precedes `@GetMapping` in the text) is captured instead of the literal
   `"/processes"` that is **present and explicit** in the correct annotation.
   Same bug in `GenerationResultController.java:31-42`
   (`GET /api/Retrieve Results` instead of `GET /api/generation-results`).
   This is worse than the “missing path” case: a correct value exists in the
   snippet but an incorrect value masks it.
2. **Method body contains a literal unrelated to the path** —
   `sample-spring-kafka-microservices/order-service/.../OrderController.java`:
   bare `@PostMapping` (no value, inherits class prefix
   `@RequestMapping("/orders")`) on a method whose body calls
   `template.send("orders", ...)` → rendered path `POST /orders/orders`
   instead of `POST /orders` (same bug with bare `@GetMapping` + body
   containing `StoreQueryParameters.fromNameAndType("orders", ...)` →
   `GET /orders/orders` instead of `GET /orders`). Direct regression on the Q24
   fix (class/method prefix merge): its test fixtures do not cover the case
   “bare method annotation + body containing an unrelated literal”.
3. **`groupId=` captured instead of `topics=`** — see Q5 below
   (same root cause, listed separately because the impact is Kafka-specific).

**Product consequence** : these wrong values never appear as `<dynamic>`
(the existing marker for “unresolved value”) — they look correct, which makes
them undetectable without ground truth. This silently breaks `cccr graph`'s
`paths_match` (caller/callee correlation) and `cccr flow` (route/topic
resolution by name).

**AC** :
- `_extract_rest_path` / Kafka topic extraction only examine the arguments of
  the annotation targeted by the rule (`@GetMapping(...)`,
  `@KafkaListener(...)`), never the text of preceding annotations nor the
  method body, to find the path/topic literal.
- Non-regression test for each of the 3 cases above (preceding Swagger
  annotation with literal, bare method + body with unrelated literal,
  `groupId`/neighbor attribute in `@KafkaListener`) : the extracted literal is
  always the one from the correct attribute, or `<dynamic>` if no literal
  exists in the correct attribute — never a literal from elsewhere in the
  snippet.
- Existing Q24 (`test_rest_endpoints.py`) and Q25
  (`test_kafka_endpoints.py`) tests stay green.

### [ ] Q4 : false positive — `cccr.rest.java.call-put` (and probably `call-delete`) matches `Map.put()`/`Context.setVariable()`-style calls, not only `RestTemplate`

**Files** : `ccc-radar-skill` (`skills/cccr/rules/rest/java.yaml`,
rules `cccr.rest.java.call-put` and `call-delete` — outside this repo but rule
shipped by default to every microservices audit, see `SKILL.md`),
`docs/SPEC-TECH.md` if `ccc-radar` documents the contract of these rules.

**Description** : already identified once (`Q21` in an earlier backlog,
on `eventuate-tram-examples-customers-and-orders`) and **still present** —
reproduced again here on `fully-completed-microservices-Java-Springboot`,
7 occurrences. `cccr.rest.java.call-put` uses only the pattern `$REST.put(...)`
with no type constraint on `$REST`: it matches any `.put(...)` call,
whatever the receiver.
- `GlobalExceptionHandler.java` (duplicated identically in 4 services —
  `customer`, `order`, `payment`, `product`) : `errors.put(fieldName,
  errorMessage)` on a `Map<String,String>`
  (`handleMethodArgumentNotValidException`, line 32) → detected as
  `call rest PUT <dynamic>`. None of those 4 handlers performs any network call.
- `EmailService.java:47-49,84-87` : `variables.put("customerName",
  customerName)` etc. on a `Map<String,Object>` (Thymeleaf templating context)
  → detected as `call rest PUT /customerName`,
  `call rest PUT /amount`, etc.

On those repos, these false positives are mixed with real REST calls without
any distinct signal (same `role=call`, `system=rest`) — they pollute
`cccr endpoints`/`cccr graph` with edges that do not exist.

**AC** :
- Pattern constrained by type (`metavariable-pattern` on a declaration
  `RestTemplate $REST = ...` or equivalent Semgrep construct to restrict the
  receiver), or at minimum exclusion of known collection types
  (`pattern-not-inside` on `Map<...>`/`Properties`/`Context`).
- Same audit and fix for `cccr.rest.java.call-delete`
  (`$REST.delete(...)`, same risk with `List.delete`/`Repository.delete`).
- Test: Java fixture with a `Map.put(k, v)` next to a real
  `restTemplate.put(url, body)` → only the latter is indexed as an endpoint.

---

## P1 — Silent false negatives (real sites not detected, with no `<dynamic>` marker)

### [ ] Q5 : Kafka topic resolved as `groupId` when `topics=` references an unresolved cross-class constant

**Files** : `src/ccc_radar/scanner.py` (`@KafkaListener` topic extraction,
same function as Q3), `tests/test_kafka_endpoints.py`.

**Description** : reproduced twice on `microservices-demo`. When
`topics = TOPIC` references a `static final` field imported from **another**
class (not an `@Value`, therefore outside K2 resolution scope), the
`topics=` literal is not resolved — but instead of falling back to
`<dynamic>`, the scanner captures the **next** literal found in the
annotation, namely `groupId="..."`:
```java
private static final String TOPIC =
    KafkaTopicConfiguration.IMAGE_GENERATOR_MANAGER_IMAGE_GENERATOR_EVENTS_TOPIC;

@KafkaListener(topics = TOPIC, groupId = "image-generation-manager")
```
`cccr endpoints` returns `topic = "image-generation-manager"` (actually the
`groupId` — the real topic is
`"image-generation-manager.image-generator-events"`,
defined in `KafkaTopicConfiguration.java:11`). Same on
`GenerateImageRequestEventConsumer.java:43`
(`topic="image-generator"` instead of
`"image-generator.generation-requests"`). In both cases, the wrong value
**looks** like a plausible topic name (it even matches the Maven module name),
which makes it especially misleading without ground truth — `cccr flow`/
`cccr graph` would produce silently wrong producer/consumer correlations.

**AC** :
- When `topics=` is not a direct literal and is not resolved by the existing
  `@Value` resolution (K2), the topic is `<dynamic>` — never the value of
  another named attribute in the same annotation (`groupId`,
  `containerFactory`, etc.).
- Non-regression test: fixture with `@KafkaListener(topics = CONST,
  groupId = "some-group")` where `CONST` is a static field from another class
  → topic `<dynamic>`, never `"some-group"`.
- Evaluate whether K2 resolution (`@Value`) can be extended to `static final`
  constants local to the file/imported class (cross-file constant resolution) —
  at least documented as a known limitation in `docs/SPEC-TECH.md` if not
  handled here.

### [ ] Q6 : outbound REST call built through string concatenation — absent from the inventory, not even marked `<dynamic>`

**Files** : `src/ccc_radar/scanner.py` (rule/extraction for
`RestTemplate.exchange`/`getForObject`/etc., consistency with `topic_dynamic`
K2).

**Description** : reproduced on `fully-completed-microservices-Java-Springboot`,
`services/order/.../product/ProductClient.java:34-39` :
```java
restTemplate.exchange(productUrl + "/purchase", POST, requestEntity, responseType)
```
where `productUrl` comes from `@Value("${application.config.product-url}")`.
This call — a real order-service → product-service dependency
(`/purchase`) — **does not appear anywhere** in `cccr endpoints`: neither as a
`call` entry with a resolved path nor as `<dynamic>`. Unlike Kafka topic
handling (K2, explicit `topic_dynamic=True` when resolution fails), the absence
of a simple literal on a REST call seems to make the Semgrep rule match itself
fail rather than fall back to a `<dynamic>` marker — the site silently
disappears instead of being reported as unresolved.

**AC** :
- Same policy as K2 for REST calls: a `RestTemplate`/`WebClient`/Feign call
  whose URL is not a simple literal but an expression (concatenation,
  variable) produces a `role=call` endpoint with `topic_dynamic=True`
  (or equivalent), not a total absence.
- Test: fixture with `restTemplate.exchange(base + "/suffix", ...)` → one
  `call` endpoint `<dynamic>` is produced, not zero endpoints.

### [ ] Q7 : declarative Spring Cloud Gateway routes (YAML) still invisible — reconfirmed on 3 independent repos

**Files** : `src/ccc_radar/scanner.py` (new function outside the Semgrep
pipeline, see note already present in an earlier backlog),
`src/ccc_radar/models.py` (`source="config"`, never implemented), `src/ccc_radar/indexer.py`,
`docs/SPEC-TECH.md`, `docs/SPEC-FONC.md`.

**Description** : already identified earlier (`Q26`) on
`spring-petclinic-microservices` alone; reconfirmed this session on **3
independent repos**, with greater relative weight than previously estimated — in
each case it is the system's primary external HTTP facade that is invisible:
- `spring-petclinic-microservices` : 4 explicit routes
  (`spring.cloud.gateway.server.webflux.routes` in
  `spring-petclinic-api-gateway/src/main/resources/application.yml:20-45`,
  `Path=/api/{vet,visit,customer,genai}/** → lb://{service}`) + implicit auto-routes
  (`discovery.locator.enabled: true`, lines 7-8) for each registered Eureka
  service.
- `fully-completed-microservices-Java-Springboot` : 5 explicit routes in
  `services/config-server/src/main/resources/configurations/gateway-service.yml:10-29`
  (`customer-service`, `order-service`, `order-lines-service`,
  `product-service`, `payment-service`) + the same
  `discovery.locator.enabled: true` flag.
- `booking-microservices-java-spring-boot` : 3 routes in
  `src/apigateway/src/main/resources/application-dev.yml:11-31`, with a
  `Path=/api/{version}/flight/**` predicate containing a path template.

**AC** (reusing the Q26 template already written) :
- New extraction function (direct YAML parsing, not a Semgrep rule — same
  spirit as `_load_flat_spring_properties`) that detects
  `spring.cloud.gateway.routes`/
  `spring.cloud.gateway.server.webflux.routes` and produces one
  `MessageEndpoint` per route (`role="call"`, `system="rest"`,
  `topic="<predicate Path=>"`, `source="config"`,
  `framework="spring-cloud-gateway"`).
- Handles the `Path=` predicate with `{version}`/`**` template without silently
  truncating it.
- `discovery.locator.enabled: true` : at least one warning in the rendering
  (“additional routes may exist through auto-discovery, not enumerated”) rather
  than total silence on implicit routes.
- Wiring in `indexer.index_repo`, exposed through `cccr endpoints`/MCP
  `list_endpoints` without visible interface change.
- Test: fixture `application.yml` with multiple `lb://`/`http://` routes,
  `Path=` predicates with and without template → one endpoint per route.

### [ ] Q8 : auto-generated Spring Data REST CRUD endpoints (`@RepositoryRestResource`) are invisible

**Files** : `ccc-radar-skill` (`skills/cccr/rules/rest/java.yaml`,
new rule), `docs/SPEC-TECH.md`.

**Description** : reproduced on `microservices-kafka-mq`,
`microservice-order/src/main/java/de/oriontec/microservice/order/logic/OrderRepository.java:9` :
```java
@RepositoryRestResource(collectionResourceRel = "order", path = "order")
public interface OrderRepository extends PagingAndSortingRepository<Order, Long> { ... }
```
It automatically generates a full CRUD API (`GET/POST/PUT/PATCH/DELETE
/order`, `/order/{id}`, plus the custom query method exposed at
`/order/search/lastUpdate`) with **no** `@RequestMapping`-like annotation
visible to current rules (all anchored on `@GetMapping`/
`@RequestMapping`/etc.). `cccr endpoints` reports only the 2 endpoints from the
same service's explicit `@RestController` (`AppRestController`), entirely
missing this second, real HTTP surface.

**AC** :
- New `endpoint-inventory` rule (or dedicated extraction if not cleanly
  expressible in Semgrep) recognizing `@RepositoryRestResource` on a
  `Repository` interface, producing 5 endpoints (`GET` collection,
  `GET` item, `POST`, `PUT`/`PATCH`, `DELETE`) on the declared `path=` (or
  the entity-derived name if `path=` is absent).
- Respects `@RepositoryRestResource(exported = false)` — no endpoint produced
  in that case (verified on `ItemRepository.java`/`CustomerRepository.java`
  in the same repo, which explicitly use it to disable export).
- Test: fixture with one exported
  `@RepositoryRestResource(path="foo")` repository and a second one with
  `exported = false` → only the first produces endpoints.

---

## P2 — Scope limitations to document (current behavior is correct, but silent)

### [ ] Q9 : no signal at all when the repo uses an out-of-scope messaging/RPC middleware (RabbitMQ, JMS, gRPC) — false sense of completeness

**Files** : `src/ccc_radar/render.py` (`render_summary_text`/`render_endpoints_text`),
`docs/SPEC-FONC.md`.

**Description** : `booking-microservices-java-spring-boot` uses neither
Kafka nor `RestTemplate`/`WebClient`/Feign for inter-service communication —
everything goes through RabbitMQ (generic reflection-based outbox pattern,
no queue/exchange name literal in code) for async and gRPC for sync.
`cccr endpoints` returns 16 endpoints (all inbound REST routes), 0
`produce`/`consume`/`call` site — exit 0, no warning. An operator reading this
result without knowing the source code would wrongly conclude that this system
has no messaging/inter-service calls, whereas it actually has a rich
RabbitMQ+gRPC topology that the tool is simply not designed to see (legitimate
scope limitation, documented in `SKILL.md` — “Java + Spring + Maven
microservices”, REST + Kafka only — but invisible in use).

**AC** :
- `cccr summary`/`cccr endpoints` report, when the repo contains dependencies
  `spring-boot-starter-amqp`/`grpc-*`/`spring-jms` (best-effort detection via
  `pom.xml`/`build.gradle`) but 0 Kafka/`call` endpoint is detected, that the
  current coverage does not include that messaging type — not total silence on
  exit 0.
- Explicitly documented in `docs/SPEC-FONC.md`/`README.md` : current scope =
  Kafka (annotated Spring Kafka) + REST (Spring MVC/RestTemplate/
  WebClient/Feign) only; RabbitMQ, JMS, gRPC, Eventuate Tram,
  functional Spring Cloud Stream remain out of scope.

### [ ] Q10 : framework auto-exposed endpoints (Actuator, Swagger/OpenAPI UI) not inventoried — accepted limitation, document only

**Files** : `docs/SPEC-FONC.md`.

**Description** : confirmed on `microservices-demo` and
`spring-petclinic-microservices` — `/actuator/health`, `/actuator/metrics`,
`/actuator/prometheus`, `/swagger-ui.html`, `/v3/api-docs` are exposed on
almost all services through `management.endpoints.web.exposure.include=...`
(config, not annotated Java code) and never appear in `cccr endpoints`.
Unlike Q7/Q8, this is not a real application-architecture gap (these routes are
generic, identical on every Spring Boot service) — low priority, documentation
alone is enough for now rather than a new rule.

**AC** :
- `docs/SPEC-FONC.md` explicitly documents that `cccr endpoints` does not cover
  framework auto-exposed endpoints (Actuator, springdoc/Swagger UI, Eureka
  `/eureka/**`, Config Server REST API) — no code change required to close this
  item, only documentation.
