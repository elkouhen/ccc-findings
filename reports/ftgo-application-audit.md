# ftgo-application audit croise cccr vs lecture directe

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/ftgo-application` |
| Branch | `master` |
| HEAD | `558dfc5` |
| Commit date | `2022-09-03T21:27:37+09:00` |
| Last commit subject | `#161 parameterize Dockerfile SQL scripts using dependency versions` |
| cccr state | `.cccr/config.yml` and `.cccr/findings.db` present; repository reindexed after the Gradle/REST/Gateway fixes (`endpoint-inventory-v5`) |
| Report generated | `2026-07-14T16:07:23+02:00` |

## Artifacts

| Method | Diagram | Supporting data |
|---|---|---|
| cccr | [`ftgo-application.cccr.drawio`](ftgo-application.cccr.drawio) | [`ftgo-application.cccr.endpoints.json`](ftgo-application.cccr.endpoints.json), [`ftgo-application.cccr.graph.json`](ftgo-application.cccr.graph.json), [`ftgo-application.cccr.microservices.json`](ftgo-application.cccr.microservices.json) |
| Direct analysis | [`ftgo-application.direct.drawio`](ftgo-application.direct.drawio) | inventory reconstructed from the code paths cited in this report |

## Summary

| Method | Service nodes | Workspace services | HTTP exposed | HTTP called | Kafka produced | Kafka consumed | HTTP graph edges | Kafka graph edges |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cccr | 8 | 8 | 24 | 8 | 0 | 0 | 6 | 0 |
| Direct analysis | 8 | 8 | 24 | 8 | 8 | 11 | 6 | 10 |

- `cccr microservices` and `cccr graph` now agree on the same 8 Gradle services.
- REST endpoint inventory is now aligned with the direct read, including Spring Cloud Gateway/WebFlux routes and `GET /orders?consumerId`.
- Remaining gaps are concentrated on Eventuate/Tram Kafka extraction and on 2 gateway wildcard HTTP edges that stay labeled `POST /orders/**` instead of the concrete downstream routes.

## Service diff

| Scope | Present in both | Only cccr | Only direct analysis | Probable reason |
|---|---|---|---|---|
| Service nodes used in the graph | ftgo-accounting-service, ftgo-api-gateway, ftgo-consumer-service, ftgo-delivery-service, ftgo-kitchen-service, ftgo-order-history-service, ftgo-order-service, ftgo-restaurant-service | None | None | N/A |
| Workspace service discovery (`cccr microservices`) | ftgo-accounting-service, ftgo-api-gateway, ftgo-consumer-service, ftgo-delivery-service, ftgo-kitchen-service, ftgo-order-history-service, ftgo-order-service, ftgo-restaurant-service | None | None | Gradle workspace discovery is now handled correctly. |

## HTTP endpoint diff

### Exposed endpoints

| Category | Entries | Probable reason |
|---|---|---|
| Shared (24) | GET /accounts/{accountId}; POST /consumers (gateway); PUT /consumers; POST /consumers (consumer-service); GET /consumers/{consumerId}; POST /couriers/{courierId}/availability; GET /deliveries/{deliveryId}; POST /tickets/{ticketId}/accept; GET /restaurants/{restaurantId} (kitchen); GET /orders; GET /orders?consumerId; GET /orders/{orderId} (gateway); POST /orders (gateway); PUT /orders; POST /orders/**; PUT /orders/**; GET /orders/{orderId} (order-history); POST /orders (order-service); GET /orders/{orderId} (order-service); POST /orders/{orderId}/cancel; POST /orders/{orderId}/revise; GET /restaurants/{restaurantId} (order-service); POST /restaurants; GET /restaurants/{restaurantId} (restaurant-service) | N/A |
| Only cccr (0) | None | N/A |
| Only direct analysis (0) | None | N/A |

### Called endpoints

| Category | Entries | Probable reason |
|---|---|---|
| Shared (8) | ftgo-api-gateway -> POST /consumers; PUT /consumers; POST /orders; PUT /orders; POST /orders/**; PUT /orders/**; GET /orders; GET /orders/{orderId} | N/A |
| Only cccr (0) | None | N/A |
| Only direct analysis (0) | None | N/A |

## Kafka endpoint diff

| Category | Entries | Probable reason |
|---|---|---|
| Shared | None | `cccr` still detects no Kafka endpoint in this repository. |
| Only cccr | None | N/A |
| Only direct analysis - produced (8) | ftgo-consumer-service -> `net.chrisrichardson.ftgo.consumerservice.domain.Consumer`; ftgo-order-service -> `consumerService`, `kitchenService`, `accountingService`, `orderService`, `net.chrisrichardson.ftgo.orderservice.domain.Order`; ftgo-kitchen-service -> `net.chrisrichardson.ftgo.kitchenservice.domain.Ticket`; ftgo-restaurant-service -> `net.chrisrichardson.ftgo.restaurantservice.domain.Restaurant` | Eventuate/Tram producers are expressed through `DomainEventPublisher`, `AbstractAggregateDomainEventPublisher`, `CommandEndpointBuilder`, and `CommandWithDestinationBuilder.send(...)`, which are outside the current Spring Kafka-focused extractor surface. |
| Only direct analysis - consumed (11) | ftgo-consumer-service -> `consumerService`; ftgo-accounting-service -> `accountingService`, `net.chrisrichardson.ftgo.consumerservice.domain.Consumer`; ftgo-order-service -> `orderService`, `net.chrisrichardson.ftgo.restaurantservice.domain.Restaurant`; ftgo-kitchen-service -> `kitchenService`, `net.chrisrichardson.ftgo.restaurantservice.domain.Restaurant`; ftgo-delivery-service -> `net.chrisrichardson.ftgo.kitchenservice.domain.Ticket`, `net.chrisrichardson.ftgo.orderservice.domain.Order`, `net.chrisrichardson.ftgo.restaurantservice.domain.Restaurant`; ftgo-order-history-service -> `net.chrisrichardson.ftgo.orderservice.domain.Order` | Eventuate/Tram consumers are expressed through `SagaCommandHandlersBuilder.fromChannel(...)` and `DomainEventHandlersBuilder.forAggregateType(...)`, which are not currently indexed as Kafka consumers. |

> OrderService also produces and consumes the orderService command channel for internal saga orchestration; the self-loop is kept in the inventory but omitted from the direct diagram for readability.

## Graph edge diff

| Category | Entries | Probable reason |
|---|---|---|
| Shared - HTTP topology (6) | ftgo-api-gateway -> ftgo-consumer-service; ftgo-api-gateway -> ftgo-order-service (POST /orders); ftgo-api-gateway -> ftgo-order-service (cancel); ftgo-api-gateway -> ftgo-order-service (revise); ftgo-api-gateway -> ftgo-order-history-service; ftgo-api-gateway -> ftgo-order-service (GET /orders/{orderId}) | Source/target topology now matches the direct analysis. |
| Shared - exact HTTP labels (4) | ftgo-api-gateway -> ftgo-consumer-service :: POST /consumers; ftgo-api-gateway -> ftgo-order-service :: POST /orders; ftgo-api-gateway -> ftgo-order-history-service :: GET /orders; ftgo-api-gateway -> ftgo-order-service :: GET /orders/{orderId} | N/A |
| Only cccr - HTTP (2) | ftgo-api-gateway -> ftgo-order-service :: POST /orders/** (matched to `POST /orders/{orderId}/cancel`); ftgo-api-gateway -> ftgo-order-service :: POST /orders/** (matched to `POST /orders/{orderId}/revise`) | Gateway wildcard proxy routes are matched to the right downstream handlers, but the edge label still keeps the proxy pattern instead of the concrete callee route. |
| Only direct analysis - HTTP (2) | ftgo-api-gateway -> ftgo-order-service :: POST /orders/{orderId}/cancel; ftgo-api-gateway -> ftgo-order-service :: POST /orders/{orderId}/revise | Direct analysis expands the wildcard gateway route to the concrete downstream handlers. |
| Only direct analysis - Kafka (10) | ftgo-consumer-service -> ftgo-accounting-service :: `net.chrisrichardson.ftgo.consumerservice.domain.Consumer`; ftgo-restaurant-service -> ftgo-order-service / ftgo-kitchen-service / ftgo-delivery-service :: `net.chrisrichardson.ftgo.restaurantservice.domain.Restaurant`; ftgo-order-service -> ftgo-consumer-service / ftgo-kitchen-service / ftgo-accounting-service :: `consumerService`, `kitchenService`, `accountingService`; ftgo-order-service -> ftgo-order-history-service / ftgo-delivery-service :: `net.chrisrichardson.ftgo.orderservice.domain.Order`; ftgo-kitchen-service -> ftgo-delivery-service :: `net.chrisrichardson.ftgo.kitchenservice.domain.Ticket` | Same root cause as the Kafka endpoint diff: Eventuate/Tram channels and aggregate event streams are invisible to the current extractor, so no Kafka graph edge can be built. |

## Direct-analysis evidence used

- Runtime services in docker-compose: `docker-compose.yml:93-248`.
- API gateway downstream URLs: `docker-compose.yml:246-248`.
- API gateway routes and WebClient call: `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/consumers/ConsumerConfiguration.java:15-18`, `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/orders/OrderConfiguration.java:24-36`, `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/proxies/OrderServiceProxy.java:22-26`.
- HTTP controllers: `ftgo-accounting-service/.../AccountsController.java:15-29`, `ftgo-consumer-service/.../ConsumerController.java:10-31`, `ftgo-delivery-service/.../DeliveryServiceController.java:10-27`, `ftgo-kitchen-service/.../KitchenController.java:9-21`, `ftgo-kitchen-service/.../RestaurantController.java:13-25`, `ftgo-order-history-service/.../OrderHistoryController.java:18-45`, `ftgo-order-service/.../OrderController.java:19-72`, `ftgo-order-service/.../RestaurantController.java:14-26`, `ftgo-restaurant-service/.../RestaurantController.java:11-29`.
- Kafka/Eventuate producers and consumers: `ftgo-consumer-service/.../ConsumerService.java:25-30`, `ftgo-consumer-service-api/.../ConsumerServiceChannels.java:3-5`, `ftgo-consumer-service/.../ConsumerServiceCommandHandlers.java:18-22`, `ftgo-order-service/.../CreateOrderSaga.java:20-34`, `ftgo-order-service/.../CancelOrderSaga.java:31-91`, `ftgo-order-service/.../ReviseOrderSaga.java:32-102`, `ftgo-order-service-api/.../OrderServiceChannels.java:3-6`, `ftgo-kitchen-service-api/.../KitchenServiceChannels.java:3-6`, `ftgo-accounting-service-api/.../AccountingServiceChannels.java:4-7`, `ftgo-restaurant-service-api/.../RestaurantServiceChannels.java:3-6`, `ftgo-accounting-service/.../AccountingEventConsumer.java:16-24`, `ftgo-accounting-service/.../AccountingServiceCommandHandler.java:26-32`, `ftgo-order-service/.../OrderEventConsumer.java:19-24`, `ftgo-order-service/.../OrderCommandHandlers.java:27-40`, `ftgo-kitchen-service/.../KitchenServiceEventConsumer.java:18-23`, `ftgo-kitchen-service/.../KitchenServiceCommandHandler.java:22-36`, `ftgo-delivery-service/.../DeliveryMessageHandlers.java:26-35`, `ftgo-order-history-service/.../OrderHistoryEventHandlers.java:33-41`, `ftgo-restaurant-service/.../RestaurantService.java:20-24`, `ftgo-order-service/.../OrderService.java:76-88, 103-175`, `ftgo-kitchen-service/.../KitchenService.java:37-114`.

## Prioritized improvement candidates

| Priority | Candidate file | Title | Files concerned | Description | CA |
|---:|---|---|---|---|---|
| 1 | `archive/BACKLOG-17.md` | Eventuate/Tram Kafka inventory and graph support | `src/ccc_radar/scanner.py`, `src/ccc_radar/graph.py`, `src/ccc_radar/models.py`, `tests/`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md` | Add extraction for `CommandEndpointBuilder`, `CommandWithDestinationBuilder.send(...)`, `SagaCommandHandlersBuilder.fromChannel(...)`, `DomainEventHandlersBuilder.forAggregateType(...)`, and `DomainEventPublisher` / `AbstractAggregateDomainEventPublisher`. This remains the largest gap on ftgo: 8 produced topics, 11 consumed topics, 10 inter-service Kafka edges. | On ftgo-application, `cccr endpoints --system kafka --json` returns the 8 produced and 11 consumed endpoints above, and `cccr graph --json` returns the 10 Kafka edges above with zero HTTP regressions. |
| 2 | `archive/BACKLOG-18.md` | Expand wildcard gateway edges to concrete downstream routes | `src/ccc_radar/graph.py`, `src/ccc_radar/render.py`, `tests/`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md` | When a gateway proxy route such as `POST /orders/**` resolves to concrete handlers, preserve or project the downstream route in the graph edge label instead of keeping the wildcard proxy pattern. This closes the last remaining HTTP diff on ftgo. | On ftgo-application, `cccr graph --json` replaces the two `POST /orders/**` edges with `POST /orders/{orderId}/cancel` and `POST /orders/{orderId}/revise`, while keeping the same source/target topology. |
