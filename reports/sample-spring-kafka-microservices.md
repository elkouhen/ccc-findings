# sample-spring-kafka-microservices

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/sample-spring-kafka-microservices` |
| Origin | https://github.com/piomin/sample-spring-kafka-microservices |
| Branch | master |
| HEAD | `4e1ed6b4` |
| Commit date | 2026-06-24T21:52:16Z |
| Last commit subject | Update dependency net.datafaker:datafaker to v2.7.0 (#134) |
| Working tree clean | no |
| Tracked files | 45 |
| pom.xml files | 5 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:17:09Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 3 |
| Nodes | 6 |
| Edges | 16 |
| HTTP flows | 0 |
| Kafka flows | 8 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/sample-spring-kafka-microservices.svg`](assets/sample-spring-kafka-microservices.svg) · [`assets/sample-spring-kafka-microservices.d2`](assets/sample-spring-kafka-microservices.d2)

<img src="assets/sample-spring-kafka-microservices.svg" alt="Graph for sample-spring-kafka-microservices" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

| Producer | Topic | Consumer | Producer site | Consumer site |
|---|---|---|---|---|
| order-service | orders | payment-service | `order-service/src/main/java/pl/piomin/order/OrderApp.java:74-80` | `payment-service/src/main/java/pl/piomin/payment/PaymentApp.java:30-37` |
| order-service | orders | stock-service | `order-service/src/main/java/pl/piomin/order/OrderApp.java:74-80` | `stock-service/src/main/java/pl/piomin/stock/StockApp.java:29-36` |
| order-service | orders | payment-service | `order-service/src/main/java/pl/piomin/order/controller/OrderController.java:40-40` | `payment-service/src/main/java/pl/piomin/payment/PaymentApp.java:30-37` |
| order-service | orders | stock-service | `order-service/src/main/java/pl/piomin/order/controller/OrderController.java:40-40` | `stock-service/src/main/java/pl/piomin/stock/StockApp.java:29-36` |
| order-service | orders | payment-service | `order-service/src/main/java/pl/piomin/order/service/OrderGeneratorService.java:32-32` | `payment-service/src/main/java/pl/piomin/payment/PaymentApp.java:30-37` |
| order-service | orders | stock-service | `order-service/src/main/java/pl/piomin/order/service/OrderGeneratorService.java:32-32` | `stock-service/src/main/java/pl/piomin/stock/StockApp.java:29-36` |
| payment-service | payment-orders | order-service | `payment-service/src/main/java/pl/piomin/payment/service/OrderManageService.java:36-36` | `order-service/src/main/java/pl/piomin/order/OrderApp.java:71-72` |
| stock-service | stock-orders | order-service | `stock-service/src/main/java/pl/piomin/stock/service/OrderManageService.java:36-36` | `order-service/src/main/java/pl/piomin/order/OrderApp.java:74-78` |

### HTTP

None.

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| base-domain | shared-module | yes | 0 | 0 | `/Users/m.el-kouhen/examples/sample-spring-kafka-microservices/base-domain` |
| order-service | microservice | yes | 9 | 0 | `/Users/m.el-kouhen/examples/sample-spring-kafka-microservices/order-service` |
| payment-service | microservice | yes | 2 | 1 | `/Users/m.el-kouhen/examples/sample-spring-kafka-microservices/payment-service` |
| stock-service | microservice | yes | 2 | 0 | `/Users/m.el-kouhen/examples/sample-spring-kafka-microservices/stock-service` |
