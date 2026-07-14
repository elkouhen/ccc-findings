# ftgo-application

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/ftgo-application` |
| Origin | https://github.com/microservices-patterns/ftgo-application.git |
| Branch | master |
| HEAD | `558dfc53` |
| Commit date | 2022-09-03T21:27:37+09:00 |
| Last commit subject | #161 parameterize Dockerfile SQL scripts using dependency versions |
| Working tree clean | no |
| Tracked files | 505 |
| pom.xml files | 0 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:17:09Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 8 |
| Nodes | 8 |
| Edges | 3 |
| HTTP flows | 3 |
| Kafka flows | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/ftgo-application.svg`](assets/ftgo-application.svg) · [`assets/ftgo-application.d2`](assets/ftgo-application.d2)

<img src="assets/ftgo-application.svg" alt="Graph for ftgo-application" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

None.

### HTTP

| Caller | HTTP endpoint | Callee | Caller site | Server site |
|---|---|---|---|---|
| ftgo-api-gateway | GET /orders/{orderId} | ftgo-order-history-service | `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/proxies/OrderServiceProxy.java:23-25` | `ftgo-order-history-service/src/main/java/net/chrisrichardson/ftgo/cqrs/orderhistory/web/OrderHistoryController.java:28-34` |
| ftgo-api-gateway | GET /orders/{orderId} | ftgo-order-history-service | `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/proxies/OrderServiceProxy.java:23-25` | `ftgo-order-history-service/src/main/java/net/chrisrichardson/ftgo/cqrs/orderhistory/web/OrderHistoryController.java:40-45` |
| ftgo-api-gateway | GET /orders/{orderId} | ftgo-order-service | `ftgo-api-gateway/src/main/java/net/chrisrichardson/ftgo/apiagateway/proxies/OrderServiceProxy.java:23-25` | `ftgo-order-service/src/main/java/net/chrisrichardson/ftgo/orderservice/web/OrderController.java:44-48` |

## Discovered services

No Maven microservices were discovered from this directory.
