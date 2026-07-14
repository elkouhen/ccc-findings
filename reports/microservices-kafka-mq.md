# microservices-kafka-mq

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/microservices-kafka-mq` |
| Origin | https://github.com/kemalat/microservices-kafka-mq |
| Branch | master |
| HEAD | `5a597e23` |
| Commit date | 2020-07-15T21:49:06+03:00 |
| Last commit subject | Update README.md |
| Working tree clean | no |
| Tracked files | 65 |
| pom.xml files | 3 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:06:45Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 2 |
| Nodes | 3 |
| Edges | 2 |
| HTTP flows | 0 |
| Kafka flows | 1 |
| Cycles | 0 |
| Hotspots | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/microservices-kafka-mq.svg`](assets/microservices-kafka-mq.svg) · [`assets/microservices-kafka-mq.d2`](assets/microservices-kafka-mq.d2)

<img src="assets/microservices-kafka-mq.svg" alt="Graph for microservices-kafka-mq" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

| Producer | Topic | Consumer | Producer site | Consumer site |
|---|---|---|---|---|
| microservice-order | order | microservice-invoicing | `microservice-order/src/main/java/de/oriontec/microservice/order/logic/OrderService.java:39-40` | `microservice-invoicing/src/main/java/de/oriontec/microservice/invoicing/events/OrderKafkaListener.java:23-28` |

### HTTP

None.

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| microservice-invoicing | microservice | yes | 4 | 1 | `/Users/m.el-kouhen/examples/microservices-kafka-mq/microservice-invoicing` |
| microservice-order | microservice | yes | 11 | 0 | `/Users/m.el-kouhen/examples/microservices-kafka-mq/microservice-order` |
