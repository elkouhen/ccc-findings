# fully-completed-microservices-Java-Springboot

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot` |
| Origin | https://github.com/PramithaMJ/fully-completed-microservices-Java-Springboot.git |
| Branch | main |
| HEAD | `4a3d1d7c` |
| Commit date | 2025-03-09T15:45:11+05:30 |
| Last commit subject | Create jekyll-gh-pages.yml |
| Working tree clean | no |
| Tracked files | 181 |
| pom.xml files | 8 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:06:45Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 5 |
| Nodes | 7 |
| Edges | 8 |
| HTTP flows | 4 |
| Kafka flows | 2 |
| Cycles | 0 |
| Hotspots | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/fully-completed-microservices-Java-Springboot.svg`](assets/fully-completed-microservices-Java-Springboot.svg) · [`assets/fully-completed-microservices-Java-Springboot.d2`](assets/fully-completed-microservices-Java-Springboot.d2)

<img src="assets/fully-completed-microservices-Java-Springboot.svg" alt="Graph for fully-completed-microservices-Java-Springboot" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

| Producer | Topic | Consumer | Producer site | Consumer site |
|---|---|---|---|---|
| order | order-topic | notification | `services/order/src/main/java/com/alibou/ecommerce/kafka/OrderProducer.java:26-26` | `services/notification/src/main/java/com/alibou/ecommerce/kafka/NotificationsConsumer.java:46-64` |
| payment | payment-topic | notification | `services/payment/src/main/java/com/alibou/ecommerce/notification/NotificationProducer.java:26-26` | `services/notification/src/main/java/com/alibou/ecommerce/kafka/NotificationsConsumer.java:27-44` |

### HTTP

| Caller | HTTP endpoint | Callee | Caller site | Server site |
|---|---|---|---|---|
| order | GET /api/v1/customers/{customer-id} | customer | `services/order/src/main/java/com/alibou/ecommerce/customer/CustomerClient.java:15-16` | `services/customer/src/main/java/com/alibou/ecommerce/customer/CustomerController.java:44-49` |
| order | GET /api/v1/customers/{customer-id} | customer | `services/order/src/main/java/com/alibou/ecommerce/customer/CustomerClient.java:15-16` | `services/customer/src/main/java/com/alibou/ecommerce/customer/CustomerController.java:51-56` |
| order | POST /api/v1/payments | payment | `services/order/src/main/java/com/alibou/ecommerce/payment/PaymentClient.java:13-14` | `services/payment/src/main/java/com/alibou/ecommerce/payment/PaymentController.java:18-23` |
| order | POST /api/v1/products/purchase | product | `services/order/src/main/java/com/alibou/ecommerce/product/ProductClient.java:34-39` | `services/product/src/main/java/com/alibou/ecommerce/product/ProductController.java:29-34` |

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| config-server | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/config-server` |
| customer | microservice | yes | 6 | 1 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/customer` |
| discovery | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/discovery` |
| gateway | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/gateway` |
| notification | microservice | yes | 2 | 0 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/notification` |
| order | microservice | yes | 8 | 2 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/order` |
| payment | microservice | yes | 2 | 0 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/payment` |
| product | microservice | yes | 4 | 2 | `/Users/m.el-kouhen/examples/fully-completed-microservices-Java-Springboot/services/product` |
