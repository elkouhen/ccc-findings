# spring-petclinic-microservices

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/spring-petclinic-microservices` |
| Origin | https://github.com/spring-petclinic/spring-petclinic-microservices |
| Branch | main |
| HEAD | `305a1f13` |
| Commit date | 2026-05-17T20:20:39+02:00 |
| Last commit subject | ci: bypass PR triage for spring-petclinic org members |
| Working tree clean | no |
| Tracked files | 208 |
| pom.xml files | 9 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:06:45Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 5 |
| Nodes | 5 |
| Edges | 15 |
| HTTP flows | 15 |
| Kafka flows | 0 |
| Cycles | 0 |
| Hotspots | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/spring-petclinic-microservices.svg`](assets/spring-petclinic-microservices.svg) · [`assets/spring-petclinic-microservices.d2`](assets/spring-petclinic-microservices.d2)

<img src="assets/spring-petclinic-microservices.svg" alt="Graph for spring-petclinic-microservices" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

None.

### HTTP

| Caller | HTTP endpoint | Callee | Caller site | Server site |
|---|---|---|---|---|
| spring-petclinic-api-gateway | GET /owners/{ownerId} | spring-petclinic-customers-service | `spring-petclinic-api-gateway/src/main/java/org/springframework/samples/petclinic/api/application/CustomersServiceClient.java:36-37` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/OwnerResource.java:67-70` |
| spring-petclinic-api-gateway | GET /owners/{ownerId} | spring-petclinic-customers-service | `spring-petclinic-api-gateway/src/main/java/org/springframework/samples/petclinic/api/application/CustomersServiceClient.java:36-37` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/PetResource.java:88-92` |
| spring-petclinic-api-gateway | GET /owners/{ownerId} | spring-petclinic-visits-service | `spring-petclinic-api-gateway/src/main/java/org/springframework/samples/petclinic/api/application/CustomersServiceClient.java:36-37` | `spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java:67-70` |
| spring-petclinic-api-gateway | GET /pets/visits | spring-petclinic-visits-service | `spring-petclinic-api-gateway/src/main/java/org/springframework/samples/petclinic/api/application/VisitsServiceClient.java:43-45` | `spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java:72-76` |
| spring-petclinic-genai-service | GET /owners | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:43-45` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/OwnerResource.java:67-70` |
| spring-petclinic-genai-service | GET /owners | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:43-45` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/OwnerResource.java:75-78` |
| spring-petclinic-genai-service | GET /owners | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:43-45` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/PetResource.java:88-92` |
| spring-petclinic-genai-service | GET /owners | spring-petclinic-visits-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:43-45` | `spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java:67-70` |
| spring-petclinic-genai-service | POST /owners/ | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:71-73` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/OwnerResource.java:57-62` |
| spring-petclinic-genai-service | POST /owners/ | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:71-73` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/PetResource.java:54-66` |
| spring-petclinic-genai-service | POST /owners/ | spring-petclinic-visits-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:71-73` | `spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java:56-65` |
| spring-petclinic-genai-service | POST /owners | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:80-82` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/OwnerResource.java:57-62` |
| spring-petclinic-genai-service | POST /owners | spring-petclinic-customers-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:80-82` | `spring-petclinic-customers-service/src/main/java/org/springframework/samples/petclinic/customers/web/PetResource.java:54-66` |
| spring-petclinic-genai-service | POST /owners | spring-petclinic-visits-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/AIDataProvider.java:80-82` | `spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java:56-65` |
| spring-petclinic-genai-service | GET /vets | spring-petclinic-vets-service | `spring-petclinic-genai-service/src/main/java/org/springframework/samples/petclinic/genai/VectorStoreController.java:68-70` | `spring-petclinic-vets-service/src/main/java/org/springframework/samples/petclinic/vets/web/VetResource.java:44-48` |

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| spring-petclinic-admin-server | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-admin-server` |
| spring-petclinic-api-gateway | microservice | yes | 4 | 1 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-api-gateway` |
| spring-petclinic-config-server | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-config-server` |
| spring-petclinic-customers-service | microservice | yes | 8 | 1 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-customers-service` |
| spring-petclinic-discovery-server | microservice | yes | 0 | 0 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-discovery-server` |
| spring-petclinic-genai-service | microservice | yes | 5 | 0 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-genai-service` |
| spring-petclinic-vets-service | microservice | yes | 1 | 1 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-vets-service` |
| spring-petclinic-visits-service | microservice | yes | 3 | 0 | `/Users/m.el-kouhen/examples/spring-petclinic-microservices/spring-petclinic-visits-service` |
