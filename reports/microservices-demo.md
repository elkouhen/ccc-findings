# microservices-demo

## Repository

| Field | Value |
|---|---|
| Path | `/Users/m.el-kouhen/examples/microservices-demo` |
| Origin | https://github.com/daroshchanka/microservices-demo.git |
| Branch | main |
| HEAD | `ee8dd46e` |
| Commit date | 2024-11-03T15:49:44+03:00 |
| Last commit subject | README: move disclaimer down |
| Working tree clean | no |
| Tracked files | 127 |
| pom.xml files | 9 |
| cccr init state | already initialized |
| Report generated | 2026-07-14 13:06:45Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 2 |
| Nodes | 2 |
| Edges | 1 |
| HTTP flows | 1 |
| Kafka flows | 0 |
| Cycles | 0 |
| Hotspots | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/microservices-demo.svg`](assets/microservices-demo.svg) · [`assets/microservices-demo.d2`](assets/microservices-demo.d2)

<img src="assets/microservices-demo.svg" alt="Graph for microservices-demo" width="960">

## Graph notes and warnings

None.

## Flows

### Kafka

None.

### HTTP

| Caller | HTTP endpoint | Callee | Caller site | Server site |
|---|---|---|---|---|
| rest-contracts | POST /api/files/upload | application | `generated-files-storage/rest-contracts/src/main/java/dmax/demo/generatedfilesstorage/feign/GeneratedFilesStorageClient.java:18-19` | `generated-files-storage/application/src/main/java/dmax/demo/generatedfilesstorage/controllers/FilesController.java:36-45` |

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/generated-files-storage/application` |
| rest-contracts | shared-module | yes | 0 | 2 | `/Users/m.el-kouhen/examples/microservices-demo/generated-files-storage/rest-contracts` |
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/image-generation-manager/application` |
| kafka-contracts | shared-module | yes | 0 | 0 | `/Users/m.el-kouhen/examples/microservices-demo/image-generation-manager/kafka-contracts` |
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/image-generator/application` |
| kafka-contracts | shared-module | yes | 0 | 0 | `/Users/m.el-kouhen/examples/microservices-demo/image-generator/kafka-contracts` |
