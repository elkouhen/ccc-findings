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
| cccr init state | initialized during report generation |
| Report generated | 2026-07-14 13:00:01Z |

## cccr graph

| Field | Value |
|---|---|
| Services | 2 |
| Nodes | 2 |
| Edges | 1 |
| Cycles | 0 |
| Hotspots | 0 |
| Outbound calls in consumers | 0 |
| Warnings | 0 |

Artifacts: [`assets/microservices-demo.svg`](assets/microservices-demo.svg) · [`assets/microservices-demo.d2`](assets/microservices-demo.d2)

![Graph for microservices-demo](assets/microservices-demo.svg)

## Graph notes and warnings

None.

## Discovered services

| Service | Kind | Indexed | Endpoints | Findings | Path |
|---|---|---:|---:|---:|---|
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/generated-files-storage/application` |
| rest-contracts | shared-module | yes | 0 | 2 | `/Users/m.el-kouhen/examples/microservices-demo/generated-files-storage/rest-contracts` |
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/image-generation-manager/application` |
| kafka-contracts | shared-module | yes | 0 | 0 | `/Users/m.el-kouhen/examples/microservices-demo/image-generation-manager/kafka-contracts` |
| application | microservice | yes | 11 | 5 | `/Users/m.el-kouhen/examples/microservices-demo/image-generator/application` |
| kafka-contracts | shared-module | yes | 0 | 0 | `/Users/m.el-kouhen/examples/microservices-demo/image-generator/kafka-contracts` |
