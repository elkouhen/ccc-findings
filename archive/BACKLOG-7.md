# BACKLOG-7 — Refocusing the product positioning

## [x] N1 : Clarify the framing as “core product + microservices extension”

**Files** : `README.md`, `docs/PRD.md`, `docs/SPEC-FONC.md`.

**Description** : refocus the documentation to explicitly distinguish the core
product `cccr` (Semgrep findings index queryable by agents and developers) from
the Java/Spring microservices audit extension (REST/Kafka inventory,
inter-service graph, flow tracing). The goal is to reduce scope ambiguity
without hiding the importance of the microservices extension.

**AC** :
- the README clearly presents the core product before the microservices
  extension;
- the PRD separates the core product V1 scope from the microservices extension
  delivered afterwards;
- the functional specification indicates which commands and MCP tools belong to
  the core product versus the microservices extension.
