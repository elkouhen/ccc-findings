# BACKLOG-15 — `cccr graph` doit afficher le graphe microservices / HTTP / Kafka

## [x] N1 : Exposer la topologie inter-services dans `cccr graph`

**Files**: `src/ccc_radar/cli.py`, `src/ccc_radar/mcp_server.py`,
`src/ccc_radar/render.py`, `tests/test_cli.py`, `tests/test_mcp_server.py`,
`tests/test_k12_graph_workspace_e2e.py`, `tests/test_m3_module_graph_e2e.py`,
`tests/test_render.py`, `README.md`, `docs/SPEC-FONC.md`,
`docs/SPEC-TECH.md`.

**Description**: align `cccr graph` with its intended product goal: not only
flag likely blocking points, but also display the inter-service topology built
from indexed HTTP endpoints and Kafka topics. Keep cycles/hotspots as derived
signals, but add the base graph itself (`services` + `edges`) to text/JSON
rendering and clarify that purpose in CLI/MCP/docs.

**AC**:
- `cccr graph --json` and MCP `graph()` include the discovered services and the
  inter-service REST/Kafka edges used to derive cycles/hotspots;
- text rendering shows the topology before risk signals;
- existing cycle/hotspot behavior remains available and backward-compatible
  apart from additive output fields.
