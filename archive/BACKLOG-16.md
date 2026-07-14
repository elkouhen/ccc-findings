# BACKLOG-16 — Afficher les endpoints dans chaque nœud microservice du drawio

## [x] N1 : Lister les endpoints trouvés dans le rendu drawio de chaque service

**Files**: `src/ccc_radar/render.py`, `src/ccc_radar/cli.py`,
`tests/test_render.py`, `tests/test_k12_graph_workspace_e2e.py`,
`docs/SPEC-TECH.md`.

**Description**: enrich the drawio rendering of `cccr graph` so each
microservice node lists the endpoints discovered for that service, instead of
showing only the service name. This keeps the graph visual but makes each node
directly informative for HTTP/Kafka topology review.

**AC**:
- each service node still exists even without edges;
- the node label contains the service name and its discovered endpoints
  (`[system/role] topic`);
- existing edge styling and cycle highlighting remain unchanged.
