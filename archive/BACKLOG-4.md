# BACKLOG-4 — Remediations from the cross-audit of `microservices-kafka-mq`

## [x] N4 : Exclude Maven aggregator parents from the runtime graph and deduplicate federation

**Files** : `src/ccc_radar/maven.py`, `src/ccc_radar/workspace.py`,
`src/ccc_radar/graph.py`, `src/ccc_radar/flow.py`,
`tests/test_workspace.py`, `tests/test_graph.py`, `tests/test_flow.py`.

**Description** : prevent a `packaging=pom` Maven parent from appearing as a
fake microservice in `workspace`/`graph`/`flow`, and lock in deduplication by
federated site/edge identity so that a parent + child index no longer
artificially inflates the graph.

**AC** :
- `cccr workspace` no longer exposes a Maven aggregator parent as a deployable
  `microservice`, even if its `pom.xml` references Spring Boot;
- `cccr graph --workspace ...` and `cccr flow --workspace ...` no longer
duplicate relationships/sites when several indexes cover the same service;
- tests explicitly cover the `microservices-kafka-mq` case.

## [x] N5 : Make the embedder robust to historical configs pointing to a remote Hugging Face model

**Files** : `src/ccc_radar/embedder.py`, `src/ccc_radar/cli.py`,
`src/ccc_radar/indexer.py`, `tests/test_embedder.py`, `tests/test_cli.py`.

**Description** : when an already-initialized repo still carries a remote
`embedding_model` (`Snowflake/...`), automatically reuse the default local
model if it exists instead of failing on a TLS download; clearly report the
fallback in `cccr index`.

**AC** :
- `cccr index` succeeds with a historical remote config as long as the default
  local model exists;
- `cccr index` output explicitly indicates the fallback that was applied;
- the database stores the model that was actually used, not the unusable remote
  value from the config file.

## [x] N6 : Report and refresh stale endpoint inventories

**Files** : `src/ccc_radar/indexer.py`, `src/ccc_radar/workspace.py`,
`src/ccc_radar/cli.py`, `src/ccc_radar/mcp_server.py`,
`src/ccc_radar/render.py`, `src/ccc_radar/store.py`,
`src/ccc_radar/inventory_freshness.py`, `tests/test_indexer.py`,
`tests/test_cli.py`, `tests/test_workspace.py`, `tests/test_mcp_server.py`,
`docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`.

**Description** : persist an endpoint extractor signature, automatically trigger
full re-scan on the next `cccr index` if the stored signature is no longer
current, and warn read-only commands that are still reading an old inventory.

**AC** :
- an index without a signature or with an old signature forces a full re-scan
  on the next `cccr index`, even without modified files;
- `cccr graph`, `cccr flow`, and `cccr workspace` report a clear warning until
  the endpoint inventory has been refreshed;
- `cccr endpoints` also reports staleness in text rendering without breaking the
  existing JSON contract.
