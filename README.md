# ccc-radar (`cccr`)

Index Semgrep et inventaire d'architecture Java/Spring, complétés par [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) (`ccc`) pour la recherche de code.

`cccr` locally indexes a project's Semgrep findings (in a SQLite database
`.cccr/findings.db`), interroge les findings avec une recherche lexicale
précise, et annote les résultats de `ccc` à la requête.

The chosen positioning is intentionally **two-layered**:

- **Core product**: Semgrep findings index for agents and developers
  (`init`, `index`, `findings`, `summary`, `search`, MCP `search_findings` /
  `findings_summary` / `search` / `reindex_findings`).
- **Java/Spring microservices audit extension**: REST/Kafka inventory,
  inter-service graph, and business-object exploration (`microservices`,
  `topics`, `resources`, `.drawio` export) built on top of the same index, but to be treated
  as a microservices-focused extension still being stabilized.

## Architecture — how `cccr` extends `ccc`

`cccr` is a **companion package**, not a fork: it imports none of `ccc`'s
internal code (ADR-1). The stable engine indexes findings separately and joins
them with `ccc` results at query time. An experimental engine,
`cccr index --engine cocoindex`, prepares a more native extension: it adds a
local code chunk index in the same SQLite store (`sqlite-vec`) so that
`cccr search` can avoid text parsing of `ccc search` when that index is
available (ADR-21).

```mermaid
flowchart LR
    subgraph ccc["ccc · cocoindex-code — indexes CODE"]
        direction TB
        CODE["source files"] --> CIDX["ccc index
chunks AST + embeddings"]
        CIDX --> CDB[("target_sqlite.db
SQLite + sqlite-vec")]
        CDB --> CSEARCH["ccc search
semantic + structural"]
        CSEARCH --> CMCP["ccc mcp"]
    end

    subgraph cccr["cccr · ccc-radar — indexes findings + experimental chunks"]
        direction TB
        REPO["same source files"] --> SCAN["semgrep scan
scanner.py"]
        SCAN --> EMB["embedder.py
sentence-transformers"]
        EMB --> FDB[("findings.db
SQLite + sqlite-vec")]
        REPO --> XCHUNKS["--engine cocoindex
experimental code chunks"]
        XCHUNKS --> FDB
        FDB --> FFIND["cccr findings
natural-language findings lookup"]
        FDB --> FSEARCH["cccr search
code + findings"]
        FFIND --> FMCP["cccr mcp"]
        FSEARCH --> FMCP
    end

    FSEARCH -. "fallback: ccc_bridge.py subprocess + text parsing (ADR-10)" .-> CSEARCH
    FMCP == "search: file + line join" ==> CMCP

    CMCP --> AGENT["Claude Code
skill + MCP client"]
    FMCP --> AGENT
```

Key points:

- **No coupling to `ccc` internal code** — the stable engine always uses the
  `ccc` binary as a subprocess; the experimental engine adds a local chunk
  index to reduce that dependency without importing any `cocoindex-code`
  internal API.
- **Two indexes, one storage technology** — each keeps its own SQLite file
  (`target_sqlite.db` for code chunks, `findings.db` for findings), but both
  use `sqlite-vec`/`vec0` for vector search (ADR-17), and the same default
  embedding model (`~/models/jina-code-embeddings-1.5b`, ADR-3).
- **The join can use the local experimental index** — with `--engine cocoindex`,
  the MCP `search` tool queries local chunks first and then joins findings by
  file + lines; otherwise it keeps the `ccc search` fallback.
- **The agent (Claude Code) is the convergence point** — through the two MCP
  servers (`ccc mcp`, `cccr mcp`) and the skill, which orchestrates code
  search, findings search, and the remediation loop.

## Documentation

- [`AGENT.md`](AGENT.md) — for any agent contributing to this repo: document map and documentation maintenance rules.
- [`docs/PRD.md`](docs/PRD.md) — product: problem, vision, personas, use cases, success metrics.
- [`docs/SPEC-FONC.md`](docs/SPEC-FONC.md) — functional specification: CLI commands, MCP tools, skill, error behaviors.
- [`docs/SPEC-TECH.md`](docs/SPEC-TECH.md) — technical specification: modules, data model, SQLite schema, algorithms.
- [`docs/ADR.md`](docs/ADR.md) — architecture decisions (context, choice, consequences).
- [`reports/README.md`](reports/README.md) — example reports generated from the repositories under `~/examples`.
The Claude Code skill (`SKILL.md`) is distributed separately from this repo, in
[`ccc-radar-skill`](https://github.com/elkouhen/ccc-radar-skill); its
functional behavior remains documented in
[`docs/SPEC-FONC.md`](docs/SPEC-FONC.md).

## Related projects

- [`cocoindex-code`](https://github.com/cocoindex-io/cocoindex-code) (`ccc`)
  — the semantic code indexing and search tool that `cccr` complements (see
  “Architecture” above). `cccr` does not fork this project and imports none of
  its internal modules (ADR-1); it calls it as a subprocess and reuses its
  storage technology (`sqlite-vec`).
- [`ccc-radar-skill`](https://github.com/elkouhen/ccc-radar-skill) —
  the Claude Code skill that orchestrates `ccc`/`cccr` from the agent (see
  above).

## Installation

Prérequis : `uv` et `pipx`. `ccc` est optionnel : il ne sert qu'à
`cccr search`; les commandes d'audit (`index`, `endpoints`, `graph`, `audit`)
n'en dépendent pas.

```bash
uv tool install ccc-radar
uv tool install cocoindex-code
pipx install semgrep
env -u SSL_CERT_FILE uvx --from huggingface_hub hf download jinaai/jina-code-embeddings-1.5b --local-dir ~/models/jina-code-embeddings-1.5b
```

The default `embedding_model` points to `~/models/jina-code-embeddings-1.5b`.
When downloading via `hf`, removing `SSL_CERT_FILE` from the environment avoids
TLS failures observed on some workstations.

## Préflight d'un audit Java/Spring

Installez le skill puis indiquez explicitement l'emplacement de ses packs :

```bash
npx skills add elkouhen/ccc-radar-skill
export CCCR_RULES_ROOT="/chemin/vers/ccc-radar-skill/skills/cccr/rules"
cccr init
cccr doctor
cccr index
cccr audit
```

`cccr doctor` doit confirmer les packs REST, Kafka, liveness et Kafka security
avant de conclure sur un graphe. Sans eux, le fallback `p/security-audit` reste
valable pour les findings, mais pas pour une cartographie d'architecture.

## Upgrade

```bash
uv tool upgrade ccc-radar   # upgrades cccr only
uv tool upgrade --all       # upgrades all tools installed via uv (including cocoindex-code)
```

## Getting started

### Core product

```bash
cccr init                       # detects a Semgrep config, otherwise copies the skill packs then falls back to p/security-audit
cccr doctor                     # validates prerequisites and active architecture packs
cccr index                      # incremental scan + progress + embeddings
ccc index                       # required for cccr search
cccr search "user auth flow"    # exact ccc result set + findings from its source file/class
cccr findings "sql injection"   # precision-first lookup (all query terms must match)
cccr summary                    # aggregated view (severities, top rules, top directories)
```

The `p/security-audit` fallback is enough for the **core product** (findings).
For the microservices extension, `cccr init` must be able to copy the skill
packs (`default`, `liveness`, `rest`, `kafka`, `kafka-security`); otherwise
`cccr endpoints` / `graph` / `topics` / `resources` have no usable inventory.
During `cccr index`, the CLI prints stage progress (file inventory, delta,
Semgrep scan, persistence, embedding) before the final
`scanned=... skipped=... +findings=...` summary line.

### Java/Spring microservices extension

```bash
cccr index --engine cocoindex   # experimental: adds a local code chunk index
cccr endpoints                  # indexed REST/Kafka inventory
cccr graph                      # inter-service REST/Kafka topology
cccr graph --drawio graph.drawio --include-mongodb  # also shows indexed MongoDB collections
cccr audit                      # high-confidence architectural risks
cccr microservices              # discovery of indexed Maven/Gradle services from current dir
cccr microservices show order-service
cccr microservices topics order-service
cccr microservices resources order-service
cccr microservices implementation endpoint <endpoint-id>
cccr topics                     # discovered Kafka topics
cccr topics consumers orders.created
cccr topics producers orders.created
cccr topics neighbors orders.created
cccr topics search created
cccr topics trace orders.created  # potential Kafka flows, not runtime traces
cccr resources                  # discovered HTTP resources
cccr resources consumers "POST /payments"
cccr resources search payments
cccr modules                    # Maven/Gradle modules, entrypoints, Mongo/Kafka facts, OpenAPI files and config templates
cccr modules graph              # declared local build dependencies between modules
cccr modules graph --drawio modules.drawio
cccr modules graph --html modules.html
```

For a **Java microservices audit** driven by the `ccc-radar-skill` skill,
`cccr init` first tries to copy these packs from the skill repo into
`.cccr/rules/`, then enables them in `rules:`. The audit workflow then remains
`cccr summary` → `cccr endpoints` → `cccr graph` → `cccr findings` /
`cccr search`.

`cccr search` is a **presentation superset of `ccc search`**: same options
(`--limit`, `--offset`, `--lang`, `--path`, `--refresh`), same results, same
order and same pagination. Each result is annotated with findings from its
source file or class; findings never alter ranking. On the MCP side, the tool has the same name as `ccc`'s
(`search`) and takes the same parameters. When `cccr` falls back to the `ccc`
bridge, a ready `ccc` index (`.cocoindex_code/target_sqlite.db`, usually built
via `ccc index`) must already exist; otherwise `cccr search` now fails
immediately with an explicit message instead of hanging until the MCP request
times out.

Example with explicit rules and a full scan:

```bash
cccr init --rules rules/rules.yml
cccr index --full
cccr findings "sql injection" --severity ERROR --path "app/*" --limit 5 --context
cccr search "user auth flow" --json
```

## Development (in this repo)

```bash
uv sync
uv run cccr version
uv run pytest
```

## MCP server

`cccr` exposes an MCP server (stdio) via `cccr mcp`.

- **Core product**: `search_findings`, `findings_summary`, `search`
  (same name and parameters as `ccc`'s `search`), and `reindex_findings`.
- **Java/Spring microservices extension**: `list_endpoints`, `graph`,
  `list_workspace_services`, `trace_message_flow`.

Client registration (e.g. Claude Code):

```json
{"mcpServers": {"cccr": {"command": "cccr", "args": ["mcp"]}}}
```

For the post-patch freshness check of a specific file (remediation loop, see
[`ccc-radar-skill`](https://github.com/elkouhen/ccc-radar-skill)), also
register the official Semgrep MCP server:

```json
{"mcpServers": {"semgrep": {"command": "uvx", "args": ["semgrep-mcp"]}}}
```

For `.cccr/config.yml` configuration field details, see
[`docs/SPEC-FONC.md`](docs/SPEC-FONC.md).

## License

[Apache License 2.0](LICENSE), like the upstream
[`cocoindex-code`](https://github.com/cocoindex-io/cocoindex-code) project.
