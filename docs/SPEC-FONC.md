# Functional specification — ccc-radar (`cccr`)

> Describes the observable behavior of the three delivered surfaces: CLI, MCP
> server, and Claude Code skill. The scope is intentionally read at two levels:
> a **core product** (indexed Semgrep findings that can be searched and joined
> to code) and a **Java/Spring microservices audit extension** (REST/Kafka
> endpoints, graph, flow, workspace) built on top of the same index. For the
> internal architecture (schemas, algorithms), see [`SPEC-TECH.md`](./SPEC-TECH.md).
> For the reasoning behind the choices, see [`ADR.md`](./ADR.md).

## 1. Project configuration

File `.cccr/config.yml`, at the root of the target repo:

```yaml
rules:                  # required — paths or Semgrep config identifiers
  - rules/rules.yml
include:                # default: ["**/*"]
  - "**/*"
exclude:                # default: [".git/**", ".venv/**", "node_modules/**", ".cccr/**"]
  - ".git/**"
  - ".venv/**"
  - "node_modules/**"
  - ".cccr/**"
min_severity: INFO      # INFO | WARNING | ERROR
embedding_model: ~/models/jina-code-embeddings-1.5b
semgrep_timeout_s: 120
```

- `rules` is the only required field; if it is missing or empty, that is a
  blocking error (`ConfigError`).
- An invalid `min_severity` (outside `INFO`/`WARNING`/`ERROR`) is a blocking
  error.
- All other fields have a default value applied silently when absent from the
  file.
- The default `embedding_model` targets a model previously downloaded under
  `~/models/jina-code-embeddings-1.5b`; `~` is resolved at runtime.
- If `embedding_model` looks like a remote Hugging Face identifier
  (`org/model`) but the default local model already exists, `cccr`
  automatically reuses that local model to avoid fragile network/TLS downloads;
  `cccr index` explicitly reports that fallback and the database stores the
  model actually used.
- Independently from `include`/`exclude`: any file under a
  `src/<source-set>` directory where `<source-set>` follows the Maven/Gradle
  naming convention for test source sets (`test`, `componentTest`,
  `contractTest`, `endToEndTest`, ... — name equal to `test` or ending in
  `Test`) is **always** excluded from scanning, for both findings and
  endpoints (BACKLOG-15 H2, ADR-34; rule tightened in BACKLOG-16 P1) — neither
  configurable nor bypassable through `include`. A generic `src/<package>`
  layout (Python, JS, Rust, ...) is **not** concerned: `<package>` does not
  follow that convention. A file that was already indexed and becomes excluded
  by this rule is purged on the next `cccr index`, just like a file deleted from
  disk.

## 2. `cccr` CLI

### `cccr version`
Displays the package version (`0.1.0`).

### `cccr init [--rules PATH]...`
Creates `.cccr/config.yml`.

- Repeatable `--rules`: paths or Semgrep config identifiers (e.g.
  `rules/rules.yml`, `p/security-audit`).
- Without `--rules`: automatic detection in the order `.semgrep.yml` →
  `semgrep.yml` → `.semgrep`. If nothing is found, `cccr init` first looks for a
  local `ccc-radar-skill` repo (supported candidates:
  `~/ccc-radar-skill/skills/cccr/rules/` then
  `~/cocoindex-ext-skill/skills/cccr/rules/`) and, if it finds the five
  expected packs `default`, `liveness`, `rest`, `kafka`, `kafka-security`, it
  copies them into `.cccr/rules/` in the target repo and writes `rules:` with
  those **relative** paths (`.cccr/rules/<pack>`). If the skill is missing or
  incomplete, it falls back to the default Semgrep registry pack
  `p/security-audit` (no error): informational stdout message explaining the
  fallback and how to customize it, exit code 0. This fallback keeps the
  **core product** usable, but does not by itself activate the microservices
  extension (`endpoints` / `graph` / `workspace` / `flow`). Priority order:
  explicit `--rules` > detected local config > copied skill packs > default
  registry pack.
- If `.cccr/config.yml` already exists: explicit error, exit code 1, and the
  existing file is never overwritten.

### `cccr index [--full] [--engine manual|cocoindex]`
Indexes the project (Semgrep findings **and** REST/Kafka endpoints —
BACKLOG-11 A1).

- Default: incremental — only re-scans files added or modified since the last
  indexing (SHA-256 hash per file); files deleted from disk have their findings
  and endpoints purged.
- `--full`: forces a full scan, as if all files were modified (files deleted
  from disk are still purged).
- `--engine manual` (default): indexes findings and endpoints with the
  historical incremental engine.
- `--engine cocoindex`: experimental mode inspired by CocoIndex. It indexes the
  same findings and endpoints, and adds a local code chunk index
  (`code_chunks` + embeddings) later used by `cccr search` before falling back
  to `ccc`.
- If the endpoint extractor signature stored in the index is missing or stale,
  `cccr index` implicitly forces a full repo re-scan even without modified
  files, to refresh the REST/Kafka inventory before rewriting
  `meta.endpoint_inventory_signature`.
- Exactly one Semgrep scan per indexing: `config.rules` may mix findings rules
  (`default`, `liveness`) and endpoint inventory rules (`rest`, `kafka`,
  `metadata.category: endpoint-inventory`) — each ends up in the proper table
  without colliding (see `docs/SPEC-TECH.md`, §3). Endpoint inventory rules are
  not filtered by `min_severity`.
- One-line output:
  `scanned=<N> skipped=<N> +findings=<N> -findings=<N> +endpoints=<N> -endpoints=<N>`
  - `scanned`: number of files (re)scanned.
  - `skipped`: number of unchanged files not re-scanned.
  - `+findings`/`-findings`: findings (re)inserted / removed for scanned files
    or files deleted from disk.
  - `+endpoints`/`-endpoints`: endpoints (re)inserted / removed, same logic.
- Exit code 0 on success.
- Semgrep failure (timeout, crash, unexpected return code): error message on
  stderr, **exit code 2**, `.cccr/findings.db` remains unchanged (no partial
  write, including findings and endpoints).
- Missing or invalid `.cccr/config.yml`: error message on stderr, exit code 1.

### `cccr search "<query>" [--limit N] [--offset N] [--lang L] [--path GLOB] [--refresh] [--json]`
Semantic code search enriched with Semgrep findings that overlap each result,
then ranked while taking their severity into account (see §3,
`rank_by_severity`). Same options, same names, as `ccc search`:

| Option | Effect |
|---|---|
| `--limit N` | maximum number of results (default 5) |
| `--offset N` | pagination (default 0) |
| `--lang L` | keeps only results in language `L` (exact equality) |
| `--path GLOB` | keeps only results whose path matches the glob (style `fnmatch`) |
| `--refresh` | reindexes (incrementally) before searching |

Two code sources are possible:
- if the repo was indexed with `cccr index --engine cocoindex`, `cccr search`
  first queries the local code chunk index (`vec_code_chunks`) and does not
  depend on the text format of `ccc search` — `--lang`/`--path`/`--offset`
  filter and paginate locally, `--refresh` triggers a local incremental reindex
  (`cccr index --engine cocoindex`) before the search;
- otherwise, `cccr search` remains a **superset of `ccc search`**: same results
  (same snippets, same display format), enriched with findings, and every
  option is forwarded unchanged to the `ccc` binary.

Text rendering — identical format to `ccc search`, plus a findings block under
each relevant result:
```
--- Result 1 (score: 0.850) ---
File: src/auth.py:12-34 [python]
def login(user, password):
    ...

  ⚠ findings (max: ERROR):
  [ERROR] custom.sql-fstring  src/auth.py:18-18
    An SQL query built with an f-string allows SQL injection.
```
The displayed `score` remains the raw semantic relevance from `ccc`; the
severity boost only affects ordering.

`--json` rendering: `CodeSearchResult` object (single stable schema, see §3).

Degraded modes:
- **Experimental code index absent**: normal behavior; fallback to
  `ccc search`.
- **`ccc` unavailable** (missing from PATH, or failing): explicit error,
  stderr keeps the cause (`ccc not found in PATH...` or return code/stderr from
  `ccc`), exit code 2. In this case `cccr` does not return a successful
  findings-only-shaped result.
- **Findings index absent** (but `ccc` available): raw code results, preceded
  by the warning `findings index absent (run: cccr index): results without findings`,
  exit code 0.

### `cccr findings "<query>" [options]`
Natural-language search in indexed findings **only** (no code search) — the old
`cccr search`, renamed when `search` became the superset of `ccc search`.

| Option | Effect |
|---|---|
| `--severity S` | keeps only findings with severity ≥ S (S ∈ INFO/WARNING/ERROR ; a value outside this set — e.g. raw Semgrep severity `HIGH` — is a blocking error, exit code 2, BACKLOG-16 P4) |
| `--rule R` | keeps only findings from rule `R` (exact equality on `rule_id`) |
| `--path GLOB` | keeps only findings whose path matches the glob (style `fnmatch`) |
| `--limit N` | maximum number of results (default 5) |
| `--offset N` | pagination (default 0) |
| `--context` | adds code context (5 lines before/after, bounded to the file) |
| `--json` | structured JSON output instead of text rendering |

Text rendering, one block per result:
```
1. [ERROR] custom.sql-fstring  app/db.py:12-14  (0.83)
   An SQL query built with an f-string allows SQL injection.
```
With `--context`, the numbered code block is added afterwards (format
`{n:>5}| {line}`). If the source file disappeared or is no longer readable
since the last indexing, the finding is still displayed and the context is
reported as unavailable for that result only.

`--json` rendering of `cccr findings`: list of objects — **stable contract**
(`FindingHit`, `render.py`), also consumed by the MCP server
(`search_findings`):
```json
{
  "id": "...", "rule_id": "...", "severity": "...", "message": "...",
  "path": "...", "start_line": 0, "end_line": 0, "score": 0.0,
  "fix": null, "cwe": [], "owasp": [],
  "context": null,        // always present; string if --context succeeded
  "context_error": null   // always present; string if --context failed
}
```
`context`/`context_error` are always present (default value `null`) — stable
schema rather than keys appearing/disappearing depending on `--context`
(necessary for a correct MCP `outputSchema`, see §3).

If the index does not exist (`.cccr/findings.db` absent): exact stderr message
`Index absent. Run first: cccr index`, exit code 2.

### `cccr summary [--json]`
Aggregated view of findings.

Text rendering, 3 lines: totals by severity, top 10 rules with count, count by
first-level directory.

`--json` rendering:
```json
{
  "by_severity": {"ERROR": 2, "WARNING": 2},
  "top_rules": [{"rule_id": "...", "count": 2}, ...],
  "by_top_level_dir": {"app": 4}
}
```

Same “index absent” rules as `findings` (same message, code 2).

### `cccr endpoints [--system S] [--role R] [--topic T] [--path GLOB] [--module M] [--json]`
*Java/Spring microservices extension — beta.*

Lists indexed REST/Kafka endpoints (BACKLOG-10 K1, BACKLOG-11 A1).
Optional combinable filters:

| Option | Effect |
|---|---|
| `--system` | `rest` or `kafka` |
| `--role` | `serve`/`call` (rest) or `produce`/`consume` (kafka) |
| `--topic` | exact equality on `topic` (e.g. `"GET /orders/{id}"`, `"orders.created"`) |
| `--path` | path pattern (`fnmatch`), same style as `cccr search --path` |
| `--module` | Maven module name (artifactId, BACKLOG-13) or detected Gradle service (BACKLOG-15 H1) — `None` if neither applies |

Text rendering, one line per endpoint:
`[<system>/<role>] <topic>[ (dynamic)][ [<module>]]  <path>:<start>-<end>`

If the stored endpoint inventory is detected as stale (missing or old
signature), the text rendering adds a warning `⚠ ... relancez cccr index`.
The `--json` contract stays unchanged (bare list of `EndpointHit`).

For REST endpoints, `topic` is always canonical on the graph side:
`METHOD /path`. Absolute caller URLs (`http://service/orders`) are normalized
into a route (`/orders`); query string and fragment are ignored.
A call concatenated with a variable remains `topic_dynamic=True`, but keeps its
normalized route prefix.

Some REST endpoints are inferred outside Semgrep results when Spring materializes
them without an explicit handler that a rule can use:
- `@RequestMapping(...)` without `method=` on a Java method → `ANY /path`;
- `@RepositoryRestResource(path = "...")` → `GET/POST /path` and
  `GET/PUT/PATCH/DELETE /path/{id}` endpoints;
- `@EnableSwagger2` → `GET /swagger-ui.html`;
- `management.endpoints.web.exposure.include=*` → `GET /actuator/**`.
These endpoints stay tagged by `framework` (`spring`, `spring-data-rest`,
`swagger-ui`, `spring-actuator`) so they remain distinguishable from explicit
application routes.

`--json` rendering: list of `EndpointHit` (`id`, `role`, `system`, `topic`,
`topic_dynamic`, `source`, `framework`, `path`, `start_line`, `end_line`,
`module`, `qualified_name`). `module` first comes from the nearest Maven
`pom.xml` (artifactId, BACKLOG-13); if the repo has no `pom.xml`, it falls back
on Gradle detection (BACKLOG-15 H1, ADR-33) — the first-level directory that
contains, somewhere in its tree, a Java class with a `main()` starting Spring
Boot (`SpringApplication.run(...)`), thereby grouping all Gradle subprojects of
the same microservice together. `qualified_name` (package + Java class) is
`None` for a non-Java file.

Same “index absent” rules as `findings` (same message, code 2) — `endpoints`
lives in the same database as `findings`.

### `cccr graph [--workspace ROOT] [--json] [--drawio FILE]`
*Java/Spring microservices extension — beta.*

Likely blocking points built from indexed endpoints (BACKLOG-10 K12).
Always included: synchronous REST calls detected inside a Kafka consumer
handler **of the current project** (same file, call site inside the handler's
line range).

For inter-service cycles/hotspots, two sources are possible, tried in this
order:
1. **Without `--workspace`**: if the index covers a multi-module Maven
   directory (`cccr index` run at the parent directory, with endpoints/findings
   assigned to a module during indexing — BACKLOG-13), endpoints/findings are
   grouped by module and the graph is built directly from that single index —
   no federation needed for a monorepo.
2. **With `--workspace ROOT`**: also federates Maven microservices under `ROOT`,
   indexed **separately** (BACKLOG-11 A2, read-only —
   `discover_maven_services`/`load_federation`) — the path for services that
   live in genuinely separate repos.

Both sources feed the same algorithm (`graph.build_graph`) and report:
- **cycles**: simple cycles containing at least one synchronous REST edge
  (a `WebClient` edge, non-blocking by nature, does not count — K11), with the
  sites (file:lines) of each edge;
- **hotspots**: sites on a cycle overlapped by a finding (file+lines
  overlapping, same module/service), ranked by descending severity.

If neither is available (non-Maven repo without `--workspace`, or no Maven
module detected), `cycles`/`hotspots` remain empty, with a `note` explicitly
saying so (see ADR-27) rather than making the absence of a result ambiguous.

`--json` rendering:
```json
{
  "outbound_calls_in_consumers": [
    {"consumer": {"path": "...", "start_line": 15, "end_line": 25, "topic": "orders.created"},
     "call": {"path": "...", "start_line": 20, "end_line": 20, "topic": "POST /payments"}}
  ],
  "cycles": [
    {"services": ["service-x", "service-y", "service-z", "service-x"],
     "has_synchronous_rest": true,
     "edges": [{"kind": "rest", "from_service": "service-x", "to_service": "service-y",
                "from_site": {"path": "...", "start_line": 13, "end_line": 13, "topic": "GET /y-status"},
                "to_site": {"path": "...", "start_line": 9, "end_line": 11, "topic": "GET /y-status"}}]}
  ],
  "hotspots": [
    {"service": "service-x", "site": {"path": "...", "start_line": 13, "end_line": 13, "topic": "GET /y-status"},
     "finding_rule_id": "rules.cccr.liveness.java.new-resttemplate-no-timeout", "finding_severity": "WARNING"}
  ],
  "note": ""
}
```
`note` is empty as soon as an inter-module data source (Maven module or
`--workspace`) produced a result without warning; otherwise it concatenates the
applicable warnings, whether they come from federation (`service` not indexed,
incompatible database) or from a stale endpoint inventory on the current
project.

Same “index absent” rules as `findings`/`summary` (same message, code 2) —
`endpoints` lives in the same database as `findings` (`.cccr/findings.db`).
`--workspace` never makes the command fail: a missing or incompatible federated
service is reported in `note`, not as an error (K7 CA2).

`--drawio FILE` (BACKLOG-14 G1): instead of JSON/text rendering, writes the
complete service ↔ service graph (not only cycle edges) in `.drawio`
(mxGraph XML, directly openable in diagrams.net) to `FILE`, and displays a
short confirmation (number of services/edges). One node per service known from
the same data source as `--json` (grouped Maven modules, or `--workspace`
federation) — including a service with no edge at all. One edge per matched
REST call (call → serve) or matched Kafka event (produce → consume): solid line
for REST, dashed for Kafka, label = route/topic. Edges that belong to a
synchronous cycle (`has_synchronous_rest: true`, meaning at least one non-
`WebClient` REST edge) are highlighted in red — same signal as the
`[synchronous]` marker in text rendering. Without inter-module data, it writes a
valid document but with no node/edge and displays the same explanatory `note`
as `--json` (never a silent failure). Incompatible with `--json`: `--drawio`
takes precedence if provided. No equivalent MCP tool — a `.drawio` file is not
an agent-consumable result, unlike the JSON already returned by `graph`.

### `cccr workspace <root> [--json]`
*Java/Spring microservices extension — beta.*

Discovers Maven modules under `root` (BACKLOG-11 A2, ADR-30): one module per
found `pom.xml`, named after its `artifactId`, classified as `microservice`
(the module carries a `main()` class that runs `SpringApplication.run(...)`, or
its `pom.xml` declares Spring Boot on a runtime packaging) or `shared-module`
otherwise. Aggregator poms with `packaging=pom` are always ignored, even if
they centralize the Spring Boot plugin for their children. For each module
already indexed (`cccr index` run either inside the module itself or once at the
multi-module parent), it reads its database **read-only** (never writes into
another project's database) to count its endpoints and findings.

`--json` rendering:
```json
{
  "services": [
    {"name": "order-service", "path": "/repo/order-service", "kind": "microservice",
     "indexed": true, "endpoint_count": 4, "finding_count": 2},
    {"name": "common-lib", "path": "/repo/common-lib", "kind": "shared-module",
     "indexed": true, "endpoint_count": 0, "finding_count": 1}
  ],
  "warnings": ["payment-service (/repo/payment-service): not indexed, ignored (run cccr index in this project)."]
}
```

`endpoint_count` of a `shared-module` is always `0`: a shared module is never
handled as a runtime producer/consumer, even if endpoints were detected there by
mistake (A2 CA5). A module not indexed, with a missing database, or with an
incompatible schema does not make the command fail: it appears in `warnings`,
absent from the counts. An indexed module whose
`meta.endpoint_inventory_signature` is missing/old also adds an explicit
warning. No Maven module found → informational message, exit code 0 (not an
error — `root` may legitimately not be a Maven directory).

### `cccr flow <query> [--workspace ROOT] [--json]`
*Java/Spring microservices extension — beta.*

Resolves `<query>` into a Kafka topic or REST route (BACKLOG-10 K5): exact name
first, otherwise case-insensitive substring **if it designates a unique
route/topic** among indexed endpoints — an ambiguous match (several topics
contain the substring) fails rather than choosing arbitrarily.

Without `--workspace` only: if textual resolution fails, a last-resort
**vector similarity** fallback (BACKLOG-10 K3) looks for the nearest neighbor
among endpoints already embedded by `cccr index` (`cccr endpoints`/`cccr graph`
also depend on it indirectly, same indexing pipeline) — useful for a natural-
language query that contains no literal topic/route name. Below a minimum
similarity threshold, no result is kept (same policy as `topic_dynamic`: never
resolved by guesswork) and the failure remains the same message as for an
unsuccessful textual resolution. This fallback is not available with
`--workspace` (multi-service federation).

Without `--workspace`: searches only the current project, but `service` now
reflects the Maven module of each site (`endpoint.module`, BACKLOG-13) when the
index covers a multi-module directory — `null` only for a non-Maven repo or a
site outside the Maven tree, never to hide federation. With `--workspace ROOT`:
also federates separately indexed Maven microservices under `ROOT`
(BACKLOG-11 A2, read-only). In both cases, every site in the flow
(Kafka producer/consumer, or REST server/caller) appears assigned to its
service, and for each site the overlapping Semgrep findings (overlapping file +
lines, same service — spirit of ADR-19) are listed by `rule_id`. A stale
endpoint inventory is surfaced through `warnings` rather than silently being
confused with the absence of a site.

`--json` rendering:
```json
{
  "query": "orders.created",
  "resolved_topic": "orders.created",
  "sites": [
    {"service": "order-service", "role": "produce", "system": "kafka",
     "framework": "spring-kafka", "path": "app/OrderProducer.java",
     "start_line": 14, "end_line": 14, "topic_dynamic": false,
     "finding_rule_ids": ["rules.cccr.demo.kafka-send-fire-and-forget"]},
    {"service": "payment-service", "role": "consume", "system": "kafka",
     "framework": "spring-kafka", "path": "app/OrderConsumer.java",
     "start_line": 7, "end_line": 10, "topic_dynamic": false,
     "finding_rule_ids": []}
  ],
  "warnings": []
}
```

Query with no match, or ambiguous query (several topics match as a substring):
explicit stderr message, exit code 2. Same “index absent” rules as
`findings`/`summary` (same message, code 2) when `--workspace` is not provided;
with `--workspace`, a missing or incompatible federated service never makes
`flow` fail (same guarantees as `cccr graph --workspace`/`cccr workspace`,
K7 CA2), but is **not** silently absorbed either: it appears in `warnings` — a
missing site caused by a non-federated service must stay visible, not be
confused with the real absence of a producer/consumer.

### `cccr mcp`
Starts the MCP server (stdio) on the current repo (execution directory).
`cccr mcp --help` documents the client registration block:
```json
{"mcpServers": {"cccr": {"command": "cccr", "args": ["mcp"]}}}
```

## 3. MCP server

Eight tools, each annotated with a concrete return type (`TypedDict` or
dataclass, never `str`) — FastMCP derives an `outputSchema` from it field by
field, exposed to MCP clients in addition to the usual JSON text
(`structuredContent` *and* text `content`, both in the same response; a client
that ignores the former falls back to the latter, so there is no regression for
existing clients). An exception raised inside a tool **is no longer caught**:
it bubbles up as-is, FastMCP turns it into `ToolError` and then `isError: true`
on the protocol side — the standard signal an MCP client can detect without
parsing the response text (before: `{"error": "<message>"}` returned as a
normal result, indistinguishable from success without a client-side convention).

The first four tools below form the **core product**; the next four belong to
the **Java/Spring microservices extension**.

| Tool | Return type | Role | Notes |
|---|---|---|---|
| `search_findings(query, severity=None, rule=None, path_glob=None, limit=5, include_context=False)` | `list[FindingHit]` | Natural-language search — same contract as `cccr findings --json` | No pagination (`offset`) on the MCP side |
| `findings_summary()` | `FindingsSummary` | Low-cost aggregated view | Same structure as `cccr summary --json` |
| `reindex_findings()` | `IndexReport` (dataclass from `indexer.py`, reused as-is) | Incremental reindexing | Fields `scanned, skipped, findings_added, findings_removed, deleted_files` |
| `search(query, limit=5, offset=0, lang=None, path=None, refresh=False)` | `CodeSearchResult` | Code search annotated with the findings overlapping each result — same tool name, same parameters, and same behavior as `ccc`'s `search`, and equivalent to CLI `cccr search` (shared implementation, `code_search.py`) | Uses the experimental code index if present, otherwise `ccc` |
| `list_endpoints(system=None, role=None, topic=None, path_glob=None)` | `list[EndpointHit]` | Filterable list of indexed REST/Kafka endpoints — equivalent to CLI `cccr endpoints` | BACKLOG-10 K1, BACKLOG-11 A1 |
| `graph(workspace_root=None)` | `GraphResult` | Likely blocking points (BACKLOG-10 K12) — equivalent to CLI `cccr graph`/`cccr graph --workspace` | `cycles`/`hotspots` empty without `workspace_root` (ADR-27); real otherwise (A2 federation) |
| `list_workspace_services(root)` | `WorkspaceResult` | Maven module discovery + endpoint/finding counts per service — equivalent to CLI `cccr workspace` | Read-only (ADR-30); BACKLOG-11 A2 |
| `trace_message_flow(query, workspace_root=None)` | `FlowResultInfo` | Resolves a topic/route and lists its sites (producers/consumers, or servers/callers) with the findings overlapping them — equivalent to CLI `cccr flow`/`cccr flow --workspace` | No-match or ambiguous query → `ToolError` (BACKLOG-10 K5/K6) |

`search` adds to each code result:
- `findings`: list of findings whose `path` is identical and whose
  `[start_line, end_line]` range overlaps the code result's one (inclusive
  overlap — a single common line is enough) — same contract as `findings`,
  without the `context` field.
- `max_severity`: highest severity among attached findings, or `null` if none.

**Severity-weighted ranking** (`ccc_bridge.rank_by_severity`): the order from
`ccc search` (pure semantic relevance) is re-ordered by adding an additive boost
to `score` depending on `max_severity` (`ERROR` +0.15, `WARNING` +0.05,
`INFO`/none +0.0), then truncated to `limit`. `score` itself is not modified —
only the order takes it into account. So that this boost can promote a result
just outside `ccc`'s top `limit`, the underlying call over-fetches
(`overfetch_limit`: `limit × 3`, capped at 50) before sorting and truncating.

`CodeSearchResult` has a **single stable schema** for successful responses
(nominal or missing findings index) — not an alternate shape depending on the
case, so that `outputSchema` remains valid:
```json
{
  "results": [...],                 // without findings if the index is absent
  "findings_only_fallback": [],     // kept empty for schema compatibility
  "warning": null                   // explanatory string in degraded mode, null otherwise
}
```
If `ccc` fails or is absent: exception (`ccc not found...` or
`ccc failed...`) → `isError: true` on the MCP side, exit code 2 on the CLI.

## 4. Claude Code skill (distributed separately — `~/cocoindex-ext-skill/SKILL.md`)

Triggers: vulnerability, security, semgrep, finding, debt, audit.

UX golden rule: start with the least costly query that answers the question,
then ask for more context only when action is needed. The skill therefore
chooses among:
1. **Overview** — `findings_summary()` for a short state.
2. **Targeted search** — `search_findings(...)` for a problem or a file.
3. **Code + debt search** — `search(...)` when the question is primarily about
   code.
4. **Remediation loop** — `search_findings(..., include_context=true)` →
   patch → fresh Semgrep scan on the file if the official MCP is available →
   `reindex_findings()` → same `search_findings(...)` to confirm disappearance;
   stop and report after 2 unsuccessful attempts.

Explicit anti-patterns: do not scan the whole repo through the official Semgrep
MCP (prefer the `cccr` index), do not fix anything without reading the context,
do not remove an existing `# nosemgrep` comment, do not expose raw JSON to the
user unless explicitly asked, and use existing MCP fallbacks rather than
blocking unnecessarily.

## 5. Error behaviors — summary

| Situation | Surface | Behavior |
|---|---|---|
| `.cccr/config.yml` absent | `cccr index` | stderr + code 1 |
| No Semgrep config detected and no `--rules` | `cccr init` | first copies skill packs if available, otherwise falls back to `p/security-audit`, informational stdout message + code 0 |
| `.cccr/config.yml` already exists | `cccr init` | stderr + code 1, file unchanged |
| Semgrep fails or exceeds timeout | `cccr index` | stderr + code 2, database unchanged |
| `.cccr/findings.db` absent | `cccr findings` / `cccr summary` (and `cccr search` if `ccc` is also unavailable) | stderr (exact message) + code 2 |
| Embeddings incompatible with the query | `cccr findings` (or findings fallback of `cccr search`) | actionable stderr + code 2 |
| Any exception | MCP tools | bubbles up as-is → FastMCP `ToolError` → `isError: true` on the protocol side; the server remains usable for the next call |
| `ccc` absent or failing | `cccr search` / `search` (MCP) | explicit stderr/exception, code 2 on CLI, `isError: true` on MCP |

## 6. Liveness rule pack (BACKLOG-10 K8)

The rule pack lives in the skill repo, not in this repo: see
[`ccc-radar-skill`](https://github.com/elkouhen/ccc-radar-skill)
`skills/cccr/rules/liveness/java.yaml`, alongside the `default` pack already
distributed by the skill (ADR-24). `cccr` itself no longer ships any rule file
(`src/ccc_radar/rules/` does not exist) — it only runs Semgrep with the paths
declared in `rules:`. This repo keeps a test copy in
`tests/fixtures/liveness_repo/rules/` (`tests/test_liveness_rules.py`), kept
manually in sync with the skill copy.

Analysis target: **Java + Spring + Maven only** — scope decision, not a
temporary gap (see “Scope” below).

| Rule | Language | Severity | Detects |
|---|---|---|---|
| `cccr.liveness.java.new-resttemplate-no-timeout` | Java | WARNING | `new RestTemplate()` without timeout configuration (vs `RestTemplateBuilder`) |
| `cccr.liveness.java.blocking-join-no-timeout` | Java | WARNING | `.join()` with no argument (`Thread` or `CompletableFuture`) |
| `cccr.liveness.java.blocking-future-get-no-timeout` | Java | WARNING | `.get()` with no argument on a variable declared as `Future<T>`/`CompletableFuture<T>` |
| `cccr.liveness.java.rest-call-in-kafka-listener` | Java | ERROR | `RestTemplate` call inside a `@KafkaListener` method |
| `cccr.liveness.java.network-call-inside-synchronized` | Java | ERROR | `RestTemplate` call inside a `synchronized` block |
| `cccr.liveness.java.mongo-lock-busy-wait-poll` | Java | ERROR | MongoDB pessimistic lock (`findAndModify`/`findOneAndUpdate`) acquired through blocking polling — `while`/`for` loop also containing `Thread.sleep(...)` |
| `cccr.liveness.java.mongo-lock-inside-synchronized` | Java | ERROR | `findAndModify`/`findOneAndUpdate` call (MongoDB pessimistic lock) inside a `synchronized` block |

**Usage** : like the `default` pack, copy it into the target repo
(e.g. `.cccr/rules/liveness/`) and declare it in `rules:` — never use an
absolute path to the skill repo (ADR-24):

```yaml
rules:
  - .cccr/rules/liveness/java.yaml
```

Scope: Java (`RestTemplate`, Spring Kafka `@KafkaListener`, `synchronized`,
`Future`/`CompletableFuture`, MongoDB pessimistic locks
`findAndModify`/`findOneAndUpdate`) — the target stack is Java + Spring +
Maven; Python/JS/TS are not targets (see K8 in `archive/BACKLOG-10.md`). The
security part (cleartext SASL, `PLAINTEXT`, unsafe deserialization) is now
covered separately in the Kafka security pack.

**MongoDB pessimistic locks** — MongoDB has no native pessimistic lock like
`SELECT ... FOR UPDATE`; the pattern observed in this code style is an atomic
write (`findAndModify`/`findOneAndUpdate`) on a “locked” field, combined with a
polling loop or JVM monitor:
- `mongo-lock-busy-wait-poll` flags the Mongo call as soon as it lives in a
  `while`/`for` loop that also contains `Thread.sleep(...)` — structural co-
  occurrence (no dependence on the lock field name), strong signal of polling
  without visible timeout or backoff.
- `mongo-lock-inside-synchronized` flags the same Mongo call inside a
  `synchronized` block — the network round-trip happens while holding a JVM
  monitor, same risk as `network-call-inside-synchronized`.
- Neither rule assumes anything about the “locked” field name (no assumption on
  `locked`/`lockedAt`/etc.): the structure (loop+sleep, or synchronized) around
  the atomic write is what signals the lock usage, not a naming convention.

## 7. REST inventory rule pack (BACKLOG-10 K11)

Like the liveness pack, it lives in `ccc-radar-skill`
(`skills/cccr/rules/rest/java.yaml`, ADR-24) — test copy in
`tests/fixtures/rest_repo/`. Unlike the liveness/`default` packs, this pack is
**not a findings pack**: `metadata.severity` (`INFO`) has no meaningful
thresholding use. It is nevertheless run during `cccr index` whenever it appears
in `rules:` (microservices audit workflow of the skill), and feeds
`cccr endpoints` / `cccr graph`.

| Rule | Language | Role | Detects |
|---|---|---|---|
| `cccr.rest.java.serve-{get,post,put,delete,patch}` | Java | `serve` | Exposed Spring route (`@GetMapping`/`@PostMapping`/`@PutMapping`/`@DeleteMapping`/`@PatchMapping`, or `@RequestMapping(method=...)` for any verb) |
| `cccr.rest.java.call-{get,post,put,delete}` | Java | `call` | `RestTemplate` call (`getForObject`/`getForEntity`, `postForObject`/`postForEntity`, `put`, `delete`) |
| `cccr.rest.java.feign-{get,post,put,delete,patch}` | Java | `call` | Method of a `@FeignClient` interface annotated with `@GetMapping`/.../`@RequestMapping(method=...)` (signature with no body — declarative client, not exposed route) |
| `cccr.rest.java.webclient-{get,post,put,delete,patch}` | Java | `call` | Fluent `WebClient` call (`.get().uri(...)`, `.post().uri(...)`, ...) |

Each result carries `metadata.category: endpoint-inventory`,
`metadata.role`, `metadata.http_method`, `metadata.framework` — the contract
read by `parse_semgrep_endpoints` (see `docs/SPEC-TECH.md`, §4bis). The path is
extracted from the site text (regex on the snippet, not a Semgrep metavariable
— ADR-26): a non-literal path, or one concatenated with a variable, is marked
`topic_dynamic=True` rather than guessed. An absolute caller URL is normalized
into a canonical route (`GET http://svc/orders` → `GET /orders`) so it remains
comparable to exposed routes. A `@FeignClient` interface is never classified as
`serve`: the `serve-*` rules require a method body (`{ ... }`), absent from
Feign declarative signatures — no explicit exclusion needed. In addition,
best-effort scanner logic now:
1. resolves the base path of `@FeignClient(url = "${...}")` or
   `@FeignClient(path = "...")` and merges it into the method route, so a call
   can surface as `/api/v1/customers/{id}` instead of just `/{id}`;
2. inventories `RestTemplate.exchange(urlExpr, HttpMethod.X, ...)` even
   without a dedicated Semgrep rule, with best-effort resolution of local
   `@Value` fields, concatenated literal suffixes, and Spring Cloud Config
   Server files such as `configurations/order-service.yml`;
3. keeps a `.put(...)` match as a REST call only when the file actually shows a
   `RestTemplate` footprint, which removes `Map.put(...)` false positives.
Scope: Java only — target stack is Java + Spring + Maven (see K8/K11 in
`archive/BACKLOG-10.md`). Remaining gap: `WebClient` chain split across several
lines (`.get()` and `.uri(...)` not on the same line in the snippet —
`_find_first_literal` only searched the first line before its later
improvements).

## 8. Kafka inventory rule pack (BACKLOG-10 K2)

Like the REST pack, it lives in `ccc-radar-skill`
(`skills/cccr/rules/kafka/java.yaml`, ADR-24) — test copy in
`tests/fixtures/kafka_repo/`. Not a findings pack, but it is run during
`cccr index` whenever it appears in `rules:` (microservices audit workflow of
the skill).

| Rule | Role | Detects |
|---|---|---|
| `cccr.kafka.java.consume` | `consume` | `@KafkaListener(topics = "...")` method |
| `cccr.kafka.java.produce-template` | `produce` | `KafkaTemplate.send(topic, value, ...)` (at least 2 arguments — excludes `send(ProducerRecord)` and `send(message)`, already covered elsewhere) or `KafkaTemplate.sendDefault(...)` (implicit topic, always dynamic) |
| `cccr.kafka.java.produce-record` | `produce` | `new ProducerRecord(topic, ...)` (low-level `kafka-clients` API **and** Spring, same classes) |
| `cccr.kafka.java.consume-raw` | `consume` | `KafkaConsumer.subscribe(Collections.singletonList(...))`/`Arrays.asList(...)`/`List.of(...)` — low-level API (`confluent-kafka`), outside `@KafkaListener` |

The topic is extracted like REST (`extra.metadata.role`, no `http_method`
here), with one extra Kafka/Spring-specific case: a literal of the form
`${nested.property}` — a topic externalized into configuration
(`@KafkaListener(topics = "${app.kafka.topics.orders}")`) — is **not** treated
as a literal topic name. `cccr` tries to resolve it against repo
`application.yml`/`.yaml`/`.properties`
(`src/main/resources/` then repo root, standard Maven/Gradle layout,
supporting Spring default syntax `${prop:default}`) via
`resolve_spring_property` — see ADR-28. Resolved → `topic_dynamic=False`,
topic = found value (or default); missing and no default →
`topic_dynamic=True`, the placeholder is kept as-is (never guessed).

A variable fed by `@Value("${...}")` elsewhere in the class
(`@KafkaListener(topics = ordersTopic)`, `kafkaTemplate.send(ordersTopic,
...)`) is now followed, best-effort: `_extract_kafka_topic` finds the variable
name in the snippet, then looks for a field declaration
`@Value("${key}") ... ordersTopic;` in the same source file (regex on the text,
no Java AST or dataflow analysis between statements — same spirit as ADR-26);
the found key is resolved like a normal placeholder (`resolve_spring_property`).
A variable not fed by `@Value` in the same file (method parameter, field
initialized differently) still becomes `<dynamic>`, never guessed.
`KafkaConsumer.subscribe(...)` is deliberately restricted to the three usual
collection forms (`Collections.singletonList`/`Arrays.asList`/`List.of`) so it
never confuses an RxJava/Reactor `.subscribe(...)` (lambda/Observer, never a
`Collection<String>`) with a Kafka subscription —
`subscribe(Pattern.compile(...))` (topic-name pattern subscription) remains out
of scope. `cccr` also adds local inference for Spring producers built through
`MessageBuilder.withPayload(...).setHeader(TOPIC, ...)` then sent with
`kafkaTemplate.send(message)`: the topic is read from the `TOPIC` /
`KafkaHeaders.TOPIC` header, then resolved as a literal, Spring placeholder, or
`@Value` field with the same rules; if nothing is resolvable, it remains
`<dynamic>`.

## 9. Kafka security rule pack (BACKLOG-10 K8, security part)

Lives in `ccc-radar-skill` (`skills/cccr/rules/kafka-security/
java.yaml`, ADR-24) — test copy in
`tests/fixtures/kafka_security_repo/`. Unlike the `rest`/
`kafka` packs (inventory), these are real **findings** rules, like
`default`/`liveness` — indexed and searchable through `cccr findings`.

| Rule | Severity | Detects |
|---|---|---|
| `cccr.kafka-security.sasl-plaintext-credentials` | ERROR | `sasl.jaas.config` with a **literal** password (hard-coded `******`, not built from a variable) |
| `cccr.kafka-security.plaintext-protocol` | ERROR | `security.protocol` set to `PLAINTEXT` (literal or constant `CommonClientConfigs.SECURITY_PROTOCOL_CONFIG`) |
| `cccr.kafka-security.json-deserializer-trusts-all-packages` | ERROR | Spring Kafka `JsonDeserializer`/`ErrorHandlingDeserializer` configured with `trusted.packages = "*"` (unsafe deserialization — arbitrary class instantiation from a message) |
| `cccr.kafka-security.unsafe-java-deserialization` | ERROR | `ObjectInputStream(...).readObject()` — native Java deserialization on data potentially coming from an untrusted message |

`cccr.kafka-security.sasl-plaintext-credentials` distinguishes a hard-coded
password from a variable-injected one through `metavariable-regex` on the
source text of the literal — which carries **escaped** quotes (`\"`), not bare
quotes, because it is a Java string literal nested inside another literal (see
ADR-31, a non-obvious trap to know before writing this kind of rule).

**What is deliberately not duplicated here**: non-idempotent producer,
risky `enable.auto.commit`, and handler without DLQ/retry were in K8's initial
scope but are already covered by the `default` pack
(`skills/cccr/rules/default/b-kafka.yaml`, rules R7 and R10) — see
`archive/BACKLOG-10.md` K8. Risky `max.poll.interval.ms` remains a documented
gap (no rule, since the threshold/intent of “risky” is not unambiguous enough
for reliable detection without false positives).

Scope: Java only (see note at the top of `archive/BACKLOG-10.md`).
