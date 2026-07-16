# PRD — ccc-radar: enriching cocoindex-code with Semgrep results

| | |
|---|---|
| **Product** | ccc-radar (working name) — extension of [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) |
| **Author** | Mehdi El-Kouhen |
| **Status** | Draft v0.1 — original product vision, partly predating architecture decisions |
| **Date** | 2026-07-11 |

> **Reading note**: this document captures the product vision and use cases as
> they were stated at project kickoff. Some implementation details (e.g. `ccc
> findings`/`ccc index --with-findings` integrated into `ccc`, single LMDB+SQLite
> store) have been **replaced** by the architecture decisions recorded in
> [`ADR.md`](./ADR.md) (notably ADR-1: companion package `cccr` rather than a
> fork of `ccc`). For what has been **actually delivered**, refer to
> [`SPEC-FONC.md`](./SPEC-FONC.md) (user-visible behavior) and
> [`SPEC-TECH.md`](./SPEC-TECH.md) (real technical architecture). This PRD remains
> the reference for: the problem, the vision, the personas/use cases, and the
> success metrics — which have not changed. The repo has since developed a
> **Java/Spring microservices audit extension** (REST/Kafka inventory, graph,
> flow) that relies on the same index but was not part of this PRD's initial V1
> commitment.

---

## 1. Context and problem

`cocoindex-code` (CLI `ccc`) gives coding agents **semantic** search
(embeddings on AST chunks) and **structural** search (AST pattern matching) for
code, exposed through a Claude Code skill, MCP server, and hooks. It answers
*“where is the code that does X?”* well.

It does not answer the **quality and security** questions developers and agents
ask every day:

- *“What potential SQL injections are in this module?”*
- *“Does this file I am about to edit already carry known findings?”*
- *“Fix all violations of the `no-raw-sql` rule in `src/api/`.”*

Today, an agent that wants these answers must run Semgrep itself for every
question: slow (full scan), expensive in tokens (verbose JSON output, not
semantically filtered), and disconnected from the code context that `ccc`
already knows how to surface. Findings are neither persisted, incremental, nor
queryable in natural language.

**Opportunity**: Semgrep produces structured results (rule, severity, message,
precise location) that pair naturally with `ccc`'s AST index. By indexing
findings *alongside* the code, the agent gets a complete answer in one query:
the code, its known issues, and the context needed to fix them.

## 2. Vision and objective

> **A coding agent queries a unified “code + static analysis” index in natural language and gets relevant, sourced, token-efficient answers.**

Product goals:

1. **Index** Semgrep rule results (rules configured by the project: Semgrep
   registry, custom packs, in-house rules) in an incremental pipeline.
2. **Link** each finding to the relevant code (AST chunk via `ccc`, or at least
   file + line range), so every answer combines finding + code.
3. **Expose** that knowledge to LLMs through the same kinds of surfaces as
   `ccc`: CLI, skill, MCP server.

Non-goals (see §5): replacing Semgrep CI/CD, doing vulnerability triage,
rewriting an analysis engine.

**Chosen product framing**:

- **Core product**: indexed, searchable Semgrep findings joined to code.
- **Separate extension**: Java/Spring microservices audit (REST/Kafka
  endpoints, inter-service graph, flow tracing), important to the project but
  treated as an extension on top of the core rather than as the definition of
  the entire product.

## 3. Personas and use cases

### Personas

- **P1 — Coding agent** (Claude Code, MCP agent): main consumer. Queries the
  index before/during an edit, fixes findings on demand.
- **P2 — Developer**: uses the CLI directly to explore security/quality debt in
  their scope.
- **P3 — Tech lead / AppSec**: configures the project's Semgrep rules, tracks
  findings over time, defines thresholds.

### Priority use cases

| ID | Use case | Persona | Priority |
|----|-------------|---------|----------|
| UC1 | Natural-language search on findings: *“unsafe deserialization issues”* → relevant findings + code + rule explanation | P1, P2 | Must |
| UC2 | Pre-edit context: before modifying a file, the agent retrieves the findings that concern it (via hook or MCP query) | P1 | Must |
| UC3 | Guided remediation: *“fix the ERROR findings in `src/api/`”* → the agent iterates over findings, with the code chunk and Semgrep `fix`/message as context | P1 | Must |
| UC4 | Cross-search code ↔ findings: *“show the session handling code and its related findings”* | P1, P2 | Should |
| UC5 | Summary: *“state of findings by severity/rule in the repo”* (aggregated view, low token cost) | P2, P3 | Should |
| UC6 | Findings diff: findings that appeared/were resolved since the last indexing | P3 | Could |

## 4. Value proposition and differentiation

- **vs `semgrep scan` on demand**: answers in < 1 s (persistent index, no
  re-scan), semantically filtered and compact output (target: 70%+ token
  savings).
- **vs SAST platforms (Semgrep AppSec Platform, SonarQube)**: local-first,
  serverless, designed for the agent's inner loop, not for governance.
- **vs code-only index (`ccc` today)**: each answer can carry the “known
  issues” dimension, which no code-only embedding captures.

## 5. Scope

### Included (V1 — core product)

- Running Semgrep driven by the project's rule configuration (local rules file
  or registry pack).
- Incremental finding indexing: re-scan limited to modified files.
- Finding data model: rule (id, message, severity, category/CWE/OWASP when
  present), location (file, lines), snippet, suggested `fix`.
- Embedding of findings (rule message + metadata + snippet) into a dedicated
  vector store.
- CLI for natural-language search/filters/aggregates.
- MCP: findings search tools + cross-search code ↔ findings.
- Claude Code skill (query workflow + guided remediation).

### Java/Spring microservices audit extension (outside the initial V1 commitment)

- REST/Kafka endpoint inventory from dedicated Semgrep rules.
- Inter-service graph and flow tracing.
- Multi-service Maven workspace discovery and HTML/LikeC4 graph exports.
- Scope focused on Java/Spring repos; best-effort behavior currently being
  stabilized.

### Excluded (V1 — core product)

- Engines other than Semgrep (extensibility planned in the architecture, not delivered).
- Finding triage/workflow (assignment, persisted false positives, SLA) — outside the agent loop.
- Running Semgrep Pro / cross-repo interfile taint rules.
- Automatic fix application without an agent (Semgrep `fix` values are context supplied to the agent, not a product autofix).
- Web UI / dashboards.

## 6. Functional requirements (original vision)

> The actual delivered functional detail (commands, flags, formats) is in
> [`SPEC-FONC.md`](./SPEC-FONC.md). The F1-F4 IDs below are kept for
> traceability with the use cases in §3, but the described mechanics (`ccc findings`,
> `.cocoindex_code/settings.yml`, `ccc search --with-findings`) are those of the
> initial draft, predating ADR-1.

### F1 — Configuration
- F1.1: project config accepts a dedicated section: rule sources (paths, registry packs `p/...`), includes/excludes, minimum indexed severity, timeout.
- F1.2: initialization detects an existing Semgrep config and offers to enable it.
- F1.3: missing Semgrep installation → actionable message, the rest of the tool keeps working unchanged (strictly additive feature).

### F2 — Indexing
- F2.1: indexing runs the Semgrep scan only on new/modified files and updates the findings for those files (including deletion of obsolete findings).
- F2.2: each finding is attached to the relevant code (AST chunk when available, otherwise file).
- F2.3: findings are vectorized with an embedding model (embedded text: rule message + id + categories + normalized snippet).
- F2.4: stable finding identity (rule hash + path + fingerprint of the relevant code) to enable diffing between indexings (UC6) and avoid duplicates.
- F2.5: a full scan remains available in addition to incremental indexing.

### F3 — Querying
- F3.1: natural-language search → top-k findings by similarity, with severity/rule/path/language filters and pagination.
- F3.2: compact output by default (rule, severity, file:lines, short message); option to add the linked code context.
- F3.3: code search can be annotated with the count and max severity of findings for each result.
- F3.4: aggregates by rule/severity/directory (UC5), short table format.
- F3.5: JSON output on all commands for machine consumption.

### F4 — Agent integrations
- F4.1: MCP findings search tool returning the compact F3.2 format.
- F4.2: MCP cross-search tool for code ↔ findings.
- F4.3: skill describing when to query findings and how to run guided remediation (retrieve finding → read context → patch → reindex → verify disappearance of the finding).
- F4.4: (optional) hook to refresh the index and report findings on touched files (UC2), disableable.

## 7. Non-functional requirements

- **NF1 — Query performance**: p95 < 1 s on a 500k LOC repo already indexed.
- **NF2 — Indexing performance**: incremental Semgrep overhead < 10 s for a 20-file change with default packs; never blocking for code search.
- **NF3 — Token savings**: one top-5 search answer ≤ ~1,200 tokens.
- **NF4 — Local-first & privacy**: no code, path, finding, or query sent outside (except to a cloud embedding provider if explicitly configured).
- **NF5 — Robustness**: Semgrep failure or timeout → the existing index remains valid and queryable; findings are never silently deleted after an error.
- **NF6 — Compatibility**: Python 3.10+.

## 8. Target experience (examples)

```bash
# Setup
cccr init                              # detects a Semgrep config, otherwise copies the skill packs then activates the default registry rulesets
cccr index                             # findings, incremental

# Developer
cccr search "sql injection" --severity ERROR
cccr summary
```

```text
# Agent (via MCP / skill)
User: “fix the security issues in the payments module”
Agent: search_findings("security", path_glob="src/payments/*", severity="ERROR")
      → compact findings + context
      → patch file by file, reindex_findings, re-check that the findings are gone
```

## 9. Success metrics

| Metric | V1 target |
|----------|----------|
| Relevance: % of NL findings queries where the correct finding is in the top 5 (internal eval set) | ≥ 85 % |
| Token savings vs raw `semgrep scan --json` to answer the same question | ≥ 70 % |
| Query latency p95 (500k LOC repo) | < 1 s |
| Incremental indexing overhead (20 files) | < 10 s |
| Agent remediation loop: % of fixed findings whose finding disappears after reindexing | ≥ 90 % |
| Adoption: % of users enabling the feature after 3 months | ≥ 25 % |

## 10. Risks and mitigations

| Risk | Impact | Mitigation |
|--------|--------|------------|
| Semgrep false positives → the agent “fixes” healthy code | Trust, regressions | Configurable minimum severity; the skill requires validating the finding before patching; support existing `# nosemgrep` |
| Scan cost on large repos / heavy packs | Slow indexing | Per-file incremental mode, per-rule timeout |
| Semgrep version drift (JSON format, rule behavior) | Silent breakage | Parsing contract tested on fixtures (see ADR-8) |
| Findings embeddings not discriminative enough (repetitive rule messages) | UC1 relevance | Enriched embedded text (code snippet + categories); eval set from the MVP onward |
| Upstream dependency on `cocoindex-code` (unstable internal API) | Maintenance | Companion package rather than fork (ADR-1) |

## 11. Milestones

| Milestone | Content | Exit criterion |
|-------|---------|-------------------|
| **M1 — CLI MVP** | Configuration, indexing, CLI search/summary; relevance eval set | UC1 usable day to day; relevance/latency metrics measured |
| **M2 — Agent integration** | MCP (findings + code join), skill | UC2/UC3 demonstrated end to end in Claude Code |
| **M3 — V1** | Documentation, end-to-end eval | §9 targets reached on the internal eval set |

Real status: the **core product** corresponding to this PRD is delivered. The
repo also carries an important but distinct Java/Spring microservices audit
extension whose stabilization is still ongoing.

## 12. Remaining open questions

1. Should **deleted** findings be kept as history (audit, extended UC6) or purged? V1 chose: purge (`replace_findings_for_files` deletes then reinserts), no persisted diff — UC6 (Could) is not delivered in V1.
2. ~~Should a **default rule pack** be shipped when the project has no Semgrep config?~~ Settled: `cccr init` first tries to copy the skill packs (`default`, `liveness`, `rest`, `kafka`, `kafka-security`) and otherwise activates `p/security-audit`, `p/java`, `p/owasp-top-ten` and `p/secrets` — reducing startup friction while keeping a generic fallback (see `SPEC-FONC.md`, `init` command).
3. Policy on **Semgrep Pro** (interfile rules): still out of scope, not addressed.
