# AGENT.md — How to navigate and maintain this project's documentation

> This file is intended for any agent (Claude Code or otherwise) working on
> `ccc-radar`. It describes where each kind of documentation lives and the
> non-negotiable rule: **every change must be documented in a BACKLOG file**.

## Document map

| Document | Content | When to read it |
|---|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Problem, vision, personas, use cases, success metrics | To understand *why* the product exists and what it must achieve |
| [`docs/SPEC-FONC.md`](docs/SPEC-FONC.md) | Observable behavior: CLI commands, flags, error messages/exit codes, MCP tools, skill workflows | Before changing anything a user or agent sees (CLI, MCP, skill) |
| [`docs/SPEC-TECH.md`](docs/SPEC-TECH.md) | Modules, data model, SQLite schema, algorithms, JSON contract | Before changing internal architecture (`src/ccc_radar/*.py`) |
| [`docs/ADR.md`](docs/ADR.md) | Architecture decisions: context, choice, consequences | Before revisiting an already-settled choice — to know whether it is a D1-D6 “do not reopen” decision or a documented ADR-7+ adaptation |
| `archive/BACKLOG*.md` | Work tasks (initial implementation, remediations) — see below | For any new or ongoing work |

`README.md` remains the short entry point (installation, getting started) and
points to these documents; it does not duplicate their content.

## Hugging Face model downloads

When a model must be downloaded with `hf`, **disable `SSL_CERT_FILE` first** in
the current shell, otherwise environments with proxy/intercepted TLS often fail
with `CERTIFICATE_VERIFY_FAILED`.

Reference command for the repository's default model:

```bash
env -u SSL_CERT_FILE uvx --from huggingface_hub hf download \
  jinaai/jina-code-embeddings-1.5b \
  --local-dir ~/models/jina-code-embeddings-1.5b
```

The local path expected by default on the `cccr` side is
`~/models/jina-code-embeddings-1.5b`.

## Golden rule: every change must be documented in a BACKLOG

No task (feature, fix, refactor, documentation change) should be carried out
without a matching entry in an `archive/BACKLOG-<n>.md` file:

1. **Before starting**: check whether the task already exists in an ongoing
   backlog (`archive/BACKLOG-2.md` or the most recent one). Otherwise add it
   using the same template as the existing entries: title, `Files` (exact
   scope), `Description`, `AC` (verifiable acceptance criteria).
2. **During**: one task = one commit (`F<epic>.<n>: <title>` for the original
   implementation backlog, `R<n>: <title>` for remediations, `N<n>: <title>`
   for cross-cutting cleanup — see `archive/BACKLOG-2.md`).
3. **After**: check the box (`[ ]` → `[x]`) in the matching BACKLOG file in the
   same commit (or an explicit dedicated commit) — never let the file lie about
   the repository's real state.
4. **If the change reveals an architecture decision** (new, or a deviation from
   an existing decision): add an entry to `docs/ADR.md` (context / decision /
   consequences); do not leave it implicit in a commit message.
5. **If the change modifies observable behavior or internal architecture**:
   update `docs/SPEC-FONC.md` and/or `docs/SPEC-TECH.md` in the same commit as
   the code — these documents describe the code *as it is*, not as it was
   planned.

## BACKLOG file lifecycle

- All backlogs (completed or ongoing) live in `archive/`, sequentially
  numbered: `BACKLOG.md` (initial implementation plan, completed),
  `BACKLOG-2.md` (code review findings, ongoing), `BACKLOG-3.md`, etc.
- A new body of work (notable feature, remediation campaign) creates a new
  `archive/BACKLOG-<n>.md` rather than extending an already-closed file
  indefinitely.
- An existing and still-open backlog (unchecked boxes) receives new tasks that
  extend its subject.

## Inherited conventions (do not reopen)

Taken from `archive/BACKLOG.md` §“Conventions for the executing agent” — valid
for any present or future BACKLOG file:

1. Handle tasks in order; only start a task if its declared dependencies are
   `DONE`.
2. A task is `DONE` only when all its acceptance criteria pass, plus the global
   DoD.
3. **Global DoD**: `uv run pytest` passes completely, `uv run ruff check .`
   without errors, no file outside the task's `Files` scope is modified (any
   exception to this rule must be reported and approved before being applied —
   see `docs/ADR.md` ADR-7 for a precedent), and no `TODO` remains in the
   delivered code.
4. If an acceptance criterion is impossible to satisfy as written: stop and
   report it, do not silently reinterpret it (see `docs/ADR.md` for previous
   cases where this rule was applied).
