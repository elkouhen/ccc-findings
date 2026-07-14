# BACKLOG-17 — Afficher la progression de `cccr index`

## [x] N1 : Rendre visible la progression de l’indexation

**Files**: `src/ccc_radar/indexer.py`, `src/ccc_radar/coco_indexer.py`,
`src/ccc_radar/cli.py`, `tests/test_indexer.py`, `tests/test_cli.py`,
`README.md`, `docs/SPEC-FONC.md`.

**Description**: add visible progress feedback during `cccr index`, because a
full scan and embedding pass can take noticeable time on microservice
repositories. The CLI should emit stage messages for file inventory, delta
computation, Semgrep scan, persistence, and embedding, while keeping the final
summary line unchanged.

**AC**:
- `cccr index` prints stage progress during manual indexing;
- `cccr index --engine cocoindex` keeps the same progress behavior for the
  shared indexing stages and code chunk embedding;
- the final `scanned=... skipped=...` summary remains present.
