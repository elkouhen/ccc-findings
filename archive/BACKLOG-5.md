# BACKLOG-5 — `cccr init` installs all Semgrep skill packs by default

## [x] N1 : Automatically copy the Semgrep rule packs into the target repo during `cccr init`

**Files** : `src/ccc_radar/cli.py`, `tests/test_cli.py`,
`docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `README.md`.

**Description** : when `cccr init` receives no `--rules` and detects no local
Semgrep config, it must look for the `ccc-radar-skill` repo, copy all known
Semgrep packs (`default`, `liveness`, `rest`, `kafka`, `kafka-security`) into
`.cccr/rules/` in the target repo, then write the config with those relative
paths. If the skill is not present locally or a pack is missing, explicitly
fall back to `p/security-audit`.

**AC** :
- `cccr init` without `--rules` copies the five packs into `.cccr/rules/` and
  writes `rules:` with those relative paths when the skill repo is available;
- explicit `--rules` and a detected local config keep their current priority;
- if the skill or an expected pack is missing, `cccr init` remains usable via
  an explicit fallback to `p/security-audit`.
