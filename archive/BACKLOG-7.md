# Backlog 7 — Renforcer le couplage `ccc` ↔ `cccf` (2026-07-12)

> Objectif : dépasser le simple post-traitement (chercher du code via `ccc`,
> puis coller les findings dessus sans que ça influence rien) pour que les
> deux sources d'information (recherche sémantique de code, findings
> Semgrep) s'enrichissent mutuellement. Convention : une tâche = un commit
> (`C<n>: <titre>`), DoD globale inchangée.

### [x] C1 — Classement pondéré par sévérité dans `search_code_with_findings`
- **Fichiers** : `src/cccf/ccc_bridge.py`, `src/cccf/mcp_server.py`,
  `tests/test_ccc_bridge.py`, `docs/SPEC-FONC.md`, `docs/ADR.md`,
  `archive/BACKLOG-7.md`
- **Description** : `rank_by_severity` ré-ordonne les résultats de
  `search_code_with_findings` en boostant `score` selon `max_severity`
  (`ERROR` +0.15, `WARNING` +0.05, `INFO`/aucun +0.0) sans modifier `score`
  lui-même. `overfetch_limit` (`limit × 3`, plafonné à 50) sur-demande à
  `ccc search` en amont, sinon un résultat juste hors du top `limit` de `ccc`
  ne pourrait jamais bénéficier du boost.
- **CA** :
  1. Un résultat avec un finding `ERROR` mais un score `ccc` légèrement
     inférieur à un résultat sans finding remonte devant lui.
  2. Un résultat avec un finding mais un score nettement inférieur ne
     supplante pas un résultat clairement plus pertinent sémantiquement
     (le boost est petit devant l'écart typique des scores `ccc`).
  3. Les égalités de score+boost préservent l'ordre d'origine de `ccc`
     (tri stable).
  4. `docs/SPEC-FONC.md` documente le mécanisme et les poids.
  5. `uv run pytest` et `uv run ruff check .` passent.

### [x] C2 — `cccf search` = sur-ensemble de `ccc search` ; findings-only → `cccf findings`
- **Fichiers** : `src/cccf/code_search.py` (nouveau), `src/cccf/ccc_bridge.py`,
  `src/cccf/render.py`, `src/cccf/cli.py`, `src/cccf/mcp_server.py`,
  `tests/conftest.py` (nouveau), `tests/test_cli.py`, `tests/test_ccc_bridge.py`,
  `tests/test_e2e.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `docs/ADR.md`,
  `README.md`, `archive/BACKLOG-7.md`
- **Description** : repositionnement CLI (ADR-20). `cccf search` répond « de
  la même manière » que `ccc search` (même format de résultats, langage
  capturé par le parseur pour reproduire la ligne `File:`), enrichi d'un bloc
  findings par résultat et classé par sévérité (C1). Orchestration extraite
  dans `code_search.py`, partagée CLI/MCP. Ancienne recherche findings-only
  déplacée telle quelle sous `cccf findings`. Modes dégradés explicites
  (ccc absent → repli findings + warning ; index absent → code brut +
  warning ; les deux → erreur actionnable). Fixtures faux-`ccc` mutualisées
  dans `tests/conftest.py` (première étape de N2, BACKLOG-2).
- **CA** :
  1. `cccf search "<q>"` affiche le format `--- Result N (score) --- / File:
     path:l1-l2 [lang]` de `ccc`, avec bloc findings sous les résultats
     concernés, ordre boosté par sévérité, score affiché = score brut ccc.
  2. `cccf search --json` retourne le schéma `CodeSearchResult` stable.
  3. `cccf findings` conserve exactement l'ancien contrat (flags, JSON,
     messages d'erreur, code 2 sans index).
  4. Les trois modes dégradés sont testés (fake ccc, PATH sans ccc, index
     absent).
  5. `docs/SPEC-FONC.md`, `SPEC-TECH.md`, `README.md` (dont diagramme, rendu
     vérifié via mermaid-cli) à jour ; ADR-20 documente la décision.
  6. `uv run pytest` (72 tests) et `uv run ruff check .` passent.

## Piste évaluée et écartée pour l'instant

**Traduire un finding en pattern `ccc grep`** pour trouver des occurrences
structurellement similaires ailleurs dans le repo (au-delà de ce que la
règle Semgrep exacte a matché). Testé empiriquement sur les 4 règles de
`tests/fixtures/vuln_repo/rules/rules.yml` (traduction `$VAR` Semgrep →
`\VAR` `ccc grep`) :

| Règle | Traduction | Résultat |
|---|---|---|
| `random.random()` (pas de métavariable) | identique | ✅ fonctionne |
| `yaml.load($DATA)` (métavariable simple) | `yaml.load(\DATA)` | ✅ fonctionne |
| `cursor.execute(f"...")` (ellipsis dans une string) | — | ❌ aucune syntaxe équivalente côté `ccc grep` |
| `subprocess.run(..., shell=True, ...)` (ellipsis + kwarg littéral) | `subprocess.run(\(ARGS*\))` | ❌ matche tous les appels à la fonction, la contrainte de sécurité disparaît |

Le DSL `ccc grep` (métavariable `\NOM`, groupe variadique `\(ARGS*\)`) ne sait
pas exprimer « arguments quelconques, PUIS ce kwarg littéral, PUIS d'autres
arguments quelconques » — la forme la plus courante des règles de sécurité
réelles. Sur cet échantillon, 2 règles sur 4 se traduisent proprement.

**Si repris un jour** : ne proposer la traduction que pour les règles dont le
pattern Semgrep ne contient ni `...` ni motif composé (détectable en
inspectant le YAML de la règle avant de tenter la traduction) — plutôt que de
produire un faux résultat silencieusement trop large pour les autres.
