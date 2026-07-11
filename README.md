# ccc-findings (`cccf`)

Index Semgrep interrogeable en langage naturel, combiné à [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) (`ccc`).

`cccf` indexe localement les findings Semgrep d'un projet (dans une base
SQLite `.cccf/findings.db`), les rend interrogeables en langage naturel
(recherche par embeddings) et les joint aux résultats de recherche de code
de `ccc` à la requête.

## Documentation

- [`AGENT.md`](AGENT.md) — pour tout agent contribuant à ce repo : carte des documents et règle « tout changement se documente dans un BACKLOG ».
- [`docs/PRD.md`](docs/PRD.md) — produit : problème, vision, personas, cas d'usage, métriques de succès.
- [`docs/SPEC-FONC.md`](docs/SPEC-FONC.md) — spécification fonctionnelle : commandes CLI, tools MCP, skill, comportements d'erreur.
- [`docs/SPEC-TECH.md`](docs/SPEC-TECH.md) — spécification technique : modules, modèle de données, schéma SQLite, algorithmes.
- [`docs/ADR.md`](docs/ADR.md) — décisions d'architecture (contexte, choix, conséquences).
- `archive/` — historique du plan d'implémentation (`BACKLOG.md`) et des findings de revue de code (`BACKLOG-2.md`).

Le skill Claude Code (`SKILL.md`) est distribué séparément de ce repo, dans
`~/cocoindex-ext-skill/SKILL.md` ; son comportement fonctionnel reste
documenté dans [`docs/SPEC-FONC.md`](docs/SPEC-FONC.md#4-skill-claude-code).

## Installation

```bash
uv tool install ccc-findings
pipx install semgrep
```

## Démarrage

```bash
cccf init                       # détecte une config Semgrep, sinon utilise p/security-audit
cccf index                      # scan Semgrep incrémental + embeddings
cccf search "injection sql"     # recherche en langage naturel
cccf summary                    # vue agrégée (sévérités, top règles, top répertoires)
```

Exemple avec des règles explicites et un scan complet :

```bash
cccf init --rules rules/rules.yml
cccf index --full
cccf search "injection sql" --severity ERROR --path "app/*" --limit 5 --context
cccf search "injection sql" --json
```

## Développement (dans ce repo)

```bash
uv sync
uv run cccf version
uv run pytest
```

## Serveur MCP

`cccf` expose un serveur MCP (stdio) via `cccf mcp`, avec les tools
`search_findings`, `findings_summary`, `search_code_with_findings` et
`reindex_findings`. Enregistrement client (ex. Claude Code) :

```json
{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}
```

Pour la vérification fraîche post-patch d'un fichier précis (boucle de
correction, voir le skill `~/cocoindex-ext-skill/SKILL.md`), enregistrer
en complément le MCP Semgrep officiel :

```json
{"mcpServers": {"semgrep": {"command": "uvx", "args": ["semgrep-mcp"]}}}
```

Détail des champs de configuration `.cccf/config.yml` : voir
[`docs/SPEC-FONC.md`](docs/SPEC-FONC.md#1-configuration-du-projet).
