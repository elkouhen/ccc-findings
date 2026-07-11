# ccc-findings (`cccf`)

Index Semgrep interrogeable en langage naturel, combiné à [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) (`ccc`).

`cccf` indexe localement les findings Semgrep d'un projet (dans une base
SQLite `.cccf/findings.db`), les rend interrogeables en langage naturel
(recherche par embeddings) et les joint aux résultats de recherche de code
de `ccc` à la requête. Voir `PRD.md` pour le produit complet et
`BACKLOG.md` pour le plan d'implémentation.

## Installation

```bash
uv tool install ccc-findings
pipx install semgrep
```

## Démarrage

```bash
cccf init                       # détecte .semgrep.yml / semgrep.yml / .semgrep, ou --rules explicite
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
correction, voir `skills/cccf/SKILL.md`), enregistrer en complément le MCP
Semgrep officiel :

```json
{"mcpServers": {"semgrep": {"command": "uvx", "args": ["semgrep-mcp"]}}}
```

## Configuration `.cccf/config.yml`

Créé par `cccf init` (ou à éditer à la main) :

```yaml
rules:                 # requis — chemins ou identifiants de config Semgrep (ex. rules/rules.yml, p/security-audit)
  - rules/rules.yml
include:                # globs inclus dans le scan de fichiers (défaut : tout)
  - "**/*"
exclude:                # globs exclus du scan de fichiers
  - ".git/**"
  - ".venv/**"
  - "node_modules/**"
  - ".cccf/**"
min_severity: INFO      # INFO | WARNING | ERROR — sévérité minimale indexée
embedding_model: Snowflake/snowflake-arctic-embed-xs  # modèle sentence-transformers
semgrep_timeout_s: 120  # timeout Semgrep, en secondes
```

## Positionnement vs `ccc`

`cccf` est un package compagnon de `ccc` (cocoindex-code), pas un fork :
il indexe les findings Semgrep dans son propre store SQLite et se joint
aux résultats de `ccc` à la requête plutôt que de dupliquer son moteur de
recherche de code. Voir `PRD.md` pour la vision produit complète et les
décisions d'architecture.
