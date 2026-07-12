# Spécification technique — ccc-findings (`cccf`)

> Décrit l'architecture interne réellement livrée : modules, modèle de
> données, algorithmes, schéma SQLite, contrats internes. Pour le
> comportement observable par l'utilisateur, voir
> [`SPEC-FONC.md`](./SPEC-FONC.md). Pour le pourquoi des choix, voir
> [`ADR.md`](./ADR.md). Pour les défauts connus, voir `archive/BACKLOG-2.md`.

## 1. Carte des modules (`src/cccf/`)

| Module | Rôle | Dépend de |
|---|---|---|
| `models.py` | `Finding` (dataclass gelée) + `compute_finding_id` | — |
| `config.py` | `Config`, `load_config`, `init_config`, `ConfigError` | — |
| `scanner.py` | Exécution Semgrep (subprocess) + parsing JSON → `Finding` | `models`, `config` |
| `store.py` | `Store` : persistance SQLite (findings, chunks de code expérimentaux, hashs de fichiers, meta, embeddings) | `models` |
| `indexer.py` | `index_repo` : orchestration incrémentale (diff de fichiers → scan ciblé → embedding ; peut aussi indexer des chunks de code) | `config`, `scanner`, `store`, `embedder` |
| `coco_indexer.py` | Adaptateur expérimental `--engine cocoindex` : findings + chunks de code comme états cibles typés | `config`, `indexer`, `store` |
| `embedder.py` | `Embedder` (sentence-transformers), `finding_to_text` | `models` |
| `search.py` | `search_findings` (cosinus), `summary`, `get_context` | `store`, `models` |
| `render.py` | Sérialisation texte/JSON des résultats de recherche (findings, code+findings) et du résumé | `search`, `ccc_bridge` |
| `ccc_bridge.py` | Pont vers le CLI externe `ccc` : `search_code`, `annotate_with_findings`, `rank_by_severity` | `models`, `store` |
| `code_search.py` | `search_code_with_findings` : orchestration code (via `ccc`) + findings + classement + modes dégradés — implémentation partagée CLI/MCP | `ccc_bridge`, `config`, `embedder`, `render`, `search`, `store` |
| `cli.py` | Application Typer (`version`, `init`, `index`, `search`, `findings`, `summary`, `mcp`) | tous les modules ci-dessus |
| `mcp_server.py` | Serveur `FastMCP` stdio, 4 tools | `code_search`, `config`, `embedder`, `indexer`, `render`, `search`, `store` |

Le sens des dépendances est globalement `cli.py`/`mcp_server.py` → logique
métier → `store.py`. La factory publique d'embedder vit dans `embedder.py` et
est utilisée par le CLI comme par le serveur MCP.

## 2. Modèle de données

### `Finding` (`models.py`)
```python
@dataclass(frozen=True)
class Finding:
    id: str            # sha256(rule_id|path|start:end|snippet_normalisé)[:16]
    rule_id: str        # check_id Semgrep (peut être préfixé, voir §4)
    severity: str        # INFO | WARNING | ERROR (normalisée)
    message: str
    path: str            # relatif au repo_root, séparateurs '/'
    start_line: int
    end_line: int
    snippet: str          # lu depuis le fichier source, pas depuis Semgrep (voir ADR-8)
    fix: str | None
    cwe: list[str]
    owasp: list[str]
```

`compute_finding_id(rule_id, path, snippet, start_line, end_line)` : normalise
le snippet (`" ".join(snippet.split())` — espaces/indentation réduits) puis
`sha256(f"{rule_id}|{path}|{start_line}:{end_line}|{snippet_normalisé}")[:16]`.
La localisation rend deux occurrences identiques d'une même règle dans un même
fichier distinctes ; le compromis est que l'identité change si le finding se
décale dans le fichier.

### Schéma SQLite (`.cccf/findings.db`, géré par `Store`)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
-- clés utilisées : schema_version ("3"), embedding_model,
-- embedding_signature, embedding_dim, index_engine,
-- code_embedding_signature, code_embedding_dim

CREATE TABLE files (
    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, indexed_at TEXT NOT NULL
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, message TEXT,
    path TEXT, start_line INTEGER, end_line INTEGER, snippet TEXT,
    fix TEXT, cwe TEXT,      -- JSON-sérialisé
    owasp TEXT               -- JSON-sérialisé
);
CREATE INDEX idx_findings_path ON findings(path);
CREATE INDEX idx_findings_severity ON findings(severity);

CREATE TABLE code_chunks (
    id TEXT PRIMARY KEY, path TEXT, start_line INTEGER, end_line INTEGER,
    language TEXT, content TEXT
);
CREATE INDEX idx_code_chunks_path ON code_chunks(path);

-- Table virtuelle vec0 (extension sqlite-vec), créée paresseusement au
-- premier set_embedding() une fois la dimension connue ; recréée si la
-- dimension change (changement de modèle, ADR-16/ADR-17). meta.embedding_dim
-- fait double emploi : dimension courante ET "la table existe".
CREATE VIRTUAL TABLE vec_findings USING vec0(
    embedding float[N] distance_metric=cosine,
    +finding_id TEXT   -- colonne auxiliaire, pas indexée par le KNN
);

CREATE VIRTUAL TABLE vec_code_chunks USING vec0(
    embedding float[N] distance_metric=cosine,
    +chunk_id TEXT
);
```

`Store` est un context manager : ouverture = connexion + chargement de
l'extension `sqlite-vec` (`sqlite_vec.load`) + création de schéma si absent ;
sortie = `commit()` si aucune exception n'a été levée dans le bloc, sinon la
connexion est fermée sans commit (rollback SQLite implicite — c'est le
mécanisme qui garantit NF5 : un `SemgrepError` en cours d'indexation laisse
la base dans son état d'avant l'appel).

**Migration schema v1 → v2** (ADR-17) : à l'ouverture, si `findings.embedding`
(colonne `BLOB`, ancien format) existe encore, `Store` la supprime
(`ALTER TABLE ... DROP COLUMN`), efface `embedding_signature`/`embedding_dim`
de `meta`.

**Migration schema v2 → v3** (ADR-21) : `Store` crée paresseusement
`code_chunks` et `vec_code_chunks`, puis passe `schema_version` à `3`. Les
repos déjà indexés restent utilisables : l'index code expérimental reste vide
tant qu'un `cccf index --engine cocoindex` n'a pas été exécuté. Le prochain
`cccf index` manuel continue de fonctionner sans remplir `code_chunks`; aucune
commande de migration séparée n'est requise.

## 3. Pipeline d'indexation (`indexer.index_repo`)

```
1. Lister les fichiers du repo (rglob) matchant include/exclude (fnmatch),
   calculer leur sha256.
2. Comparer aux hashs stockés (table files) → deleted / changed / unchanged.
   Si full=True : changed = tous les fichiers actuels.
3. store.remove_files(deleted)  — purge fichiers + findings associés.
4. Si changed non vide :
     run_semgrep(repo_root, config, files=changed)
     store.replace_findings_for_files(changed, findings)  — DELETE puis INSERT,
       unique mécanisme de mise à jour (gère nativement les findings corrigés).
     set_file_hash pour chaque fichier de changed.
5. Embedding (voir §5) :
       si meta.embedding_signature != signature de l'embedder courant :
         ré-embedder TOUT store.all_findings() et mettre à jour meta.
     sinon : n'embedder que les findings de `changed` dont l'id n'a pas déjà
       un embedding en base (iter_embeddings()).
6. Retourner IndexReport(scanned, skipped, findings_added, findings_removed,
   deleted_files).
```

Avec `index_code_chunks=True` (utilisé par `coco_indexer.index_repo_with_cocoindex`) :
après le scan des fichiers changés, chaque fichier est découpé en chunks de
80 lignes maximum, typé par extension (`.py` → `python`, `.ts` →
`typescript`, fallback `text`), stocké dans `code_chunks`, puis embeddé dans
`vec_code_chunks`. Les fichiers supprimés passent par `Store.remove_files`, qui
purge findings, chunks et embeddings associés.

`cccf index --engine cocoindex` appelle cet adaptateur expérimental et écrit
`meta.index_engine = "cocoindex-prototype"`. Le moteur manuel reste le défaut et
écrit `meta.index_engine = "manual"` quand il est utilisé via la CLI.

`findings_removed` est calculé en comptant, **avant** suppression, les
findings déjà en base pour les chemins de `deleted` et de `changed` (via
`store.all_findings(path_glob=p)` — un appel par chemin, voir défaut connu R9
dans `archive/BACKLOG-2.md`).

## 4. Exécution Semgrep (`scanner.py`)

Commande construite :
```
semgrep scan --json --quiet --x-ignore-semgrepignore-files --timeout <semgrep_timeout_s>
  --config <r1> --config <r2> ...   # un par entrée de config.rules
  <fichiers de `files`>  ou  "."     # scan ciblé ou complet
```
Exécutée avec `cwd=repo_root`. Codes retour 0 et 1 sont normaux (1 = « des
findings ont été trouvés ») ; tout autre code lève `SemgrepError(stderr)`.
`--x-ignore-semgrepignore-files` est utilisé pour que le périmètre piloté par
`.cccf/config.yml` ne soit pas silencieusement réduit par les `.semgrepignore`
ou ignores par défaut de Semgrep, notamment sur les répertoires `tests/`.

**Effet de bord notable** : quand une entrée de `config.rules` contient un
chemin avec sous-répertoire (ex. `rules/rules.yml`), Semgrep préfixe le
`check_id` retourné avec les composants du chemin (`rules.custom.sql-fstring`
au lieu de `custom.sql-fstring`). C'est la valeur réelle stockée dans
`Finding.rule_id` — voir ADR-9.

`parse_semgrep_json(raw, repo_root)` mappe :
- `check_id` → `rule_id`
- `extra.severity`, normalisée via une table incluant l'ancien format
  `LOW/MEDIUM/HIGH/CRITICAL` → `INFO/WARNING/ERROR/ERROR`
- `path` relativisé à `repo_root` (gère les chemins absolus ou relatifs)
- `start.line` / `end.line`
- **snippet** : relu depuis le fichier source (`repo_root/path`, lignes
  `start_line`..`end_line`) plutôt que depuis `extra.lines` — voir ADR-8.
  Retourne `""` si le fichier n'est pas lisible ; le décodage utilise
  `encoding="utf-8", errors="replace"` pour éviter qu'un fichier legacy
  non-UTF-8 fasse échouer toute l'indexation.
- `extra.fix` → `fix`
- `extra.metadata.cwe` / `.owasp` : chaîne ou liste acceptée, normalisée en
  liste.

Le filtrage par `min_severity` est appliqué dans `run_semgrep` (après
`parse_semgrep_json`, qui retourne tout sans filtre) — appliqué **au moment
du scan uniquement** ; durcir `min_severity` en config n'affecte pas les
findings déjà indexés tant que leur fichier n'est pas re-scanné (défaut connu
R10).

## 5. Embedding et recherche

`embedder.finding_to_text(f)` — format exact (contrat figé, utilisé pour
l'index ET pour vérifier la pertinence via `eval/run_eval.py`) :
```
f"{f.rule_id} | {f.severity} | {f.message} | {' '.join(f.cwe + f.owasp)} | {f.path} | {' '.join(f.snippet.split())[:500]}"
```

`Embedder` (sentence-transformers, modèle par défaut
`Snowflake/snowflake-arctic-embed-xs`) charge le modèle paresseusement au
premier appel, encode par batch, normalise L2, retourne du `float32`.
`embed_query` réutilise `embed_texts` sur une liste à un élément. La factory
publique `make_embedder(model_name)` est cachée par modèle et mode fake dans le
processus, ce qui évite de recharger le modèle à chaque appel MCP. Chaque
embedder expose une `signature` stockée dans `meta.embedding_signature`; la
dimension vectorielle est stockée dans `meta.embedding_dim`.

`search.search_findings` (depuis ADR-17, délègue le calcul de similarité à
`sqlite-vec` au lieu d'un brute-force NumPy) :
1. Filtre d'abord en SQL/Python (`store.all_findings(severity_at_least, rule_id,
   path_glob)`) → ensemble de candidats.
2. Vérifie que le vecteur de requête a la même dimension que
   `meta.embedding_dim` ; une incompatibilité lève `EmbeddingError` avec un
   message demandant de réindexer.
3. `store.knn_search(query_vec, top_k=store.embedding_count())` — une seule
   requête `SELECT finding_id, distance FROM vec_findings WHERE embedding
   MATCH ? AND k = ? ORDER BY distance` sur **toute** la table vec0 (pas
   seulement les candidats filtrés : `vec0` n'expose pas de filtrage par
   métadonnée arbitraire côté WHERE, donc le filtre sévérité/règle/chemin est
   appliqué en Python *après* le tri, en s'arrêtant dès que `offset + limit`
   résultats appartenant à l'ensemble filtré ont été trouvés).
4. Le score retourné est `1 - distance_cosinus` (la table vec0 est déclarée
   `distance_metric=cosine`), donc équivalent au produit scalaire de l'ancien
   brute-force sur des vecteurs normalisés L2.
5. Pagine (`offset`, `limit`) sur les résultats déjà triés.

`search.summary` : `by_severity`/`top_rules` via `Store.counts_by` (SQL
`GROUP BY`), `by_top_level_dir` calculé côté Python sur
`finding.path.split("/", 1)[0]`.

`search.get_context(repo_root, finding, before=5, after=5)` : relit le
fichier source, retourne les lignes `[start_line-before, end_line+after]`
bornées à `[1, len(lignes)]`, préfixées `f"{n:>5}| {ligne}"`. Les renderers
capturent les erreurs de lecture par finding : le JSON expose `context: null`
et `context_error`, le rendu texte affiche un contexte indisponible.

## 6. Recherche code + jointure findings

`code_search.search_code_with_findings` commence par ouvrir l'index local quand
il existe. Si `meta.index_engine = "cocoindex-prototype"` et que
`vec_code_chunks` contient des embeddings, la requête est embeddée avec le même
embedder que les findings, puis `Store.knn_search_code_chunks` retourne les
chunks les plus proches sous forme de `CodeHit`. Ces hits sont annotés par
`annotate_with_findings` (égalité stricte de chemin + chevauchement inclusif de
ligne) puis reclassés par `rank_by_severity`.

Si cet index code expérimental est absent, `cccf` retombe sur le pont `ccc`.

### Pont avec `ccc` (`ccc_bridge.py`)

`ccc search <query> --limit N` est appelé en subprocess (`cwd=repo_root`).
**Le flag `--json` n'existe pas** dans la version de `ccc` installée
(vérifié via `ccc search --help`) — voir ADR-10. `search_code` parse donc le
format texte réel :
```
--- Result 1 (score: 0.657) ---
File: src/mailer.py:1-6 [python]
<contenu...>
```
via deux regex ancrées sur ce format (`_RESULT_HEADER_RE`, `_FILE_LINE_RE`),
séparant les blocs sur `\n(?=--- Result \d+ )`. Un bloc qui ne matche pas les
deux regex est silencieusement ignoré (pas d'erreur — dérive de format non
détectée, voir `archive/BACKLOG-2.md`).

`ccc` absent du PATH ou code de sortie non nul → `CccUnavailable`.

`annotate_with_findings(code_hits, store)` : jointure par égalité stricte de
chemin puis chevauchement inclusif de plage
(`finding.start_line <= hit.end_line and finding.end_line >= hit.start_line`
— une seule ligne commune suffit). Sérialise chaque finding joint sans le
champ `score` (absent du contrat F4.2 dans ce contexte, puisqu'aucune requête
sémantique n'est faite sur les findings ici).

## 7. Contrat JSON (F4.2 — figé)

Consommé par `cccf search --json`, le tool MCP `search_findings`, et (sans
`score`) par `search_code_with_findings` :
```json
{
  "id": "str", "rule_id": "str", "severity": "INFO|WARNING|ERROR",
  "message": "str", "path": "str", "start_line": 0, "end_line": 0,
  "score": 0.0, "fix": "str|null", "cwe": ["str"], "owasp": ["str"],
  "context": "str (optionnel)"
}
```
Ce schéma ne doit pas être modifié sans mettre à jour les 3 points de
sérialisation (`render.py`, `ccc_bridge.py`) — actuellement dupliqués, voir
`archive/BACKLOG-2.md` (N3).

## 8. Tests et fixtures

- `tests/fixtures/vuln_repo/` : mini-repo avec 4 fichiers vulnérables (SQL
  injection par f-string, `subprocess.run(shell=True)`, `yaml.load` sans
  Loader, `random.random` pour un token) et `rules/rules.yml` (4 règles
  Semgrep locales, jamais de pack registry — tests déterministes et
  hors-ligne).
- Tests marqués `@pytest.mark.integration` : exécutent le vrai binaire
  Semgrep (nécessaire, installé dans l'environnement CI/dev).
- Tests marqués `@pytest.mark.slow` : téléchargent le modèle
  sentence-transformers réel — **exclus par défaut** (`addopts = "-m 'not
  slow'"` dans `pyproject.toml`, voir ADR-11) ; à lancer explicitement via
  `uv run pytest -m slow`.
- `CCCF_FAKE_EMBEDDER=1` : bascule `embedder.make_embedder` sur un embedder
  déterministe (hash SHA-256, 8 dimensions, signature `fake:<model>:8`) pour les
  tests d'intégration n'ayant pas besoin de sémantique réelle. Un index créé
  avec ce fake est distingué d'un index de production via `embedding_signature`.
- `eval/run_eval.py` : indexe une copie temporaire de `vuln_repo` avec le
  vrai embedder, calcule le hit-rate top-3 sur `eval/queries.yml` (8
  requêtes FR/EN). Seuil de passage : ≥ 0,75 (mesuré : 1.00 au dernier run).
