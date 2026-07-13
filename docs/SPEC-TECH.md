# Spécification technique — ccc-findings (`cccf`)

> Décrit l'architecture interne réellement livrée : modules, modèle de
> données, algorithmes, schéma SQLite, contrats internes. Pour le
> comportement observable par l'utilisateur, voir
> [`SPEC-FONC.md`](./SPEC-FONC.md). Pour le pourquoi des choix, voir
> [`ADR.md`](./ADR.md). Pour les défauts connus, voir `archive/BACKLOG-2.md`.

## 1. Carte des modules (`src/cccf/`)

| Module | Rôle | Dépend de |
|---|---|---|
| `models.py` | `Finding` (dataclass gelée) + `compute_finding_id` ; `MessageEndpoint` (BACKLOG-10 K1) + `compute_endpoint_id` | — |
| `config.py` | `Config`, `load_config`, `init_config`, `ConfigError` | — |
| `scanner.py` | Exécution Semgrep (subprocess) + parsing JSON → `Finding` ; `run_semgrep_endpoints`/`parse_semgrep_endpoints` → `MessageEndpoint` (règles `metadata.category: endpoint-inventory`, REST K11 + Kafka K2) ; `resolve_spring_property` (K2, ADR-28) | `models`, `config` |
| `store.py` | `Store` : persistance SQLite (findings, endpoints, chunks de code expérimentaux, hashs de fichiers, meta, embeddings) | `models` |
| `indexer.py` | `index_repo` : orchestration incrémentale (diff de fichiers → scan ciblé → findings + endpoints (A1) → embedding ; peut aussi indexer des chunks de code) | `config`, `scanner`, `store`, `embedder` |
| `coco_indexer.py` | Adaptateur expérimental `--engine cocoindex` : findings + chunks de code comme états cibles typés | `config`, `indexer`, `store` |
| `embedder.py` | `Embedder` (sentence-transformers), `finding_to_text` | `models` |
| `search.py` | `search_findings` (cosinus), `summary`, `get_context` | `store`, `models` |
| `graph.py` | Graphe d'interactions dérivé à la requête (BACKLOG-10 K12) : `build_graph`, `find_cycles`, `find_outbound_calls_in_consumers`, `find_hotspots`/`rank_hotspots`, `paths_match` | `models` |
| `render.py` | Sérialisation texte/JSON des résultats de recherche (findings, code+findings), du résumé et du graphe | `search`, `ccc_bridge`, `graph` |
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

### `MessageEndpoint` (`models.py`, BACKLOG-10 K1)

```python
@dataclass(frozen=True)
class MessageEndpoint:
    id: str              # sha256(role|topic|path[|start:end])[:16]
    role: str             # produce | consume (kafka) ; serve | call (rest)
    system: str            # kafka | rest
    topic: str              # nom de topic Kafka, ou "METHODE /chemin" (rest)
    topic_dynamic: bool      # nom non résolvable statiquement (K2/K11)
    source: str               # code | manifest (K10)
    framework: str | None
    path: str                  # fichier de code, ou TOPICS.md pour source=manifest
    start_line: int
    end_line: int
    snippet: str
```

`compute_endpoint_id(role, topic, path, start_line, end_line)` :
`sha256(f"{role}|{topic}|{path}|{start_line}:{end_line}")[:16]` — pas de
snippet dans le hash (contrairement à `Finding`) : un endpoint est identifié
par *où* il est, pas par le texte exact du site d'appel. Un endpoint
`source: manifest` (K10) et un endpoint `source: code` (K2/K11) pour le même
topic ont des identités différentes car leurs `path` diffèrent (`TOPICS.md`
vs le fichier de code) — coexistence sans collision par construction, pas par
un champ dédié dans le hash.

### Schéma SQLite (`.cccf/findings.db`, géré par `Store`)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
-- clés utilisées : schema_version ("4"), embedding_model,
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

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY, role TEXT NOT NULL, system TEXT NOT NULL,
    topic TEXT NOT NULL, topic_dynamic INTEGER NOT NULL, source TEXT NOT NULL,
    framework TEXT, path TEXT NOT NULL, start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL, snippet TEXT NOT NULL
);
CREATE INDEX idx_endpoints_path ON endpoints(path);
CREATE INDEX idx_endpoints_topic ON endpoints(topic);

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

**Migration schema v3 → v4** (ADR-25) : `Store` crée `endpoints`
(`CREATE TABLE IF NOT EXISTS`), purement additive — aucune donnée existante
touchée, pas de table vectorielle associée (K1 ne fait pas d'embeddings, ça
reste dans le périmètre de K3). Une base v3 rouverte gagne juste la table,
vide jusqu'au premier `replace_endpoints_for_files`.

## 3. Pipeline d'indexation (`indexer.index_repo`)

```
1. Lister les fichiers du repo (rglob) matchant include/exclude (fnmatch),
   calculer leur sha256.
2. Comparer aux hashs stockés (table files) → deleted / changed / unchanged.
   Si full=True : changed = tous les fichiers actuels.
3. store.remove_files(deleted)  — purge fichiers + findings + endpoints
   associés (K1).
4. Si changed non vide :
     raw = invoke_semgrep_raw(repo_root, config, files=changed)  — UN SEUL
       scan Semgrep, que config.rules mélange règles de findings et règles
       d'inventaire d'endpoints (BACKLOG-11 A1) ou non.
     findings = parse_semgrep_json(raw, repo_root), filtré par min_severity
       (le filtre vivait dans run_semgrep, maintenant appliqué ici pour
       partager `raw` avec les endpoints sans rescanner).
     endpoints = parse_semgrep_endpoints(raw, repo_root)  — pas de filtre
       min_severity (K8 CA2 : ce ne sont pas des findings).
     store.replace_findings_for_files(changed, findings)  — DELETE puis INSERT,
       unique mécanisme de mise à jour (gère nativement les findings corrigés).
     store.replace_endpoints_for_files(changed, endpoints)  — même mécanique.
     set_file_hash pour chaque fichier de changed.
5. Embedding (voir §5) :
       si meta.embedding_signature != signature de l'embedder courant :
         ré-embedder TOUT store.all_findings() et mettre à jour meta.
     sinon : n'embedder que les findings de `changed` dont l'id n'a pas déjà
       un embedding en base (iter_embeddings()).
     Les endpoints ne sont pas embeddés (ADR-25 : hors périmètre K1).
6. Retourner IndexReport(scanned, skipped, findings_added, findings_removed,
   deleted_files, endpoints_added, endpoints_removed).
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

### 4bis. Extraction d'endpoints REST + Kafka (`run_semgrep_endpoints`,
BACKLOG-10 K11/K2)

Même exécution Semgrep que `run_semgrep` (factorisée dans `_invoke_semgrep`),
mais sans filtre `min_severity` : les règles d'inventaire n'ont pas de
sévérité pertinente. `parse_semgrep_endpoints(raw, repo_root)` ne garde que
les résultats dont `extra.metadata.category == "endpoint-inventory"` (les
autres résultats — findings de sécurité d'un pack lancé dans le même
`cccf index` — sont ignorés silencieusement, pas une erreur) et
`extra.metadata.system` (`"rest"` par défaut, ou `"kafka"`) ; tout autre
système est ignoré. Communs aux deux systèmes :

- `role` vient tel quel de `extra.metadata` (`serve`/`call` en REST,
  `consume`/`produce` en Kafka).
- `framework` (optionnel) vient aussi de `extra.metadata`.
- `source = "code"` toujours ici (pas de manifeste — K10).
- Champ manquant dans les métadonnées d'une règle d'inventaire (`role`, et
  `http_method` en REST) → `SemgrepError` explicite, comme un JSON malformé.

**REST** (`system: rest`, ou absent) — `_extract_rest_path(snippet)` :
premier littéral entre guillemets de la première ligne du snippet (relu
depuis le fichier source, comme `parse_semgrep_json`). Absent, ou suivi
d'une concaténation (`+`) → `topic_dynamic=True`, chemin conservé tel quel
(préfixe littéral, ou `"<dynamic>"` si aucun littéral) — jamais résolu
silencieusement (ADR-26). `topic = f"{http_method} {chemin}"` (ex.
`"GET /orders/{id}"`), `http_method` fixé par la règle (une règle = une
méthode).

**Kafka** (`system: kafka`) — `_extract_kafka_topic(snippet, repo_root)` :
même extraction de littéral que REST (`_find_first_literal`, factorisée),
puis un cas supplémentaire : un littéral de la forme `${propriete}` (Spring
property placeholder — ex. `@KafkaListener(topics = "${app.kafka.topics.
orders}")`) est résolu via `resolve_spring_property(repo_root, propriete)`
plutôt que traité comme un nom de topic littéral (ADR-28). Résolu →
`topic_dynamic=False`, `topic` = la valeur résolue ; non résolu → le
placeholder est conservé tel quel, `topic_dynamic=True`.

`resolve_spring_property(repo_root, property_key)` : `property_key` accepte
la syntaxe Spring `prop` ou `prop:défaut`. Cherche la clé (aplatie en
notation pointée pour le YAML imbriqué) dans, dans l'ordre :
`src/main/resources/application.{yml,yaml,properties}`, puis les mêmes noms
à la racine du repo — premier fichier existant qui définit la clé gagne.
Fichier absent ou YAML invalide → passe au suivant, jamais une erreur.
Clé introuvable partout → le défaut Spring s'applique s'il est présent,
sinon `None` (jamais résolu au hasard).

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

`code_search.search_code_with_findings(repo_root, query, limit, offset, lang,
path, refresh)` — mêmes paramètres que `ccc search` — commence par ouvrir
l'index local quand il existe. Si `meta.index_engine = "cocoindex-prototype"`
et que `vec_code_chunks` contient des embeddings, `refresh=True` déclenche
d'abord une réindexation incrémentale locale
(`coco_indexer.index_repo_with_cocoindex`), puis la requête est embeddée avec
le même embedder que les findings et `Store.knn_search_code_chunks(query_vec,
top_k, offset, language, path_glob)` retourne les chunks les plus proches sous
forme de `CodeHit`. `vec0` n'a pas de filtre de métadonnées natif : la
méthode sur-demande (`(offset + top_k) × 3`, plafonné à 200) puis filtre
`language`/`path_glob` en Python avant de découper `[offset:offset+top_k]` —
même schéma de sur-demande que `ccc_bridge`. Ces hits sont annotés par
`annotate_with_findings` (égalité stricte de chemin + chevauchement inclusif de
ligne) puis reclassés par `rank_by_severity`.

Si cet index code expérimental est absent, `cccf` retombe sur le pont `ccc`.

### Pont avec `ccc` (`ccc_bridge.py`)

`ccc search <query> --limit N [--offset N] [--lang L] [--path GLOB]
[--refresh]` est appelé en subprocess (`cwd=repo_root`) — les options
optionnelles ne sont ajoutées à la ligne de commande que si elles diffèrent de
leur valeur par défaut.
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

### 6bis. Graphe d'interactions (`graph.py`, BACKLOG-10 K12)

Fonctions pures, aucune écriture SQLite (ADR-27) :

- `build_graph(endpoints_by_service: dict[str, list[MessageEndpoint]]) -> list[GraphEdge]`
  — arête `"rest"` quand un endpoint `role=call` d'un service s'apparie
  (`paths_match`) à un endpoint `role=serve` d'un **autre** service ; arête
  `"kafka"` quand un `role=produce` et un `role=consume` d'**autres**
  services partagent le même `topic` (égalité stricte). Pas d'auto-arête
  (même service des deux côtés, ignoré).
- `paths_match(call_topic, serve_topic) -> bool` — `topic` a la forme
  `"MÉTHODE /chemin"` (K11). Même méthode requise ; `<dynamic>` côté call ne
  matche jamais ; sinon, segments de chemin (`/`-séparés) comparés un à un,
  un segment `{...}` d'un côté ou de l'autre accepte tout, et le call peut
  avoir **moins** de segments que la route exposée (préfixe littéral avant
  concaténation, ADR-26) mais jamais plus. Best-effort assumé (K12 CA4) :
  aucun match → aucune arête, jamais d'exception.
- `find_cycles(edges) -> list[Cycle]` — cycles simples (DFS, chaque service
  visité au plus une fois par cycle) sur le graphe services→services induit
  par `edges` ; dédoublonnés par l'ensemble des arêtes qui les composent
  (`frozenset(id(edge) ...)`), indépendamment du service de départ du
  parcours. `Cycle.has_synchronous_rest` : au moins une arête `"rest"` dans
  le cycle (toutes les arêtes REST actuelles sont des appels bloquants —
  `RestTemplate`/`requests`, pas de client async dans le pack K11).
- `find_outbound_calls_in_consumers(endpoints) -> list[OutboundCallInConsumer]`
  — pour un **seul** service (fichier/lignes non comparables entre repos) :
  un `call` dont `start_line` tombe dans `[consume.start_line,
  consume.end_line]` du même fichier. Ne dépend pas du graphe multi-service
  — fonctionne dès qu'un seul projet est indexé (K1/K11 suffisent).
- `find_hotspots(cycles, findings_by_service) -> list[Hotspot]` /
  `rank_hotspots(hotspots) -> list[Hotspot]` — pour chaque extrémité de
  chaque arête d'un cycle, jointure fichier+lignes avec les findings **du
  même service** (même chevauchement inclusif qu'en §6) ; tri par sévérité
  décroissante (`INFO < WARNING < ERROR`), tri stable.

`endpoints_by_service`/`findings_by_service` : un dict à une seule clé pour
un projet unique (usage actuel, CLI/MCP), plusieurs clés pour un scénario
multi-services (tests, et futur K7). Le graphe et les cycles ne dépendent
pas de la fédération elle-même, seulement d'avoir plusieurs jeux
d'endpoints à comparer — `cccf graph` aujourd'hui n'en fournit qu'un.

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
