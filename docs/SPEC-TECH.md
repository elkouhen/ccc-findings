# Spécification technique — ccc-radar (`cccr`)

> Décrit l'architecture interne réellement livrée : modules, modèle de
> données, algorithmes, schéma SQLite, contrats internes. Pour le
> comportement observable par l'utilisateur, voir
> [`SPEC-FONC.md`](./SPEC-FONC.md). Pour le pourquoi des choix, voir
> [`ADR.md`](./ADR.md). Pour les défauts connus, voir `archive/BACKLOG-2.md`.

## 1. Carte des modules (`src/ccc_radar/`)

| Module | Rôle | Dépend de |
|---|---|---|
| `models.py` | `Finding` (dataclass gelée) + `compute_finding_id` ; `MessageEndpoint` (BACKLOG-10 K1) + `compute_endpoint_id` | — |
| `config.py` | `Config`, `load_config`, `init_config`, `ConfigError` | — |
| `scanner.py` | Exécution Semgrep (subprocess) + parsing JSON → `Finding` ; `run_semgrep_endpoints`/`parse_semgrep_endpoints` → `MessageEndpoint` (règles `metadata.category: endpoint-inventory`, REST K11 + Kafka K2) ; `resolve_spring_property` (K2, ADR-28) ; `_module_for_path` (Maven puis repli Gradle, BACKLOG-15 H1) | `models`, `config`, `maven`, `gradle` |
| `gradle.py` | Détection de service Gradle par classe `main()` Spring Boot, en complément de `maven.py` quand aucun `pom.xml` n'existe (BACKLOG-15 H1, ADR-33) : `gradle_service_for_path` | — |
| `store.py` | `Store` : persistance SQLite (findings, endpoints, chunks de code expérimentaux, hashs de fichiers, meta, embeddings) | `models` |
| `indexer.py` | `index_repo` : orchestration incrémentale (diff de fichiers → scan ciblé → findings + endpoints (A1) → embedding ; peut aussi indexer des chunks de code) | `config`, `scanner`, `store`, `embedder` |
| `coco_indexer.py` | Adaptateur expérimental `--engine cocoindex` : findings + chunks de code comme états cibles typés | `config`, `indexer`, `store` |
| `embedder.py` | `Embedder` (sentence-transformers), `finding_to_text` | `models` |
| `search.py` | `search_findings` (cosinus), `summary`, `get_context` | `store`, `models` |
| `graph.py` | Graphe d'interactions dérivé à la requête (BACKLOG-10 K12) : `build_graph`, `find_cycles`, `find_outbound_calls_in_consumers`, `find_hotspots`/`rank_hotspots`, `paths_match` | `models` |
| `workspace.py` | Fédération read-only d'un répertoire multi-services Maven (BACKLOG-11 A2, ADR-30) : `discover_maven_services`, `load_federation` | `models`, `store` |
| `render.py` | Sérialisation texte/JSON des résultats de recherche (findings, code+findings), du résumé, du graphe et de la découverte workspace ; export visuel `.drawio` du graphe (`render_graph_drawio`, BACKLOG-14 G1) | `search`, `ccc_bridge`, `graph`, `workspace` |
| `ccc_bridge.py` | Pont vers le CLI externe `ccc` : `search_code`, `annotate_with_findings`, `rank_by_severity` | `models`, `store` |
| `code_search.py` | `search_code_with_findings` : orchestration code (via `ccc`) + findings + classement + modes dégradés — implémentation partagée CLI/MCP | `ccc_bridge`, `config`, `embedder`, `render`, `search`, `store` |
| `cli.py` | Application Typer (`version`, `init`, `index`, `search`, `findings`, `summary`, `endpoints`, `graph`, `workspace`, `mcp`) | tous les modules ci-dessus |
| `mcp_server.py` | Serveur `FastMCP` stdio, tools | `code_search`, `config`, `embedder`, `graph`, `indexer`, `render`, `search`, `store`, `workspace` |

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
    module: str | None = None          # artifactId Maven (BACKLOG-13 M1)
    qualified_name: str | None = None  # package + classe Java (BACKLOG-13 M1)
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
    module: str | None = None          # artifactId Maven (BACKLOG-13 M1)
    qualified_name: str | None = None  # package + classe Java (BACKLOG-13 M1)
```

`compute_endpoint_id(role, topic, path, start_line, end_line)` :
`sha256(f"{role}|{topic}|{path}|{start_line}:{end_line}")[:16]` — pas de
snippet dans le hash (contrairement à `Finding`) : un endpoint est identifié
par *où* il est, pas par le texte exact du site d'appel. Un endpoint
`source: manifest` (K10) et un endpoint `source: code` (K2/K11) pour le même
topic ont des identités différentes car leurs `path` diffèrent (`TOPICS.md`
vs le fichier de code) — coexistence sans collision par construction, pas par
un champ dédié dans le hash. `module`/`qualified_name` n'entrent pas dans le
hash (comme `snippet` pour `Finding`) : ce sont des métadonnées dérivées de
`path`, pas une composante de l'identité du site.

**`module`/`qualified_name` (BACKLOG-13 M1)** — calculés dans `scanner.py`
au moment de construire chaque `Finding`/`MessageEndpoint` (`parse_semgrep_json`/
`parse_semgrep_endpoints`), pas par `Store` :
- `scanner._module_for_path(repo_root, rel_path) -> str | None` (BACKLOG-15
  H1, ADR-33) — essaie d'abord `maven.module_name_for_path` (ci-dessous),
  puis retombe sur `gradle.gradle_service_for_path` si aucun `pom.xml`
  n'est trouvé. Un repo mixte fonctionne fichier par fichier ; un repo
  purement Maven ou purement Gradle n'a jamais besoin du second mécanisme.
- `maven.module_name_for_path(repo_root, rel_path) -> str | None` — nom du
  module (artifactId, repli sur le nom du répertoire) du `pom.xml` le plus
  proche en remontant depuis `rel_path` jusqu'à `repo_root` inclus, même
  bornage que `scanner._candidate_spring_roots` (jamais au-delà de
  `repo_root`). `None` si aucun `pom.xml` sur ce chemin. Résultat caché par
  `pom.xml` (`lru_cache`, un pom lu une seule fois par process). `parse_pom`
  (lecture XML minimale : `artifactId`, présence de
  `spring-boot-maven-plugin`) est partagée avec `workspace.py`
  (`discover_maven_services`) — plus de duplication depuis cette tâche.
- `gradle.gradle_service_for_path(repo_root, rel_path) -> str | None`
  (BACKLOG-15 H1, ADR-33) — un `build.gradle` n'a pas de marqueur universel
  équivalent à `spring-boot-maven-plugin` (plugins de convention custom via
  `buildSrc`). Signal utilisé à la place : `gradle._service_roots(repo_root)`
  parcourt tout le repo (`rglob("*.java")`, caché par `repo_root`) pour
  trouver les classes portant un `main()` qui appelle
  `SpringApplication.run(...)` (regex, pas d'AST) ; le premier segment de
  chemin (répertoire de premier niveau) de chaque classe ainsi trouvée
  devient un nom de service, et tout fichier sous ce même premier segment y
  est rattaché — un microservice Gradle réparti sur plusieurs sous-projets
  (`<service>/<service>-domain`, `-restapi`, ... `-main`) est ainsi regroupé
  sous un seul nom. `None` si le premier segment ne correspond à aucun
  service détecté.
- `scanner._java_qualified_name(repo_root_str, rel_path) -> str | None` —
  `None` pour un fichier non-`.java` ; sinon `package + "." + nom_de_fichier`
  si une déclaration `package ...;` est trouvée par regex (pas d'AST),
  sinon juste le nom de fichier. Caché par fichier (`lru_cache`).

### Schéma SQLite (`.cccr/findings.db`, géré par `Store`)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
-- clés utilisées : schema_version ("5"), embedding_model,
-- embedding_signature, embedding_dim, index_engine,
-- code_embedding_signature, code_embedding_dim, endpoint_embedding_dim

CREATE TABLE files (
    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, indexed_at TEXT NOT NULL
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, message TEXT,
    path TEXT, start_line INTEGER, end_line INTEGER, snippet TEXT,
    fix TEXT, cwe TEXT,      -- JSON-sérialisé
    owasp TEXT,              -- JSON-sérialisé
    module TEXT, qualified_name TEXT   -- BACKLOG-13 M1
);
CREATE INDEX idx_findings_path ON findings(path);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_module ON findings(module);

CREATE TABLE code_chunks (
    id TEXT PRIMARY KEY, path TEXT, start_line INTEGER, end_line INTEGER,
    language TEXT, content TEXT
);
CREATE INDEX idx_code_chunks_path ON code_chunks(path);

CREATE TABLE endpoints (
    id TEXT PRIMARY KEY, role TEXT NOT NULL, system TEXT NOT NULL,
    topic TEXT NOT NULL, topic_dynamic INTEGER NOT NULL, source TEXT NOT NULL,
    framework TEXT, path TEXT NOT NULL, start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL, snippet TEXT NOT NULL,
    module TEXT, qualified_name TEXT   -- BACKLOG-13 M1
);
CREATE INDEX idx_endpoints_path ON endpoints(path);
CREATE INDEX idx_endpoints_module ON endpoints(module);
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

-- BACKLOG-10 K3 : même mécanique paresseuse, gatée par meta.endpoint_embedding_dim.
CREATE VIRTUAL TABLE vec_endpoints USING vec0(
    embedding float[N] distance_metric=cosine,
    +endpoint_id TEXT
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
tant qu'un `cccr index --engine cocoindex` n'a pas été exécuté. Le prochain
`cccr index` manuel continue de fonctionner sans remplir `code_chunks`; aucune
commande de migration séparée n'est requise.

**Migration schema v3 → v4** (ADR-25) : `Store` crée `endpoints`
(`CREATE TABLE IF NOT EXISTS`), purement additive — aucune donnée existante
touchée. `vec_endpoints` (BACKLOG-10 K3) arrive après, sans bump de
`SCHEMA_VERSION` : comme `vec_findings`/`vec_code_chunks`, elle est créée
paresseusement au premier `set_endpoint_embedding()`, gatée par
`meta.endpoint_embedding_dim` — même raisonnement que pour l'ajout de
`vec_code_chunks` en v2→v3 (ADR-21), qui n'avait pas non plus nécessité de
bump séparé pour sa propre table vectorielle.

**Migration schema v4 → v5** (ADR-32, BACKLOG-13 M1) : `Store._migrate_module_columns`
ajoute `module`/`qualified_name` à `findings`/`endpoints` via `ALTER TABLE
... ADD COLUMN` (guardé par `PRAGMA table_info`, idempotent) puis crée les
index associés — purement additif, `NULL` pour les lignes existantes
jusqu'au prochain `cccr index` qui les recalcule. Contrainte d'ordonnancement
notable : les `CREATE INDEX ... ON findings(module)`/`endpoints(module)` ne
peuvent pas être dans le même `executescript` que les `CREATE TABLE IF NOT
EXISTS` — sur une base v4 existante, la colonne `module` n'existe pas
encore à ce moment-là (`CREATE TABLE IF NOT EXISTS` n'ajoute pas de colonne
à une table déjà là) ; les deux `CREATE INDEX` vivent donc dans
`_migrate_module_columns`, après l'`ALTER TABLE`, jamais dans le script
initial.

## 3. Pipeline d'indexation (`indexer.index_repo`)

```
1. Lister les fichiers du repo (rglob), en excluant d'abord tout fichier
   sous un répertoire src/<jeu-de-sources> où <jeu-de-sources> suit la
   convention Maven/Gradle de nommage des source sets de test ("test" ou
   se terminant par "Test" — indexer._is_test_source, BACKLOG-15 H2,
   ADR-34 — revient sur ADR-14/R2, décision explicite ; règle resserrée en
   BACKLOG-16 P1 pour ne pas capturer un layout src/<package> générique
   type Python/JS/Rust), puis matchant include/exclude (fnmatch),
   calculer leur sha256.
2. Comparer aux hashs stockés (table files) → deleted / changed / unchanged.
   Un fichier exclu par _is_test_source qui était indexé avant cette
   décision se retrouve dans deleted (absent de current_hashes) et est
   purgé au prochain index, sans mécanisme dédié.
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
`typescript`, fallback `text`), stocké dans `code_chunks`. Le ré-embedding
suit le même principe que pour les findings (BACKLOG-16 P5, comble un
trou laissé par X3/BACKLOG-8) : si `meta.code_embedding_signature` diffère
de la signature courante de l'embedder, **tous** les chunks existants
(`store.all_code_chunks()`) sont ré-embeddés, pas seulement ceux des
fichiers `changed` — sinon un changement de modèle à dimension égale (la
seule condition qui recrée `vec_code_chunks`, voir §5) laisserait des
vecteurs de modèles différents coexister silencieusement. Sinon, seuls
les chunks des fichiers `changed` sont (ré-)embeddés. Les fichiers
supprimés passent par `Store.remove_files`, qui purge findings, chunks et
embeddings associés.

`cccr index --engine cocoindex` appelle cet adaptateur expérimental et écrit
`meta.index_engine = "cocoindex-prototype"`. Le moteur manuel reste le défaut et
écrit `meta.index_engine = "manual"` quand il est utilisé via la CLI.

Le tool MCP `reindex_findings` (BACKLOG-16 P3) respecte ce même choix :
il lit `meta.index_engine` et dispatche vers `index_repo_with_cocoindex`
si sa valeur est `"cocoindex-prototype"`, sinon vers `index_repo` (et écrit
alors `"manual"`, parité avec la CLI) — sans cela, un repo indexé avec
`--engine cocoindex` verrait ses chunks de code ne plus jamais être
rafraîchis dès qu'un agent réindexe via MCP plutôt que la CLI.

`findings_removed` / `endpoints_removed` sont calculés en comptant, **avant**
suppression, les lignes déjà en base pour les chemins de `deleted` et de
`changed`, via des requêtes SQL `COUNT(*) WHERE path IN (...)` batchées par
paquets sous la limite de binds SQLite.

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
`.cccr/config.yml` ne soit pas silencieusement réduit par les `.semgrepignore`
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
`cccr index` — sont ignorés silencieusement, pas une erreur) et
`extra.metadata.system` (`"rest"` par défaut, ou `"kafka"`) ; tout autre
système est ignoré. Communs aux deux systèmes :

- `role` vient tel quel de `extra.metadata` (`serve`/`call` en REST,
  `consume`/`produce` en Kafka).
- `framework` (optionnel) vient aussi de `extra.metadata`.
- `source = "code"` toujours ici (pas de manifeste — K10).
- Champ manquant dans les métadonnées d'une règle d'inventaire (`role`, et
  `http_method` en REST) → `SemgrepError` explicite, comme un JSON malformé.
- `module`/`qualified_name` (BACKLOG-13 M1) calculés systématiquement à la
  construction, pour `Finding` (`parse_semgrep_json`) comme pour
  `MessageEndpoint` : `maven.module_name_for_path(repo_root, path)` et
  `scanner._java_qualified_name(str(repo_root), path)` — voir §2.

**REST** (`system: rest`, ou absent) — `_extract_rest_path(snippet, repo_root,
source_path, start_line)` :
premier littéral entre guillemets du snippet (relu depuis le fichier
source, comme `parse_semgrep_json`), recherché ligne par ligne dans
l'ordre — pas seulement la première (BACKLOG-10 K13 : une chaîne fluent
`WebClient` peut répartir `.get()` et `.uri(...)` sur deux lignes ; le
snippet reste borné exactement par `start_line`/`end_line` du match
Semgrep, jamais de code hors de l'appel). Absent, ou suivi d'une
concaténation (`+`) sur la même ligne → `topic_dynamic=True`, chemin
conservé comme préfixe littéral exploitable (ou `"<dynamic>"` si aucun
littéral) — jamais résolu silencieusement (ADR-26). Les URLs
absolues/scheme-relative sont normalisées en route canonique
(`http://order-service/orders?x=1` →
`/orders`) : host, query string et fragment sont jetés, slash initial forcé,
slashes répétés compactés. `topic = f"{http_method} {chemin}"` (ex.
`"GET /orders/{id}"`), `http_method` fixé par la règle (une règle = une
méthode).

**Préfixe `@RequestMapping` de classe (BACKLOG Q24)** : une règle
`endpoint-inventory` REST est bornée à la méthode annotée — elle ne voit
jamais le `@RequestMapping` porté par la classe englobante, alors que
Spring MVC le préfixe silencieusement au chemin de la méthode.
`_class_base_path(repo_root, source_path, start_line)` retrouve la
classe/interface la plus proche au-dessus de `start_line` (best-effort ligne
par ligne, ADR-26 — pas d'AST) et son éventuel `@RequestMapping` de classe.
Deux cas où l'absence de littéral au niveau méthode ne veut *pas* dire
`<dynamic>` : une annotation vide (`@GetMapping`) ou ne portant que des
attributs non liés au chemin (`method=`/`produces=`/`consumes=`/`headers=`/
`params=`/`name=`) hérite silencieusement du chemin de classe côté Spring —
`_mapping_args_have_only_non_path_attrs` distingue ce cas d'une valeur
réellement inconnue (référence à une constante, expression). Le préfixe et
le chemin de méthode sont chacun normalisés séparément puis rejoints par
segments (`_join_rest_paths`) plutôt que concaténés puis renormalisés : une
concaténation naïve `"" + "/" + "/orders/{id}"` produit `"//orders/{id}"`,
que `_normalize_rest_path` interprète à tort comme une URL
protocole-relative (`http://orders/{id}`, `orders` avalé comme nom d'hôte).
Un `@RequestMapping` de classe présent mais sans valeur littérale rend tout
le chemin `<dynamic>`, y compris si la méthode a elle-même un chemin
littéral (le préfixe réel reste inconnu).

**Kafka** (`system: kafka`) — `_extract_kafka_topic(snippet, repo_root,
source_path)` :
même extraction de littéral que REST (`_find_first_literal`, factorisée),
puis un cas supplémentaire : un littéral de la forme `${propriete}` (Spring
property placeholder — ex. `@KafkaListener(topics = "${app.kafka.topics.
orders}")`) est résolu via `resolve_spring_property(repo_root, propriete,
source_path)` plutôt que traité comme un nom de topic littéral (ADR-28).
Résolu → `topic_dynamic=False`, `topic` = la valeur résolue ; non résolu →
le placeholder est conservé tel quel, `topic_dynamic=True`.

**Kafka Streams DSL (BACKLOG Q25)** : second style d'intégration Kafka,
distinct de l'idiome impératif `@KafkaListener`/`KafkaTemplate.send`
(`StreamsBuilder.stream(...)` = consume, `KStream.to(...)` = produce).
Règles volontairement restreintes aux formes portant un marqueur Kafka
Streams sans ambiguïté (`Consumed.with(...)`/`Produced.with(...)`, ou
nichées dans un `.join(...)`/`.peek(...)`) — un `$X.stream($TOPIC)`/
`$X.to($TOPIC)` bare collisionnerait avec `Arrays.stream(x)`/
`Collection.stream()`/`Mono.to(...)` (Reactor)/mappers `.to(Class)`, même
logique que `cccr.kafka.java.consume-raw`. `.to("topic")` est fréquemment
chaîné après un `.peek(...)` dont le lambda peut contenir un littéral (message
de log) avant le topic dans le texte du snippet — `_KAFKA_STREAMS_TO_RE`
recherche spécifiquement le littéral qui suit directement `.to(`, prioritaire
sur la recherche générique du premier littéral (qui prendrait à tort le
message de log). Un `.join(...)` et le `.peek(...).to(...)` qui le suit dans
la même expression chaînée peuvent produire deux endpoints avec le même
`start_line` (le second englobe le premier comme préfixe de sa propre
expression) — `end_line` diffère toujours, pas de collision d'id
(`compute_endpoint_id` inclut les deux).

**Variable alimentée par `@Value` (BACKLOG-10 K2, reliquat)** : quand
`_find_first_literal` ne trouve aucun littéral du tout (ex.
`@KafkaListener(topics = ordersTopic)`, `kafkaTemplate.send(ordersTopic,
...)`), `_extract_kafka_topic` tente `_BARE_TOPIC_VAR_RE` sur la première
ligne du snippet pour isoler le nom de la variable (après `topics = `,
`.send(` ou `ProducerRecord(`), puis `_resolve_value_annotated_variable
(repo_root, source_path, var_name)` : cherche dans le **même fichier
source** une déclaration `@Value("${clé}") ... var_name;`
(`_VALUE_FIELD_RE`, regex sur le texte — pas d'AST Java, pas de suivi
inter-fichiers ni de résolution d'héritage) via `_load_value_annotated_fields`
(caché par fichier, `lru_cache`), puis résout la clé trouvée comme un
placeholder normal (`resolve_spring_property`). Variable absente des champs
`@Value` du fichier → `<dynamic>`, comme avant cette tâche.

**API bas niveau `kafka-clients` (BACKLOG-10 K2, reliquat)** : produire via
`new ProducerRecord(...)` était déjà couvert avant cette tâche (même classe
`org.apache.kafka.clients.producer.ProducerRecord`, Spring ou non).
Consommer via l'API bas niveau ne l'était pas : `cccr.kafka.java.consume-raw`
(côté skill) capte `$CONSUMER.subscribe(Collections.singletonList(...))`/
`Arrays.asList(...)`/`List.of(...)` — restreint à ces trois formes pour ne
jamais confondre avec un `.subscribe(...)` non-Kafka (RxJava/Reactor
prennent un lambda/`Observer`, jamais une `Collection<String>` construite
par ces helpers). `subscribe(Pattern.compile(...))` (abonnement par motif
de nom) n'est pas couvert — documenté, pas traité en silence.

`resolve_spring_property(repo_root, property_key, source_path=None)` :
`property_key` accepte la syntaxe Spring `prop` ou `prop:défaut`. Cherche la
clé (aplatie en notation pointée pour le YAML imbriqué) dans les configs
Spring découvertes autour du fichier source : d'abord le module qui contient
`source_path` (ancêtres du fichier + `src/main/resources` / racine du module),
puis le repo parent. Noms supportés : `application.{yml,yaml,properties}`,
`bootstrap.{yml,yaml,properties}` et variantes profilées
`application-*.{yml,yaml,properties}` / `bootstrap-*.{...}`. Les fichiers
sont parsés une seule fois par process via `lru_cache`. Fichier absent ou YAML
invalide → passe au suivant, jamais une erreur. Clé introuvable partout → le
défaut Spring s'applique s'il est présent, sinon `None` (jamais résolu au
hasard).

`scanner.clear_analysis_caches()` (BACKLOG-16 P2) vide tous les `lru_cache`
d'analyse best-effort par chemin (`_java_qualified_name`,
`_load_flat_spring_properties`, `_load_value_annotated_fields`,
`maven._cached_module_name`, `gradle._service_roots`) — appelé en tête de
`indexer.index_repo`. Ces caches accélèrent une indexation en cours (un
même `application.yml`/`pom.xml` lu plusieurs fois), mais un serveur MCP
est un process long-vivant : sans purge à chaque indexation, une propriété
Spring, un artifactId ou un package Java modifiés entre deux `cccr index`
resteraient résolus avec leur ancienne valeur.

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
1. Filtre d'abord en SQL (`store.all_findings(severity_at_least, rule_id,
   path_glob)`) → ensemble de candidats.
2. Vérifie que le vecteur de requête a la même dimension que
   `meta.embedding_dim` ; une incompatibilité lève `EmbeddingError` avec un
   message demandant de réindexer.
3. `store.knn_search(query_vec, top_k=...)` interroge `vec_findings` avec un
   `k` sur-demandé (facteur 3, minimum 20, puis doublement progressif si
   besoin) au lieu de demander d'emblée toute la table vec0. `vec0`
   n'exposant pas de filtre métadonnée arbitraire côté WHERE, le filtre
   sévérité/règle/chemin reste appliqué en Python après le KNN, mais la
   requête n'escalade vers plus de voisins que si `offset + limit` résultats
   filtrés n'ont pas encore été trouvés.
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

Si cet index code expérimental est absent, `cccr` retombe sur le pont `ccc`.

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

`annotate_with_findings(code_hits, store)` : charge uniquement les findings des
chemins présents dans `code_hits`, puis joint par égalité stricte de chemin et
chevauchement inclusif de plage
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
  le cycle, à l'exception des arêtes dont le site d'appel est `WebClient`
  (framework `webclient`, non bloquant par nature, K11) : un cycle composé
  uniquement d'appels réactifs reste rapporté (c'est un cycle), mais
  `has_synchronous_rest` est `False` — pas de fausse alerte de blocage
  synchrone pour un flux qui ne bloque pas de thread.
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

`endpoints_by_service`/`findings_by_service` : deux façons de produire ce
dict multi-clés, consommées indifféremment par `build_graph`/`find_cycles`/
`find_hotspots` — le graphe et les cycles ne dépendent que de la *forme* du
dict, jamais de son origine :
- `workspace.load_federation` (§6ter) — plusieurs services indexés
  **séparément**, fédérés à la requête (BACKLOG-11 A2).
- `group_endpoints_by_module(endpoints) -> dict[str, list[MessageEndpoint]]`
  / `group_findings_by_module(findings) -> dict[str, list[Finding]]`
  (BACKLOG-13 M2) — un **seul** index couvrant plusieurs modules Maven
  (`endpoint.module`/`finding.module`, M1), sans fédération. Un endpoint/
  finding sans module (`None`) est exclu du regroupement : sans nom stable,
  il ne peut jamais former une arête inter-service fiable — choix
  délibérément conservateur (moins de cycles détectés plutôt qu'un cycle
  inventé entre deux sites non attribués qui se retrouveraient
  arbitrairement dans le même compartiment `None`).

CLI `cccr graph`/tool MCP `graph` (§2/§3) : sans `--workspace`/
`workspace_root`, tentent d'abord `group_endpoints_by_module` sur les
endpoints du projet courant ; si le résultat est non vide, construisent le
graphe directement (pas de fédération). Sinon (aucun module Maven détecté),
`cycles`/`hotspots` restent vides avec la note explicite — même
comportement qu'avant BACKLOG-13. `--workspace`/`workspace_root` fourni
déclenche toujours la fédération complète, inchangée.

### 6bis-bis. Export visuel du graphe (`render.py`, BACKLOG-14 G1)

`render_graph_drawio(services: list[str], edges: list[GraphEdge], cycles:
list[Cycle]) -> str` — fonction pure, aucune dépendance à SQLite ni au
CLI. Rend le graphe **complet** (toutes les arêtes de `build_graph`, pas
seulement celles des cycles, contrairement à `render_graph_json`) en XML
mxGraph (format natif diagrams.net/drawio) :
- un nœud (`mxCell vertex="1"`) par nom de `services`, y compris un
  service sans aucune arête — disposition initiale en grille
  (`ceil(sqrt(n))` colonnes), purement indicative : diagrams.net réorganise
  librement à l'ouverture ;
- une arête (`mxCell edge="1"`) par `GraphEdge`, reliée par `source`/
  `target` aux nœuds correspondants (une arête dont un service n'est pas
  dans `services` est silencieusement ignorée — ne devrait pas arriver en
  usage normal, `edges` et `services` viennent de la même source) ; style
  pointillé (`dashed=1`) pour `kind="kafka"`, trait plein pour `"rest"` ;
  libellé = `edge.to_endpoint.topic` (route ou nom de topic) ;
- les arêtes appartenant à un cycle dont `has_synchronous_rest=True` sont
  identifiées par `id(edge)` (mêmes objets `GraphEdge` que ceux passés
  dans `cycles`, jamais de comparaison par valeur) et coloriées en rouge
  (`strokeColor=#d32f2f`) — même signal que le marqueur `[synchrone]` du
  rendu texte.

Toute valeur dérivée du code source (nom de service, route/topic) est
échappée via `xml.sax.saxutils.quoteattr` avant interpolation dans un
attribut XML — jamais de f-string brute sur du contenu non fiable, pour
qu'un nom de service ou un chemin contenant `<`/`&`/`"` ne puisse jamais
produire un document mal formé (BACKLOG-14 G1 CA3).

`cccr graph --drawio FICHIER` (CLI, §2) : calcule `services_by_name`/
`edges`/`cycles` exactement comme pour `--json` (même branchement
`--workspace`/regroupement par module), écrit le résultat de
`render_graph_drawio` à `FICHIER`, affiche une confirmation courte puis,
si `render_graph_json(...)["note"]` est non vide (aucune donnée
inter-modules), l'affiche aussi — jamais d'échec silencieux, un fichier
sans nœud/arête reste un document XML valide (CA2). Pas de tool MCP
équivalent (§3) : un fichier n'est pas un résultat JSON exploitable par un
agent.

### 6ter. Fédération multi-services (`workspace.py`, BACKLOG-11 A2, ADR-30)

`maven.py` (nouveau, BACKLOG-13 M1, ADR-32) factorise la lecture minimale de
`pom.xml` partagée entre `workspace.py` et `scanner.py` :
- `parse_pom(pom_path) -> tuple[str | None, bool]` — `(artifactId,
  is_spring_boot_app)`, `(None, False)` si le pom est illisible/mal formé
  (un module cassé ne bloque jamais les autres).
- `module_name_for_path(repo_root, rel_path) -> str | None` — utilisé par
  `scanner.py` (§4bis), pas par `workspace.py` (voir §6bis).

- `discover_maven_services(root: Path) -> list[DiscoveredService]` —
  `root.rglob("pom.xml")`, triés par chemin. Pour chaque `pom.xml` :
  `artifactId` (XML, avec ou sans espace de noms Maven déclaré, via
  `maven.parse_pom`) comme nom de service, repli sur le nom du répertoire
  si le pom est illisible/mal formé/sans `artifactId`. `kind =
  "microservice"` si le texte du pom contient `spring-boot-maven-plugin`,
  `"shared-module"` sinon — recherche textuelle simple, pas de résolution
  de modèle Maven (parent POM, profils). `indexed` :
  `<module>/.cccr/findings.db` existe.
- `load_federation(services) -> FederationResult` — pour chaque service
  indexé, ouvre `Store(service.path, readonly=True)` : `findings_by_service`
  toujours peuplé (un module partagé peut porter des findings pertinents
  pour les hotspots) ; `endpoints_by_service` seulement pour
  `kind="microservice"` (A2 CA5 — un module partagé n'est jamais une source
  d'endpoints). Service non indexé, base introuvable ou schéma incompatible
  (`StoreError`) → message ajouté à `warnings`, la fédération continue avec
  les autres services (K7 CA2).
- `Store(path, readonly=True)` (`store.py`) : connexion SQLite
  `file:...?mode=ro` (URI), pas de `_create_schema()`/migration, pas de
  `commit()` en sortie — voir ADR-30 pour la garantie de non-écriture.
  `StoreError` si la base est absente (avant la tentative de connexion) ou
  si `schema_version` ne correspond pas au schéma courant.

`FederationResult.endpoints_by_service`/`.findings_by_service` sont
directement les dicts multi-clés que `graph.build_graph`/`find_hotspots`
(§6bis) attendent — `workspace.py` ne connaît rien du graphe, `graph.py` ne
connaît rien de Maven ni de SQLite : le couplage se fait uniquement par la
forme des deux dicts.

`tests/test_k7_federation_e2e.py` (BACKLOG-10 K7) enchaîne les trois
couches sur de vraies fixtures : deux microservices Maven indexés
séparément via la CLI (`cccr init`/`cccr index`, chacun ignorant l'autre),
fédérés par `discover_maven_services`/`load_federation`, puis
`graph.build_graph` détecte l'arête Kafka entre le producteur et le
consommateur — la seule preuve de bout en bout, hors K1/K2/K11 chacun
testés isolément, que la chaîne complète fonctionne.

### 6quater. Traçage d'un flux (`flow.py`, BACKLOG-10 K5)

Fonctions pures, aucune écriture SQLite :

- `resolve_topic(query, all_topics) -> str | None` — nom exact d'abord ;
  sinon sous-chaîne insensible à la casse, seulement si elle désigne un
  **unique** topic/route parmi `all_topics` (ambigu → `None`, jamais un choix
  arbitraire).
- `resolve_topic_by_similarity(store, embedder, query, endpoints,
  min_score=0.35) -> str | None` (BACKLOG-10 K3) — dernier recours quand
  `resolve_topic` échoue : plus proche voisin parmi les endpoints déjà
  embeddés dans `store` (`Store.knn_search_endpoints`, §2 `vec_endpoints`),
  mais seulement si son score dépasse `min_score` — sous ce seuil, `None`
  plutôt qu'un candidat non pertinent (même philosophie que
  `topic_dynamic` : jamais résolu au hasard). Contrairement à
  `resolve_topic`/`trace_flow`, cette fonction touche SQLite et l'embedder :
  elle vit dans `flow.py` (cohérence thématique) mais n'est pas pure — les
  appelants CLI/MCP l'invoquent explicitement en retombant du `FlowError`
  de `trace_flow`, jamais `trace_flow` elle-même. Seuil non calibré
  empiriquement contre un modèle réel (point de départ documenté) — voir
  `archive/BACKLOG-10.md` K3 pour le détail de cette réserve.
- `trace_flow(query, endpoints_by_service, findings_by_service, warnings=None)
  -> FlowResult` — résout `query` via `resolve_topic` (échec →
  `FlowError`), puis pour chaque endpoint dont `topic == resolved_topic`
  dans n'importe quel service, construit un `FlowSite` (`service`,
  `endpoint`, `findings` qui le recouvrent — même jointure fichier+lignes
  que `graph.find_hotspots`, esprit ADR-19). `endpoints_by_service`/
  `findings_by_service` ont la même forme que celles de `workspace.py`
  (§6ter) mais avec `None` comme clé possible (mode projet courant, hors
  fédération) — `flow.py` ne connaît rien de Maven, `workspace.py` ne
  connaît rien de `flow.py` : couplage uniquement par la forme des dicts.
  `warnings` (avertissements de fédération K7 CA2, déjà émis par
  `load_federation`) sont reportés tels quels sur `FlowResult.warnings` —
  jamais absorbés silencieusement : un site manquant à cause d'un service
  non fédéré doit rester visible, distinct d'une absence réelle de
  producteur/consommateur.

- `group_endpoints_by_module_for_flow(endpoints) -> dict[str | None,
  list[MessageEndpoint]]` / `group_findings_by_module_for_flow(findings)`
  (BACKLOG-13 M3) — regroupe par `endpoint.module`/`finding.module`, mais
  **sans exclure** les entrées sans module (clé `None` conservée),
  contrairement à `graph.group_endpoints_by_module` : lister tous les sites
  d'un topic est le contrat de `flow`, et `trace_flow` ne compare jamais
  les clés entre elles (pas de risque de fausse arête à éviter ici,
  contrairement au graphe).

CLI `cccr flow <requête> [--workspace ROOT]` (§2 SPEC-FONC) : sans
`--workspace`, `endpoints_by_service = group_endpoints_by_module_for_flow
(store.all_endpoints())` sur le projet courant — `service` reflète le
module Maven de chaque site quand l'index en couvre plusieurs (BACKLOG-13),
`None` sinon ; avec `--workspace`, réutilise `discover_maven_services`/
`load_federation` (§6ter) tel quel. `render_flow_json`/`render_flow_text`
(`render.py`) forment le contrat `--json`/texte, partagé avec le tool MCP
`trace_message_flow` (BACKLOG-10 K6).

**Repli par similarité (BACKLOG-10 K3)**, uniquement en mode projet courant
(pas de fédération — chaque service fédéré aurait besoin de sa propre
requête KNN sur son propre store, non câblé) : quand `trace_flow` lève
`FlowError`, le CLI/MCP retente via `resolve_topic_by_similarity` avant
d'abandonner ; `ConfigError`/`EmbeddingError` pendant cette tentative
(config absente, modèle indisponible) sont absorbées silencieusement
**seulement pour retomber sur l'erreur textuelle d'origine**, jamais pour
masquer un autre problème — testé dans `tests/test_flow.py` (seuil, avec
des vecteurs construits directement) et `tests/test_k5_flow_e2e.py`/
`tests/test_mcp_server.py` (câblage CLI/MCP, en substituant
`resolve_topic_by_similarity` plutôt qu'en dépendant d'un embedder réel/faux
sur du texte arbitraire — non calibré, voir `archive/BACKLOG-10.md` K3).

## 7. Contrat JSON (F4.2 — figé)

Consommé par `cccr search --json`, le tool MCP `search_findings`, et (sans
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
- `CCCR_FAKE_EMBEDDER=1` : bascule `embedder.make_embedder` sur un embedder
  déterministe (hash SHA-256, 8 dimensions, signature `fake:<model>:8`) pour les
  tests d'intégration n'ayant pas besoin de sémantique réelle. Un index créé
  avec ce fake est distingué d'un index de production via `embedding_signature`.
- `eval/run_eval.py` : indexe une copie temporaire de `vuln_repo` avec le
  vrai embedder, calcule le hit-rate top-3 sur `eval/queries.yml` (8
  requêtes FR/EN). Seuil de passage : ≥ 0,75 (mesuré : 1.00 au dernier run).
