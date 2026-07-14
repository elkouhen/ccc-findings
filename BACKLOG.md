# BACKLOG — Revue de code qualité/robustesse (2026-07-13)

Revue complète de `src/cccf/*.py` (~4 300 lignes), avec exécution réelle du CLI
sur ce repo. État de départ : `uv run pytest` 254 tests verts, `uv run ruff
check .` sans erreur — la dette n'est pas dans les tests mais dans la gestion
d'erreurs, la cohérence CLI/MCP et des choix d'implémentation fragiles.

Convention : mêmes règles que `AGENT.md` (une tâche = un commit `Q<n>: <titre>`,
DoD globale = pytest + ruff verts, périmètre `Fichiers` respecté). Ordre de
traitement : P0 → P1 → P2 ; dans un même niveau, l'ordre listé.

Trois défauts ont été **constatés en exécution** sur ce repo (pas seulement en
lecture) : Q1 (traceback brut de ~330 lignes sur `cccf index --full` sans
réseau), Q5 (index pollué par l'embedder de test, signature `fake:…` dans
`findings.db`), Q6 (`cccf search` rend une sortie totalement vide).

**2026-07-13, complément** : vérification sur un repo réel du persona cible —
[`eventuate-tram-examples-customers-and-orders`](../eventuate-tram-examples-customers-and-orders/)
(microservices Gradle + sagas Kafka, l'exemple même que le PRD vise). Trois
défauts vérifiés en base après `cccf index`, dont un faux positif de règle et
un angle mort qui invalide la fonctionnalité phare (`graph`/`flow`, K12) sur
ce type d'app — voir Q21-Q23 en tête de P0.

---

## P0 — Crashs et tracebacks bruts exposés à l'utilisateur

### [ ] Q21 : faux positif — `cccf.rest.java.call-put` matche `Map.put()`

**Fichiers** : `.cccf/rules/rest/java.yaml` (règle projet, à corriger dans
chaque projet qui la déploie), `docs/SPEC-TECH.md` (règles livrées par
défaut si ces YAML sont le gabarit distribué — à vérifier).

**Description** : vérifié sur `eventuate-tram-examples-customers-and-orders`
(repo réel, persona cible microservices Kafka). La règle `cccf.rest.java.call-put`
a pour seul pattern `$REST.put(...)` (`.cccf/rules/rest/java.yaml:130`), sans
aucune contrainte de type sur `$REST` — elle matche **n'importe quel** appel
`.put(...)`, pas seulement `RestTemplate.put(url, ...)`. En base :

```
sqlite3 .cccf/findings.db "SELECT path, snippet FROM endpoints WHERE role='call';"
→ Customer.java:65  creditReservations.put(orderId, orderTotal)
```

`creditReservations` est un `Map<...,...>` — un simple `Map.put()` est indexé
comme un « Appel REST client (PUT) ». Sur ce repo, c'est **le seul** appel
REST détecté au total (`role=call`), et c'est un faux positif : `cccf graph`
ne peut construire aucune arête REST fiable. `cccf.rest.java.call-delete`
(`$REST.delete(...)`) est exposée au même risque (`List.delete`,
`Repository.delete`, etc.) — à auditer en même temps.

**CA** :
- Pattern contraint par type ou par nom de variable/import
  (`pattern-either` avec `$REST: RestTemplate` via
  `metavariable-pattern`/`generic` typage Semgrep, ou a minima
  `pattern-not: $MAP.put(...)` sur les types collection connus).
- Test : fixture Java avec un `Map.put(k, v)` à côté d'un vrai
  `restTemplate.put(url, body)` → seul le second est indexé comme endpoint.
- Même audit pour `call-delete`.

### [ ] Q22 : angle mort total sur le messaging par middleware (Eventuate Tram et assimilés) — `graph`/`flow` invalidés sur le persona cible

**Fichiers** : `.cccf/rules/kafka/java.yaml` (règles projet), `docs/PRD.md`,
`docs/SPEC-TECH.md`, `src/cccf/scanner.py` (extraction topic, si de nouvelles
règles nécessitent une extraction différente)

**Description** : vérifié sur `eventuate-tram-examples-customers-and-orders` —
**0 endpoint Kafka indexé sur tout le repo** (`SELECT system FROM endpoints
GROUP BY system` → uniquement `rest`), alors que c'est un exemple de sagas
Kafka multi-services (customer-service, order-service, order-history-service,
order-history-text-search-service communiquent tous par événements). Cause :
les règles `cccf.kafka.java.consume`/`produce-template` ne reconnaissent que
`@KafkaListener`/`KafkaTemplate.send` (Spring Kafka brut). Le code réel
utilise l'abstraction du framework de messaging (Eventuate Tram) :

```java
// CustomerSnapshotEventConsumer.java
public DomainEventHandlers domainEventHandlers() {
  return DomainEventHandlersBuilder
      .forAggregateType("...customers.domain.Customer")
      .onEvent(CustomerSnapshotEvent.class, this::handleCustomerSnapshotEvent)
      .build();
}
```

Aucun littéral de topic n'apparaît même dans ce code (résolu par le framework
via le nom du type d'agrégat) — une règle Semgrep supplémentaire matchant la
forme `DomainEventHandlersBuilder.forAggregateType(...).onEvent(...)` devra
donc produire un `topic` synthétique (ex. `aggregate:<FQN>`), pas extraire un
littéral comme le fait `_extract_kafka_topic` aujourd'hui.

**Conséquence produit** : `cccf graph` ne trouve aucun cycle/hotspot
inter-services sur l'app même que K12/le PRD ciblent (« points de blocage
probables dans une architecture distribuée ») — la fonctionnalité phare rend
un résultat vide et silencieux sur le cas d'usage qui la justifie.

**CA** :
- Au moins une règle `endpoint-inventory` reconnaissant l'idiome
  `DomainEventHandlersBuilder`/`DomainEventPublisher` d'Eventuate Tram (le
  framework le plus probable derrière ce repo étant un exemple officiel de
  sa librairie).
- `_extract_kafka_topic`/le modèle `MessageEndpoint` acceptent un topic non
  extrait d'un littéral (ex. dérivé du type d'agrégat) sans le marquer
  `topic_dynamic=True` à tort.
- Sur ce repo, après correction : `cccf graph` (sans `--workspace`, grouping
  par module Gradle déjà fonctionnel) fait apparaître au moins les arêtes
  Kafka produce/consume entre `customer-service`/`order-history-text-search-service`.
- Documenter dans SPEC-TECH/PRD que la couverture Kafka est limitée à
  Spring Kafka brut par défaut, et que les frameworks de messaging
  (Eventuate Tram, Axon, Spring Cloud Stream) nécessitent des règles dédiées
  non fournies — pour ne pas laisser croire à une couverture générale.

### [ ] Q23 : `cccf workspace`/`--workspace` ignore les repos 100% Gradle

**Fichiers** : `src/cccf/workspace.py`, `tests/test_workspace.py`

**Description** : vérifié sur `eventuate-tram-examples-customers-and-orders`
(21 `build.gradle`, 0 `pom.xml`) : `cccf workspace .` répond « Aucun module
Maven découvert (pom.xml introuvable) ». `discover_maven_services`
(workspace.py:34-51) ne cherche que `root.rglob("pom.xml")`. Pourtant
l'attribution de module *au sein d'un même index* fonctionne très bien sur ce
repo via `gradle.py` (BACKLOG-15/ADR-33, détection par classe `main()`
Spring Boot) : `SELECT module FROM endpoints GROUP BY module` renvoie
correctement les 4 services (`customer-service`, `order-service`,
`order-history-service`, `order-history-text-search-service`). La fédération
multi-dépôts (`cccf workspace <root>`, `cccf graph --workspace`) reste donc
impossible sur un repo Gradle pur, alors que le grouping mono-index (sans
fédération) couvre déjà ce cas.

**CA** :
- `discover_maven_services` (à renommer `discover_services` si le périmètre
  s'étend) découvre aussi les services Gradle : un service par racine
  identifiée par `gradle.py::_service_roots` (déjà utilisé pour l'attribution
  mono-index), avec le même critère microservice/shared-module (présence
  d'une classe `main()` Spring Boot dans l'arborescence du service).
- `cccf workspace .` sur ce repo liste les 4 services Gradle avec leur
  statut indexé/non indexé et leurs comptes endpoints/findings.
- Test avec fixture multi-services Gradle (aucun `pom.xml`).

### [ ] Q1 : envelopper le chargement du modèle d'embedding dans `EmbeddingError`

**Fichiers** : `src/cccf/embedder.py`, `tests/test_embedder.py`

**Description** : `Embedder._load()` (embedder.py:39-44) appelle
`SentenceTransformer(model_name)` sans aucune gestion d'erreur. Premier
lancement sans réseau (ou SSL cassé) → téléchargement HuggingFace échoue →
traceback brut de plusieurs centaines de lignes (constaté :
`SSL: CERTIFICATE_VERIFY_FAILED` puis `RuntimeError: Cannot send a request, as
the client has been closed` remontés tels quels à travers `cli.py:136`, qui ne
catche que `SemgrepError`/`EmbeddingError`). Idem pour `embed_texts()` en cas
d'échec à l'inférence.

**CA** :
- Toute exception levée dans `_load()`/`embed_texts()` est réenveloppée en
  `EmbeddingError` avec un message ≤ 3 lignes indiquant : le modèle visé, la
  cause courte, et les remèdes (réessayer avec réseau, pré-télécharger le
  modèle, `HF_HUB_OFFLINE=1` si déjà en cache).
- `cccf index` sans réseau et sans modèle en cache → exit 2, message court,
  zéro traceback.
- Test unitaire : monkeypatch de `SentenceTransformer` qui lève une exception
  arbitraire → `EmbeddingError` attendue.

### [ ] Q2 : gestion d'erreurs uniforme dans toutes les commandes CLI

**Fichiers** : `src/cccf/cli.py`, `tests/test_cli.py`

**Description** : `findings_cmd` appelle `load_config` (cli.py:208) et
`make_embedder` **hors** de tout `try` — un `ConfigError` (config supprimée
entre l'index et la recherche, YAML invalide) part en traceback brut, alors que
`index_cmd` (cli.py:122-125) le gère proprement. `summary_cmd`, `endpoints_cmd`,
`graph_cmd` n'ont aucun garde non plus (moins exposés mais `yaml.YAMLError`
d'une config corrompue traverse aussi `load_config` sans être convertie en
`ConfigError`).

**CA** :
- Un helper unique (ex. `_load_config_or_exit(repo_root)`) utilisé par toutes
  les commandes qui lisent la config ; plus aucun appel nu à `load_config` dans
  `cli.py`.
- `load_config` convertit `yaml.YAMLError` en `ConfigError` (fichier + cause).
- Tests : `cccf findings q` sans config → exit ≠ 0 + message une ligne ;
  config YAML invalide → idem, pas de traceback.

### [ ] Q3 : ne plus faire échouer toute l'indexation sur une sévérité Semgrep inconnue

**Fichiers** : `src/cccf/scanner.py`, `tests/test_scanner.py`

**Description** : `_normalize_severity` (scanner.py:35-39) lève `SemgrepError`
si la sévérité n'est pas dans `_SEVERITY_MAP`. Or Semgrep émet aussi
`EXPERIMENT` et `INVENTORY` selon les règles/versions : **un seul** finding
exotique fait échouer tout `cccf index`. Un outil d'indexation doit dégrader,
pas s'arrêter.

**CA** :
- Sévérité inconnue → le finding est ignoré (ou mappé sur `INFO`, au choix
  documenté dans SPEC-TECH) avec un avertissement agrégé sur stderr
  (`N findings ignorés (sévérité non supportée : X)`), l'indexation continue.
- Test : fixture JSON avec un résultat `severity: "EXPERIMENT"` au milieu de
  résultats valides → les valides sont indexés.

### [ ] Q4 : durcir le parsing Semgrep (KeyError brut, chemin hors repo, binaire absent)

**Fichiers** : `src/cccf/scanner.py`, `tests/test_scanner.py`

**Description** : trois trous dans le même module :
1. `parse_semgrep_endpoints` accède à `result["extra"]` (scanner.py:413) hors
   du `try` — un résultat sans `extra` lève un `KeyError` brut au lieu du
   `SemgrepError` que lèvent les autres champs.
2. `_relative_path` (scanner.py:62-66) : `Path.relative_to` lève `ValueError`
   si le chemin absolu renvoyé par Semgrep n'est pas sous `repo_root.resolve()`
   (cas réel sur macOS : repo sous `/tmp` vs `/private/tmp`, ou repo ouvert via
   symlink).
3. `invoke_semgrep_raw` (scanner.py:488) : si `semgrep` n'est pas dans le PATH,
   `subprocess.run` lève `FileNotFoundError` brut — le PRD (F1.3) exige un
   message actionnable.

**CA** :
- Les trois cas lèvent `SemgrepError` avec message explicite ; pour (3) :
  « semgrep introuvable — installez-le (pipx install semgrep) ou vérifiez le
  PATH ».
- Pour (2) : repli sur le chemin tel quel (posix) plutôt qu'un crash.
- Un test par cas.

### [ ] Q5 : garde-fou contre la pollution d'un index réel par `FakeEmbedder`

**Fichiers** : `src/cccf/embedder.py`, `src/cccf/cli.py`, `tests/test_embedder.py`

**Description** : `make_embedder` (embedder.py:85-86) bascule silencieusement
sur `FakeEmbedder` si `CCCF_FAKE_EMBEDDER=1` traîne dans l'environnement. C'est
arrivé sur ce repo même : `findings.db` porte une signature `fake:…` et toute
recherche échoue avec « Signature d'embedding incompatible » jusqu'à un
`cccf index --full` — sans jamais dire *pourquoi* l'index est pollué.

**CA** :
- `cccf index` affiche l'embedder effectif dans son rapport (ex.
  `engine=manual embedder=sentence-transformers:…`) et un
  `⚠ embedder de test (CCCF_FAKE_EMBEDDER=1) — index inutilisable en réel`
  bien visible quand le fake est actif.
- Le message « Signature d'embedding incompatible » (search.py:63-66) mentionne
  la cause probable quand la signature indexée commence par `fake:`.
- Test : index avec fake → warning présent dans la sortie.

---

## P1 — Comportement observable incohérent ou opaque

### [ ] Q6 : jamais de sortie vide — messages « aucun résultat » explicites

**Fichiers** : `src/cccf/render.py`, `src/cccf/cli.py`, `tests/test_render.py`

**Description** : constaté : `cccf search "database query"` rend une chaîne
**vide** (zéro octet, exit 0). `render_code_search_text` et
`render_search_text` renvoient `""` sur liste vide ; `render_summary_text` rend
une ligne vide + « top règles : » orphelin sur index vide. Impossible de
distinguer « pas de résultat » d'un bug.

**CA** :
- Liste vide → `Aucun résultat.` (search/findings), `Aucun finding indexé.`
  (summary) ; le JSON reste `[]`/inchangé.
- Tests de rendu pour chaque commande à résultat vide.

### [ ] Q7 : rendu `summary` lisible

**Fichiers** : `src/cccf/render.py`, `tests/test_render.py`

**Description** : `render_summary_text` (render.py:143-153) produit
`ERROR 1` en première ligne, sans libellé — illisible hors contexte (constaté).

**CA** : première ligne préfixée (`sévérités : ERROR 1 | WARNING 3 | INFO 2`),
sévérités ordonnées ERROR → INFO (aujourd'hui : ordre arbitraire du dict), test
mis à jour.

### [ ] Q8 : purger le jargon interne (BACKLOG-xx, ADR) des chaînes visibles

**Fichiers** : `src/cccf/cli.py`, `src/cccf/render.py`, `src/cccf/mcp_server.py`

**Description** : les textes d'aide Typer (`endpoints_cmd`, `graph_cmd`,
`flow_cmd`, options `--module`/`--workspace`/`--drawio`), la note
`_NO_CROSS_MODULE_DATA_NOTE` (render.py:216-222, constatée en sortie de
`cccf graph`) et les descriptions des tools MCP (lues par l'agent qui décide
de l'appel !) citent « BACKLOG-10 K12 », « BACKLOG-11 A2 », « BACKLOG-13 » —
des références de gestion de projet incompréhensibles hors du repo. Les
docstrings de code peuvent les garder ; pas les chaînes servies à
l'utilisateur/l'agent.

**CA** :
- `grep -rn "BACKLOG" src/cccf/` ne matche plus aucune chaîne affichée
  (help Typer, notes, descriptions de tools MCP) — uniquement des commentaires
  ou docstrings internes non exposés (attention : la docstring d'une fonction
  décorée `@app.command`/`@mcp.tool()` EST exposée).
- Les textes réécrits disent ce que l'utilisateur doit faire, pas d'où vient
  la feature.

### [ ] Q9 : parité des paramètres CLI ↔ MCP

**Fichiers** : `src/cccf/mcp_server.py`, `tests/test_mcp_server.py`

**Description** : le tool MCP `search_findings` n'expose pas `offset`
(pagination impossible, la CLI l'a) ; `list_endpoints` n'expose pas `module`
(la CLI `endpoints --module` l'a). Un agent qui pagine ou filtre par module
doit repasser par le CLI.

**CA** : les deux paramètres ajoutés, mêmes défauts que la CLI, tests MCP.

### [ ] Q10 : unifier la sémantique de `--path` (GLOB SQLite vs fnmatch)

**Fichiers** : `src/cccf/store.py`, `docs/SPEC-FONC.md`, `tests/test_store.py`

**Description** : `all_findings`/`all_endpoints` filtrent via `path GLOB ?`
(sensible à la casse, sémantique SQLite), tandis que
`knn_search_code_chunks` (store.py:651) filtre via `fnmatch.fnmatch`
(insensible à la casse sur macOS, sémantique différente pour `[...]`). Le même
`--path` ne donne pas les mêmes résultats selon la commande. Au passage,
`_glob_to_sqlite` (store.py:27-28) est une fonction identité qui ne fait que
suggérer une conversion qui n'existe pas.

**CA** : une seule sémantique (recommandé : `fnmatch` partout, appliqué en
Python — les volumes sont faibles), `_glob_to_sqlite` supprimée, comportement
documenté dans SPEC-FONC, test qui vérifie la cohérence entre les deux chemins.

### [ ] Q11 : supprimer la branche morte du repli « findings-only »

**Fichiers** : `src/cccf/cli.py`, `src/cccf/render.py`, `tests/test_render.py`

**Description** : `search_code_with_findings` renvoie **toujours**
`findings_only_fallback=[]` (code_search.py:123,152 — ADR-31 ne conserve le
champ que pour la compat de schéma JSON). La branche cli.py:184-186 et
`render_fallback_findings_text` (render.py:130-140) sont donc inatteignables.

**CA** : branche CLI et fonction de rendu supprimées ; le champ JSON reste
(compat ADR-31) ; pytest vert.

### [ ] Q12 : documenter et uniformiser les codes de sortie

**Fichiers** : `src/cccf/cli.py`, `docs/SPEC-FONC.md`

**Description** : aujourd'hui : erreurs de config → 1, erreurs
Semgrep/embedding/recherche/index absent → 2, tracebacks non gérés → 1 (via
l'exception). La règle n'est écrite nulle part et n'est pas systématique.

**CA** : tableau des codes dans SPEC-FONC (0 succès, 1 erreur d'usage/config,
2 erreur d'exécution), chaque `typer.Exit` du CLI aligné dessus.

---

## P2 — Robustesse d'indexation, performances, dette structurelle

### [ ] Q13 : exclusions par défaut adaptées au persona (Maven/Gradle/JS)

**Fichiers** : `src/cccf/config.py`, `src/cccf/workspace.py`, `tests/test_config.py`, `tests/test_workspace.py`

**Description** : `DEFAULT_EXCLUDE = [".git/**", ".venv/**", "node_modules/**",
".cccf/**"]` — mais le persona principal est un microservice Maven/Gradle :
`target/**`, `build/**`, `dist/**`, `.idea/**` ne sont pas exclus. Conséquence :
Semgrep scanne le build output (findings dupliqués sources générées/copiées,
indexation lente, hachage sha256 de jars). De même,
`discover_maven_services` (workspace.py:42) fait `rglob("pom.xml")` sans
exclusion — un `pom.xml` copié sous `target/` devient un faux « module ».

**CA** :
- `DEFAULT_EXCLUDE` enrichi (`target/**`, `build/**`, `dist/**`, `.idea/**`,
  `.gradle/**`) ; les configs existantes ne sont pas migrées (documenté).
- `discover_maven_services` ignore tout `pom.xml` dont le chemin contient un
  segment `target`/`build`/`node_modules`.
- Tests pour les deux.

### [ ] Q14 : `invoke_semgrep_raw` — chunking argv et timeout global

**Fichiers** : `src/cccf/scanner.py`, `tests/test_scanner.py`

**Description** : la liste `files` (fichiers modifiés) est passée entière en
argv (scanner.py:486) : un premier index incrémental après un gros rebase peut
dépasser `ARG_MAX` (E2BIG). Et `subprocess.run` n'a pas de `timeout=` : le
`--timeout` transmis à Semgrep est *par règle et par fichier* — un semgrep qui
pend au réseau (résolution d'un pack registry `p/…`) bloque `cccf index`
indéfiniment.

**CA** :
- Au-delà de ~500 fichiers, découpage en plusieurs invocations Semgrep dont
  les sorties JSON sont fusionnées (ou passage par `--include`/batch file).
- `subprocess.run(..., timeout=<global>)` dérivé de la config (ex.
  `semgrep_timeout_s * marge`), `TimeoutExpired` → `SemgrepError` actionnable.
- Tests avec un faux binaire semgrep.

### [ ] Q15 : performances du store et de l'indexeur

**Fichiers** : `src/cccf/store.py`, `src/cccf/indexer.py`, `tests/test_store.py`

**Description** :
1. indexer.py:308 et 315 reconstruisent l'ensemble des ids embeddés via
   `iter_embeddings()`/`iter_endpoint_embeddings()` — qui chargent **tous les
   vecteurs** en mémoire pour n'en garder que l'id. Il faut des méthodes
   `embedded_finding_ids()`/`embedded_endpoint_ids()` (`SELECT finding_id FROM
   vec_findings`).
2. `replace_findings_for_files`/`replace_endpoints_for_files`/
   `replace_code_chunks_for_files` insèrent ligne à ligne → `executemany`.
3. `_sha256_file` hache sans limite de taille — un binaire de 2 Go dans le
   repo est intégralement lu à chaque `cccf index` (atténué par Q13, mais un
   cap type « > 10 Mo → taille+mtime comme empreinte » évite le pire).

**CA** : les trois points traités, comportement identique (tests existants
verts), nouvelles méthodes testées.

### [ ] Q16 : dédupliquer les constantes de sévérité et les familles `vec_*`

**Fichiers** : `src/cccf/models.py`, `src/cccf/store.py`, `src/cccf/scanner.py`, `src/cccf/ccc_bridge.py`, `src/cccf/graph.py`, `src/cccf/config.py`, `src/cccf/search.py`

**Description** : `SEVERITY_ORDER` est défini 2× (store.py:15, scanner.py:18),
`_SEVERITY_RANK` 2× (ccc_bridge.py:10, graph.py:10), `VALID_SEVERITIES` encore
ailleurs (config.py:12) — cinq copies de la même vérité. Dans `store.py`, les
trois familles findings/endpoints/chunks dupliquent quasi à l'identique
`_ensure_*_vec_table` / `_delete_*_embeddings` / `set_*_embedding` /
`*_embedding_count` / `iter_*_embeddings` / `knn_search*` (~150 lignes de
copier-coller paramétrable par (table, colonne id, clé meta)).

**CA** :
- Une seule définition des sévérités dans `models.py` (ordre + rang dérivé),
  importée partout ; `grep -rn "SEVERITY_ORDER = " src/` → 1 résultat.
- Un helper interne unique paramétré par espace de vecteurs dans `store.py` ;
  API publique inchangée ; pytest vert.

### [ ] Q17 : ouvrir le store en lecture seule pour les commandes de lecture

**Fichiers** : `src/cccf/cli.py`, `src/cccf/mcp_server.py`, `src/cccf/store.py`

**Description** : `summary`, `endpoints`, `graph`, `flow`, `findings` ouvrent
`Store(repo_root)` en écriture : `__enter__` rejoue `_create_schema` +
migrations + `commit` à chaque lecture. Une commande de consultation ne doit
pas pouvoir muter la base (ni la créer vide si le fichier a disparu entre le
`_require_index` et l'ouverture).

**CA** : toutes les commandes de lecture passent `readonly=True` (le chemin
readonly existe déjà pour la fédération) ; seuls `index`/`reindex_findings`
ouvrent en écriture ; message clair si la base readonly est incompatible.

### [ ] Q18 : racine du serveur MCP configurable

**Fichiers** : `src/cccf/mcp_server.py`, `src/cccf/cli.py`, `docs/SPEC-FONC.md`

**Description** : `_repo_root()` = `Path.cwd()` (mcp_server.py:49-50) — le
serveur dépend entièrement du cwd choisi par le client MCP. Claude Code lance
au dossier projet, mais tout autre client (ou un lancement via wrapper) casse
silencieusement : `_require_index` échoue ou, pire, `reindex_findings` crée un
`.cccf/` dans un répertoire arbitraire.

**CA** : `cccf mcp --root <dir>` (et/ou variable `CCCF_ROOT`) prioritaire sur
le cwd ; documenté dans SPEC-FONC et dans la docstring d'enregistrement client.

### [ ] Q19 : stabilité des identifiants de findings au décalage de lignes

**Fichiers** : `src/cccf/models.py`, `src/cccf/indexer.py`, `docs/SPEC-TECH.md`, `docs/ADR.md`

**Description** (tâche de conception, à trancher avant de coder) :
`compute_finding_id` inclut `start_line:end_line` — ajouter une ligne en tête
de fichier change l'id de **tous** les findings du fichier : ré-embedding
complet du fichier à chaque édition et diff « apparus/résolus » (UC6 du PRD)
structurellement faux. Le paramètre `start_line=None` du modèle montre que
l'id sans lignes était prévu ; il a besoin d'un discriminant d'occurrence pour
deux snippets identiques (`rule|path|snippet|n-ième occurrence`).

**CA** : ADR tranchant l'alternative (id positionnel actuel vs id contenu +
occurrence), puis implémentation : déplacer un bloc de code sans le modifier
conserve son id de finding ; migration de schéma documentée.

### [ ] Q20 : rapport d'indexation `--full` non trompeur

**Fichiers** : `src/cccf/indexer.py`, `tests/test_indexer.py`

**Description** : en `--full`, tous les fichiers sont « changed » :
`findings_removed` compte tout l'existant puis `findings_added` le recrée —
le rapport affiche `+N -N` alors que rien n'a changé. L'utilisateur ne peut
pas distinguer un vrai churn d'un re-scan.

**CA** : le rapport distingue re-scan et churn réel (ex. comparer les ids
avant/après : `+ajoutés -disparus =inchangés`), test sur un `--full` sans
modification → `+0 -0`.

## P0quater — Angles morts de la revue d'architecture, confirmés sur 4 repos réels (2026-07-14)

Revue comparative de 4 repos microservices REST/Kafka (`eventuate-tram-examples-
customers-and-orders`, `sample-spring-kafka-microservices`,
`spring-petclinic-microservices`, `microservices-kafka-mq`) avec `cccf
endpoints`/graphes drawio à l'appui. Constat transverse préalable : seul
`eventuate-tram-examples` avait un pack de règles `endpoint-inventory` (REST +
Kafka) réellement déployé et référencé dans `.cccf/config.yml` — les 3 autres
tournaient avec le seul pack `p/security-audit` et remontaient 0 endpoint,
silencieusement (`cccf endpoints` vide, pas d'avertissement). Hors périmètre
direct de ce backlog (c'est un défaut de déploiement/documentation du pack,
pas du moteur d'extraction), mais à garder en tête : `cccf init`/la doc
devraient rendre l'absence de règles d'inventaire visible plutôt que silencieuse.

### [x] Q24 : fusionner le préfixe `@RequestMapping` de classe avec le chemin méthode

**Fichiers** : `src/cccf/scanner.py`, `tests/test_rest_endpoints.py`,
`tests/fixtures/rest_repo/app/java/OwnerController.java`, `docs/SPEC-TECH.md`

**Description** : vérifié sur `spring-petclinic-microservices` (`OwnerResource.java`,
classe annotée `@RequestMapping("/owners")`) et confirmé indépendamment sur
`microservices-kafka-mq` (`AppRestController.java`, `@RequestMapping("/api")`) —
une règle `endpoint-inventory` REST est bornée à la méthode annotée
(`pattern: @GetMapping(...) $RET $METHOD(...) { ... }`), elle ne voit jamais le
`@RequestMapping` de la classe englobante. Deux symptômes : une méthode avec
chemin explicite sort sous-qualifiée (`GET /{ownerId}` au lieu de
`GET /owners/{ownerId}`), une méthode sans valeur explicite (`@GetMapping`
seul, hérite du chemin de classe côté Spring) sort `<dynamic>`. Dans les deux
cas, `graph.paths_match` ne peut plus corréler l'appel client réel au bon
endpoint serveur — sur `spring-petclinic-microservices`, seuls 2 des 4 appels
inter-services réels détectés côté appelant étaient corrélables avant ce
correctif.

**CA** :
- `_extract_rest_path` fusionne le préfixe de classe (best-effort ligne par
  ligne, ADR-26) avec le chemin de méthode, y compris quand ce dernier est
  vide (annotation sans valeur explicite ou ne portant que des attributs non
  liés au chemin). ✅
- Assemblage par segments (`_join_rest_paths`), pas par concaténation brute
  suivie de renormalisation (piège : `"" + "/" + "/orders/{id}"` →
  `"//orders/{id}"`, interprété à tort comme une URL protocole-relative par
  `_normalize_rest_path`, `orders` avalé comme hôte). ✅
- Test : classe avec `@RequestMapping` de base + méthodes avec/sans valeur
  explicite → chemins complets corrects, plus aucun faux `<dynamic>` évitable.
  ✅ (`test_java_class_level_request_mapping_prefix_is_merged_into_method_path`)
- Aucune régression sur les contrôleurs sans `@RequestMapping` de classe
  (comportement identique à avant). ✅

### [ ] Q25 : détecter les endpoints Kafka Streams DSL (`StreamsBuilder.stream`/`KStream.to`)

**Fichiers** : `tests/fixtures/kafka_repo/rules/java.yaml`,
`tests/fixtures/kafka_repo/app/java/`, `tests/test_kafka_endpoints.py`,
`docs/SPEC-TECH.md`. Nécessite aussi le report de ces règles dans le repo
`ccc-findings-skill` (ADR-24, hors d'atteinte depuis ce repo — signalé, pas fait).

**Description** : vérifié sur `sample-spring-kafka-microservices`
(`order-service/.../OrderApp.java`) — `@EnableKafkaStreams`/`StreamsBuilder`
est un second style d'intégration Kafka, distinct de l'idiome imperatif
`@KafkaListener`/`KafkaTemplate.send` déjà couvert. `order-service` consomme
`payment-orders`/`stock-orders` (jointure Kafka Streams) et republie sur
`orders` — 4 endpoints Kafka réels non détectés, dont 2 qui traversent une
frontière de service (payment-service/stock-service → order-service).

**CA** :
- Nouvelle règle `consume` : `StreamsBuilder.stream($TOPIC, Consumed.with(...))`
  et la forme imbriquée `$STREAM.join($BUILDER.stream($TOPIC), ...)` (couvre
  les deux formes réellement observées dans `OrderApp.java`).
- Nouvelle règle `produce` : `$STREAM.to($TOPIC, Produced.with(...))` et
  `$STREAM.peek(...).to($TOPIC)`.
- Volontairement **pas** de pattern bare `$X.stream($TOPIC)`/`$X.to($TOPIC)`
  sans marqueur Kafka Streams (`Consumed`/`Produced`/`.join`/`.peek`) — trop
  proche de `Arrays.stream(x)`/`Collection.stream()`/`.to()` Reactor ou
  mapper, même principe que `cccf.kafka.java.consume-raw` (déjà restreint à 3
  formes précises pour éviter les faux positifs RxJava/Reactor). Limitation
  documentée : un `.to("topic")` isolé sans marqueur ni `.peek()` précédent
  n'est pas détecté — préféré à un faux positif (même politique que
  `graph.paths_match`, BACKLOG-10 K12 CA4).
- Test : fixture reproduisant le repo réel (join sur deux topics + republication)
  → 4 endpoints Kafka détectés avec le bon rôle/topic.

### [ ] Q26 : scanner les routes déclaratives Spring Cloud Gateway (YAML)

**Fichiers** : `src/cccf/scanner.py` (nouvelle fonction, hors pipeline
Semgrep), `src/cccf/models.py` (`source` a déjà une valeur `manifest` prévue
mais jamais implémentée — K10), `src/cccf/indexer.py`, `docs/SPEC-TECH.md`,
`docs/SPEC-FONC.md`, tests + fixtures dédiées.

**Description** : vérifié sur `spring-petclinic-microservices` — les routes
`spring.cloud.gateway.routes` (`application.yml` de `spring-petclinic-api-gateway`)
sont des dépendances inter-services réelles (`/api/vet/** → lb://vets-service`,
etc.) mais 100% invisibles : aucune règle Semgrep ne couvre le YAML, seul le
Java est scanné. Sur ce repo, 4 routes de gateway réelles ne sont vues par
aucun mécanisme actuel.

**CA** :
- Nouvelle fonction d'extraction (pas une règle Semgrep — parsing YAML direct,
  même esprit que `_load_flat_spring_properties`) qui repère
  `spring.cloud.gateway.routes` dans les fichiers de config Spring
  conventionnels et produit un `MessageEndpoint` par route
  (`role="call"`, `system="rest"`, `topic="* <predicate Path=>"`,
  `source="config"`, `framework="spring-cloud-gateway"`).
- `source="config"` : nouvelle valeur de `MessageEndpoint.source` (jusqu'ici
  seul `"code"` existe réellement ; `"manifest"`/K10 documenté mais jamais
  implémenté — décision à documenter en ADR si le champ `source` gagne une
  troisième valeur avec une sémantique différente de K10).
- Câblage dans `indexer.index_repo` (appelé en plus de
  `run_semgrep_endpoints`, jamais à la place) + exposé par `cccf endpoints`/MCP
  `list_endpoints` sans changement d'interface visible.
- Test : fixture `application.yml` avec plusieurs routes `lb://`/`http://` et
  prédicats `Path=` → un endpoint par route, chemin de prédicat normalisé.
