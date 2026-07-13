# BACKLOG-16 — Revue en profondeur : robustesse / simplicité / correction

> Issu d'une revue transverse du code (`src/cccf/*.py`, tests) le 2026-07-13.
> Préfixe de commit : `P<n>: <titre>`. Ordre = priorité décroissante.
> Chaque bug a été confirmé par lecture croisée ou reproduction avant d'être
> listé ici (P1 et P4 reproduits en REPL, P2/P3/P5 confirmés par grep :
> aucune relecture de `code_embedding_signature`, aucun `cache_clear`,
> aucun `index_engine` dans `mcp_server.py`).

## Corrections (bugs confirmés)

- [x] **P1 — `_is_test_source` exclut tout layout `src/<pkg>` non-Java (CRITIQUE)**
  - Fichiers : `src/cccf/indexer.py`, `tests/test_indexer.py`
  - Description : `_is_test_source("src/cccf/store.py")` renvoie `True` :
    tout repo Python/JS/Rust en layout `src/` (dont `cccf` lui-même) est
    intégralement exclu de l'indexation depuis BACKLOG-15 H2 (ADR-34).
    La règle « `src/<x>` avec `x != main` » n'est valide que pour des
    source sets Maven/Gradle.
  - Correctif proposé : ne traiter `src/<x>` comme jeu de sources de test
    que si `x` suit la convention de nommage des source sets de test
    (`x == "test"` ou `x` se termine par `Test`), OU exiger qu'un frère
    `src/main` existe sur le chemin. La première option reste pure
    (pas d'I/O) et couvre `test`, `componentTest`, `contractTest`,
    `endToEndTest`.
  - CA :
    - `_is_test_source("src/cccf/store.py") is False` ;
    - `_is_test_source("svc/src/test/java/T.java") is True` ;
    - `_is_test_source("svc/src/contractTest/java/T.java") is True` ;
    - `_is_test_source("src/main/java/A.java") is False`.

- [x] **P2 — Caches `lru_cache` périmés dans le serveur MCP long-vivant**
  - Fichiers : `src/cccf/scanner.py`, `src/cccf/maven.py`, `src/cccf/gradle.py`,
    `src/cccf/indexer.py`, `tests/test_scanner.py`
  - Description : `_java_qualified_name`, `_load_flat_spring_properties`,
    `_load_value_annotated_fields`, `_cached_module_name`, `_service_roots`
    sont cachés par chemin pour la durée du process. Dans le serveur MCP
    (process long-vivant), `reindex_findings` — dont la docstring dit
    explicitement « appeler après un patch » — resservira des packages,
    propriétés Spring, artifactIds et topics résolus périmés après
    modification des fichiers.
  - Correctif proposé : `clear_analysis_caches()` (appelant les
    `cache_clear()` des cinq fonctions) invoquée en tête de `index_repo`.
    Le bénéfice intra-indexation du cache est conservé ; seule la
    péremption inter-indexations disparaît.
  - CA : test qui indexe, modifie `application.yml` (nouveau nom de topic),
    réindexe dans le même process, et observe le nouveau topic.

- [x] **P3 — MCP `reindex_findings` ignore le moteur d'indexation du store**
  - Fichiers : `src/cccf/mcp_server.py`, `tests/test_mcp_server.py`
  - Description : le tool appelle `index_repo` directement (moteur manuel,
    sans chunks). Sur un repo indexé avec `--engine cocoindex`,
    `index_engine` reste `cocoindex-prototype` mais les chunks de code ne
    sont pas rafraîchis → le tool `search` sert des chunks périmés après
    réindexation.
  - Correctif proposé : lire `store.get_meta("index_engine")` et dispatcher
    vers `index_repo_with_cocoindex` quand il vaut `ENGINE_META_VALUE`,
    comme le fait la CLI ; sinon poser `index_engine=manual` (parité CLI).
  - CA : test MCP : index cocoindex, modification d'un fichier,
    `reindex_findings`, `search` renvoie le contenu à jour.

- [ ] **P4 — `--severity` invalide → `ValueError` brute (CLI et MCP)**
  - Fichiers : `src/cccf/search.py` (ou `store.py`), `tests/test_search.py`
  - Description : `cccf findings q --severity HIGH` lève
    `ValueError: 'HIGH' is not in list` (traceback non géré), idem via le
    tool MCP `search_findings`. Les sévérités Semgrep (`LOW/HIGH/...`) sont
    pourtant acceptées à l'indexation, l'utilisateur peut légitimement les
    essayer à la requête.
  - Correctif proposé : valider contre `VALID_SEVERITIES` en tête de
    `search_findings` et lever une erreur métier propre (message listant
    les valeurs autorisées, code de sortie 2 côté CLI — même contrat que
    `min_severity` dans `config.py`).
  - CA : exit code 2 + message explicite côté CLI ; erreur MCP propre.

- [ ] **P5 — `code_embedding_signature` écrite mais jamais relue**
  - Fichiers : `src/cccf/coco_indexer.py`, `src/cccf/indexer.py`,
    `tests/test_indexer.py`
  - Description : au changement de modèle d'embedding, les findings et
    endpoints sont ré-embeddés (comparaison de `embedding_signature`),
    mais pas les chunks de code : `vec_code_chunks` n'est reconstruite que
    si la *dimension* change. Deux modèles de même dimension → vecteurs
    mixtes silencieux, recherche faussée. (Recoupe X3 du BACKLOG-PRIORITY.)
  - Correctif proposé : comparer `code_embedding_signature` au début de
    l'indexation cocoindex ; en cas d'écart, ré-embedder tous les chunks
    (comme les findings).
  - CA : test avec deux FakeEmbedder de même dim et signatures distinctes :
    tous les chunks sont ré-embeddés au changement.

- [ ] **P6 — Un seul finding malformé fait échouer toute l'indexation**
  - Fichiers : `src/cccf/scanner.py`, `tests/test_scanner.py`
  - Description : deux points durs dans `parse_semgrep_json` :
    (a) une sévérité inconnue (`_normalize_severity`) lève `SemgrepError`
    et avorte tout l'index ; (b) `_relative_path` lève une `ValueError`
    *non enveloppée* si Semgrep renvoie un chemin hors de `repo_root`
    (symlink, worktree).
  - Correctif proposé : (a) mapper une sévérité inconnue sur `WARNING`
    avec un avertissement stderr plutôt qu'échouer ; (b) attraper
    `ValueError` et conserver le chemin tel quel (posix) ou ignorer le
    résultat avec avertissement — dans les deux cas, jamais d'abandon
    global pour un résultat isolé.
  - CA : sortie Semgrep contenant une sévérité exotique + un chemin hors
    repo → l'index aboutit, les autres findings sont indexés.

## Robustesse

- [ ] **P7 — `invoke_semgrep_raw` : liste de fichiers en argv non bornée**
  - Fichiers : `src/cccf/scanner.py`, `tests/test_scanner.py`
  - Description : au premier index (ou `--full`) d'un gros repo, tous les
    chemins passent en arguments de la commande `semgrep` → dépassement
    d'`ARG_MAX` (~256 Ko sur macOS) et échec opaque. (Recoupe A5/A7.)
  - Correctif proposé : batcher les fichiers (paquets de ~400) et
    concaténer les `results` des scans, ou scanner `.` quand
    `changed == tous les fichiers`.
  - CA : test unitaire sur le batching (fake `subprocess.run` comptant les
    invocations et la taille d'argv).

- [x] **P8 — 8 tests d'intégration dépendent du réseau (modèle HF réel)**
  - Fichiers : `tests/test_k5_flow_e2e.py`, `tests/test_k7_federation_e2e.py`,
    `tests/test_mcp_server.py` (2 tests), `tests/test_k12_graph_workspace_e2e.py`,
    `tests/test_m3_module_graph_e2e.py` (selon les cas)
  - Description : ces tests invoquent `cccf index` sans
    `CCCF_FAKE_EMBEDDER=1` → téléchargement HuggingFace à froid (8 échecs
    SSL constatés lors de cette revue). `test_mcp_server.py` pose déjà la
    variable dans sa fixture pour les autres tests.
  - Correctif proposé : poser `CCCF_FAKE_EMBEDDER=1` (monkeypatch) dans ces
    tests — ils vérifient la plomberie flow/fédération, pas la qualité
    d'embedding. Attention : `_make_embedder_cached` est un `lru_cache`
    process-wide, poser la variable *avant* tout `make_embedder` du test.
  - CA : `uv run pytest` passe sans réseau (cache HF vide).

- [ ] **P9 — `discover_maven_services` ramasse les pom.xml de build**
  - Fichiers : `src/cccf/workspace.py`, `tests/test_workspace.py`
  - Description : `root.rglob("pom.xml")` inclut `target/` (poms copiés par
    shade/archetype), `node_modules/`, répertoires cachés → services
    fantômes dans la fédération et le graphe.
  - Correctif proposé : filtrer les chemins dont un segment est `target`,
    `build`, `node_modules` ou commence par `.`.
  - CA : fixture avec `svc/target/classes/META-INF/.../pom.xml` → non
    découvert.

- [ ] **P10 — Validation de config incomplète**
  - Fichiers : `src/cccf/config.py`, `tests/test_config.py`
  - Description : `semgrep_timeout_s: abc` → `ValueError` brute ;
    `include: "*.py"` (string au lieu de liste) est accepté et itéré
    caractère par caractère par `_matches_any` (aucun fichier ne matche,
    silencieusement).
  - Correctif proposé : envelopper le cast int dans `ConfigError` ; rejeter
    include/exclude/rules non-listes avec message explicite.
  - CA : chaque config invalide → `ConfigError` avec message ciblé,
    exit code 1.

## Simplicité (sans changement de comportement)

- [ ] **P11 — Nettoyages mécaniques**
  - Fichiers : `src/cccf/store.py`, `src/cccf/indexer.py`
  - Description / correctifs :
    - `_glob_to_sqlite` est l'identité → supprimer la fonction et l'appel ;
    - `iter_embeddings()` / `iter_endpoint_embeddings()` sont utilisés par
      l'indexeur uniquement pour récupérer les *ids* mais matérialisent
      tous les vecteurs → ajouter `embedded_finding_ids()` /
      `embedded_endpoint_ids()` (`SELECT <id> FROM vec_*`) et les utiliser
      dans `index_repo` ;
    - boucles d'`INSERT` unitaires dans `replace_*_for_files` →
      `executemany` ;
    - sentinelle `set_meta("embedding_dim", "")` → `DELETE FROM meta` via
      un `delete_meta(key)` explicite.
  - CA : `uv run pytest` inchangé ; aucun changement de contrat JSON.

- [ ] **P12 — Dédupliquer la logique de repli similarité de `flow`**
  - Fichiers : `src/cccf/flow.py` (ou nouveau helper), `src/cccf/cli.py`,
    `src/cccf/mcp_server.py`
  - Description : le bloc « `trace_flow` → `FlowError` →
    `resolve_topic_by_similarity` → retry » est copié-collé entre
    `cli.flow_cmd` et `mcp_server.trace_message_flow` (~20 lignes chacun).
  - Correctif proposé : extraire `trace_flow_with_similarity_fallback(...)`
    dans `flow.py`, appelé des deux côtés.
  - CA : tests CLI et MCP existants inchangés.

- [ ] **P13 — Parité CLI ↔ MCP des paramètres de lecture**
  - Fichiers : `src/cccf/mcp_server.py`, `tests/test_mcp_server.py`
  - Description : le tool `search_findings` n'expose pas `offset`
    (la CLI oui) ; `list_endpoints` n'expose pas `module` (la CLI oui).
    Un agent ne peut ni paginer les findings ni filtrer l'inventaire par
    module.
  - Correctif proposé : ajouter les deux paramètres, mêmes défauts que la
    CLI.
  - CA : tests MCP de pagination et de filtre module.

- [ ] **P14 — `cli.findings_cmd` : `load_config` hors du bloc d'erreurs**
  - Fichiers : `src/cccf/cli.py`, `tests/test_cli.py`
  - Description : si `.cccf/findings.db` existe mais que `config.yml` a
    disparu, `ConfigError` remonte en traceback brut (les autres commandes
    l'attrapent).
  - Correctif proposé : envelopper comme dans `index_cmd`/`search`.
  - CA : suppression de `config.yml` après index → message propre, exit 2.

## Déjà tracké ailleurs (ne pas dupliquer)

- Hash streaming / batch SQL / gros repos → A5 (reliquat) / A7 / R8 / R9
  (BACKLOG-PRIORITY n°5) ; P7 en est le sous-cas le plus urgent.
- Unification `SEVERITY_ORDER` / `_SEVERITY_RANK` (4 modules) → N1
  (BACKLOG-PRIORITY n°14).
- Invalidation des embeddings de chunks → X3 (BACKLOG-PRIORITY n°8) ;
  P5 en est le correctif minimal immédiat sans attendre la migration
  CocoIndex.
