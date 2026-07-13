# Backlog 13 — Attribution module Maven + classe Java à l'indexation (2026-07-13)

> Objectif : retour utilisateur direct — le mode `--workspace` (fédération
> multi-dépôts, BACKLOG-11 A2) impose d'indexer chaque module Maven
> séparément, ce qui est ressenti comme une charge artificielle pour un
> monorepo (un seul dépôt Git, plusieurs modules Maven, déjà indexé en un
> seul passage à la racine). Cette tâche fait qu'une seule indexation du
> répertoire parent suffit à détecter des cycles/hotspots inter-modules,
> sans passer par la fédération — voir `docs/ADR.md` ADR-32 pour la
> décision complète.
>
> Convention : une tâche = un commit (`M<n>: <titre>`), DoD globale
> inchangée (voir `AGENT.md`).

## Constat de revue

La fédération A2/K7 reste indispensable pour des services qui vivent dans
des dépôts Git réellement séparés. Mais pour le cas — très courant —
d'un monorepo Maven multi-modules, elle est superflue : le répertoire
parent est déjà scanné en un seul passage par `cccf index`, il manque
seulement l'attribution de chaque finding/endpoint à son module pour que
`cccf graph`/`cccf flow` puissent grouper et détecter les relations
inter-modules sans jamais toucher à `--workspace`.

## Tâches

### [x] M1 — Module Maven + nom qualifié Java attribués à l'indexation
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/maven.py` (nouveau), `src/cccf/models.py`,
  `src/cccf/scanner.py`, `src/cccf/store.py`, `src/cccf/workspace.py`,
  `tests/test_maven.py` (nouveau), `tests/test_store.py`,
  `tests/test_kafka_endpoints.py`, `docs/ADR.md`, `docs/SPEC-TECH.md`
- **Description** : `Finding`/`MessageEndpoint` gagnent `module: str |
  None` (artifactId du `pom.xml` le plus proche en remontant depuis le
  fichier jusqu'à `repo_root`) et `qualified_name: str | None` (package +
  classe Java, `None` pour un fichier non-Java). Calculés dans
  `scanner.py` à la construction de chaque `Finding`/`MessageEndpoint`.
  Schéma SQLite v4 → v5, purement additif.
- **CA** :
  1. `module_name_for_path(repo_root, rel_path)` retrouve le bon module
     dans une arborescence multi-modules, `None` sans `pom.xml`, jamais de
     remontée au-delà de `repo_root`.
  2. `_java_qualified_name` extrait `package + classe` par regex sur la
     déclaration `package ...;`, `None` pour un fichier non-Java.
  3. Migration v4 → v5 additive : une base existante s'ouvre sans erreur,
     `module`/`qualified_name` valent `NULL` jusqu'au prochain `cccf index`.
  4. `parse_pom` partagé entre `workspace.py` et `scanner.py` (pas de
     duplication de la lecture XML).
- **Statut** : livré. `src/cccf/maven.py` (nouveau) : `parse_pom` (repris
  de l'ancien `workspace._parse_pom`, renommé public) et
  `module_name_for_path` (borné comme
  `scanner._candidate_spring_roots` — jamais au-delà de `repo_root`,
  résultat caché par `pom.xml`, `lru_cache`). `scanner._java_qualified_name`
  (regex `package ...;` + nom de fichier, caché par fichier). Les deux sont
  appelés dans `parse_semgrep_json`/`parse_semgrep_endpoints` pour chaque
  `Finding`/`MessageEndpoint` construit. `Store` : colonnes `module`/
  `qualified_name` sur `findings`/`endpoints` (`CREATE TABLE IF NOT
  EXISTS` pour une base neuve, `ALTER TABLE ... ADD COLUMN` guardé par
  `PRAGMA table_info` pour une base v4 existante — `SCHEMA_VERSION` passé
  à `"5"`), index dédiés, filtre `module` sur `all_findings`/
  `all_endpoints`. Testé dans `tests/test_maven.py` (bornage, repli sans
  artifactId, absence de `pom.xml`, non-évasion hors `repo_root`,
  priorité au pom le plus proche dans un arbre multi-modules),
  `tests/test_store.py` (migration v4→v5), `tests/test_kafka_endpoints.py`
  (attribution réelle sur la fixture `kafka_workspace` indexée en un seul
  scan du répertoire parent).

### [x] M2 — Regroupement par module (`graph.group_endpoints_by_module`/`group_findings_by_module`)
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/graph.py`, `tests/test_graph.py`,
  `docs/SPEC-TECH.md`
- **Description** : transformer une liste plate d'endpoints/findings
  (venant d'un seul index multi-modules) en la même forme de dict
  (`dict[str, list[...]]`) que `workspace.load_federation` produit déjà —
  `build_graph`/`find_cycles`/`find_hotspots` n'ont aucun changement à
  faire, ils consomment indifféremment les deux sources.
- **CA** :
  1. Endpoints/findings groupés par `module`, endpoints/findings sans
     module exclus (jamais de fausse arête entre deux sites non attribués
     qui se retrouveraient arbitrairement dans le même compartiment).
  2. `build_graph`/`find_cycles` détectent un vrai cycle à partir d'un
     dict produit par ce regroupement, sans modification de `graph.py`
     au-delà des deux nouvelles fonctions.
- **Statut** : livré. `group_endpoints_by_module`/`group_findings_by_module`
  ignorent les entrées `module is None`. Testé unitairement
  (`tests/test_graph.py`) et de bout en bout via M3.

### [x] M3 — `cccf graph`/`cccf flow` sans `--workspace` groupent par module
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/cli.py`, `src/cccf/mcp_server.py`,
  `src/cccf/flow.py`, `src/cccf/render.py`, `tests/test_cli.py`,
  `tests/test_mcp_server.py`, `tests/test_m3_module_graph_e2e.py`
  (nouveau), `docs/SPEC-FONC.md`
- **Description** : `cccf graph`/tool MCP `graph`, sans `--workspace`,
  tentent d'abord le regroupement par module (M2) avant de retomber sur
  l'ancien comportement (cycles/hotspots vides + note explicite) si aucun
  module Maven n'est détecté. `cccf flow`/`trace_message_flow`, sans
  `--workspace`, attribuent chaque site à son module au lieu de toujours
  renvoyer `service: null`.
- **CA** :
  1. `cccf graph --json` (sans `--workspace`) sur un répertoire parent
     multi-modules indexé en un seul passage rapporte un vrai cycle/hotspot
     inter-modules.
  2. Un repo non-Maven (ou sans `--workspace`) continue de renvoyer la note
     explicite — non-régression.
  3. `cccf flow` (sans `--workspace`) attribue `service` au module Maven
     réel plutôt que `null` quand l'index en couvre plusieurs.
  4. `--workspace` continue de fonctionner exactement comme avant (chemin
     inchangé pour des services dans des dépôts séparés).
- **Statut** : livré. `render_graph_json` : `workspace_provided`/
  `workspace_warnings` renommés `cross_module_data_available`/`warnings`
  (sémantique élargie : "une source de données inter-modules a produit un
  résultat", pas seulement "`--workspace` a été fourni") ; le message
  `_NO_CROSS_MODULE_DATA_NOTE` remplace `_NO_WORKSPACE_NOTE` et mentionne
  les deux chemins possibles. `cccf flow`/`trace_message_flow` utilisent
  `flow.group_endpoints_by_module_for_flow`/`group_findings_by_module_for_flow`
  — variante qui **ne supprime jamais** un endpoint/finding sans module
  (clé `None` conservée, contrairement à M2) : `flow` doit lister tous les
  sites d'un topic, pas seulement ceux attribuables à un module. `cccf
  endpoints` gagne `--module` (filtre) et `EndpointHit.module`/
  `qualified_name` (exposition). Testé de bout en bout dans
  `tests/test_m3_module_graph_e2e.py` : la fixture `rest_cycle_workspace`
  (3 services, cycle REST A→B→C→A, déjà utilisée par
  `test_k12_graph_workspace_e2e.py` en mode fédéré) indexée **une seule
  fois** à la racine reproduit le même cycle sans `--workspace` ; la
  fixture `kafka_workspace` indexée une seule fois attribue bien
  `order-service`/`payment-service` aux sites `cccf flow` correspondants.

## Ce que cette tâche ne remplace pas

La fédération A2/K7 (`cccf workspace`, `--workspace` sur `graph`/`flow`)
reste le seul chemin pour des microservices qui vivent dans des dépôts Git
réellement séparés (pas de répertoire parent commun indexable en un seul
passage). Les deux mécanismes coexistent, `--workspace` prenant le pas
quand il est fourni — voir ADR-32.

## Reste à couvrir

- `cccf findings`/`search_findings` (recherche KNN, pas un simple `SELECT`)
  n'ont pas de filtre `--module`/`module` — seul `cccf endpoints` l'a reçu
  dans cette tâche.
- Pas de commande dédiée pour indexer automatiquement chaque module d'un
  monorepo en une seule invocation (`cccf init`/`cccf index` restent à
  lancer une fois, à la racine, comme pour un repo simple — c'est
  justement ce que cette tâche rend suffisant).
