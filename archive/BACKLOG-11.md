# Backlog 11 — Durcissement audit microservices (2026-07-13)

> Objectif : transformer le socle `cccf` actuel — recherche code + findings,
> règles liveness, modèle d'endpoints et graphe local — en outil plus fiable
> pour auditer une base microservices complexe : inventaire exploitable,
> fédération multi-repos et performance sur grands dépôts.
>
> Convention : une tâche = un commit (`A<n>: <titre>`), DoD globale inchangée
> (voir `AGENT.md`).

## Constat de revue

`cccf` est pertinent comme assistant d'audit repo par repo : il joint recherche
sémantique et findings Semgrep, expose un MCP utilisable par l'agent, et porte
des règles spécifiques aux risques REST/Kafka. L'écart principal avec un audit
d'architecture distribuée complet est le passage de signaux locaux à une vue
inter-services fiable : endpoints réellement indexés, plusieurs bases fédérées,
et exécution robuste sur grands volumes.

## Tâches

### [x] A1 — Brancher l'inventaire d'endpoints dans `cccf index`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/indexer.py`, `src/cccf/scanner.py`,
  `src/cccf/store.py`, `src/cccf/cli.py`, `src/cccf/mcp_server.py`,
  `src/cccf/render.py`, `tests/test_indexer.py`, `tests/test_cli.py`,
  `tests/test_mcp_server.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`
- **Description** : exécuter les règles d'inventaire d'endpoints pendant
  l'indexation normale, en plus des findings Semgrep. Les endpoints REST et
  Kafka doivent être remplacés incrémentalement par fichier, consultables via
  CLI/MCP, et utilisables par `cccf graph` sans nécessiter de remplissage manuel
  de la table `endpoints`.
- **CA** :
  1. `cccf index` peuple `endpoints` pour les fichiers changés et supprime les
     endpoints d'un fichier supprimé.
  2. Les règles d'inventaire sont traitées comme des endpoints, pas comme des
     findings filtrés par `min_severity`.
  3. Une commande CLI et un tool MCP exposent la liste filtrable des endpoints
     (`system`, `role`, `topic`, `path`).
  4. `cccf graph` retourne des résultats issus d'une indexation standard, sans
     fixture injectée directement dans le store.
  5. Les docs décrivent le comportement observable et le pipeline interne.
- **Statut** : livré. `indexer.index_repo` fait un seul scan Semgrep
  (`scanner.invoke_semgrep_raw`, ADR-29) partagé entre `parse_semgrep_json`
  (findings, désormais filtre les résultats `category: endpoint-inventory`)
  et `parse_semgrep_endpoints` (endpoints, pas de filtre `min_severity`,
  CA2) — `store.replace_endpoints_for_files` par fichier changé,
  `store.remove_files` purge aussi les endpoints (déjà vrai depuis K1).
  `IndexReport` gagne `endpoints_added`/`endpoints_removed`. CLI `cccf
  endpoints` et tool MCP `list_endpoints` (CA3), filtrables `system`/`role`/
  `topic`/`path`. CA4 testé de bout en bout (`cccf init` + `cccf index` +
  `cccf graph`/`cccf endpoints` sur `tests/fixtures/endpoint_index_repo/`,
  sans rien injecter dans le store à la main) : un `@KafkaListener`
  contenant un appel `RestTemplate` ressort correctement de `cccf graph`.
  Docs à jour (`docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, ADR-29).

### [ ] A2 — Fédérer un répertoire multi-services pour le graphe distribué
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/graph.py`, `src/cccf/store.py`,
  `src/cccf/cli.py`, `src/cccf/mcp_server.py`, `src/cccf/render.py`,
  `tests/test_graph.py`, `tests/test_cli.py`, `tests/test_mcp_server.py`,
  `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `docs/ADR.md`
- **Description** : permettre à `cccf` d'analyser un répertoire parent contenant
  tous les microservices et des composants partagés (modules Maven communs),
  puis de lire les index `.cccf/findings.db` des sous-projets en lecture seule,
  chacun associé à un nom de service ou de module. L'objectif est de construire
  des arêtes REST/Kafka inter-services, détecter des cycles et classer les
  hotspots par findings recouvrants. La fédération reste locale-first : pas de
  serveur central, pas de broker ou registry interrogé au runtime.
- **CA** :
  1. Une configuration ou option CLI déclare un répertoire racine à explorer et
     permet d'identifier les sous-projets représentant des microservices ou des
     modules Maven partagés.
  2. Chaque sous-projet fédéré reçoit un nom logique stable, dérivé de sa
     configuration Maven ou d'une configuration explicite quand la détection
     automatique est ambiguë.
  3. Le graphe REST relie un endpoint `call` d'un service à un endpoint `serve`
     d'un autre service quand méthode et chemin matchent.
  4. Le graphe Kafka relie `produce` et `consume` sur topic identique entre
     services distincts.
  5. Les modules partagés Maven sont distingués des microservices déployables :
     ils peuvent porter des findings et du code appelé, mais ne sont pas traités
     comme producteurs/consommateurs runtime sauf endpoint explicite.
  6. Les cycles inter-services sont rendus en JSON et texte avec les sites
     fichier/lignes des deux extrémités.
  7. Les hotspots croisent cycles et findings par service, fichier et lignes,
     puis classent les résultats par sévérité.
  8. Une base absente, non initialisée ou incompatible est signalée comme
     erreur explicite, pas ignorée silencieusement.

### [ ] A5 — Optimiser l'indexation et la recherche pour grands repos
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/indexer.py`, `src/cccf/store.py`,
  `src/cccf/search.py`, `src/cccf/ccc_bridge.py`, `tests/test_indexer.py`,
  `tests/test_store.py`, `tests/test_search.py`, `docs/SPEC-TECH.md`
- **Description** : réduire les lectures complètes en mémoire et les scans SQL
  non bornés afin que `cccf` reste utilisable sur des monorepos ou de grands
  ensembles de microservices. Les filtres courants doivent être poussés en SQL
  quand c'est possible, les hash de fichiers doivent être calculés en streaming,
  et les jointures findings/code/endpoints doivent éviter de charger tout le
  store quand seule une tranche est nécessaire.
- **CA** :
  1. `_sha256_file` lit les fichiers par blocs, pas via `read_bytes()`.
  2. `Store.all_findings` et `Store.all_endpoints` appliquent `severity`,
     `rule_id`, `system`, `role`, `topic` et `path` au plus près de SQLite.
  3. L'annotation d'une liste de résultats code ne charge que les findings des
     chemins concernés.
  4. Les suppressions/remplacements par lots respectent la limite SQLite de
     paramètres bindés.
  5. Les tests couvrent un volume synthétique suffisant pour prouver que les
     chemins filtrés ne scannent pas inutilement tout le store.
  6. La documentation technique indique les garanties de complexité attendues
     et les limites restantes de `sqlite-vec` sur les filtres post-KNN.
