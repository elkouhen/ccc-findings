# Backlog 10 — Architecture distribuée : échanges de messages Kafka (2026-07-12)

> Objectif : étendre `cccf` pour qu'un agent puisse raisonner sur une
> architecture distribuée à base de messages Kafka — *« qui produit / consomme
> le topic X ? »*, *« trace le flux des événements de commande »*, *« quels
> problèmes de sécurité sur les consommateurs de paiements ? »* — sans trahir
> la philosophie de `ccc`/`cccf`.
>
> Convention : une tâche = un commit (`K<n>: <titre>`), DoD globale inchangée
> (voir `AGENT.md`).

## Principe directeur

L'idée clé qui respecte la philosophie existante : **les échanges de messages
sont modélisés comme des *endpoints statiques* extraits du code** (un site de
production ou de consommation d'un topic, avec fichier + lignes), pas comme
des flux runtime. L'extraction réutilise le moteur déjà en place — Semgrep,
avec des metavariables qui capturent le nom du topic — et le stockage réutilise
le store existant (SQLite + `sqlite-vec`, embeddings du même modèle). La
« vue distribuée » est une **jointure à la requête** entre endpoints, schémas
d'événements, code et findings — exactement comme `search_code_with_findings`
joint déjà code et findings par fichier + lignes (esprit ADR-19).

## Exclusions délibérées (philosophie ccc/cccf)

- **Pas de connexion runtime** aux brokers Kafka ni à un Schema Registry
  distant : analyse 100 % statique des fichiers du repo (NF4 local-first).
  Un export local de schémas suffit.
- **Pas de base centrale ni de serveur** : la dimension multi-dépôts (K7) est
  une fédération *en lecture seule* de fichiers SQLite locaux, à la requête.
- **Pas d'analyse taint inter-services** : Semgrep Pro / interfile reste hors
  scope (PRD §5, question ouverte §12.3).
- **Kafka d'abord, mais modèle extensible** : le champ `system` des endpoints
  permet d'autres brokers (RabbitMQ, SQS…) plus tard — non livré, comme
  « autres moteurs que Semgrep » dans le PRD.

## Tâches

### [ ] K1 — Modèle de données `message_endpoints`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/models.py`, `src/cccf/store.py`,
  `tests/test_store.py`, `docs/SPEC-TECH.md`, `docs/ADR.md`
- **Description** : nouvelle entité `MessageEndpoint` — `role`
  (`produce`|`consume`), `system` (`kafka`), `topic`, `topic_dynamic` (bool),
  `framework`, fichier, lignes, extrait, identité stable (même esprit
  qu'ADR-5/ADR-15 : hash rôle + topic + chemin + localisation). Table SQLite
  dédiée avec remplacement incrémental par fichier (même mécanique que
  `replace_findings_for_files`). Nouvel ADR : « les échanges de messages sont
  des endpoints statiques extraits du code ».
- **CA** :
  1. Schéma créé à l'init du store, migration transparente d'une base existante.
  2. Remplacement par fichier testé : réindexer un fichier remplace ses
     endpoints sans toucher aux autres.
  3. L'identité est stable à contenu identique, change si le topic ou la
     localisation change.

### [ ] K2 — Règles Semgrep d'extraction des endpoints Kafka
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/rules/kafka/` (nouveau, embarqué dans le package),
  `tests/fixtures/kafka/*`, `tests/test_scanner.py`, `docs/SPEC-TECH.md`
- **Description** : pack local de règles d'*inventaire* (pas des findings de
  sécurité) avec metavariables capturant le topic, couvrant les frameworks
  principaux : Python (`kafka-python`, `confluent-kafka` —
  `producer.send/produce`, `consumer.subscribe`), Java/Spring
  (`@KafkaListener`, `KafkaTemplate.send`), JS (`kafkajs`). Un topic non
  littéral (variable, config) est capturé comme expression et marqué
  `topic_dynamic: true` — jamais résolu silencieusement. Conforme ADR-4 :
  règles embarquées et testées sur fixtures locales, pas de pack registry
  dans les tests.
- **CA** :
  1. Une fixture par framework ; chaque fixture produit les endpoints
     attendus (rôle, topic, lignes).
  2. Topic dynamique → endpoint présent, marqué dynamique, expression
     conservée en clair.
  3. Le parsing de la sortie Semgrep de ces règles est testé sur fixtures
     JSON (esprit ADR-8).

### [ ] K3 — Pipeline d'indexation des endpoints + embeddings
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/indexer.py`, `src/cccf/scanner.py`,
  `src/cccf/embedder.py`, `src/cccf/store.py`, `docs/SPEC-TECH.md`,
  `docs/SPEC-FONC.md`
- **Description** : `cccf index` exécute en plus le pack K2 (scan Semgrep
  dédié, sur le même périmètre incrémental de fichiers), stocke les endpoints
  (K1) et les vectorise — texte embeddé : rôle + topic + framework + extrait
  normalisé — dans une table `vec0` dédiée (mêmes mécanismes qu'ADR-16/17,
  même modèle d'embedding par défaut, ADR-3). Un échec du scan d'extraction
  n'invalide jamais l'index findings existant (NF5).
- **CA** :
  1. `cccf index` sur une fixture crée endpoints + embeddings.
  2. Incrémental : seul un fichier modifié est re-scanné pour ses endpoints.
  3. Échec/timeout du scan d'extraction → findings intacts, erreur signalée,
     code de sortie documenté.

### [ ] K4 — Indexation des contrats d'événements locaux (schémas)
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/indexer.py`, `src/cccf/store.py`,
  `src/cccf/models.py`, `docs/SPEC-TECH.md`, `docs/SPEC-FONC.md`
- **Description** : indexer les fichiers de schéma présents dans le repo
  (Avro `.avsc`, Protobuf `.proto`, AsyncAPI `.yml`/`.yaml`) comme documents
  `message_schemas` embarqués (embeddings pour la recherche NL), liés aux
  topics : lien explicite pour AsyncAPI (`channels`), heuristique par nom
  (record/schéma ↔ topic) sinon. Pas de connexion à un Schema Registry — un
  export local de schémas est le chemin supporté (NF4).
- **CA** :
  1. Fixture avec `.avsc` + `asyncapi.yml` → schémas indexés et liés au topic.
  2. Une recherche NL (« événement de règlement de paiement ») retrouve le
     schéma pertinent.
  3. Schéma sans topic résolu → indexé quand même, lien absent, pas d'erreur.

### [ ] K5 — CLI `cccf flow`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/flow.py` (nouveau), `src/cccf/cli.py`,
  `tests/test_cli.py`, `docs/SPEC-FONC.md`
- **Description** : `cccf flow <topic|requête NL>` — résout le(s) topic(s)
  (nom exact, sinon similarité vectorielle sur les endpoints/schémas), puis
  affiche : producteurs, consommateurs (fichier:lignes, framework), schéma lié
  (si K4), et pour chaque site les findings Semgrep qui le recouvrent
  (réutilise la jointure fichier + lignes existante, esprit ADR-19). Sortie
  compacte par défaut (NF3), `--json` pour consommation machine.
- **CA** :
  1. Sur fixture : `cccf flow orders` liste producteur et consommateur avec
     fichier:lignes et findings recouvrants.
  2. Une requête NL approximative retrouve le bon topic.
  3. Topic inconnu → message explicite, code de sortie non nul documenté.
  4. Contrat `--json` documenté dans SPEC-FONC et testé.

### [ ] K6 — Tool MCP `trace_message_flow` + mise à jour du skill
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/mcp_server.py`, `tests/test_mcp_server.py`,
  `docs/SPEC-FONC.md` ; repo `ccc-findings-skill` : `skills/cccf/SKILL.md`
- **Description** : même contrat que K5 en sortie structurée (ADR-18 :
  `TypedDict`, erreurs via `ToolError`). Le skill gagne une section « tracer
  un flux de messages » : quand l'utiliser, et la boucle type — `flow` →
  lire les sites → corriger → `reindex_findings` → vérifier.
- **CA** :
  1. Tool listé par `cccf mcp`, sortie structurée testée.
  2. Topic inconnu → `ToolError` explicite.
  3. `SKILL.md` mis à jour dans le repo skill (commit séparé là-bas).

### [ ] K7 — Workspace multi-dépôts (fédération read-only)
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/workspace.py` (nouveau), `src/cccf/cli.py`,
  `src/cccf/mcp_server.py`, `docs/ADR.md`, `docs/SPEC-FONC.md`
- **Description** : un système distribué s'étale sur plusieurs dépôts (le
  producteur d'un topic vit rarement dans le repo de son consommateur). Un
  fichier de workspace (`~/.cccf/workspaces/<nom>.yml`) liste les chemins de
  projets déjà indexés ; `cccf flow --workspace <nom>` (et le tool MCP) ouvre
  chaque `findings.db` **en lecture seule** et fusionne les endpoints par
  topic. Nouvel ADR : fédération à la requête de fichiers SQLite locaux —
  pas de base centrale, pas de démon, pas de réseau. Un repo listé mais non
  indexé → avertissement, pas d'échec global.
- **CA** :
  1. Deux repos fixtures (producteur dans A, consommateur dans B) →
     `cccf flow orders --workspace` relie les deux, chaque site attribué à
     son repo.
  2. Repo manquant/non indexé signalé sans faire échouer la requête.
  3. Aucune écriture dans les bases des autres projets.

### [ ] K8 — Pack de règles sécurité/qualité Kafka (findings)
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/rules/kafka-security/` (ou doc pointant un pack
  registry), fixtures de tests, `docs/SPEC-FONC.md`
- **Description** : à la différence de K2 (inventaire), de vraies règles de
  *findings* : désérialiseurs non sûrs côté consumer, credentials SASL en
  clair, `security.protocol` PLAINTEXT, handler de consommation sans gestion
  d'erreur/DLQ, producteur non idempotent. Réutilise le pipeline findings
  existant tel quel ; opt-in via `cccf init --rules` (cohérent ADR-13).
- **CA** :
  1. Chaque règle testée sur fixture positive + négative.
  2. Les findings produits sont indexés et interrogeables comme n'importe
     quel finding (`cccf findings "désérialisation kafka"`).

### [ ] K9 — Éval : requêtes NL sur les flux de messages
- **Priorité** : BASSE
- **Fichiers** : `eval/queries.yml`, `eval/run_eval.py`
- **Description** : étendre le jeu d'éval avec des questions type « qui
  consomme les événements de paiement ? », « désérialisation non sûre de
  messages » pour mesurer la pertinence top-5 (métrique PRD §9) sur les
  endpoints et findings Kafka.
- **CA** :
  1. Jeu d'éval exécutable sur les fixtures Kafka.
  2. Scores rapportés dans la sortie d'éval existante.
