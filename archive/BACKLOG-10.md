# Backlog 10 — Architecture distribuée : messages Kafka + appels REST (2026-07-12)

> Objectif : étendre `cccf` pour qu'un agent puisse raisonner sur un ensemble
> de microservices interconnectés par des appels REST et des messages Kafka —
> *« qui produit / consomme le topic X ? »*, *« qui appelle cette route ? »*,
> *« trace le flux des événements de commande »* — et surtout **localiser les
> points de blocage probables** d'une application qui se verrouille par
> intermittence (appels sans timeout, appels bloquants dans les handlers de
> consommation, cycles d'appels synchrones entre services) — sans trahir la
> philosophie de `ccc`/`cccf`.
>
> Convention : une tâche = un commit (`K<n>: <titre>`), DoD globale inchangée
> (voir `AGENT.md`).
>
> **Cible d'analyse : Java + Spring + Maven uniquement.** Décision de
> périmètre (2026-07-13), pas un manque temporaire : un volet Python avait
> été livré pour K8 (liveness) et K11 (REST) puis retiré. Les tâches encore
> ouvertes (K2, K9, etc.) ne couvrent que Java/Spring sauf mention contraire
> explicite.

## Principe directeur

L'idée clé qui respecte la philosophie existante : **les échanges entre
services (messages Kafka *et* appels REST) sont modélisés comme des
*endpoints statiques*** (un site de production/consommation d'un topic, ou
d'exposition/appel d'une route, avec fichier + lignes), pas comme des flux
runtime — extraits soit du code (K2 Kafka, K11 REST : moteur Semgrep déjà en
place, metavariables sur le nom du topic ou le chemin de route), soit d'un
manifeste déclaratif versionné (K10, `TOPICS.md`, pour ce qui n'est pas
résolvable statiquement). Les deux sources produisent la même entité
(`source: code`|`manifest`, K1) et partagent le stockage existant (SQLite +
`sqlite-vec`, embeddings du même modèle). La « vue distribuée » est une
**jointure à la requête** entre endpoints (toutes sources), schémas
d'événements, code et findings — exactement comme `search_code_with_findings`
joint déjà code et findings par fichier + lignes (esprit ADR-19). Le graphe
d'interactions et les cycles (K12) sont eux aussi **dérivés à la requête**,
jamais persistés.

## Exclusions délibérées (philosophie ccc/cccf)

- **Pas de connexion runtime** aux brokers Kafka ni à un Schema Registry
  distant : analyse 100 % statique des fichiers du repo (NF4 local-first).
  Un export local de schémas suffit.
- **Pas de base centrale ni de serveur** : la dimension multi-dépôts (K7) est
  une fédération *en lecture seule* de fichiers SQLite locaux, à la requête.
- **Pas d'analyse taint inter-services** : Semgrep Pro / interfile reste hors
  scope (PRD §5, question ouverte §12.3).
- **Kafka et REST d'abord, modèle extensible** : le champ `system`
  (`kafka`|`rest`) des endpoints permet d'autres protocoles (RabbitMQ, SQS,
  gRPC…) plus tard — non livré, comme « autres moteurs que Semgrep » dans
  le PRD.
- **Détection statique = candidats, pas preuve** : `cccf` désigne les motifs
  et structures propices au blocage ; la confirmation d'un verrouillage vécu
  reste du ressort du runtime (thread dumps, consumer lag, tracing), hors
  scope.

## Ordre de réalisation (objectif : localiser les points de blocage)

Le symptôme visé — l'application se verrouille par intermittence — dicte
l'ordre :

1. **Phase 1 — détecteurs immédiats** : K8 (règles liveness). Aucune
   dépendance aux autres tâches : le pipeline findings existant suffit,
   valeur dès la première indexation d'un service.
2. **Phase 2 — cartographier les échanges** : K1 (modèle généralisé
   kafka+rest), K2 et K11 (extraction), K3 (pipeline).
3. **Phase 3 — croiser** : K7 (fédération multi-dépôts), K12 (cycles et
   hotspots — la réponse directe à « où sont les endroits problématiques »),
   K10 (manifeste : complète les arêtes que l'extraction rate), K5/K6
   (surfaces CLI/MCP).
4. **Phase 4 — confort** : K4 (schémas), K9 (éval).

## Tâches

### [x] K1 — Modèle de données `message_endpoints`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/models.py`, `src/cccf/store.py`,
  `tests/test_store.py`, `docs/SPEC-TECH.md`, `docs/ADR.md`
- **Description** : nouvelle entité `MessageEndpoint` — `role`
  (`produce`|`consume` pour Kafka, `serve`|`call` pour REST), `system`
  (`kafka`|`rest`), `topic` (nom de topic Kafka, ou méthode HTTP + chemin de
  route normalisé pour REST), `topic_dynamic` (bool),
  `source` (`code`|`manifest`, voir K10), `framework`, fichier, lignes,
  extrait, identité stable (même esprit qu'ADR-5/ADR-15 : hash rôle + topic +
  chemin + localisation ; pour `source: manifest`, la localisation est le
  chemin du `TOPICS.md` et non une ligne de code — voir K10). Table SQLite
  dédiée avec remplacement incrémental par fichier (même mécanique que
  `replace_findings_for_files`). Nouvel ADR : « les échanges de messages sont
  des endpoints statiques extraits du code ou déclarés en manifeste ».
- **CA** :
  1. Schéma créé à l'init du store, migration transparente d'une base existante.
  2. Remplacement par fichier testé : réindexer un fichier remplace ses
     endpoints sans toucher aux autres.
  3. L'identité est stable à contenu identique, change si le topic ou la
     localisation change.
  4. `source` distingue un endpoint extrait de code (K2) d'un endpoint
     déclaré en manifeste (K10) ; les deux peuvent coexister pour le même
     topic sans collision d'identité (chemins différents).
- **Statut** : livré. `MessageEndpoint`, `compute_endpoint_id`, table SQLite
  `endpoints`, filtres `Store.all_endpoints`, remplacement par fichier et
  migration additive en schéma v4 sont présents et testés.

### [x] K2 — Règles Semgrep d'extraction des endpoints Kafka
- **Priorité** : HAUTE
- **Fichiers** : repo `ccc-findings-skill` : `skills/cccf/rules/kafka/`
  (nouveau — ADR-24, jamais dans `ccc-findings`) ; ce repo :
  `tests/fixtures/kafka/*`, `tests/test_scanner.py`, `docs/SPEC-TECH.md`
- **Description** : pack local de règles d'*inventaire* (pas des findings de
  sécurité), Java/Spring uniquement (cible Java + Spring + Maven — voir note
  en tête de fichier) : consommation (`@KafkaListener`), production
  (`KafkaTemplate.send`, `new ProducerRecord(...)`). Le topic est extrait du
  snippet par regex, pas par métavariable Semgrep (indisponible sans session
  `semgrep login`, ADR-26) — un topic non littéral (variable, config) ou non
  résolu est marqué `topic_dynamic: true`, jamais résolu au hasard. Cas
  particulier à traiter : un topic donné comme propriété Spring
  (`@KafkaListener(topics = "${app.kafka.topics.orders}")`) n'est **pas**
  un nom de topic mais une clé de configuration — tenter une résolution
  contre `application.yml`/`.properties` du repo (support du défaut
  `${prop:default}`) avant de retomber sur dynamique si la clé est
  introuvable. Conforme ADR-4 : règles embarquées et testées sur fixtures
  locales, pas de pack registry dans les tests.
- **CA** :
  1. Fixtures produce/consume ; chaque fixture produit les endpoints
     attendus (rôle, topic, lignes).
  2. Topic dynamique (variable, sans littéral) → endpoint présent, marqué
     dynamique, expression conservée en clair.
  3. Topic en propriété Spring résolue via `application.yml`/`.properties`
     → topic littéral résolu, `topic_dynamic=False` ; non résolue → clé
     conservée telle quelle, `topic_dynamic=True`.
  4. Le parsing de la sortie Semgrep de ces règles est testé sur fixtures
     JSON (esprit ADR-8).
- **Statut** : livré — 3 règles Java (`consume`, `produce-template`,
  `produce-record`), `skills/cccf/rules/kafka/java.yaml` côté skill.
  `resolve_spring_property` (ADR-28) résout un placeholder `${prop}`/
  `${prop:défaut}` contre `application.yml`/`.yaml`/`.properties`
  (`src/main/resources/` puis racine, layout Maven/Gradle standard, YAML
  imbriqué aplati en clés pointées) ; non résolu → placeholder conservé,
  `topic_dynamic=True`. `_extract_kafka_topic`/`parse_semgrep_endpoints`
  dans `scanner.py` (même fonction que K11, désormais partagée entre REST
  et Kafka via `metadata.system`), testés dans `tests/test_kafka_endpoints.
  py` (fixtures réelles incluant un `application.yml`, + tests unitaires de
  `resolve_spring_property`). Pas encore branché dans `cccf index` ni dans
  une commande CLI/MCP (K3 — voir A1 dans `archive/BACKLOG-11.md`). Restent
  à couvrir : profils Spring (`application-prod.yml`), suivi d'une variable
  alimentée par `@Value(...)` ailleurs dans la classe, `confluent-kafka`
  (API bas niveau hors Spring).

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
  4. Un topic présent à la fois côté code (K2) et côté manifeste (K10) donne
     deux endpoints distincts (`source` différent) affichés ensemble par
     `cccf flow` (K5) — pas de fusion silencieuse, pas de conflit qui bloque
     l'indexation.

### [ ] K4 — Indexation des contrats d'événements locaux (schémas)
- **Priorité** : BASSE (phase 4)
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
- **Priorité** : HAUTE (prérequis de K12 : sans fédération, pas de cycle
  inter-services visible)
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

### [ ] K8 — Pack de règles liveness (+ sécurité) Kafka/REST (findings)
- **Priorité** : HAUTE (phase 1 — le seul livrable sans aucune dépendance :
  le pipeline findings existant suffit)
- **Fichiers** : repo `ccc-findings-skill` : `skills/cccf/rules/liveness/`,
  `skills/cccf/rules/kafka-security/` (ADR-24, jamais dans `ccc-findings`) ;
  ce repo : fixtures de test, `docs/SPEC-FONC.md`
- **Description** : à la différence de K2/K11 (inventaire), de vraies règles
  de *findings*, recentrées sur l'objectif « points de blocage ». Volet
  **liveness** (prioritaire) : appel HTTP sans timeout (`requests`/`httpx`
  sans `timeout=`, `RestTemplate` par défaut…), appel REST synchrone dans un
  handler de consommation Kafka, attente bloquante (`.get()`, `.join()`,
  `.result()`) dans un chemin de traitement, verrou tenu autour d'une I/O
  réseau, configs consumer risquées (`max.poll.interval.ms`,
  `enable.auto.commit`), handler sans gestion d'erreur/DLQ, retry sans
  backoff. Volet **sécurité** (second) : désérialiseurs non sûrs côté
  consumer, credentials SASL en clair, `security.protocol` PLAINTEXT,
  producteur non idempotent. Réutilise le pipeline findings existant tel
  quel ; opt-in via `cccf init --rules` (cohérent ADR-13).
- **CA** :
  1. Chaque règle testée sur fixture positive + négative.
  2. Les findings produits sont indexés et interrogeables comme n'importe
     quel finding (`cccf findings "appel bloquant dans un consumer"`).
  3. Le pack liveness s'exécute sur un projet où aucune autre tâche K n'est
     livrée (indépendance vérifiée).
- **Statut** : volet Java/Spring livré (5 règles : `new RestTemplate()` sans
  timeout, `.join()`/`Future.get()` sans timeout, appel REST dans un
  `@KafkaListener`, appel réseau sous `synchronized`). Un volet Python a été
  livré puis retiré : la cible d'analyse est Java + Spring + Maven
  uniquement (décision de périmètre, pas un manque temporaire — voir la
  note en tête de ce fichier). Le pack ne vit plus dans `ccc-findings` — il
  est distribué par `ccc-findings-skill` (`skills/cccf/rules/liveness/
  java.yaml`, ADR-24), aux côtés du pack `default` déjà présent côté skill.
  `ccc-findings` garde une copie de test (`tests/fixtures/liveness_repo/`,
  `tests/test_liveness_rules.py`, `docs/SPEC-FONC.md#6-pack-de-règles-
  liveness-backlog-10-k8`). Restent à faire : volet sécurité (SASL,
  PLAINTEXT, désérialisation), configs consumer risquées
  (`max.poll.interval.ms`), handler sans DLQ, retry sans backoff.

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

### [ ] K10 — Endpoints déclarés via manifeste `TOPICS.md`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/manifest.py` (nouveau), `src/cccf/indexer.py`,
  `src/cccf/store.py`, `tests/fixtures/kafka-manifest/*`,
  `tests/test_manifest.py`, `docs/SPEC-TECH.md`, `docs/SPEC-FONC.md`
- **Description** : source d'endpoints complémentaire à K2, pour les topics
  non résolvables statiquement dans le code (nom dynamique/config) ou
  documentés côté équipe plutôt qu'inférés. Convention retenue :

  - **Fichier** : `TOPICS.md` à la racine de chaque microservice (un par
    service dans un monorepo), découvert par glob (`**/TOPICS.md`, mêmes
    règles d'include/exclude que le scan Semgrep).
  - **Format** : frontmatter YAML délimité par `---` (même convention que
    les `SKILL.md`), suivi de Markdown libre non parsé (indexé comme chunk
    de doc, comme tout `.md` aujourd'hui — pas utilisé pour l'extraction).
    Parsing déterministe via `pyyaml` (`yaml.safe_load` du bloc frontmatter
    uniquement), aucune tentative d'extraction depuis la prose (cohérent
    ADR-4/ADR-8 : pas de parsing flou).
  - **Champs** : `service` (optionnel, sinon nom du dossier), `system`
    (optionnel, défaut `kafka`), `topics[]` avec par entrée : `topic`
    (obligatoire), `mode` (obligatoire — `read` | `write` | `read-write`),
    `pattern` (bool optionnel, motif de nom plutôt que nom exact — pendant
    manifeste de `topic_dynamic`), `framework` (optionnel, informatif),
    `schema` (optionnel, chemin relatif vers un fichier indexé par K4),
    `description` (optionnel, texte libre).

    ```markdown
    ---
    service: order-service
    system: kafka
    topics:
      - topic: orders.created
        mode: write
        framework: kafka-python
        schema: schemas/orders.created.avsc
        description: "Émis à la création d'une commande."
      - topic: orders.payment.requested
        mode: read
        description: "Consommé pour déclencher le paiement."
      - topic: orders.status
        mode: read-write
        description: "Lu pour l'état courant, réécrit après transition."
    ---
    ```

  - **Ingestion** : `mode: write` → 1 `MessageEndpoint(role=produce,
    source=manifest)` ; `mode: read` → 1 `role=consume` ; `mode: read-write`
    → 2 endpoints (`produce` + `consume`). Localisation = chemin du
    `TOPICS.md` (+ ligne de l'entrée YAML, best-effort, hors identité).
    `schema` relie l'endpoint au document indexé par K4 quand résolu.
  - **Robustesse** : frontmatter absent/invalide → fichier ignoré avec
    avertissement à l'indexation (`cccf index`), jamais d'échec global
    (NF5) — même politique qu'un échec de scan Semgrep sur un fichier.

- **CA** :
  1. Fixture `TOPICS.md` avec les trois `mode` → nombre et rôles d'endpoints
     attendus, `source: manifest` sur chacun.
  2. `mode: read-write` produit bien deux endpoints distincts.
  3. Frontmatter invalide (YAML cassé, `mode` hors énumération) → avertissement,
     index existant intact, pas d'exception qui casse `cccf index`.
  4. `schema` résolu relie l'endpoint au document K4 correspondant ; `schema`
     absent ou introuvable → endpoint indexé quand même, lien absent.
  5. Un topic déclaré en manifeste ET détecté en code (K2) apparaît comme
     deux endpoints dans `cccf flow` (K5), pas de fusion silencieuse (CA K3.4).

### [ ] K11 — Règles Semgrep d'extraction des endpoints REST
- **Priorité** : HAUTE (phase 2 — pendant REST de K2)
- **Fichiers** : repo `ccc-findings-skill` : `skills/cccf/rules/rest/`
  (nouveau — ADR-24, jamais dans `ccc-findings`) ; ce repo :
  `tests/fixtures/rest/*`, `tests/test_scanner.py`, `docs/SPEC-TECH.md`
- **Description** : même mécanique que K2, pour les deux faces d'un appel
  REST. Côté **serveur** (`role: serve`) : routes exposées — Spring
  (`@GetMapping`/`@PostMapping`/`@RequestMapping`), Flask/FastAPI
  (décorateurs de route), Express (`app.get/post/...`). Côté **client**
  (`role: call`) : sites d'appel — `requests`/`httpx`,
  `RestTemplate`/`WebClient`/Feign, `fetch`/`axios` — avec méthode HTTP et
  chemin d'URL capturés en metavariables. Une URL non littérale (base URL en
  config, f-string) → endpoint marqué dynamique (même sémantique que
  `topic_dynamic`), jamais résolue silencieusement. `system: rest`, le champ
  `topic` porte « méthode + chemin normalisé » (ex. `GET /orders/{id}`).
  Conforme ADR-4 : règles embarquées, testées sur fixtures locales.
- **CA** :
  1. Une fixture par framework, côtés serveur et client ; endpoints attendus
     (rôle, méthode, chemin, lignes).
  2. URL dynamique → endpoint présent, marqué dynamique, expression conservée.
  3. Parsing testé sur fixtures JSON (esprit ADR-8).
- **Statut** : Java (Spring `@*Mapping`/`@RequestMapping` GET, `RestTemplate`)
  livré — 9 règles, `skills/cccf/rules/rest/java.yaml` côté skill (le volet
  Python livré puis retiré, cible Java + Spring + Maven uniquement — voir
  note en tête de fichier). Extraction par regex sur le snippet plutôt que
  par métavariable Semgrep : les métavariables se sont révélées
  indisponibles sans session `semgrep login` (ADR-26) — la méthode HTTP
  vient donc de `metadata.http_method` (une règle = une méthode), seul le
  chemin est extrait du texte, avec le même principe `topic_dynamic` que K2
  pour ce qui n'est pas un littéral. `parse_semgrep_endpoints`/
  `run_semgrep_endpoints` dans `scanner.py`, testés dans
  `tests/test_rest_endpoints.py` (fixtures réelles + fixtures JSON pour les
  cas d'erreur). Pas encore branché dans `cccf index` ni dans une commande
  CLI/MCP (K3, K5/K6 — voir A1 dans `archive/BACKLOG-11.md`). Reste à
  couvrir : `@RequestMapping` méthodes non-GET, `WebClient`/Feign.

### [ ] K12 — Graphe d'interactions et hotspots de blocage (`cccf graph`)
- **Priorité** : HAUTE (phase 3 — la réponse directe à « où sont les
  endroits problématiques »)
- **Fichiers** : `src/cccf/graph.py` (nouveau), `src/cccf/cli.py`,
  `src/cccf/mcp_server.py`, tests, `docs/SPEC-FONC.md`, `docs/ADR.md`
- **Description** : construit **à la requête** (jamais persisté — nouvel
  ADR) le graphe services ↔ endpoints à partir des endpoints fédérés (K7) :
  arête REST synchrone quand un `call` s'apparie à un `serve` (méthode +
  chemin, appariement par segments littéral ↔ template `{param}`,
  best-effort), arête Kafka quand un `produce` rencontre un `consume` du
  même topic. Détections, par gravité :
  1. **Cycles contenant au moins une arête REST synchrone** (risque de
     blocage distribué) ;
  2. **Appel sortant dans un handler de consommation** (croisement d'un
     `consume` et d'un `call` dans le même fichier/plage) ;
  3. **Hotspots** : sites à la fois sur un cycle *et* recouverts par un
     finding liveness (K8) — jointure fichier + lignes existante, classement
     pondéré par sévérité (esprit ADR-19).
  Sortie compacte (NF3) + `--json` ; tool MCP associé. Les arêtes que
  l'extraction rate (URL en config) se complètent via le manifeste K10
  (extension `rest:` du frontmatter, à spécifier le moment venu).
- **CA** :
  1. Fixture 3 services avec cycle REST A→B→C→A → cycle détecté, rapporté
     avec les sites (fichier:lignes) de chaque arête.
  2. Handler Kafka contenant un appel REST → signalé.
  3. Un site sur cycle + finding liveness K8 remonte en tête des hotspots.
  4. Appariement testé chemin littéral ↔ template ; non-appariement → arête
     absente, jamais d'erreur ni de fausse arête.
  5. Aucune table de graphe dans le schéma SQLite (dérivation pure à la
     requête).
- **Statut** : `src/cccf/graph.py` livré — `build_graph`/`paths_match`
  (appariement littéral↔template, best-effort, CA4), `find_cycles` (DFS,
  déduplication par ensemble d'arêtes), `find_outbound_calls_in_consumers`
  (CA2), `find_hotspots`/`rank_hotspots` (CA3) ; testés sur fixture 3
  services avec cycle A→B→C→A (CA1), aucune table graphe en base (CA5,
  ADR-27). `cccf graph`/tool MCP `graph` livrés (CLI + MCP), mais ne
  rapportent aujourd'hui que CA2 (`find_outbound_calls_in_consumers`) : CA1/
  CA3 (cycles, hotspots) demandent des endpoints de **plusieurs services**,
  donc K7 (fédération multi-dépôts, non livré) — `cycles`/`hotspots` sont
  vides dans la sortie réelle, avec une `note` explicite plutôt qu'un vide
  silencieux. L'algorithme lui-même (testé en isolation avec des endpoints
  multi-services construits à la main) est prêt à recevoir K7 sans
  modification.
