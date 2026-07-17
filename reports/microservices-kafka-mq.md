# microservices-kafka-mq — rapport d'audit `cccr`

Boucle d'amélioration du 17 juillet 2026. Périmètre : Java/Spring, HTTP REST,
Kafka. Les protocoles hors périmètre (gRPC, RabbitMQ/AMQP, messagerie
propriétaire) sont signalés séparément ; leur absence du graphe HTTP/Kafka n'est
pas un faux négatif.

## Étape 0 — Préflight et traçabilité

- **Dépôt** : `~/examples/microservices-kafka-mq` (multi-module Maven,
  Spring Boot **2.1.1.RELEASE**, Java 8).
- **Commit/branche** : `5a597e2382013e6faeb85ec4f417bf4eed838088` (`master`,
  branche à jour avec `origin/master`).
- **État Git** : propre ; seuls `.cccf/`, `.cccr/`, `.gitignore`, `graph.drawio`
  sont non suivis (index local et artefacts d'analyse, hors commits).
- **Versions** : `cccr` 0.1.0, Semgrep 1.169.0, Python 3.13 (`.venv` du dépôt
  `ccc-radar`).
- **`cccr doctor`** : tous les prérequis verts — CLI, Semgrep, `ccc` (optionnel),
  configuration `.cccr/config.yml`, packs **REST / Kafka / liveness /
  Kafka security** actifs, modèle d'embeddings local, index présent.
- **Régénération** : `rm -rf .cccr && cccr init && cccr index --full --semgrep`
  (régénération complète autorisée dans le dépôt exemple, sans toucher au code ni
  aux fichiers de build). 68 fichiers scannés, 7 findings de sécurité, **21
  endpoints** (19 REST + 2 Kafka).

> **Reproductibilité** — l'inventaire `cccr` dépend du drapeau `--semgrep`. Par
> défaut, `cccr index` **n'exécute pas Semgrep** et omet alors les mappings
> Spring MVC method-level (`@GetMapping`, `@PostMapping`, `@RequestMapping(method=)`)
> — dont `POST/GET /api/order` du `AppRestController`. Pour l'audit HTTP complet,
> il faut `cccr index --full --semgrep`. C'est l'option retenue ici. Ce point est
> repris au backlog (P2).

Sorties brutes : `reports/raw/kafka-mq-{microservices,modules,apis,topics,mongodb,graph,coverage}.json`
et `kafka-mq-audit.txt`.

## Étape 2 — Analyse directe (référence, hors `cccr`)

Lecture ciblée du code de production (`src/test` exclu). Dépôt trompeur : le nom
« kafka-mq » évoque une messagerie propriétaire, mais le code est **Kafka pur**.
La mention RabbitMQ/JMS dans le `README.md` n'est qu'une comparaison en prose.

### Services (2)
- **microservice-order** — `spring.application.name=order`, port 8080,
  `OrderApp` `@SpringBootApplication`. Dépendances notables : `spring-boot-starter-data-jpa`,
  **`spring-boot-starter-data-rest`**, `spring-kafka`, `spring-boot-starter-security`,
  springfox-swagger2.
- **microservice-invoicing** — `spring.application.name=invoicing`, port 8081,
  `InvoiceApp` `@SpringBootApplication`. Dépendances : `spring-boot-starter-data-jpa`,
  `spring-boot-starter-web`, `spring-kafka` (**pas** de data-rest).

### HTTP servi — Spring MVC explicite
| # | Service | Méthode | Chemin | Preuve (fichier:ligne) |
|---|---------|---------|--------|------------------------|
| H1 | order | POST | `/api/order` | `controller/AppRestController.java:53` |
| H2 | order | GET | `/api/order` | `controller/AppRestController.java:69` |
| H3 | invoicing | ANY | `/` | `web/InvoiceController.java:27` (`@RequestMapping("/")` sans `method` ⇒ toutes méthodes) |
| H4 | invoicing | GET | `/{id}` | `web/InvoiceController.java:22` |

### HTTP servi — Spring Data REST (auto-généré, base `/`, order seul)
`spring-boot-starter-data-rest` est présent côté order ; `SpringRestDataConfig`
ne fixe ni `baseUri` ni d'exposition globale ⇒ base `/`. Spring Data REST expose
donc tout repository sans `exported=false` :
- **OrderRepository** `@RepositoryRestResource(path="order")` → `/order`, `/order/{id}`,
  `/order/search/lastUpdate` (CRUD + recherche).
- **UserRepository** (`JpaRepository<User,Integer>`, **sans** annotation) → `/users`,
  `/users/{id}`, etc. (exposition par défaut, probablement involontaire — fuit le
  contenu de la table utilisateurs).
- `CustomerRepository`, `ItemRepository` : `exported=false` → non exposés.

### HTTP appelé (clients)
**Aucun.** Pas de `RestTemplate`/`WebClient`/OpenFeign en production. La dépendance
`httpclient` (invoicing) n'est pas utilisée dans le code de production. ⇒ **Aucune
arête HTTP inter-services.**

### Kafka
| # | Rôle | Topic | Framework | Service | Preuve (fichier:ligne) |
|---|------|-------|-----------|---------|------------------------|
| K1 | producteur | `order` | `KafkaTemplate.send` (JsonSerializer) | order | `logic/OrderService.java:40` |
| K2 | consommateur | `order` | `@KafkaListener` (InvoiceDeserializer) | invoicing | `events/OrderKafkaListener.java:23` |

Aucun Kafka Streams, Spring Cloud Stream, `poll`/`subscribe` natif, `ProducerRecord`.
**Arête résolue** : `order --produit--> topic 'order' --consommé par--> invoicing`.

### Mongo
**Aucun.** Repositories JPA relationnels (`PagingAndSortingRepository`/`JpaRepository`,
entités `@Entity`/`@Table`), base MySQL configurée. Aucun `@Document`,
`MongoRepository`, `MongoTemplate`.

### Hors périmètre
**Aucun protocole dans le code.** Pas de gRPC, AMQP/RabbitMQ, JMS, WebSocket.

### Exclusion des tests (vérifiée)
Les listeners/producteurs de test (`kafka/KafkaListenerBean.java`, `OrderKafkaTest`,
`InvoiceKafkaTest`) sont correctement **exclus** de l'inventaire de production.

## Étape 1 — Inventaire `cccr` (après correction, `--full --semgrep`)

`cccr microservices` détecte **2 microservices** (`microservice-order`,
`microservice-invoicing`, `starts_application=true`, technologies Java/Spring Boot/Kafka).
`cccr modules` liste en plus l'agrégateur `microservices-kafka` (`kind=aggregator`).

Endpoints REST servis (19) + Kafka (2) = 21. Détail REST avec preuves :

| Service | Endpoint | Framework | Preuve (fichier:ligne) |
|---------|----------|-----------|------------------------|
| invoicing | `ANY /` | spring | `web/InvoiceController.java:28` |
| invoicing | `GET /{id}` | spring | `web/InvoiceController.java:22` |
| invoicing | `GET /actuator/**` | spring-actuator | `application.properties:1` |
| order | `POST /api/order` | spring | `controller/AppRestController.java:53` |
| order | `GET /api/order` | spring | `controller/AppRestController.java:69` |
| order | `GET /order` · `POST /order` · `GET/PUT/PATCH/DELETE /order/{id}` | spring-data-rest | `logic/OrderRepository.java:9` |
| order | `GET /users` · `POST /users` · `GET/PUT/PATCH/DELETE /users/{id}` | spring-data-rest | `repository/UserRepository.java:10` |
| order | `GET /swagger-ui.html` | swagger-ui | `config/SwaggerConfig.java:27` |
| order | `GET /actuator/**` | spring-actuator | `application.properties:1` |

Kafka : topic `order`, producteur `microservice-order` (type `Order`), consommateur
`microservice-invoicing` (type `Invoice`). `cccr analyze coverage` : 21 intégrations,
**30 relations toutes haute confiance**, **rien de non résolu**. `cccr export microservices`
produit l'arête `order → topic 'order' → invoicing` avec sites précis
(`OrderService.java:39-40`, `OrderKafkaListener.java:23-28`).

**Audit** : `cccr analyze audit` signale — à juste titre — un **contrat de message
Kafka potentiellement incompatible** : *« `order` publie Order mais consomme Invoice »*
(confiance medium). C'est un vrai smell (le producteur sérialise des `Order`, le
consommateur désérialise en `Invoice` via `InvoiceDeserializer`).

## Étape 3 — Comparaison structurée et note

### 1. Services/modules
| Présents dans les deux | Seulement `cccr` | Seulement analyse directe |
|---|---|---|
| microservice-order, microservice-invoicing | `microservices-kafka` (agrégateur, à juste titre) | — |

`cccr` classe order/invoicing `kind=library` dans `modules` mais `kind=microservice`
dans `microservices` (cohérent : seuls les modules démarrant une app remontent
comme services). Pas d'écart fonctionnel.

### 2. HTTP
| Endpoint (direct) | `cccr` | Cause éventuelle d'écart |
|---|---|---|
| `POST /api/order`, `GET /api/order` | ✅ | — |
| `ANY /`, `GET /{id}` (invoicing) | ✅ | `cccr` restitue `ANY /` (plus exact que « GET » : `@RequestMapping("/")` sans méthode) |
| SDR `/order` (CRUD) | ✅ | — |
| **SDR `/users` (CRUD)** | ✅ **(après correction)** | **Faux négatif pré-fix** : `UserRepository` n'a pas de `@RepositoryRestResource(path=…)`, donc aucun littéral de chemin. Corrigé (path dérivé par pluralisation, gâté sur la dépendance data-rest). |
| SDR `/order/search/lastUpdate` | ❌ | Ressource de recherche SDR non couverte (P2). |
| `GET /actuator/**`, `GET /swagger-ui.html` | ✅ (tagués `spring-actuator`/`swagger-ui`) | Endpoints framework réels, mais mélangés aux APIs métier dans `http_apis_exposed` (P2 ergonomie). |

Aucun endpoint inventé. Aucun faux positif métier.

### 3. Kafka (endpoints + usage méthode)
| Élément (direct) | `cccr` | Écart |
|---|---|---|
| Producteur `order` — `KafkaTemplate.send` (`OrderService.java:40`) | ✅ `OrderService.java:39-40` | — |
| Consommateur `order` — `@KafkaListener` (`OrderKafkaListener.java:23`) | ✅ `OrderKafkaListener.java:23-28` | — |
| Types message `Order` (pub) / `Invoice` (cons) | ✅ | — |
| Arête `order → 'order' → invoicing` | ✅ résolue, haute confiance | — |

Aucun écart Kafka. Listener de test (`KafkaListenerBean`) correctement absent.

### 4. Mongo
| Élément (direct) | `cccr` | Écart |
|---|---|---|
| Aucune collection, aucune opération | ✅ `cccr mongodb` vide | — (aucun faux positif) |

### 5. Arêtes
| Arête (direct) | `cccr` | Écart |
|---|---|---|
| Kafka `order → topic 'order' → invoicing` | ✅ | — |
| HTTP inter-services | aucune (aucun client HTTP) | ✅ aucune |

### 6. Hors périmètre
Aucun protocole constaté dans le code. Rien à signaler.

### Note `cccr` : **4,5 / 5**

Justification : couverture **quasi complète** du périmètre annoncé.
- Services 2/2, Kafka producteur/consommateur/topic/arête **parfait**, types de
  message corrects, **audit pertinent** sur l'incompatibilité Order/Invoice.
- HTTP : les 4 endpoints Spring MVC explicites détectés, **plus** le SDR annoté
  (`/order`) **et**, après correction, le SDR par défaut (`/users`).
- Mongo : aucun faux positif (correctement vide).
- Arêtes : Kafka résolue avec sites précis ; aucune arête HTTP inventée.

Demi-point retiré pour : (a) ressources de recherche SDR (`/order/search/lastUpdate`)
non couvertes ; (b) endpoints framework (actuator, swagger) mêlés aux APIs métier
dans la vue de synthèse ; (c) index par défaut (sans `--semgrep`) qui omet les
mappings Spring MVC method-level. Aucune pénalité pour les éléments dynamiques ou
hors périmètre.

## Diagrammes

- Inventaire direct (référence) : `reports/assets/microservices-kafka-mq-direct.drawio`
  (export `…-direct.png`).
- Inventaire `cccr` (post-fix `/users`) : `reports/assets/microservices-kafka-mq-cccr.drawio`
  (export `…-cccr.png`).

Les deux diagrammes (`scripts/gen_kafka_mq_diagrams.py`) représentent un nœud par
service et par topic Kafka, une arête Kafka `order → 'order' → invoicing`, et
mentionnent l'absence d'arête HTTP.

## Limites et axes d'amélioration (déportés au backlog)

- **P2 — SDR par défaut** (corrigé cette boucle) : `UserRepository` exposait `/users`
  sans annotation. Correction : `src/ccc_radar/scanner.py::_infer_spring_data_rest_endpoints`
  + gate classpath `_module_has_spring_data_rest`. Régressions :
  `tests/test_rest_endpoints.py` (3 nouveaux tests).
- **P2 — Ressources de recherche SDR** non couvertes (`/<base>/search/<méthode>`).
- **P2 — Séparation framework/métier** dans `http_apis_exposed` (actuator, swagger).
- **P2 — Index sans Semgrep** : les mappings Spring MVC method-level ne sont détectés
  que par le pack Semgrep `rest`. Le détecteur local ne fusionne pas le préfixe de
  classe `@RequestMapping` pour ces méthodes (limitation documentée
  `scanner.py:440-449`).
- **Prérequis (non régression du code)** : 2 tests `parse_semgrep_kafka_endpoint`
  échouent sur le baseline `d342d7b` (antérieur à cette boucle) ; à traiter
  séparément.
