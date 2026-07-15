# Backlog d'amélioration — boucle d'audit des exemples

Établi le 15 juillet 2026 après analyse croisée de `cccr` et du code source de :

- `spring-petclinic-microservices`
- `sample-spring-kafka-microservices`
- `microservices-kafka-mq`
- `booking-microservices-java-spring-boot`
- `fully-completed-microservices-Java-Springboot`

Le répertoire `reports/` a été supprimé comme demandé. Les dépôts d'exemple et
leurs index existants n'ont pas été modifiés ; les lectures nécessitant une
migration ont été faites sur des copies temporaires.

## Priorité P0 — rendre l'indexation exécutable et les audits réellement non mutatifs

- [x] **P0 — Accepter les chemins de répertoire des packs dans `cccr doctor`.** Les configurations produites par `cccr init` référencent `.cccr/rules/rest` (sans slash terminal) ; le préflight les signalait à tort comme absents et pouvait empêcher une indexation pourtant opérationnelle. Corrigé dans `src/ccc_radar/doctor.py`, avec régression `tests/test_doctor_audit.py::test_doctor_accepts_pack_directory_paths`.
- [ ] **P0 — Détecter les microservices à partir de l'artefact déployable.** Ne retenir qu'un module Maven/Gradle applicatif doté d'un artefact effectif, et exclure les répertoires conteneurs (`services`, `src`) ainsi que les bibliothèques communes (`buildingblocks`). Critère d'acceptation : Booking ne retourne plus `src`/`buildingblocks`, Fully Completed ne retourne plus `services`, et les noms correspondent aux artifacts.
- [x] **P0 — Isoler les fichiers d'état Semgrep dans un répertoire configurable et inscriptible.** `scanner.py` transmet désormais `SEMGREP_LOG_FILE` (surcharge `CCCR_SEMGREP_LOG_FILE`), désactive le contrôle de version et les métriques. Régression couverte par `tests/test_scanner.py::test_invoke_semgrep_uses_private_writable_log` ; les 8 tests scanner passent.
- [ ] **P0 — Ouvrir les commandes de lecture avec un `Store` en lecture seule.** `endpoints` et `graph` ouvrent aujourd'hui la base en écriture et lancent une migration de schéma. Sur les trois index non migrés (`sample-spring-kafka-microservices`, Booking et fully-completed), cela échoue par `attempt to write a readonly database`. Les commandes de consultation et les outils MCP associés doivent utiliser `Store(..., readonly=True)` et retourner un diagnostic de compatibilité sans mutation.
- [ ] **P0 — Définir et tester la stratégie de compatibilité des index.** Une base v6/v7 ne peut pas être lue par le binaire courant (schéma v11) sans réindexation. Ajouter un test d'acceptation avec une base historique en lecture seule et un message qui précise : consultation compatible, ou version attendue et commande de régénération.

## Priorité P1 — fiabiliser l'inventaire et le graphe HTTP/Kafka

- [x] **P1 — Inventorier les opérations d'un contrat OpenAPI local.**
  `spring-petclinic-rest` implémente des interfaces générées : les contrôleurs
  ne portent pas les verbes des routes, mais `src/main/resources/openapi.yml`
  est la preuve de production. Corrigé dans `src/ccc_radar/scanner.py` avec
  `tests/test_rest_endpoints.py::test_openapi_contract_operations_are_inferred`.
  Critère vérifié : après réindexation, les 37 opérations contractuelles et la
  route Spring `ANY /` sont présentes avec fichier et ligne ; aucune arête n'est
  inventée.

- [ ] **P1 — Inventorier les collections Mongo implicites.** `fully-completed-microservices-Java-Springboot` emploie `@Document` sans `collection` dans Customer et Notification ; l'analyse directe les confirme, tandis que `cccr modules` retourne une liste vide. Fichiers pressentis : `src/ccc_radar/modules.py`, `tests/test_modules.py`. Critère d'acceptation : une annotation `@Document` sans argument produit une collection explicitement marquée comme issue de la convention Spring, avec fichier et ligne de preuve.
- [ ] **P1 — Résoudre les appels et topics configurés.** Couvrir les propriétés, constantes et configurations multi-modules pour les clients HTTP et topics Kafka, tout en conservant l'indication dynamique lorsque la résolution échoue. Les appels métier Booking doivent devenir des arêtes lorsque la cible est résoluble, sans relier les appels de test à une API de production.
- [ ] **P1 — Réindexer les cinq exemples dès que Semgrep est exécutable, puis produire le diff automatique contre l'inventaire direct.** Les anciennes bases signalent explicitement un inventaire obsolète pour `microservices-kafka-mq` (v7), `sample-spring-kafka-microservices` (v7) et `fully-completed-microservices-Java-Springboot` (v6). Sans cette étape, les écarts ne peuvent pas être attribués de manière fiable à l'analyseur.
- [ ] **P1 — Ajouter des fixtures de non-régression Kafka Streams.** `sample-spring-kafka-microservices` emploie à la fois `@KafkaListener`, `KafkaTemplate.send`, `builder.stream(...)` et `.to(...)`. L'index historique trouve 5 producteurs et 5 consommateurs Kafka, dont les topics `orders`, `payment-orders` et `stock-orders`. Conserver ce scénario complet dans une fixture e2e avec attentes sur les arêtes producteur → topic → consommateur.
- [ ] **P1 — Tester les routes HTTP avec préfixe de classe, routes génériques et appels sortants.** Petclinic contient des `@RequestMapping` de classe et des `@GetMapping`/`@PostMapping`/`@PutMapping`; l'index existant recense 20 routes servies et 10 appels REST. Ajouter un oracle direct qui vérifie la fusion des préfixes et exclut les routes génériques de passerelle (`/**`) lorsqu'elles ne permettent pas d'établir une arête précise.
- [ ] **P1 — Conserver les routes Gateway spécifiques dans le graphe.** Représenter le préfixe `Path` et les transformations de route au lieu de réduire l'arête à `ANY /**`. Critère d'acceptation : les quatre relations Petclinic affichent leur préfixe public et leur cible `lb://`.
- [ ] **P1 — Corriger la représentation des relations dans la sortie JSON et vérifier son contrat.** Les diagrammes draw.io temporaires sont générés, mais le consommateur JSON doit s'appuyer sur `from_node`/`to_node`; ajouter des tests de contrat et documenter ces champs afin d'éviter les intégrations qui cherchent `from`/`to`.

## Priorité P2 — élargir la couverture de protocoles et la qualité de rapport

- [ ] **P2 — Rapprocher les opérations Mongo des repositories injectés.** `spring-boot-project-example` expose `customer` et `apiLog`, mais les appels `findAll`, `findById` et `save` ne sont pas encore reliés aux receivers Mongo dans `cccr modules`. Fichiers pressentis : `src/ccc_radar/modules.py`, `tests/test_modules.py`. Critère d'acceptation : les appels sur un champ typé `MongoRepository` apparaissent avec opération, fichier, ligne et collection lorsque celle-ci est résoluble.
- [ ] **P2 — Ajouter RabbitMQ/AMQP.** Booking emploie `RabbitmqConfiguration` et des échanges/queues : son index historique ne rapporte qu'un producteur Kafka et aucune arête, alors que le code contient une messagerie RabbitMQ structurante. Introduire des endpoints et arêtes AMQP ou annoncer explicitement ce protocole comme hors périmètre.
- [ ] **P2 — Ajouter gRPC.** Booking utilise des stubs gRPC bloquants (par exemple l'appel de réservation vers Flight). Le graphe HTTP/Kafka ne peut pas représenter ces dépendances synchrones ; modéliser `grpc_call`/`grpc_serve` et les intégrer aux signaux de blocage.
- [ ] **P2 — Distinguer le code de production des tests dans l'analyse directe et les règles.** `microservices-kafka-mq` contient un `@KafkaListener` de test en plus du consommateur de production. Les rapports doivent exclure ces signaux par défaut et permettre de les inclure explicitement.
- [ ] **P2 — Régénérer les rapports et exports draw.io une fois la boucle P0/P1 verte.** Créer un rapport par dépôt avec le tableau de diff, les raisons d'écart et une image exportée du diagramme. Ne pas recréer `reports/` avant confirmation si sa suppression devait être définitive.
- [ ] **P2 — Rendre le diagramme direct reproductible.** Produire automatiquement le second diagramme Draw.io depuis l'inventaire direct, avec un diff calculé plutôt qu'un rapprochement manuel.

## Observations de base

| Dépôt | Inventaire `cccr` existant | Signaux directs notables |
| --- | --- | --- |
| spring-petclinic-microservices | 30 endpoints REST (20 serveurs, 10 appels), 10 arêtes | mappings Spring et clients REST ; pas de Kafka détecté |
| sample-spring-kafka-microservices | 10 Kafka (5 producteurs, 5 consommateurs), 3 REST, 8 arêtes | listeners, `KafkaTemplate` et Kafka Streams sur `orders`, `payment-orders`, `stock-orders` |
| microservices-kafka-mq | 2 Kafka (1/1), 13 REST, 1 arête | producteur et consommateur `order`, plus un listener de test |
| booking-microservices-java-spring-boot | 1 Kafka, 15 REST, 0 arête | RabbitMQ et gRPC présents ; couverture protocolaire insuffisante |
| fully-completed-microservices-Java-Springboot | 4 Kafka (2/2), 18 REST, 5 arêtes | flux `order-topic` et `payment-topic` ; inventaire obsolète |
