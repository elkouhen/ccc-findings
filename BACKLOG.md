# Backlog issu des audits d’exemples

## P0 — Découverte de microservices fondée sur l’artifact déployable

**Fichiers pressentis :** `src/ccc_radar/workspace.py`, `src/ccc_radar/maven.py`, `src/ccc_radar/gradle.py`, tests workspace.

Ne retenir comme microservice qu’un module Maven/Gradle applicatif avec artifact effectif. Exclure les répertoires conteneurs (`services`, `src`) et bibliothèques communes (`buildingblocks`). Confirmé par Booking et Fully Completed.

**CA :** Booking ne retourne plus `src`/`buildingblocks`; Fully Completed ne retourne plus `services`; les noms retournés correspondent aux artifacts.

## P1 — Résolution des appels et topics configurés

**Fichiers pressentis :** `scanner.py`, règles REST/Kafka du skill, tests scanner.

Résoudre les clients HTTP et topics déclarés par propriétés, constantes ou configuration multi-modules, en préservant l’indication dynamique si la résolution échoue.

**CA :** les appels métier de Booking créent des arêtes quand la cible est résoluble; aucun appel de test n’est relié à une API de production.

## P1 — Routes Gateway spécifiques dans le graphe

**Fichiers pressentis :** `scanner.py`, `graph.py`, tests graph.

Conserver le préfixe `Path` et la route transformée par les filtres Gateway, plutôt que seulement `ANY /**`, afin que l’étiquette de relation reste explicite.

**CA :** les quatre relations Petclinic affichent leur préfixe public et leur cible `lb://`.

## P2 — Marquage explicite des endpoints de test

**Fichiers pressentis :** `scanner.py`, `indexer.py`, `models.py`, rendu.

Exclure par défaut `src/test` de l’inventaire d’architecture ou ajouter `source: test` et un filtre CLI.

**CA :** les tests Kafka/REST de microservices-kafka-mq et Sample Kafka ne gonflent pas le graphe production.

## P2 — Diagramme direct reproductible

**Fichiers pressentis :** nouveau module d’analyse directe/outillage de rapport.

Produire automatiquement un second Draw.io à partir de l’inventaire direct, au lieu d’un rapprochement manuel documenté.

**CA :** chaque rapport contient deux diagrammes comparables et leur diff est calculé.
