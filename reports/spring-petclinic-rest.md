# Audit — spring-petclinic-rest

Commit analysé : `c7b5f5e9e90af2e5b94a40dd77b2a53dc33f67bd` (`master`, seul état non suivi : `.cccr/`). Préflight : `cccr version` 0.1.0, packs `default`, `rest`, `kafka`, `liveness` et `kafka-security` actifs ; `cccr doctor --json` est vert. Semgrep autonome échoue dans ce sandbox en tentant d'écrire `~/.semgrep/semgrep.log`, mais `cccr` lui fournit `SEMGREP_LOG_FILE` privé et l'indexation complète a réussi (125 fichiers, 7 findings).

Les sorties JSON fraîches sont dans [`reports/raw`](raw/) : `petclinic-{microservices,modules,endpoints,graph,audit}.json`. Après suppression/recréation autorisée de `.cccr`, le premier index n'extrayait que `ANY /`; l'analyse directe avait été terminée avant cette consultation : les implémentations Java réalisent des interfaces générées et le contrat de production `src/main/resources/openapi.yml` porte les verbes et chemins. Ce faux négatif a été corrigé puis l'exemple a été réindexé.

| Inventaire final | Services | HTTP servis production | Kafka | Mongo | Arêtes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `cccr` | 1 | 38 | 0 | 0 (JPA, pas Mongo) | 0 |
| lecture directe | 1 | 38 | 0 | 0 | 0 |

## Inventaire et diff

| Catégorie | Présents dans les deux | Seulement `cccr` | Seulement direct |
| --- | --- | --- | --- |
| Service/module | `spring-petclinic-rest` — Maven, `PetClinicApplication` démarre Spring | — | — |
| HTTP | `ANY /` (`RootRestControllerV1.java:42`) et 37 opérations OpenAPI (`openapi.yml`, lignes 34–1848) | — | — |
| Kafka et usage | aucun producer, consumer, listener, poll, Streams ou Cloud Stream | — | — |
| Mongo collections/opérations | aucune ; les `findById`/`findAll`/`save` sont des repositories JPA | — | — |
| Arêtes HTTP/Kafka | aucune : pas de client HTTP ni de Kafka détectable | — | — |

Les 37 opérations contractuelles ont les clés normalisées `MÉTHODE chemin` et une preuve ligne par ligne dans `openapi.yml` (par exemple `GET /oops:34`, `POST /owners:66`, `DELETE /vets/{vetId}:1794`). Le préfixe `/api` porté par les contrôleurs est un préfixe de déploiement de leurs implémentations ; le contrat décrit les chemins d'API, donc aucun rapprochement artificiel n'a été fait. Il n'y a ni protocole complémentaire observé ni route dynamique non résolue.

Note `cccr` finale : **5/5**. Avant correctif : 1/38 routes (faux négatif P1 reproductible). Après le correctif OpenAPI et réindexation : couverture complète des services, HTTP, Kafka, Mongo et arêtes applicables.

![Graphe cccr](assets/spring-petclinic-rest-cccr.png)

![Graphe direct](assets/spring-petclinic-rest-direct.png)
