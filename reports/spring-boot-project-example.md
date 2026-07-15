# Audit — spring-boot-project-example

Préflight et indexation exécutés sur `/private/tmp/ccc-radar-audit/copies/spring-boot-project-example` : Semgrep 1.169.0, `cccr` 0.1.0, packs REST/Kafka/liveness/kafka-security actifs. Sorties brutes : `/private/tmp/ccc-radar-audit/{preflight,raw}/spring-boot-project-example.*`.

| Inventaire | HTTP servis | Kafka | Graphe |
| --- | ---: | ---: | --- |
| `cccr` | 7 | 0 | aucune arête |
| lecture directe | 7 | 0 | aucune arête |

Les sept routes Spring sont présentes dans les deux inventaires : `POST /customer`, `GET /customer`, `GET /customer/{id}`, `PATCH /customer/{id}`, `PUT /customer/{id}`, `DELETE /customer/{id}` (`CustomerController.java:48–167`) et `GET /refCustomer` (`CustomerRefController.java:45`). Aucun client HTTP, producer ou consumer Kafka de production n’a été trouvé ; l’absence d’arête n’est pas une anomalie.

Mongo est hors inventaire courant de `cccr`, mais la lecture directe confirme les collections `customer` (`CustomerEntity.java:22`) et `apiLog` (`ApiLogEntity.java:17`), les repositories Mongo associés, et les opérations `findAll`, `findById` et `save` dans `CustomerServiceImpl.java:61,76,96,122,141` ainsi que `ApiLogAspect.java:96`. Ceci est un manque de couverture P2, pas un écart HTTP/Kafka.

`cccr modules` réindexé expose désormais les deux collections (`customer`, `apiLog`) ; il ne matérialise toutefois pas encore les opérations de repository (compteur nul). Il s’agit donc d’un écart Mongo de précision à conserver dans le backlog, sans effet sur le graphe HTTP/Kafka. Aucun usage Kafka de production n’est observé ni inventorié.

| Catégorie | Présents dans les deux | Seulement `cccr` | Seulement direct |
| --- | --- | --- | --- |
| HTTP | 7 routes ci-dessus | — | — |
| Kafka / usage | — | — | — |
| Mongo | — | — | collections et opérations documentées ci-dessus |
| Arêtes | — | — | — |

![cccr](assets/spring-boot-project-example-cccr.png)
![direct](assets/spring-boot-project-example-direct.png)
