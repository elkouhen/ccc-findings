# Audit — booking-microservices-java-spring-boot

Préflight : `main` / `ea481c3`, état local préservé. Index historique v6 migré uniquement dans `/private/tmp/ccc-radar-audit`; packs actifs mais modèle d'embeddings absent. Semgrep 1.169.0, `cccr` 0.1.0.

Analyse directe : 15 routes HTTP sur Booking, Flight et Passenger ; Mongo `@Document`/repositories ; appel gRPC bloquant Booking → Flight et configuration RabbitMQ. RabbitMQ et gRPC sont hors périmètre HTTP/Kafka, donc ne sont pas des faux négatifs.

| Inventaire | REST | Kafka | Graphe |
| --- | ---: | ---: | --- |
| cccr historique | 15 | 1 | 4 services, 0 arête |
| direct | 15 | 0 Kafka confirmé | gRPC/RabbitMQ hors périmètre |

Diff : index obsolète et protocole Kafka non confirmé par le code direct ; réindexation requise après disponibilité du modèle. Sources : `/private/tmp/ccc-radar-audit/booking-microservices-java-spring-boot-endpoints.json`.

## Kafka et Mongo — rapprochement détaillé

| Catégorie | `cccr` réindexé | Analyse directe de production | Conclusion |
| --- | --- | --- | --- |
| Kafka | un `send` dynamique dans `buildingblocks/.../TransactionPipelineBehavior.java:40` | aucun `KafkaTemplate`, `ProducerRecord`, listener, poll, subscribe, Streams ou Cloud Stream confirmé | endpoint dynamique non rapprochable ; aucune arête Kafka inventée |
| Mongo collections | `bookings`; `aircrafts`, `airports`, `flights`, `seats`; `passengers` | mêmes collections via `@Document` dans Booking, Flight et Passenger | conforme |
| Mongo opérations | 15 appels détectés dans Flight/Passenger | `save` des read-models, p. ex. `CreateBookingMongoCommandHandler.java:29`, `CreatePassengerMongoCommandHandler.java:30` | couverture de méthodes disponible dans `modules`; pas encore un endpoint de graphe |

Les appels REST trouvés dans `buildingblocks/testbase` sont des fixtures et ne sont pas interprétés comme relations de production. RabbitMQ/AMQP (`RabbitmqConfiguration`) et gRPC (stub Flight appelé depuis Booking) restent explicitement hors périmètre HTTP/Kafka. Le support Mongo est utile pour l’inventaire de module, mais son rendu comparatif complet reste P2.

![cccr](assets/booking-microservices-java-spring-boot-cccr.png)
![direct](assets/booking-microservices-java-spring-boot-direct.png)
