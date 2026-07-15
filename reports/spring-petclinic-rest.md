# Audit — spring-petclinic-rest

Préflight sur copie temporaire : Semgrep 1.169.0, `cccr` 0.1.0 et les cinq packs actifs. La copie a été indexée sans toucher au dépôt source ; sorties reproductibles : `/private/tmp/ccc-radar-audit/{preflight,raw}/spring-petclinic-rest.*`.

| Inventaire | HTTP production | Kafka | Mongo |
| --- | ---: | ---: | --- |
| `cccr` | 1 (`ANY /`) | 0 | non inventorié |
| lecture directe | 1 route Spring déclarée localement ; contrats HTTP hérités des interfaces non résolus | 0 | non observé |

Les contrôleurs portent principalement le seul préfixe `@RequestMapping("/api")` et implémentent des contrats API générés/externes : aucun verbe ni chemin de méthode n’est localement prouvable dans ces classes. Le seul endpoint local complet est `ANY /` dans `RootRestControllerV1.java:42`; il est présent dans les deux inventaires. Il n’y a donc pas de faux négatif confirmé sur une route HTTP résolue, ni d’arête HTTP/Kafka à former.

| Catégorie | Présents dans les deux | Seulement `cccr` | Seulement direct |
| --- | --- | --- | --- |
| HTTP | `ANY /` | — | — |
| Kafka / usage | — | — | — |
| Mongo collections/opérations | — | — | — |
| Arêtes | — | — | — |

Limite documentée : la résolution des annotations héritées depuis un contrat OpenAPI/généré est une amélioration P2 si les sources du contrat sont placées dans le périmètre d’indexation ; elle ne doit pas inventer de verbes à partir des implémentations.

## Kafka et Mongo

Le contrat `src/main/resources/openapi.yml` est identifié par `cccr modules`, mais aucun Kafka ou Mongo n’est observé. Les appels `findById`, `findAll` et `save` de `ClinicServiceImpl.java` sont des repositories JPA ; l’annotation `@Documented` de validation n’est pas une annotation Mongo. Les inventaires Kafka et Mongo restent donc vides des deux côtés.

![cccr](assets/spring-petclinic-rest-cccr.png)
![direct](assets/spring-petclinic-rest-direct.png)
