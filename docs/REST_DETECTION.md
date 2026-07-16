# Détection REST et Clients OpenAPI Générés

## Fonctionnalités ajoutées

Deux nouvelles fonctionnalités de détection ont été ajoutées à ccc-radar :

### 1. Détection des classes @RestController

ccc-radar détecte maintenant automatiquement les classes Java annotées avec `@RestController` dans chaque module.

**Informations détectées :**
- Nom de la classe du contrôleur
- Chemin relatif du fichier source
- Nombre total de contrôleurs par module

**Exemple d'utilisation :**

```bash
# Lister les modules avec leurs contrôleurs REST
cccr modules list

# Voir les détails d'un module spécifique
cccr modules show my-service

# Exporter avec les informations de contrôleurs
cccr modules --json > modules.json
```

**Exemple de sortie :**

```text
[maven/library] user-service version=1.0.0 chemin=/services/user-service 
rest_controllers=2 
- UserController (src/main/java/com/example/controller/UserController.java)
- OrderController (src/main/java/com/example/controller/OrderController.java)
```

### 2. Détection des clients OpenAPI générés

ccc-radar détecte maintenant les clients REST générés par le plugin Maven `openapi-generator-maven-plugin`.

**Détection automatique :**
- Détection du plugin dans les fichiers `pom.xml`
- Analyse des répertoires `target/generated-sources/openapi/`
- Liste des fichiers clients générés avec leurs chemins relatifs

**Chemins analysés :**
- `target/generated-sources/openapi/`
- `target/generated-sources/openapi-mapstruct/`
- `target/generated-sources/openapi-nullable/`

**Exemple d'utilisation :**

```bash
# Voir les clients générés d'un module
cccr modules show api-client-service

# Format JSON pour l'intégration
cccr modules --json | jq '.[] | select(.openapi_generated_clients | length > 0)'
```

## Schéma de base de données

Le schéma de la base de données a été mis à jour vers la version 15 pour inclure ces nouvelles informations :

```sql
ALTER TABLE modules ADD COLUMN rest_controllers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE modules ADD COLUMN openapi_generated_clients TEXT NOT NULL DEFAULT '[]';
```

## Structure des données

### ModuleSummary (JSON)

```json
{
  "name": "user-service",
  "rest_controllers": [
    "UserController (src/main/java/com/example/controller/UserController.java)",
    "OrderController (src/main/java/com/example/controller/OrderController.java)"
  ],
  "openapi_generated_clients": [
    "target/generated-sources/openapi/ExternalApi.java",
    "target/generated-sources/openapi/ProductsApi.java"
  ]
}
```

### ModuleDetail (format texte étendu)

```
[maven/library] user-service
version=1.0.0
chemin=/services/user-service
démarre l'application=true
collections Mongo=user,order
opérations Mongo=15
opérations Kafka=3
points bloquants=0
OpenAPI=src/main/resources/openapi.yaml
Contrôleurs REST (2)=UserController (src/main/java/com/example/controller/UserController.java), OrderController (src/main/java/com/example/controller/OrderController.java)
Clients OpenAPI générés (2)=target/generated-sources/openapi/ExternalApi.java, target/generated-sources/openapi/ProductsApi.java
```

## Cas d'utilisation

### Architecture et documentation

1. **Inventaire d'architecture** : Identifier rapidement quels modules exposent des APIs REST
2. **Impact analysis** : Comprendre quels modules utilisent des clients générés vs des clients manuels
3. **Documentation** : Générer automatiquement la documentation des contrôleurs REST

### Migration et maintenance

1. **Détection de clients dupliqués** : Identifier les modules qui génèrent des clients pour les mêmes APIs
2. **Audit de licence** : Identifier l'utilisation de clients générés par openapi-generator
3. **Refactorisation** : Localiser tous les contrôleurs REST dans une architecture microservices

### Intégration CI/CD

1. **Validation d'architecture** : Vérifier que les nouveaux services suivent les patterns REST attendus
2. **Génération de rapports** : Exporter automatiquement les inventaires de contrôleurs
3. **Détection de drift** : Comparer les contrôleurs détectés avec la documentation attendue

## Tests

Les fonctionnalités sont couvertes par des tests unitaires dans `tests/test_rest_detection.py` :

- `test_has_rest_controllers_with_restcontroller_annotation`
- `test_has_rest_controllers_multiple_controllers`
- `test_has_rest_controllers_without_restcontroller`
- `test_has_openapi_generator_plugin_with_plugin`
- `test_has_openapi_generator_plugin_without_plugin`
- `test_detect_openapi_generated_clients_with_plugin`
- `test_detect_openapi_generated_clients_without_plugin`
- `test_detect_openapi_generated_clients_no_generated_files`
- `test_module_enrichment_includes_rest_controllers_and_generated_clients`
- `test_rest_controller_case_insensitive`

## Limitations

### Détection @RestController

- **Détection statique** : Analyse uniquement le code source présent
- **Spring MVC uniquement** : Détecte les annotations Spring standard, pas les frameworks custom
- **Fichiers Java uniquement** : Ne détecte pas les contrôleurs dans d'autres langages

### Détection openapi-generator

- **Maven uniquement** : La détection automatique du plugin fonctionne pour Maven
- **Chemins standard** : Analyse uniquement les répertoires générés standards
- **Plugins Gradle** : Non encore supporté (à venir)

## Migration depuis la version 14

Si vous avez une base de données existante avec le schéma version 14 :

```bash
# La migration est automatique au prochain indexage
cccr index

# Vérifier la version du schéma
sqlite3 .cccr/findings.db "SELECT value FROM meta WHERE key = 'schema_version';"
```

Les nouvelles colonnes sont ajoutées automatiquement avec des valeurs par défaut vides.

## Exemples d'utilisation avancée

### Filtrer les modules avec contrôleurs REST

```bash
cccr modules --json | jq '.[] | select(.rest_controllers | length > 0) | .name'
```

### Trouver les modules utilisant openapi-generator

```bash
cccr modules --json | jq '.[] | select(.openapi_generated_clients | length > 0) | {name, openapi_generated_clients}'
```

### Compter les contrôleurs par module

```bash
cccr modules --json | jq '[.[] | {name, count: (.rest_controllers | length)}]'
```

### Générer un rapport d'architecture

```bash
cccr export microservices --html architecture.html
```

Le rapport HTML inclura maintenant les informations sur les contrôleurs REST et les clients générés.

## Implémentation technique

### Fichiers modifiés

- `src/ccc_radar/modules.py` : Ajout de `_has_rest_controllers()`
- `src/ccc_radar/maven.py` : Ajout de `_has_openapi_generator_plugin()` et `detect_openapi_generated_clients()`
- `src/ccc_radar/store.py` : Migration vers le schéma version 15
- `src/ccc_radar/render.py` : Mise à jour des fonctions de rendu
- `tests/test_rest_detection.py` : Tests unitaires complets

### Patterns de détection

**@RestController :**
```java
// Forme simple
@RestController
public class UserController { }

// Forme pleinement qualifiée
@org.springframework.web.bind.annotation.RestController
public class OrderController { }
```

**openapi-generator-maven-plugin :**
```xml
<plugin>
    <groupId>org.openapitools</groupId>
    <artifactId>openapi-generator-maven-plugin</artifactId>
    <!-- ... -->
</plugin>
```

## Version et compatibilité

- **Version du schéma** : 15
- **Version minimale de ccc-radar** : 0.1.0+
- **Compatibilité** : Migration automatique depuis la version 14
- **Performance** : Impact négligeable sur les performances d'indexation

## Support et contributeurs

Pour toute question ou problème :
- Issues GitHub : [ccc-radar/issues]
- Documentation : `docs/REST_DETECTION.md`
- Tests : `tests/test_rest_detection.py`

---

**Ajouté dans la version 0.1.0** - Schéma version 15