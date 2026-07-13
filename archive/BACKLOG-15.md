# Backlog 15 — Support Gradle et exclusion du code de test (2026-07-13)

> Objectif : retour utilisateur direct sur un audit réel
> (`eventuate-tram-examples-customers-and-orders`, monorepo Gradle
> multi-modules) — deux trous constatés en le pointant avec `cccf graph
> --drawio` :
> 1. le graphe restait vide malgré un index non vide : l'attribution de
>    module (BACKLOG-13 M1) et la fédération (BACKLOG-11 A2) sont
>    Maven-only (`pom.xml`), et ce repo n'a aucun `pom.xml` (100% Gradle) ;
> 2. un appel REST dans un fichier de test (`ApiGatewayComponentTest.java`)
>    ressortait comme site d'interaction réel dans l'inventaire endpoints.
>
> Convention : une tâche = un commit (`H<n>: <titre>`), DoD globale
> inchangée (voir `AGENT.md`).

## Tâches

### [x] H1 — Détection de service Gradle par classe `main()` Spring Boot
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/gradle.py` (nouveau), `src/cccf/scanner.py`,
  `tests/test_gradle.py` (nouveau), `docs/ADR.md`, `docs/SPEC-TECH.md`
- **Description** : contrairement à Maven, un `build.gradle` n'a pas de
  marqueur universel équivalent à `spring-boot-maven-plugin` (plugins de
  convention custom via `buildSrc`, ex. `ServicePlugin` dans le repo
  eventuate — masque le plugin Spring Boot standard). Signal choisi,
  explicitement demandé par l'utilisateur : une classe Java portant un
  `main()` qui appelle `SpringApplication.run(...)` identifie un service
  déployable, indépendamment du build tool. `gradle.gradle_service_for_path`
  scanne le repo une fois (caché par process) pour collecter le premier
  segment de chemin (répertoire de premier niveau) de chaque classe ainsi
  identifiée ; tout fichier sous ce même premier segment (sous-projets
  Gradle `-domain`/`-restapi`/`-persistence`/... d'un même microservice
  réparti sur plusieurs `build.gradle`) est rattaché au même nom de
  service. `scanner._module_for_path` essaie d'abord `maven.
  module_name_for_path` (inchangé — choix explicite de l'utilisateur de
  garder la détection `pom.xml`/`spring-boot-maven-plugin` pour Maven), et
  ne retombe sur la détection Gradle que si aucun `pom.xml` n'est trouvé.
- **CA** :
  1. Un microservice Gradle réparti sur plusieurs sous-projets
     (`<service>/<service>-domain`, `<service>-restapi`, ...
     `<service>-main` avec la classe `main()`) voit tous ses fichiers
     attribués au même module, y compris les sous-projets sans classe
     `main()` propre.
  2. Une classe avec un `main()` qui ne démarre pas Spring
     (`SpringApplication.run` absent) n'est jamais prise pour un service.
  3. Un répertoire de premier niveau sans classe `main()` Spring Boot nulle
     part dans son arbre (tests end-to-end, scripts de déploiement) reste
     sans module (`None`), comme aujourd'hui pour un fichier hors
     arborescence Maven.
  4. Un repo Maven (au moins un `pom.xml`) n'est jamais affecté : la
     détection Gradle n'est jamais essayée en premier.
- **Statut** : livré. `gradle.py` (nouveau) : `_is_spring_boot_main_class`
  (regex `static void main(` + `SpringApplication.run(`, même esprit
  qu'ADR-26 — pas d'AST), `_service_roots` (parcours `rglob("*.java")` du
  repo, caché par `repo_root`), `gradle_service_for_path`.
  `scanner._module_for_path` (nouveau, factorise les deux appels findings/
  endpoints) : `module_name_for_path(...) or gradle_service_for_path(...)`.
  Testé dans `tests/test_gradle.py` (4 tests : regroupement multi-
  sous-projets, `main()` sans Spring ignoré, répertoire sans service,
  fichier à la racine). Voir ADR-33.

### [x] H2 — Exclusion du code de test de tout le scan (findings + endpoints)
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/indexer.py`,
  `tests/fixtures/test_source_exclusion_repo/` (nouveau),
  `tests/test_indexer.py`, `docs/ADR.md`, `docs/SPEC-TECH.md`,
  `docs/SPEC-FONC.md`
- **Description** : décision explicite de l'utilisateur, prise en toute
  connaissance de cause (voir ADR-34) — revient sur BACKLOG-2 R2/ADR-14
  (« ne jamais exclure silencieusement les tests d'un scan de sécurité »).
  `indexer._is_test_source(rel_path)` exclut tout fichier sous un
  répertoire `src/<jeu-de-sources>` où `<jeu-de-sources> != "main"`
  (convention Maven/Gradle : `main` est le seul nom de source set
  universel, `test`/`componentTest`/`contractTest`/`endToEndTest`/... sont
  tous des variantes de test) — logique sur les segments du chemin, pas un
  pattern glob `fnmatch` (qui ne respecte pas les frontières de
  répertoire et confondrait un paquet `com.foo.testutils` sous `src/main`
  avec un vrai jeu de sources de test).
- **CA** :
  1. Un fichier sous `src/test/java`, `src/componentTest/java`, etc. ne
     produit ni finding ni endpoint, même s'il déclenche les mêmes règles
     que son équivalent sous `src/main/java`.
  2. Un fichier déjà indexé qui devient exclu par ce changement (config
     existante, nouvel index après mise à jour) est purgé au prochain
     `cccf index`, exactement comme un fichier supprimé du disque — pas de
     migration dédiée nécessaire (le mécanisme `deleted = previous_paths -
     current_paths` de `index_repo` le couvre déjà).
  3. Un fichier sous `src/main/...` n'est jamais affecté, y compris si un
     de ses répertoires ou son contenu contient la sous-chaîne « test »
     (ex. package `testutils`).
- **Statut** : livré. `_is_test_source` (nouveau, `indexer.py`), appliqué
  dans `_list_repo_files` avant les filtres `config.exclude`/`include`
  existants. Fixture `tests/fixtures/test_source_exclusion_repo/` (un
  `OrderConsumer.java` sous `src/main`, un `OrderConsumerTest.java`
  identique sous `src/test`, mêmes règles System.out.println + Kafka
  listener) : testé de bout en bout dans `tests/test_indexer.py`
  (`test_index_repo_excludes_files_under_a_non_main_source_set` — 1
  finding + 1 endpoint, tous deux sous `src/main`, malgré des règles qui
  matchent identiquement dans `src/test`). CA2 non testé explicitement
  (découle directement du mécanisme `deleted` déjà couvert par les tests
  existants de suppression de fichier). Voir ADR-34.
