# Backlog Priority — ordre de traitement consolidé (2026-07-13)

> Vue consolidée des tâches `archive/BACKLOG*.md`, après revue des statuts.
> Les tâches terminées restent listées en bas pour traçabilité ; l'ordre utile
> de travail est la section « Tâches ouvertes ».

## Cadrage de priorité 2026-07-13

La priorité produit est l'audit d'un **répertoire parent contenant tous les
microservices et des composants partagés Maven**, pas une fédération de dépôts
indépendants. Les tâches K7/K12 restent utiles, mais leur réalisation doit être
orientée par A2 : découverte de sous-projets Maven, distinction
microservice déployable vs module partagé, puis graphe REST/Kafka entre
services.

## Tâches ouvertes — ordre recommandé

| Rang | Tâche | Priorité | Source | Pourquoi maintenant |
|---:|---|---|---|---|
| 1 | K2 — Règles Semgrep d'extraction des endpoints Kafka | HAUTE | `archive/BACKLOG-10.md` | Le modèle `MessageEndpoint` existe ; il manque l'inventaire Kafka pour cartographier les flux asynchrones. |
| 2 | A1 / K3 — Brancher l'inventaire d'endpoints dans `cccf index` | HAUTE | `archive/BACKLOG-11.md`, `archive/BACKLOG-10.md` | Conditionne l'usage réel de `cccf graph` : les endpoints ne doivent plus être injectés manuellement dans le store. |
| 3 | A2 / K7 adapté / K12 — Explorer le répertoire multi-services et exposer cycles/hotspots | HAUTE | `archive/BACKLOG-11.md`, `archive/BACKLOG-10.md` | Cible audit microservices : répertoire parent avec services et modules Maven partagés, graphe REST/Kafka et hotspots. |
| 4 | K11 — Compléter les règles d'inventaire REST | HAUTE | `archive/BACKLOG-10.md` | Java/Python sont partiellement livrés ; restent notamment WebClient/Feign, Express/JS et certains cas `@RequestMapping`/Flask. |
| 5 | K8 — Compléter le pack liveness/sécurité | HAUTE | `archive/BACKLOG-10.md` | Le volet liveness Python/Java est livré ; restent sécurité Kafka, JS/TS, configs consumer risquées, DLQ/retry. |
| 6 | A5 / A7 / R8 / R9 — Optimiser l'indexation et les compteurs grands repos | MOYENNE | `archive/BACKLOG-11.md`, `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Nécessaire pour le répertoire multi-services : hash streaming, batch SQL, filtres poussés en SQLite, compteurs exacts. |
| 7 | X3 — Déléguer l'invalidation embeddings/modèle à la mémoïsation CocoIndex | MOYENNE-HAUTE | `archive/BACKLOG-8.md` | Le prototype X2/X4 existe ; il faut éviter les embeddings de chunks périmés quand modèle ou logique changent. |
| 8 | A14 / X6 — Préparer la migration de schéma, stockage et distribution | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-8.md` | Le schéma SQLite est passé en v4 et le mode expérimental impose une stratégie de backend/migration avant généralisation. |
| 9 | A8 / R10 — Rendre les filtres de lecture cohérents avec la configuration courante | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Empêche `search`/`summary` de servir des findings qui ne correspondent plus à `min_severity`, `include` ou `exclude`. |
| 10 | A6 — Durcir le pont `ccc` contre les changements de format | MOYENNE-HAUTE | `archive/BACKLOG-4.md` | Reste utile comme garde-fou court terme pour les index manuels et les repos non migrés vers l'index code expérimental. |
| 11 | X5 — Ajouter un mode live/fraîcheur continue pour les agents | MOYENNE | `archive/BACKLOG-8.md` | Les exemples CocoIndex supportent `live=True` ; cette capacité améliorerait directement l'usage MCP/agent. |
| 12 | A9 — Ajouter une commande de diagnostic de santé de l'index | MOYENNE | `archive/BACKLOG-4.md` | Rend les problèmes de config/base/embeddings/Semgrep actionnables avant usage agent. |
| 13 | N1 — Unifier l'ordre des sévérités | MOYENNE | `archive/BACKLOG-2.md` | Réduit le risque d'incohérence entre scanner, store, config et pont `ccc`. |
| 14 | N2 — Unifier les fakes et fixtures de tests | MOYENNE | `archive/BACKLOG-2.md` | Le runtime est centralisé, mais les fakes/fixtures de tests restent dupliqués. |
| 15 | N3 — Unifier la sérialisation `Finding → dict` et le rendu summary | MOYENNE | `archive/BACKLOG-2.md` | Réduit les duplications entre CLI, MCP et pont `ccc`, et limite les écarts de contrat JSON. |
| 16 | A10 — Transformer l'évaluation de pertinence en garde-fou exploitable | MOYENNE | `archive/BACKLOG-4.md` | Rend mesurable la qualité de la recherche sémantique avant diffusion plus large. |
| 17 | A11 — Mesurer latence et coût token des réponses principales | MOYENNE | `archive/BACKLOG-4.md` | Vérifie les promesses produit p95 < 1 s et réduction de sortie vs Semgrep brut. |
| 18 | A13 — Définir la stratégie de distribution du skill séparé | MOYENNE | `archive/BACKLOG-4.md` | Clarifie ce qu'installe réellement le package Python et comment distribuer/mettre à jour le skill externe. |

## Regroupements conseillés

1. **Vue microservices exploitable** : K2 → A1/K3 → A2/K7/K12.
2. **Complétude des détecteurs** : K11 → K8.
3. **Scalabilité du répertoire multi-services** : A5/A7/R8/R9.
4. **Invalidation, schema et migration** : X3 → A14/X6 → A8/R10.
5. **Garde-fou court terme du pont actuel** : A6.
6. **Fraîcheur et diagnostic agent** : X5 → A9.
7. **Nettoyage transverse** : N1 → N2 → N3.
8. **Mesure produit et distribution** : A10 → A11 → A13.

## Prochaine séquence recommandée

| Étape | Objectif | Résultat attendu |
|---:|---|---|
| 1 | Livrer K2 | Les producers/consumers Kafka sont extraits comme `MessageEndpoint`. |
| 2 | Livrer A1/K3 | `cccf index` peuple automatiquement `endpoints` pour REST + Kafka. |
| 3 | Livrer A2 | Un répertoire parent Maven est exploré, avec noms stables pour services et modules partagés. |
| 4 | Finaliser K12 | `cccf graph` rapporte cycles, appels sortants dans consumers et hotspots inter-services. |
| 5 | Traiter A5 | Les performances tiennent sur le répertoire multi-services complet. |

## Tâches terminées

| Tâche | Source | Statut |
|---|---|---|
| F0.1 à F7.2 — Implémentation initiale | `archive/BACKLOG.md` | Terminé |
| R1 — Les fichiers racine du repo ne sont jamais indexés | `archive/BACKLOG-2.md` | Terminé |
| R2 — Les répertoires `tests/` des repos utilisateurs sont silencieusement exclus du scan | `archive/BACKLOG-2.md` | Terminé |
| R3 — `CCCF_FAKE_EMBEDDER` peut empoisonner un index de prod de façon indétectable | `archive/BACKLOG-2.md` | Terminé |
| R4 — Le serveur MCP recharge le modèle d'embedding à chaque appel de tool | `archive/BACKLOG-2.md` | Terminé |
| R5 — Un seul fichier non-UTF-8 fait échouer toute l'indexation | `archive/BACKLOG-2.md` | Terminé |
| R6 — Collision d'IDs de findings quand le snippet est vide ou dupliqué | `archive/BACKLOG-2.md` | Terminé |
| R7 — `get_context` crashe sur index périmé et détruit tout le résultat MCP | `archive/BACKLOG-2.md` | Terminé |
| S1 — `cccf init` se replie sur un pack registry par défaut | `archive/BACKLOG-3.md` | Terminé |
| A1 — Garantir que le périmètre configuré est réellement indexé | `archive/BACKLOG-4.md` | Terminé |
| A2 — Rendre l'identité des findings non ambiguë | `archive/BACKLOG-4.md` | Terminé |
| A3 — Dégrader proprement quand l'index est périmé | `archive/BACKLOG-4.md` | Terminé |
| A4 — Centraliser et cacher la factory d'embedder | `archive/BACKLOG-4.md` | Terminé |
| A5 — Détecter les embeddings incompatibles avant la recherche | `archive/BACKLOG-4.md` | Terminé |
| A12 — Corriger les incohérences de documentation fonctionnelle | `archive/BACKLOG-4.md` | Terminé |
| UX1 — Simplifier le parcours d'usage du skill | `archive/BACKLOG-5.md` | Terminé |
| X1 — Cadrer l'option d'extension native CocoIndex vs package compagnon | `archive/BACKLOG-8.md` | Terminé |
| X2 — Prototyper un indexer findings déclaratif avec CocoIndex | `archive/BACKLOG-8.md` | Terminé |
| X4 — Préparer une jointure code + findings à l'indexation | `archive/BACKLOG-8.md` | Terminé |
| E1 — Faire échouer `cccf search` si `ccc search` échoue | `archive/BACKLOG-9.md` | Terminé |
| K1 — Modèle de données `message_endpoints` | `archive/BACKLOG-10.md` | Terminé |
