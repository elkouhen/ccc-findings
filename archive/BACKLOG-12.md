# Backlog 12 — Fiabilisation audit Java microservices (2026-07-13)

> Objectif : corriger les écarts les plus bloquants identifiés pendant la revue
> approfondie du repo `ccc-findings` et du repo skill `ccc-findings-skill`,
> pour que `cccf` soit réellement exploitable comme outil d'audit Java/Spring/
> Maven orienté microservices.
>
> Convention : une tâche = un commit (`J<n>: <titre>`), DoD globale inchangée
> (voir `AGENT.md`).

## Tâches

### [x] J1 — Normaliser les endpoints REST appelants pour le graphe
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/scanner.py`, `tests/test_rest_endpoints.py`,
  `docs/SPEC-TECH.md`, `docs/SPEC-FONC.md`
- **Description** : convertir les appels clients `RestTemplate` extraits comme
  URLs absolues (`POST http://service/orders`) en routes canoniques
  compatibles avec les routes exposées (`POST /orders`). Les hosts, query
  strings et fragments n'ont pas de valeur pour le graphe statique ; seule la
  route HTTP normalisée doit rester dans `topic`.
- **CA** :
  1. Les appels absolus HTTP/HTTPS sont stockés comme `METHOD /path`.
  2. Les appels concaténés restent `topic_dynamic=True`, mais conservent leur
     préfixe de route normalisé.
  3. Les routes serveur et appelant deviennent comparables par `paths_match`.
- **Statut** : livré. `_extract_rest_path` normalise désormais les URLs
  absolues vers un chemin canonique.

### [x] J2 — Rendre l'inventaire d'endpoints réellement par défaut pour le workflow d'audit
- **Priorité** : HAUTE
- **Fichiers** : `README.md`, `docs/SPEC-FONC.md`,
  `../ccc-findings-skill/skills/cccf/SKILL.md`
- **Description** : aligner la doc et le skill sur le vrai workflow produit :
  l'audit Java microservices doit copier puis activer par défaut les packs
  `default`, `liveness`, `rest` et `kafka`, afin que `cccf index` produise
  findings **et** endpoints exploitables par `cccf endpoints` / `cccf graph`.
- **CA** :
  1. Le skill documente explicitement les 4 packs par défaut.
  2. Le README/SPEC distinguent le fallback générique `p/security-audit` du
     workflow d'audit microservices piloté par le skill.
  3. La séquence recommandée `summary` → `endpoints` → `graph` → `findings`
     est visible dans la doc.
- **Statut** : livré. Le skill et la doc produit décrivent maintenant le
  workflow d'audit microservices et les packs d'inventaire activés par défaut.

### [x] J3 — Pousser les filtres et compteurs au plus près de SQLite
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/store.py`, `src/cccf/indexer.py`,
  `src/cccf/search.py`, `src/cccf/ccc_bridge.py`, `tests/test_store.py`,
  `tests/test_search.py`, `tests/test_ccc_bridge.py`, `docs/SPEC-TECH.md`
- **Description** : éviter les scans complets en mémoire pour les chemins
  supprimés/modifiés, les listes d'endpoints filtrées et l'annotation
  `search_code_with_findings`. Les suppressions/remplacements doivent aussi
  respecter la limite de paramètres SQLite.
- **CA** :
  1. Les compteurs `findings_removed` / `endpoints_removed` ne passent plus par
     `all_findings(path_glob=...)` pour chaque fichier.
  2. `Store.all_findings` / `Store.all_endpoints` poussent les filtres en SQL.
  3. Les listes de chemins > limite de bind SQLite restent supportées.
  4. `annotate_with_findings` ne charge que les findings des chemins concernés.
- **Statut** : livré. Les requêtes et suppressions par chemin sont batchées,
  filtrées en SQL, et `search_findings` ne demande plus toute la table vec0
  d'emblée.

### [x] J4 — Cacher et élargir la résolution des propriétés Spring
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/scanner.py`, `tests/test_kafka_endpoints.py`,
  `docs/SPEC-TECH.md`
- **Description** : parser les fichiers Spring une seule fois par process et
  mieux refléter les layouts réels Maven multi-modules : config du module du
  fichier source d'abord, puis repo parent, avec support des variantes
  `application-*.yml` / `bootstrap*.yml`.
- **CA** :
  1. Les fichiers YAML / properties sont mis en cache.
  2. Un fichier source sous un module Maven résout d'abord les configs de ce
     module.
  3. Les variantes `application-prod.yml` et `bootstrap*.yml` sont prises en
     compte en best-effort.
- **Statut** : livré. La résolution Spring est désormais cacheée et
  orientée module source.

### [x] J5 — Recentrer le skill sur le vrai parcours d'audit `cccf`
- **Priorité** : HAUTE
- **Fichiers** : `../ccc-findings-skill/skills/cccf/SKILL.md`,
  `../ccc-findings-skill/skills/cccf/references/management.md`,
  `../ccc-findings-skill/skills/cccf/references/settings.md`,
  `README.md`, `docs/SPEC-FONC.md`
- **Description** : arrêter de présenter `cccf` comme une simple variante de
  `ccc search`. Le skill doit devenir `cccf`-first : installation complète,
  usage des endpoints/graph, réglages `.cccf/config.yml`, et dépendance explicite
  à `ccc` pour la recherche de code seulement.
- **CA** :
  1. Les références management/settings ne parlent plus de `ccc init` comme si
     c'était la commande projet.
  2. L'installation mentionne `cccf`, `semgrep` et `ccc`.
  3. Le skill explique quand utiliser `summary`, `endpoints`, `graph`,
     `findings` et `search`.
- **Statut** : livré. Les docs skill ont été réécrites autour du workflow
  `cccf`, avec la dépendance `ccc` explicitée au bon endroit.
