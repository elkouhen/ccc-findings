# Backlog Priority — ordre de traitement consolidé (2026-07-12)

> Vue consolidée des tâches `archive/BACKLOG*.md`, après revue des statuts.
> Les tâches terminées restent listées en bas pour traçabilité ; l'ordre utile
> de travail est la section « Tâches ouvertes ».

## Tâches ouvertes — ordre recommandé

| Rang | Tâche | Priorité | Source | Pourquoi maintenant |
|---:|---|---|---|---|
| 1 | A6 — Durcir le pont `ccc` contre les changements de format | MOYENNE-HAUTE | `archive/BACKLOG-4.md` | Reste utile comme garde-fou court terme pour les index manuels et les repos non migrés vers l'index code expérimental. |
| 2 | X3 — Déléguer l'invalidation embeddings/modèle à la mémoïsation CocoIndex | MOYENNE-HAUTE | `archive/BACKLOG-8.md` | Le prototype X2/X4 existe ; il faut maintenant éviter les embeddings de chunks périmés quand modèle ou logique changent. |
| 3 | A14 / X6 — Préparer la migration de schéma, stockage et distribution | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-8.md` | Devient transversal : le schéma SQLite est passé en v3 et le mode expérimental impose une stratégie de backend/migration avant généralisation. |
| 4 | A8 / R10 — Rendre les filtres de lecture cohérents avec la configuration courante | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Empêche `search`/`summary` de servir des findings qui ne correspondent plus à `min_severity`, `include` ou `exclude`. |
| 5 | R9 — Corriger les compteurs de findings supprimés | MOYENNE | `archive/BACKLOG-2.md` | Les compteurs `-findings=` peuvent être faux pour des chemins contenant des caractères glob (`[id]`) et coûtent trop cher sur beaucoup de fichiers ; à traiter seulement si l'indexer manuel reste actif. |
| 6 | A7 / R8 — Batcher les opérations SQLite dépendantes du nombre de fichiers | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Nécessaire pour éviter `too many SQL variables` sur gros monorepos si le stockage SQLite actuel reste le backend principal. |
| 7 | X5 — Ajouter un mode live/fraîcheur continue pour les agents | MOYENNE | `archive/BACKLOG-8.md` | Les exemples CocoIndex supportent `live=True` ; cette capacité améliorerait directement l'usage MCP/agent. |
| 8 | A9 — Ajouter une commande de diagnostic de santé de l'index | MOYENNE | `archive/BACKLOG-4.md` | Rend les problèmes de config/base/embeddings/Semgrep actionnables avant usage agent. |
| 9 | N1 — Unifier l'ordre des sévérités | MOYENNE | `archive/BACKLOG-2.md` | Réduit le risque d'incohérence entre scanner, store, config et pont `ccc`. |
| 10 | N2 — Unifier les fakes et fixtures de tests | MOYENNE | `archive/BACKLOG-2.md` | Le runtime est maintenant centralisé, mais les fakes/fixtures de tests restent dupliqués. |
| 11 | N3 — Unifier la sérialisation `Finding → dict` et le rendu summary | MOYENNE | `archive/BACKLOG-2.md` | Réduit les duplications entre CLI, MCP et pont `ccc`, et limite les écarts de contrat JSON. |
| 12 | A10 — Transformer l'évaluation de pertinence en garde-fou exploitable | MOYENNE | `archive/BACKLOG-4.md` | Rend mesurable la qualité de la recherche sémantique avant diffusion plus large. |
| 13 | A11 — Mesurer latence et coût token des réponses principales | MOYENNE | `archive/BACKLOG-4.md` | Vérifie les promesses produit p95 < 1 s et réduction de sortie vs Semgrep brut. |
| 14 | A13 — Définir la stratégie de distribution du skill séparé | MOYENNE | `archive/BACKLOG-4.md` | Clarifie ce qu'installe réellement le package Python et comment distribuer/mettre à jour le skill externe. |

## Regroupements conseillés

1. **Garde-fou court terme du pont actuel** : A6.
2. **Invalidation, schema et migration** : X3 → A14/X6 → A8/R10.
3. **Scalabilité store actuel si conservé** : R9 → A7/R8.
4. **Fraîcheur et diagnostic agent** : X5 → A9.
5. **Nettoyage transverse** : N1 → N2 → N3.
6. **Mesure produit et distribution** : A10 → A11 → A13.

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
