# Backlog Priority — ordre de traitement consolidé (2026-07-12)

> Vue consolidée des tâches `archive/BACKLOG*.md`, après revue des statuts.
> Les tâches terminées restent listées en bas pour traçabilité ; l'ordre utile
> de travail est la section « Tâches ouvertes ».

## Tâches ouvertes — ordre recommandé

| Rang | Tâche | Priorité | Source | Pourquoi maintenant |
|---:|---|---|---|---|
| 1 | A6 — Durcir le pont `ccc` contre les changements de format | MOYENNE-HAUTE | `archive/BACKLOG-4.md` | Évite une recherche code vide silencieuse si le format texte de `ccc search` change ; préserve le fallback MCP. |
| 2 | A14 — Préparer une politique de versionnement du schéma SQLite | MOYENNE | `archive/BACKLOG-4.md` | Devient prioritaire car les tâches récentes ont ajouté des métadonnées d'embeddings et modifié l'identité des findings sans vraie stratégie de migration. |
| 3 | A8 / R10 — Rendre les filtres de lecture cohérents avec la configuration courante | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Empêche `search`/`summary` de servir des findings qui ne correspondent plus à `min_severity`, `include` ou `exclude`. |
| 4 | R9 — Corriger les compteurs de findings supprimés | MOYENNE | `archive/BACKLOG-2.md` | Les compteurs `-findings=` peuvent être faux pour des chemins contenant des caractères glob (`[id]`) et coûtent trop cher sur beaucoup de fichiers. |
| 5 | A7 / R8 — Batcher les opérations SQLite dépendantes du nombre de fichiers | MOYENNE | `archive/BACKLOG-4.md`, `archive/BACKLOG-2.md` | Nécessaire pour éviter `too many SQL variables` sur gros monorepos ; peut être traité avec R9 via un helper SQL partagé. |
| 6 | A9 — Ajouter une commande de diagnostic de santé de l'index | MOYENNE | `archive/BACKLOG-4.md` | Rend les problèmes de config/base/embeddings/Semgrep actionnables avant usage agent. |
| 7 | N1 — Unifier l'ordre des sévérités | MOYENNE | `archive/BACKLOG-2.md` | Réduit le risque d'incohérence entre scanner, store, config et pont `ccc`. |
| 8 | N2 — Unifier les fakes et fixtures de tests | MOYENNE | `archive/BACKLOG-2.md` | Le runtime est maintenant centralisé, mais les fakes/fixtures de tests restent dupliqués. |
| 9 | N3 — Unifier la sérialisation `Finding → dict` et le rendu summary | MOYENNE | `archive/BACKLOG-2.md` | Réduit les duplications entre CLI, MCP et pont `ccc`, et limite les écarts de contrat JSON. |
| 10 | A10 — Transformer l'évaluation de pertinence en garde-fou exploitable | MOYENNE | `archive/BACKLOG-4.md` | Rend mesurable la qualité de la recherche sémantique avant diffusion plus large. |
| 11 | A11 — Mesurer latence et coût token des réponses principales | MOYENNE | `archive/BACKLOG-4.md` | Vérifie les promesses produit p95 < 1 s et réduction de sortie vs Semgrep brut. |
| 12 | A13 — Définir la stratégie de distribution du skill séparé | MOYENNE | `archive/BACKLOG-4.md` | Clarifie ce qu'installe réellement le package Python et comment distribuer/mettre à jour le skill externe. |

## Regroupements conseillés

1. **Robustesse intégration** : A6.
2. **Cohérence index/config/schema** : A14 → A8/R10.
3. **Scalabilité store** : R9 → A7/R8.
4. **UX diagnostic** : A9.
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
