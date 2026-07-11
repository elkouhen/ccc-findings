# Backlog 5 — Revue UX du skill `cccf` (2026-07-12)

> Objectif : rendre le skill `cccf` simple, agréable et sûr à utiliser par un
> agent de codage, sans exiger que l'agent relise toute la documentation produit.
> Convention : une tâche = un commit (`UX<n>: <titre>`), DoD globale inchangée.

### [x] UX1 — Simplifier le parcours d'usage du skill
- **Fichiers** : `~/cocoindex-ext-skill/SKILL.md`, `docs/SPEC-FONC.md`,
  `archive/BACKLOG-5.md`
- **Description** : revoir le skill du point de vue d'un agent utilisateur :
  clarifier quand l'utiliser, quelle action faire en premier, comment choisir le
  bon tool MCP, comment corriger un finding sans sur-scanner le repo, et comment
  répondre à l'utilisateur avec un résultat court. Le skill doit privilégier un
  chemin heureux simple, puis documenter les cas d'erreur/fallbacks.
- **CA** :
  1. Le skill contient une règle d'or, un démarrage rapide et une table de choix
     des tools (`findings_summary`, `search_findings`,
     `search_code_with_findings`, `reindex_findings`).
  2. La boucle de correction est décrite en peu d'étapes, avec une limite claire
     de deux tentatives et un fallback si le MCP Semgrep officiel est absent.
  3. Les anti-patterns protègent l'expérience utilisateur : pas de scan complet
     Semgrep via MCP, pas de patch sans contexte, pas de long dump JSON dans la
     réponse finale.
  4. `docs/SPEC-FONC.md` reflète le comportement du skill mis à jour.
