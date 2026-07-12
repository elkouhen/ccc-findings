# Backlog 9 — Erreurs `ccc` non masquées (2026-07-12)

> Objectif : garantir que `cccf search` ne transforme pas une panne du service
> `ccc` sous-jacent en résultat de succès dégradé.
>
> Convention : une tâche = un commit (`E<n>: <titre>`), DoD globale inchangée.

### [x] E1 — Faire échouer `cccf search` si `ccc search` échoue
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/code_search.py`, `tests/conftest.py`,
  `tests/test_ccc_bridge.py`, `tests/test_cli.py`, `docs/SPEC-FONC.md`,
  `docs/ADR.md`, `archive/BACKLOG-9.md`
- **Description** : supprimer le repli `findings_only_fallback` quand le pont
  `ccc` échoue (`ccc` absent ou code retour non nul). Une panne `ccc` doit
  remonter comme erreur CLI/MCP explicite, afin que l'appelant ne confonde pas
  une recherche code indisponible avec un résultat findings-only valide.
- **CA** :
  1. Un faux `ccc` qui retourne un code non nul fait échouer `cccf search` avec
     code de sortie 2.
  2. Le tool MCP `search_code_with_findings` lève une exception dans le même cas.
  3. Le message d'erreur conserve le code retour et stderr de `ccc`.
  4. L'index code expérimental (`--engine cocoindex`) reste indépendant de `ccc`
     quand il est disponible.
