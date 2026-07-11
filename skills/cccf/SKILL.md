---
name: cccf
description: Interroger et corriger la dette sécurité/qualité d'un repo via l'index Semgrep de ccc-findings. Déclencheurs — vulnérabilité, sécurité, semgrep, finding, dette, audit.
---

# ccc-findings (cccf)

Index Semgrep local, interrogeable en langage naturel, joint au code via `ccc`.
Utilise les tools MCP `search_findings`, `findings_summary`,
`search_code_with_findings` et `reindex_findings` exposés par `cccf mcp`.

## Installation

1. **Semgrep** (dépendance requise par `cccf`) : `pipx install semgrep` (ou
   `brew install semgrep`).
2. **cccf** : `uv tool install ccc-findings` (ou `pipx install ccc-findings`).
3. **Modèle d'embedding** : téléchargé automatiquement au premier `cccf index`
   (`sentence-transformers`, modèle `Snowflake/snowflake-arctic-embed-xs` par
   défaut, ~100 Mo) — accès réseau nécessaire une seule fois, les exécutions
   suivantes réutilisent le cache local (`~/.cache/huggingface`).
4. **Initialiser et indexer le repo cible** :
   ```bash
   cd <votre-repo>
   cccf init                # détecte .semgrep.yml/semgrep.yml/.semgrep, ou --rules <chemin-ou-pack>
   cccf index
   ```
5. **Enregistrer le serveur MCP `cccf`** auprès du client (ex. `.mcp.json` à
   la racine du projet pour Claude Code, ou l'équivalent de votre client) :
   ```json
   {"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}
   ```
6. **(Recommandé) Enregistrer aussi le MCP Semgrep officiel**, utilisé à
   l'étape 4 du Workflow 3 pour la vérification fraîche post-patch :
   ```json
   {"mcpServers": {"semgrep": {"command": "uvx", "args": ["semgrep-mcp"]}}}
   ```
   Sans lui, cette étape est simplement sautée : `reindex_findings` +
   `search_findings` (étapes 5-6 du Workflow 3) suffisent à vérifier la
   disparition du finding, avec une confiance moindre qu'un scan frais.

## Workflow 1 — Explorer les problèmes connus

1. Appeler `search_findings(query="<description du problème>", limit=5)`.
2. Sur le finding retenu, rappeler `search_findings` avec le même filtre et
   `include_context: true` pour obtenir le code entourant le finding.

## Workflow 2 — Avant de modifier un fichier

1. Appeler `search_findings(path_glob="<fichier>*")` pour lister les
   findings connus sur ce fichier avant de le patcher.

## Workflow 3 — Boucle de correction (correction guidée)

1. `search_findings(query="...", severity="ERROR", path_glob="...")` pour
   lister les findings à corriger.
2. Relire le contexte de chaque finding (`include_context: true`).
3. Patcher le code, en respectant le champ `fix` du finding s'il est fourni.
4. Si le MCP Semgrep officiel est disponible, appeler son tool
   `semgrep_scan` sur le seul fichier modifié pour une vérification fraîche
   immédiate (ne pas scanner tout le repo).
5. Appeler `reindex_findings` pour mettre à jour l'index `cccf`.
6. Rappeler `search_findings` avec le même filtre qu'à l'étape 1 pour
   confirmer la disparition du finding.
7. Si le finding persiste après 2 tentatives de correction, ne pas
   réessayer une 3e fois : rapporter le blocage à l'utilisateur.

## Workflow 4 — Vue d'ensemble

1. Appeler `findings_summary()` pour un état agrégé (sévérités, top
   règles) à faible coût de tokens.

## Recherche croisée code + findings

Pour explorer du code en tenant compte de sa dette sécurité, préférer
`search_code_with_findings(query="...")` à une recherche `ccc` seule : il
annote chaque résultat de code des findings Semgrep connus qui le
recouvrent.

## Anti-patterns

- Ne pas scanner tout le repo via le MCP Semgrep officiel (`semgrep_scan`
  sans cible précise) : utiliser l'index `cccf` (`search_findings`,
  `findings_summary`) pour tout ce qui est déjà indexé, et ne réserver le
  MCP Semgrep officiel qu'à la vérification post-patch d'un fichier précis.
- Ne pas corriger un finding sans avoir lu son contexte
  (`include_context: true` ou lecture directe du fichier).
- Ne pas supprimer un commentaire `# nosemgrep` existant : il reflète une
  décision déjà prise sur un faux positif.
