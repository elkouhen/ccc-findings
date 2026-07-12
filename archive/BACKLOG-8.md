# Backlog 8 — Extension native CocoIndex de l'indexation `ccc` (2026-07-12)

> Objectif : transformer la revue de `../cocoindex/examples` en tâches
> actionnables pour faire évoluer `cccf` vers un mécanisme d'extension plus
> adapté que l'approche actuelle : index Semgrep manuel dans `.cccf/findings.db`
> + appel subprocess à `ccc search` + parsing texte + jointure tardive.
>
> Les exemples les plus utiles pour ce chantier sont :
> - `../cocoindex/examples/code_embedding/` : pipeline code
>   `walk_dir -> detect language -> split AST/text -> embed -> target vectoriel`,
>   avec `@coco.fn(memo=True)`, `ContextKey(..., detect_change=True)`,
>   `PatternFilePathMatcher`, `mount_each`, `declare_vector_index` et
>   `live=True`.
> - `../cocoindex/examples/files_transform/` : transformation fichier -> cible
>   fichier, simple et déclarative, utile pour penser le remplacement du
>   diff manuel `rglob + sha256`.
> - `../cocoindex/examples/postgres_source/` : source relationnelle typée,
>   cible typée, clé primaire composite, utile pour modéliser les findings comme
>   lignes déclarées plutôt que comme mutations SQL impératives.
> - `../cocoindex/docs/src/content/docs/programming_guide/core_concepts.mdx` :
>   modèle `TargetState = Transform(SourceState)`, traitement incrémental,
>   mémoïsation et suppression automatique des états cibles orphelins.
>
> Convention : une tâche = un commit (`X<n>: <titre>`), DoD globale inchangée.

## Constats de revue

L'architecture actuelle de `cccf` reproduit à la main plusieurs mécanismes que
CocoIndex fournit déjà : détection des fichiers modifiés, invalidation quand le
code ou le modèle change, suppression des lignes cibles quand une source
disparaît, batch atomique par composant et mode live. Elle ajoute aussi un point
fragile spécifique : la dépendance au format texte de `ccc search` documentée
dans ADR-10 et déjà priorisée par A6.

Le mécanisme d'extension le plus adapté semble donc être une extension
d'indexation déclarative, construite comme un flow CocoIndex, où les findings
Semgrep sont des états cibles typés rattachés aux fichiers/chunks indexés. La
jointure code + findings devrait idéalement être produite ou préparée au moment
de l'indexation, pas reconstruite à chaque requête depuis une sortie CLI
humaine.

---

### [x] X1 — Cadrer l'option d'extension native CocoIndex vs package compagnon
- **Priorité** : HAUTE
- **Fichiers** : `docs/ADR.md`, `docs/SPEC-TECH.md`, `README.md`,
  `archive/BACKLOG-8.md`
- **Description** : réévaluer explicitement ADR-1 à la lumière des exemples
  CocoIndex. Comparer trois options :
  1. conserver `cccf` comme package compagnon mais remplacer son indexer manuel
     par une App CocoIndex dédiée aux findings ;
  2. contribuer une extension directement dans `cocoindex-code` / `ccc` pour
     indexer les diagnostics sécurité dans le même flow que les chunks de code ;
  3. construire un nouvel index unifié `code + findings` inspiré de
     `examples/code_embedding`, sans dépendre du binaire `ccc`.
- **CA** :
  1. Une ADR documente l'option retenue, les options rejetées et les impacts sur
     ADR-1/ADR-10.
  2. La décision dit clairement si `cccf` peut dépendre d'API CocoIndex
     publiques ou s'il doit rester limité à `ccc` comme binaire externe.
  3. Le risque de couplage amont est comparé au risque actuel de parsing texte
     de `ccc search`.
  4. Le README et la spec technique ne promettent plus implicitement une
     architecture si la décision la rend obsolète.

### [x] X2 — Prototyper un indexer findings déclaratif avec CocoIndex
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/indexer.py` ou nouveau module `src/cccf/coco_indexer.py`,
  `src/cccf/store.py`, `tests/test_indexer.py`, `tests/fixtures/vuln_repo/`,
  `docs/SPEC-TECH.md`, `archive/BACKLOG-8.md`
- **Description** : remplacer le coeur `rglob -> sha256 -> deleted/changed ->
  run_semgrep -> replace_findings_for_files` par un prototype CocoIndex :
  `localfs.walk_dir(..., PatternFilePathMatcher(...), live=True)` monte un
  composant par fichier ; un `@coco.fn(memo=True)` exécute Semgrep sur le fichier
  ou le lot minimal compatible ; les findings sont déclarés dans une cible typée
  avec clé primaire stable.
- **CA** :
  1. Sur `tests/fixtures/vuln_repo`, le prototype produit les mêmes findings que
     l'indexer actuel.
  2. Modifier un fichier ne rescane que le composant nécessaire, sauf limite
     Semgrep explicitement documentée.
  3. Supprimer ou renommer un fichier supprime les findings orphelins sans appel
     manuel à `store.remove_files`.
  4. Les règles `include`/`exclude` de `.cccf/config.yml` sont traduites vers
     `PatternFilePathMatcher` sans divergence avec le comportement documenté.
  5. Le prototype peut rester derrière un flag expérimental tant que la
     migration de stockage n'est pas décidée.

### [ ] X3 — Déléguer l'invalidation embeddings/modèle à la mémoïsation CocoIndex
- **Priorité** : MOYENNE-HAUTE
- **Fichiers** : `src/cccf/embedder.py`, `src/cccf/indexer.py` ou
  `src/cccf/coco_indexer.py`, `src/cccf/store.py`, `tests/test_embedder.py`,
  `tests/test_indexer.py`, `docs/SPEC-TECH.md`, `archive/BACKLOG-8.md`
- **Description** : exploiter le pattern `ContextKey[Embedder](..., detect_change=True)`
  et des fonctions `@coco.fn(memo=True)` pour que le changement de modèle,
  d'embedder ou de transformation invalide naturellement les embeddings
  concernés. L'objectif est de remplacer la logique ad hoc
  `embedding_signature` / `embedding_dim` / ré-embedding complet quand c'est
  possible, ou de la réduire à un garde-fou de compatibilité.
- **CA** :
  1. Un changement de modèle force le recalcul des embeddings nécessaires sans
     mélange de dimensions en cible.
  2. Un changement de texte de finding réutilise les embeddings identiques quand
     CocoIndex peut les mémoïser.
  3. Les erreurs de dimension restent actionnables côté recherche.
  4. La spec explique ce qui relève encore de `Store` et ce qui relève du moteur
     CocoIndex.

### [x] X4 — Préparer une jointure code + findings à l'indexation
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/ccc_bridge.py`, `src/cccf/code_search.py`,
  `src/cccf/render.py`, `src/cccf/store.py`, `tests/test_ccc_bridge.py`,
  `tests/test_e2e.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`,
  `archive/BACKLOG-8.md`
- **Description** : étudier puis prototyper une cible où les findings sont déjà
  reliés aux chunks de code par `path + plage de lignes` pendant l'indexation,
  sur le modèle `examples/code_embedding` (`start_line`, `end_line`, chunk,
  embedding). Cela doit réduire la dépendance au format de sortie de `ccc search`
  et rendre `search_code_with_findings` requêtable depuis un schéma stable.
- **CA** :
  1. La stratégie choisie évite de parser une sortie humaine pour obtenir les
     champs `path`, `start_line`, `end_line`, `language`, `score`.
  2. Un résultat de recherche code peut retourner ses findings associés sans
     parcourir tous les findings en Python à chaque requête.
  3. Le score sémantique code et les métadonnées sécurité restent séparés dans
     le contrat JSON, même si le classement combine les deux.
  4. Le mode dégradé est explicite si l'index unifié n'est pas disponible.

### [ ] X5 — Ajouter un mode live/fraîcheur continue pour les agents
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/cli.py`, `src/cccf/mcp_server.py`,
  `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `README.md`,
  `archive/BACKLOG-8.md`
- **Description** : reprendre le mécanisme `live=True` + `cocoindex update -L`
  observé dans les exemples pour offrir un index findings/code toujours frais
  pendant une session agent. Le mode doit être explicite, observable et sûr :
  pas de processus caché lancé par surprise, pas de scan complet en boucle.
- **CA** :
  1. Une commande ou procédure documentée permet de lancer l'indexation live.
  2. Le serveur MCP peut signaler si l'index est frais, en rattrapage, absent ou
     en erreur.
  3. Les changements de fichiers sont visibles dans les résultats sans relancer
     manuellement `cccf index`.
  4. Les limites de plateforme (watch filesystem, Semgrep lent, absence de
     dépendances CocoIndex) sont documentées.

### [ ] X6 — Planifier la migration stockage et distribution
- **Priorité** : MOYENNE
- **Fichiers** : `pyproject.toml`, `src/cccf/store.py`, `src/cccf/cli.py`,
  `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `docs/ADR.md`,
  `archive/BACKLOG-8.md`
- **Description** : décider comment introduire CocoIndex sans casser les
  utilisateurs actuels : dépendance optionnelle ou obligatoire, conservation de
  `.cccf/findings.db`, nouvelle cible Postgres/sqlite-vec, commande de migration
  ou réindexation complète. Cette tâche doit être traitée avant de rendre
  l'indexer CocoIndex non expérimental.
- **CA** :
  1. Le chemin de migration depuis un index `.cccf/findings.db` existant est
     documenté.
  2. Les dépendances nouvelles sont justifiées et installables avec `uv`.
  3. Les commandes existantes gardent un comportement clair pendant la période
     de transition.
  4. Les specs indiquent quel backend est supporté officiellement en V1.
