# Backlog — ccc-findings (`cccf`) : index Semgrep interrogeable par LLM, combiné à CCC

> Implémente la **stratégie 3** du PRD (`PRD.md`) : les findings Semgrep sont indexés
> et vectorisés localement, interrogeables en langage naturel, joints aux résultats
> code de CCC ; le MCP Semgrep officiel sert de canal de vérification post-patch.

## Décisions d'architecture (déjà tranchées — ne pas rediscuter)

| # | Décision | Justification |
|---|----------|---------------|
| D1 | **Package compagnon** Python `ccc-findings` (CLI `cccf`), pas de fork de cocoindex-code | Zéro dépendance aux API internes de CCC ; la jointure avec CCC se fait à la requête via `ccc search --json` + recouvrement `fichier + plage de lignes` |
| D2 | **Store = un seul fichier SQLite** (`.cccf/findings.db`), embeddings en BLOB, similarité cosinus brute-force en Python/NumPy | Un repo compte au plus quelques milliers de findings : le brute-force est < 50 ms, pas besoin de LMDB/index ANN |
| D3 | Embeddings via `sentence-transformers`, modèle par défaut `Snowflake/snowflake-arctic-embed-xs` (même défaut que CCC), configurable | Cohérence avec CCC, local-first |
| D4 | Les tests utilisent **des règles Semgrep locales** (fichiers YAML dans les fixtures), jamais les packs registry `p/...` | Tests déterministes et hors-ligne |
| D5 | Identité stable d'un finding : `sha256(rule_id + "|" + path + "|" + snippet_normalisé)[:16]` où `snippet_normalisé` = lignes du finding, whitespace réduit à un espace | Survit aux décalages de lignes ; permet diff et déduplication |
| D6 | Python ≥ 3.10, gestion de projet avec `uv`, tests avec `pytest` | Aligné sur l'écosystème cocoindex-code |

## Conventions pour l'agent exécutant

1. Traiter les tâches **dans l'ordre** ; ne commencer une tâche que si toutes ses dépendances (`Deps`) sont `DONE`.
2. Une tâche est `DONE` uniquement quand **tous ses critères d'acceptation (CA) passent**, plus la DoD globale.
3. **DoD globale** (toutes tâches) : `uv run pytest` passe entièrement ; `uv run ruff check .` sans erreur ; aucun fichier hors du périmètre `Fichiers` de la tâche n'est modifié ; pas de `TODO` laissé dans le code livré.
4. Ne pas implémenter en avance le contenu d'une tâche future. Si un CA est impossible à satisfaire tel quel, s'arrêter et signaler, ne pas réinterpréter.
5. Cocher la case de statut de la tâche dans ce fichier (`[ ]` → `[x]`) quand elle est `DONE`.
6. Chaque tâche = un commit, message : `F<epic>.<n>: <titre de la tâche>`.

---

## EPIC 0 — Socle projet

### [ ] F0.1 — Scaffolding du package
- **Deps** : —
- **Taille** : S
- **Fichiers** : `pyproject.toml`, `src/cccf/__init__.py`, `src/cccf/cli.py`, `tests/test_smoke.py`, `.gitignore`, `README.md`
- **Description** : créer le package `ccc-findings` géré par `uv`. Dépendances runtime : `typer`, `pyyaml`, `numpy`, `sentence-transformers`, `mcp`. Dépendances dev : `pytest`, `ruff`. Déclarer le point d'entrée console `cccf = cccf.cli:app`. `cli.py` : application Typer avec une commande `version` qui affiche la version du package. `.gitignore` : `.venv`, `__pycache__`, `.cccf/`, `*.db`.
- **CA** :
  1. `uv sync` réussit.
  2. `uv run cccf version` affiche `0.1.0`.
  3. `uv run pytest` passe (le test smoke importe `cccf` et vérifie la version).

### [ ] F0.2 — Fixtures : mini-repo vulnérable + règles Semgrep locales
- **Deps** : F0.1
- **Taille** : S
- **Fichiers** : `tests/fixtures/vuln_repo/app/db.py`, `tests/fixtures/vuln_repo/app/shell.py`, `tests/fixtures/vuln_repo/app/clean.py`, `tests/fixtures/vuln_repo/rules/rules.yml`
- **Description** : construire un dépôt de test. `db.py` : fonction construisant une requête SQL par f-string passée à `cursor.execute(...)`. `shell.py` : appel `subprocess.run(cmd, shell=True)` avec variable. `clean.py` : code sans défaut. `rules.yml` : deux règles Semgrep custom — `custom.sql-fstring` (severity ERROR, pattern `cursor.execute(f"...")`, métadonnée `cwe: CWE-89`) et `custom.subprocess-shell-true` (severity WARNING, pattern `subprocess.run(..., shell=True)`, métadonnée `cwe: CWE-78`). Chaque règle a un `message` d'une phrase.
- **CA** :
  1. `semgrep scan --config tests/fixtures/vuln_repo/rules/rules.yml tests/fixtures/vuln_repo/app --json` retourne exactement 2 findings : 1 ERROR dans `db.py`, 1 WARNING dans `shell.py`, 0 dans `clean.py`. (Semgrep doit être installé ; sinon `pipx install semgrep` d'abord.)

### [ ] F0.3 — Configuration projet `.cccf/config.yml`
- **Deps** : F0.1
- **Taille** : S
- **Fichiers** : `src/cccf/config.py`, `tests/test_config.py`
- **Description** : dataclass `Config` avec champs : `rules` (liste de chemins ou identifiants de config Semgrep, requis), `include` (globs, défaut `["**/*"]`), `exclude` (globs, défaut `[".git/**", ".venv/**", "node_modules/**", ".cccf/**"]`), `min_severity` (`INFO`|`WARNING`|`ERROR`, défaut `INFO`), `embedding_model` (défaut `Snowflake/snowflake-arctic-embed-xs`), `semgrep_timeout_s` (défaut 120). Fonction `load_config(repo_root: Path) -> Config` qui lit `<repo_root>/.cccf/config.yml` ; erreur explicite `ConfigError` si fichier absent ou champ `rules` manquant. Fonction `init_config(repo_root, rules_path)` qui écrit un fichier de config par défaut.
- **CA** :
  1. Tests : chargement d'un YAML valide, valeurs par défaut appliquées, erreur claire si `rules` absent, erreur claire si fichier absent.

---

## EPIC 1 — Scanner Semgrep

### [ ] F1.1 — Modèle de données `Finding`
- **Deps** : F0.3
- **Taille** : S
- **Fichiers** : `src/cccf/models.py`, `tests/test_models.py`
- **Description** : dataclass gelée `Finding` : `id: str`, `rule_id: str`, `severity: str` (normalisée `INFO|WARNING|ERROR`), `message: str`, `path: str` (relatif au repo, séparateurs `/`), `start_line: int`, `end_line: int`, `snippet: str`, `fix: str | None`, `cwe: list[str]`, `owasp: list[str]`. Fonction `compute_finding_id(rule_id, path, snippet) -> str` implémentant D5 (normalisation : `" ".join(snippet.split())`, sha256 hex tronqué à 16 caractères).
- **CA** :
  1. Test : deux snippets identiques à l'indentation près donnent le même id.
  2. Test : changer `rule_id`, `path` ou le contenu du snippet change l'id.

### [ ] F1.2 — Exécution Semgrep et parsing JSON
- **Deps** : F1.1, F0.2
- **Taille** : M
- **Fichiers** : `src/cccf/scanner.py`, `tests/test_scanner.py`, `tests/fixtures/semgrep_output.json`
- **Description** : fonction `run_semgrep(repo_root: Path, config: Config, files: list[str] | None) -> list[Finding]`. Elle construit la commande : `semgrep scan --json --quiet --timeout <semgrep_timeout_s>` + un `--config <r>` par entrée de `config.rules` + soit les chemins de `files` (scan ciblé), soit `repo_root` (scan complet). Exécution via `subprocess.run` (capture stdout, `check=False` ; codes retour 0 et 1 = OK car 1 signifie « findings trouvés » ; autre code → exception `SemgrepError` avec stderr). Parsing séparé dans `parse_semgrep_json(raw: str, repo_root: Path) -> list[Finding]` : mapper `results[].check_id → rule_id`, `extra.severity` (mapper aussi les niveaux `LOW/MEDIUM/HIGH/CRITICAL` vers `INFO/WARNING/ERROR/ERROR`), `extra.message`, `path` relativisé, `start.line`/`end.line`, `extra.lines → snippet`, `extra.fix`, `extra.metadata.cwe` et `.owasp` (accepter chaîne ou liste, normaliser en liste). Filtrer sous `min_severity`. `tests/fixtures/semgrep_output.json` : une sortie JSON Semgrep réelle capturée sur le vuln_repo (générée une fois, committée).
- **CA** :
  1. Test unitaire sur la fixture JSON : 2 findings, champs corrects, ids stables.
  2. Test d'intégration (marqué `@pytest.mark.integration`) : `run_semgrep` sur `vuln_repo` retourne 2 findings ; avec `files=["app/db.py"]`, 1 seul.
  3. Test : `min_severity: ERROR` filtre le WARNING.
  4. Test : sortie JSON malformée → `SemgrepError` avec message explicite.

---

## EPIC 2 — Store SQLite

### [ ] F2.1 — Schéma et cycle de vie de la base
- **Deps** : F1.1
- **Taille** : M
- **Fichiers** : `src/cccf/store.py`, `tests/test_store.py`
- **Description** : classe `Store` (context manager) sur `<repo_root>/.cccf/findings.db`. À l'ouverture, créer si besoin les tables :
  - `meta(key TEXT PRIMARY KEY, value TEXT)` — stocke `schema_version` (=`1`), `embedding_model`, `last_index_at` ;
  - `files(path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, indexed_at TEXT NOT NULL)` ;
  - `findings(id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, message TEXT, path TEXT, start_line INT, end_line INT, snippet TEXT, fix TEXT, cwe TEXT, owasp TEXT, embedding BLOB)` avec index sur `path` et `severity` ; `cwe`/`owasp` sérialisés en JSON.
  Méthodes : `replace_findings_for_files(paths: list[str], findings: list[Finding])` (transaction : DELETE des findings de ces paths puis INSERT — c'est l'unique mécanisme de mise à jour, il gère nativement la disparition de findings corrigés), `set_file_hash(path, sha)`, `remove_files(paths)` (supprime lignes `files` + findings associés), `get_file_hashes() -> dict[str, str]`, `all_findings(filters) -> list[Finding]` (filtres optionnels : `severity_at_least`, `rule_id`, `path_glob` via `fnmatch` en Python), `set_embedding(finding_id, vector: np.ndarray)` (stockage `float32.tobytes()`), `iter_embeddings() -> Iterable[tuple[str, np.ndarray]]`, `counts_by(dim)` pour `rule_id`/`severity`.
- **CA** :
  1. Tests : insertion puis relecture fidèle d'un `Finding` complet (y compris cwe liste).
  2. Test : `replace_findings_for_files(["app/db.py"], [])` supprime les findings de ce fichier et ne touche pas les autres.
  3. Test : embedding stocké puis relu égal (np.allclose).
  4. Test : réouverture de la base existante → pas d'erreur, `schema_version` lu.

### [ ] F2.2 — Indexation incrémentale orchestrée
- **Deps** : F2.1, F1.2, F0.3
- **Taille** : M
- **Fichiers** : `src/cccf/indexer.py`, `tests/test_indexer.py`
- **Description** : fonction `index_repo(repo_root, config, store, full: bool = False) -> IndexReport`. Algorithme :
  1. Lister les fichiers du repo matchant `include`/`exclude` (via `pathlib` + `fnmatch`), calculer leur sha256.
  2. Comparer à `store.get_file_hashes()` → ensembles `added`, `modified`, `deleted`, `unchanged`. Si `full=True`, tout est considéré modifié.
  3. `store.remove_files(deleted)`.
  4. Si `added+modified` non vide : `run_semgrep(files=added+modified)` ; regrouper les findings par path ; `replace_findings_for_files(added+modified, findings)` (les fichiers scannés sans finding sont bien passés dans `paths` pour purger leurs anciens findings) ; mettre à jour les hashs.
  5. Retourner `IndexReport(scanned: int, skipped: int, findings_added: int, findings_removed: int, deleted_files: int)`.
  L'embedding n'est PAS fait ici (voir F3.2).
- **CA** :
  1. Test : premier run sur `vuln_repo` copié en tmpdir → 2 findings, `scanned == nb de fichiers`.
  2. Test : second run sans modification → `scanned == 0`, findings inchangés.
  3. Test : corriger `db.py` (remplacer la f-string par une requête paramétrée) puis réindexer → le finding ERROR disparaît, le WARNING reste.
  4. Test : supprimer `shell.py` puis réindexer → son finding disparaît.

---

## EPIC 3 — Embeddings et recherche sémantique

### [ ] F3.1 — Service d'embedding
- **Deps** : F0.3
- **Taille** : S
- **Fichiers** : `src/cccf/embedder.py`, `tests/test_embedder.py`
- **Description** : classe `Embedder(model_name)` chargeant paresseusement (au premier appel) le modèle `sentence-transformers`. Méthodes `embed_texts(texts: list[str]) -> np.ndarray` (batch, normalisation L2, float32) et `embed_query(text) -> np.ndarray`. Fonction module `finding_to_text(f: Finding) -> str` retournant exactement : `f"{f.rule_id} | {f.severity} | {f.message} | {' '.join(f.cwe + f.owasp)} | {f.path} | {' '.join(f.snippet.split())[:500]}"`.
- **CA** :
  1. Test `finding_to_text` : format exact vérifié sur un finding exemple.
  2. Test (marqué `@pytest.mark.slow`, car télécharge le modèle) : `embed_texts` retourne shape `(n, dim)`, vecteurs de norme ≈ 1.

### [ ] F3.2 — Vectorisation des findings à l'indexation
- **Deps** : F3.1, F2.2
- **Taille** : S
- **Fichiers** : `src/cccf/indexer.py` (modification), `tests/test_indexer.py` (ajout)
- **Description** : étendre `index_repo` : après l'étape 4, embedder (`finding_to_text`) les findings nouvellement insérés dont `embedding IS NULL` et les stocker via `set_embedding`. Écrire `embedding_model` dans `meta` ; si le modèle configuré diffère de celui en base, ré-embedder TOUS les findings et mettre à jour `meta`. Paramètre `embedder` injecté (permet un `FakeEmbedder` en test qui retourne des vecteurs déterministes basés sur un hash du texte).
- **CA** :
  1. Test avec `FakeEmbedder` : après indexation, chaque finding a un embedding non nul.
  2. Test : changement de `embedding_model` en config → tous les embeddings recalculés (le fake compte ses appels).

### [ ] F3.3 — Recherche sémantique et agrégats
- **Deps** : F3.2
- **Taille** : M
- **Fichiers** : `src/cccf/search.py`, `tests/test_search.py`
- **Description** :
  - `search_findings(store, embedder, query: str, severity: str | None, rule: str | None, path_glob: str | None, limit: int = 5, offset: int = 0) -> list[SearchHit]` : filtrer d'abord en SQL/fnmatch, puis cosinus (`candidats @ query_vec`, vecteurs déjà normalisés) sur les candidats, tri décroissant, pagination. `SearchHit = (finding: Finding, score: float)`.
  - `summary(store) -> Summary` : totaux par sévérité, top 10 règles avec compte, compte par répertoire de premier niveau.
  - `get_context(repo_root, finding, before: int = 5, after: int = 5) -> str` : lit le fichier source et retourne les lignes `start_line-before` à `end_line+after`, préfixées de leur numéro (`f"{n:>5}| {ligne}"`).
- **CA** :
  1. Test avec `FakeEmbedder` déterministe : la requête reprenant les mots du message SQL classe le finding SQL premier.
  2. Test : filtre `severity="ERROR"` exclut le WARNING ; `path_glob="app/shell*"` ne retourne que shell.
  3. Test `get_context` : numéros de lignes corrects, bornes clampées au fichier.
  4. Test `summary` : comptes exacts sur le vuln_repo indexé.

---

## EPIC 4 — CLI

### [ ] F4.1 — Commandes `init` et `index`
- **Deps** : F2.2, F3.2
- **Taille** : M
- **Fichiers** : `src/cccf/cli.py`, `tests/test_cli.py`
- **Description** : avec `typer.testing.CliRunner` pour les tests.
  - `cccf init [--rules PATH]...` : crée `.cccf/config.yml` (via `init_config`). Sans `--rules`, détecter dans l'ordre `.semgrep.yml`, `semgrep.yml`, `.semgrep/` ; si rien trouvé, échouer avec le message : `Aucune config Semgrep détectée. Relancez avec --rules <chemin-ou-pack>.` Ne jamais écraser une config existante (erreur explicite).
  - `cccf index [--full]` : charge config, ouvre store, `index_repo`, affiche le rapport sur une ligne : `scanned=N skipped=N +findings=N -findings=N` et code retour 0. Erreur Semgrep → message sur stderr, code retour 2, base laissée intacte (NF5 du PRD).
- **CA** :
  1. Test : `init` sur repo sans config Semgrep → code ≠ 0 et message exact ci-dessus.
  2. Test : `init --rules rules/rules.yml` puis `index` (FakeEmbedder injecté via variable d'env `CCCF_FAKE_EMBEDDER=1` gérée dans `cli.py`) → rapport correct.
  3. Test : `index` deux fois → second run `scanned=0`.

### [ ] F4.2 — Commandes `search` et `summary`
- **Deps** : F4.1, F3.3
- **Taille** : M
- **Fichiers** : `src/cccf/cli.py` (modification), `src/cccf/render.py`, `tests/test_cli.py` (ajout)
- **Description** :
  - `cccf search "<query>" [--severity S] [--rule R] [--path GLOB] [--limit N] [--offset N] [--context] [--json]`. Rendu texte compact par ligne de résultat : `1. [ERROR] custom.sql-fstring  app/db.py:12-14  (0.83)` puis le message indenté ; avec `--context`, ajouter le bloc de code de `get_context`. Rendu `--json` : liste d'objets `{id, rule_id, severity, message, path, start_line, end_line, score, fix, cwe, owasp, context?}` — ce schéma est un **contrat** consommé par le MCP (F5) et le skill (F6), ne pas le modifier ensuite.
  - `cccf summary [--json]` : rendu texte 3 lignes max (sévérités, top règles, top répertoires) ; JSON structuré sinon.
  - Si la base n'existe pas : message `Index absent. Lancez d'abord: cccf index` et code 2.
- **CA** :
  1. Test : sortie `--json` de `search` parse en JSON et contient les clés du contrat.
  2. Test : `--context` inclut la ligne incriminée du fichier source.
  3. Test : base absente → message exact et code 2.

---

## EPIC 5 — Serveur MCP

### [ ] F5.1 — Serveur MCP stdio avec tools findings
- **Deps** : F4.2
- **Taille** : M
- **Fichiers** : `src/cccf/mcp_server.py`, `src/cccf/cli.py` (ajout commande `mcp`), `tests/test_mcp_server.py`
- **Description** : serveur `FastMCP` (package `mcp`), lancé par `cccf mcp` (stdio), repo = cwd. Tools :
  - `search_findings(query: str, severity: str | None = None, rule: str | None = None, path_glob: str | None = None, limit: int = 5, include_context: bool = False) -> str` : retourne le JSON du contrat F4.2 sérialisé. Docstring du tool (visible par le LLM) : `Recherche en langage naturel dans les findings Semgrep indexés du repo. Utiliser AVANT de modifier du code pour connaître les problèmes connus, et pour localiser des vulnérabilités par description.`
  - `findings_summary() -> str` : JSON du summary. Docstring : `Vue agrégée des findings (sévérités, top règles). Utiliser pour une vue d'ensemble à faible coût.`
  - `reindex_findings() -> str` : lance `index_repo` incrémental, retourne le rapport en JSON. Docstring : `Met à jour l'index des findings après modification de fichiers. Appeler après un patch pour vérifier la disparition d'un finding.`
  La logique métier est appelée directement (pas de subprocess vers `cccf`). Toute exception → retour JSON `{"error": "<message>"}`, jamais de crash du serveur.
- **CA** :
  1. Test : via le client in-memory de `mcp` (ou appel direct des fonctions tools), `search_findings` sur le vuln_repo indexé retourne le JSON attendu.
  2. Test : repo non indexé → `{"error": ...}` explicite, le serveur répond encore ensuite.
  3. `cccf mcp --help` documente l'enregistrement client : bloc JSON `{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}`.

### [ ] F5.2 — Tool combiné `search_code_with_findings` (jointure CCC)
- **Deps** : F5.1
- **Taille** : M
- **Fichiers** : `src/cccf/ccc_bridge.py`, `src/cccf/mcp_server.py` (modification), `tests/test_ccc_bridge.py`
- **Description** : c'est la jointure D1 avec CCC.
  - `ccc_bridge.search_code(repo_root, query, limit) -> list[CodeHit]` : exécute `ccc search "<query>" --json --limit N` en subprocess ; parser `path`, `start_line`, `end_line`, `score`, `content` (adapter les noms de clés à la sortie réelle de `ccc` ; si le format diffère, corriger le parsing, pas le reste). Si `ccc` absent du PATH ou erreur → `CccUnavailable`.
  - `annotate_with_findings(code_hits, store) -> list[dict]` : pour chaque hit, joindre les findings dont `path` égal et dont `[start_line, end_line]` **chevauche** la plage du hit ; ajouter au hit `findings: [contrat F4.2 sans context]` et `max_severity`.
  - Tool MCP `search_code_with_findings(query, limit=5)` : retourne les hits annotés en JSON ; si `CccUnavailable`, retourner `{"error": "ccc non disponible", "fallback": <résultat de search_findings(query)>}` — le tool reste utile sans CCC. Docstring : `Recherche sémantique de code (via ccc) annotée des findings Semgrep connus sur chaque résultat. Outil à privilégier pour explorer du code en tenant compte de sa dette sécurité.`
- **CA** :
  1. Test unitaire `annotate_with_findings` avec hits factices : chevauchement inclusif correct (hit 10–20 matche finding 20–22 ? oui si chevauche d'au moins une ligne : 20 ∈ [10,20] → oui ; hit 10–19 vs finding 20–22 → non).
  2. Test avec un faux `ccc` (script shell dans le PATH du test émettant un JSON fixe) : sortie annotée conforme.
  3. Test : `ccc` absent → fallback avec la clé `fallback` renseignée.

---

## EPIC 6 — Skill agent et boucle de correction

### [ ] F6.1 — Skill Claude Code
- **Deps** : F5.2
- **Taille** : S
- **Fichiers** : `skills/cccf/SKILL.md`
- **Description** : rédiger le skill (frontmatter `name: cccf`, `description` avec les déclencheurs : vulnérabilité, sécurité, semgrep, finding, dette, audit). Corps — les 4 workflows, chacun en étapes numérotées avec le tool exact à appeler :
  1. *Explorer les problèmes connus* : `search_findings` (limit 5, puis `include_context: true` sur le finding retenu).
  2. *Avant de modifier un fichier* : `search_findings(path_glob="<fichier>*")`.
  3. *Boucle de correction* (la référence UC3) : `search_findings` → lire le contexte → patcher (en respectant `fix` s'il existe) → **vérification fraîche via le MCP Semgrep officiel** `semgrep_scan` sur le seul fichier modifié si ce serveur est disponible → `reindex_findings` → re-`search_findings` sur le même filtre pour confirmer la disparition → si le finding persiste, ne PAS réessayer plus de 2 fois, rapporter.
  4. *Vue d'ensemble* : `findings_summary`.
  Inclure une section « Anti-patterns » : ne pas scanner tout le repo via le MCP Semgrep (utiliser l'index), ne pas corriger un finding sans avoir lu son contexte, ne pas supprimer un commentaire `# nosemgrep` existant.
- **CA** :
  1. Le fichier respecte le format skill (frontmatter YAML valide, < 150 lignes).
  2. Chaque workflow cite uniquement des tools existants (F5.1/F5.2 + `semgrep_scan` du MCP officiel).

### [ ] F6.2 — Documentation d'installation et README
- **Deps** : F6.1
- **Taille** : S
- **Fichiers** : `README.md`
- **Description** : README couvrant : installation (`uv tool install ccc-findings` + `pipx install semgrep`), démarrage (`cccf init` → `cccf index` → `cccf search`), enregistrement MCP (bloc JSON de F5.1 + celui du MCP Semgrep officiel `uvx semgrep-mcp` pour la vérification post-patch), configuration `.cccf/config.yml` commentée champ par champ, positionnement vs CCC (2 phrases + renvoi au `PRD.md`).
- **CA** :
  1. Toutes les commandes du README sont copiables-collables et cohérentes avec le CLI réel (vérifier chaque `--flag` contre `cccf --help`).

---

## EPIC 7 — Qualité et évaluation

### [ ] F7.1 — Jeu d'évaluation de pertinence
- **Deps** : F4.2
- **Taille** : M
- **Fichiers** : `eval/queries.yml`, `eval/run_eval.py`, `tests/fixtures/vuln_repo/app/` (2 fichiers vulnérables supplémentaires + 2 règles ajoutées dans `rules.yml`)
- **Description** : enrichir le vuln_repo à ≥ 4 findings distincts (ajouter p.ex. un `yaml.load` sans Loader → règle `custom.unsafe-yaml`, et un `random.random` pour usage crypto → règle `custom.weak-random`). `queries.yml` : ≥ 8 requêtes NL en français et en anglais, chacune avec le `finding_id_attendu` (par `rule_id` + `path`). `run_eval.py` : indexe le repo avec le VRAI embedder, exécute chaque requête, calcule le **top-3 hit rate**, affiche le tableau requête/attendu/obtenu/rang, code retour ≠ 0 si hit rate < 0.75.
- **CA** :
  1. `uv run python eval/run_eval.py` s'exécute et affiche un hit rate ≥ 0.75. Si < 0.75 : ajuster `finding_to_text` (F3.1) et documenter le changement dans le rapport de tâche — c'est le seul cas autorisé de retour sur une tâche antérieure.

### [ ] F7.2 — Test de bout en bout
- **Deps** : F5.2, F4.2
- **Taille** : S
- **Fichiers** : `tests/test_e2e.py`
- **Description** : test d'intégration (marqué `integration`) déroulant le scénario complet sur une copie tmpdir du vuln_repo, avec le vrai Semgrep et le FakeEmbedder : `init` → `index` → `search --json` (finding SQL trouvé) → correction du fichier `db.py` → `index` → `search` (finding disparu) → `summary` cohérent. Utiliser le CliRunner, chaîner les asserts sur les sorties JSON.
- **CA** :
  1. `uv run pytest -m integration` passe.
  2. Le test échoue de façon lisible si une étape casse (asserts avec messages).

---

## Ordre d'exécution recommandé

```
F0.1 → F0.2 → F0.3 → F1.1 → F1.2 → F2.1 → F2.2 → F3.1 → F3.2 → F3.3
     → F4.1 → F4.2 → F5.1 → F5.2 → F6.1 → F6.2 → F7.1 → F7.2
```

Jalons PRD : fin F4.2 = **M1 (MVP CLI)** · fin F6.2 = **M2 (intégration agent)** · fin F7.2 = **M3 (V1)**.
