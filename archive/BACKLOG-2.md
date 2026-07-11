# Backlog 2 — Corrections issues de la revue de code (2026-07-12)

> Résultats de la revue multi-angles (8 finders + vérification empirique) menée sur
> l'ensemble du module livré (F0.1 → F7.2). 10 findings confirmés, classés par
> sévérité décroissante, plus 3 thèmes de nettoyage transverses.
> Conventions identiques à `BACKLOG.md` : une tâche = un commit (`R<n>: <titre>`),
> DoD globale inchangée (`uv run pytest` vert, `ruff check` propre).

## Findings de correction (correctness / efficacité)

### [x] R1 — Les fichiers racine du repo ne sont jamais indexés
- **Fichier** : `src/cccf/indexer.py:36` (+ `src/cccf/config.py` `DEFAULT_INCLUDE`)
- **Sévérité** : CRITIQUE — trou d'index silencieux
- **Vérifié** : `fnmatch("setup.py", "**/*") == False` (fnmatch exige un `/` dans le chemin)
- **Scénario** : un repo avec un `setup.py` vulnérable à la racine et la config par
  défaut → `cccf index` le saute sans erreur, aucun finding n'entre en base. Les
  tests passent uniquement parce que `vuln_repo` n'a aucun fichier racine.
- **Fix proposé** : normaliser la sémantique d'include (traiter `**/*` comme
  « tout », ou tester aussi `fnmatch(rel_path, "*")` pour les chemins sans `/`),
  et ajouter un fichier racine vulnérable au fixture pour verrouiller le cas.

### [x] R2 — Les répertoires `tests/` des repos utilisateurs sont silencieusement exclus du scan
- **Fichier** : `src/cccf/scanner.py:110` (`run_semgrep`)
- **Sévérité** : CRITIQUE — fausse impression de sécurité
- **Contexte** : le `.semgrepignore` racine ajouté en F0.2 ne corrige que CE repo ;
  le `.semgrepignore` par défaut de Semgrep (pattern `tests/`) reste actif dans
  tout repo cible.
- **Scénario** : chez un utilisateur, `cccf index` affiche `scanned=N` sans erreur,
  mais les vulnérabilités des helpers de test (credentials en dur, injections dans
  les utilitaires) sont absentes de l'index, sans aucun signal.
- **Fix proposé** : faire de `config.include/exclude` la source de vérité unique du
  périmètre : passer `--x-ignore-semgrepignore-files` (flag interne, à pin de
  version) OU générer un `.semgrepignore` dans le repo cible depuis la config, OU a
  minima remonter le rapport `paths.skipped` de Semgrep en avertissement.

### [x] R3 — `CCCF_FAKE_EMBEDDER` peut empoisonner un index de prod de façon indétectable
- **Fichier** : `src/cccf/cli.py:87` (`_make_embedder`, `_FakeEmbedder`)
- **Sévérité** : HAUTE
- **Scénario** : indexer avec la variable posée (vecteurs sha256 8-dim, mais
  `meta.embedding_model` enregistre le nom du VRAI modèle) puis chercher sans →
  `ValueError: shapes (8,) and (384,) not aligned`, traceback brut. Une
  réindexation incrémentale mixe les dimensions en base de façon permanente.
- **Fix proposé** : sortir le hook de test du code de prod (injection de
  l'embedder au point de composition, fake déplacé dans `tests/conftest.py`) ; si
  un switch runtime reste souhaité, l'enregistrer dans `meta` pour que
  l'incompatibilité index/requête soit détectée et déclenche un ré-embed.

### [x] R4 — Le serveur MCP recharge le modèle d'embedding à chaque appel de tool
- **Fichier** : `src/cccf/mcp_server.py:44` (et `:91`)
- **Sévérité** : HAUTE — NF1 (p95 < 1 s) structurellement inatteignable
- **Scénario** : le cache de `Embedder._load` est par instance et `_make_embedder`
  est appelé à chaque invocation de `search_findings`/`reindex_findings` → 1 à 5 s
  de chargement disque par requête dans un processus longue durée.
- **Fix proposé** : factory public `make_embedder(model_name)` dans `embedder.py`
  avec `functools.lru_cache`, importé par `cli.py` ET `mcp_server.py` (règle au
  passage l'inversion de dépendance MCP → CLI, voir N2).

### [x] R5 — Un seul fichier non-UTF-8 fait échouer toute l'indexation
- **Fichier** : `src/cccf/scanner.py:44` (`_read_snippet`)
- **Sévérité** : HAUTE
- **Scénario** : un fichier legacy latin-1 (un `é` en 0xE9 dans un commentaire
  suffit) matché par une règle → `read_text()` lève `UnicodeDecodeError`
  (sous-classe de `ValueError`, pas de `OSError`) → `cccf index` meurt en
  traceback, le rollback de `Store` annule tout : rien n'est indexé.
- **Fix proposé** : `read_text(encoding="utf-8", errors="replace")` + catch
  élargi ; à terme préférer `extra.lines` de Semgrep quand disponible (voir R6).

### [x] R6 — Collision d'IDs de findings quand le snippet est vide ou dupliqué
- **Fichiers** : `src/cccf/scanner.py:46`, `src/cccf/models.py:5`, `src/cccf/store.py:130`
- **Sévérité** : HAUTE — sous-rapportage silencieux
- **Scénario** : fichier illisible (course de suppression, permissions CI) →
  snippet `""` → `compute_finding_id(rule, path, "")` identique pour tous les
  findings de même règle+chemin → l'upsert `ON CONFLICT(id)` n'en garde qu'un ;
  `summary`/`search` sous-rapportent sans signal. Même mécanisme pour deux
  occurrences identiques de la même ligne vulnérable dans un fichier lisible.
- **Fix proposé** : inclure `start_line` dans l'identité (évolution de D5, migration
  de schéma nécessaire) ou échouer bruyamment sur snippet vide ; remplacer l'upsert
  par un INSERT strict + assertion, pour que toute collision devienne visible.

### [x] R7 — `get_context` crashe sur index périmé et détruit tout le résultat MCP
- **Fichier** : `src/cccf/search.py:72` (+ `render.py`, `mcp_server.py`)
- **Sévérité** : MOYENNE-HAUTE — frappe précisément la boucle de correction du skill
- **Scénario** : indexer, puis supprimer/renommer un fichier flaggé sans réindexer
  (état transitoire normal de la boucle F6.1) → `search --context` lève
  `FileNotFoundError` en traceback ; via MCP avec `include_context=true`, le
  `except` global transforme TOUS les hits (y compris valides) en un unique
  `{"error": ...}`.
- **Fix proposé** : dégrader par finding (`context: null` + champ `context_error`)
  au lieu de globalement.

### [ ] R8 — « too many SQL variables » au premier index d'un gros monorepo
- **Fichier** : `src/cccf/store.py:111` (`remove_files`, `replace_findings_for_files`)
- **Sévérité** : MOYENNE
- **Vérifié** : SQLite 3.50.4 du venv → `OperationalError` à 40 000 paramètres
  (limite 32 766).
- **Scénario** : premier `cccf index` d'un repo de plus de ~32 k fichiers →
  `changed` contient tous les chemins, le `DELETE ... IN (?,...)` explose,
  l'indexation entière échoue.
- **Fix proposé** : batcher les clauses `IN` par tranches de ~900 paramètres
  (helper unique partagé par les deux méthodes).

### [ ] R9 — Compteurs de findings faux : chemins littéraux passés comme motifs fnmatch
- **Fichier** : `src/cccf/indexer.py:86` (et `:92`) → `store.all_findings(path_glob=p)`
- **Sévérité** : MOYENNE
- **Vérifié** : `fnmatch("app/[id].py", "app/[id].py") == False` (convention
  Next.js/SvelteKit).
- **Scénario** : le compteur `-findings=` (rapport CLI et JSON MCP) est faux pour
  ces fichiers — le DELETE réel (égalité SQL) est correct, donc les compteurs
  divergent du réel. En prime O(chemins × findings) : 500 fichiers modifiés sur
  10 k findings = 500 full-scans pour un compteur.
- **Fix proposé** : `SELECT COUNT(*) FROM findings WHERE path IN (...)` (nouvelle
  méthode `Store.count_findings_for_paths`), fnmatch réservé aux vrais globs
  utilisateur.

### [ ] R10 — `min_severity` durci dans la config n'est jamais appliqué à l'index existant
- **Fichier** : `src/cccf/scanner.py:129` (filtre au scan uniquement)
- **Sévérité** : MOYENNE
- **Scénario** : indexer avec `min_severity: INFO` (le WARNING de `shell.py` entre
  en base), passer la config à `ERROR` → l'index incrémental répond `scanned=0`
  (les hashs de fichiers n'ont pas changé, la config n'est pas hachée) et
  `search`/`summary` continuent de servir le WARNING indéfiniment.
- **Fix proposé** : appliquer aussi le seuil à la lecture (`all_findings`), ou
  inclure un hash de la config dans `meta` et forcer un full scan quand il change.

## Nettoyage transverse (reuse / architecture)

### [ ] N1 — Unifier l'ordre des sévérités (défini 4×)
- `scanner.py:9`, `store.py:13`, `ccc_bridge.py:9` (`_SEVERITY_RANK`),
  `config.py:12` (`VALID_SEVERITIES`) → une seule constante dans `models.py`,
  rang dérivé. Ajouter un niveau aujourd'hui = 4 éditions synchronisées, avec
  `KeyError`/`ValueError` runtime si on en oublie une.

### [ ] N2 — Un seul factory d'embedder, un seul faux embedder
- 3 fakes quasi identiques (`cli.py:_FakeEmbedder`, `tests/test_indexer.py`,
  `tests/test_search.py`) et `mcp_server.py` qui importe le privé
  `cli._make_embedder` (inversion de dépendance MCP → CLI, qui tire typer).
  → factory public dans `embedder.py`, fakes dans `tests/conftest.py`
  (conftest à créer : les fixtures repo_copy sont aussi dupliquées dans 5 fichiers
  de test). Se traite naturellement avec R3 et R4.
- **Statut revue 2026-07-12** : partiellement traité par A4/R4/R3
  (`make_embedder` public et cache côté runtime, plus d'import MCP → CLI). Reste
  ouvert tant que les fakes/fixtures de tests ne sont pas unifiés dans
  `tests/conftest.py`.

### [ ] N3 — Une seule sérialisation `Finding → dict` et un seul rendu summary
- `ccc_bridge._finding_to_dict` duplique le mapping de `render.render_search_json`
  (et omet `score`, contrat F4.2 non respecté pour `search_code_with_findings`) ;
  `mcp_server.findings_summary` recopie inline `render.render_summary_json`.
  → `render.finding_to_dict()` unique, importé partout ; MCP appelle
  `render_summary_json`.

## Notes hors backlog

- **Transparence DoD** : `addopts = "-m 'not slow'"` (ajouté en F3.1 dans
  `pyproject.toml`) fait que `uv run pytest` n'exécute jamais le test slow du
  modèle réel. À arbitrer : le garder (confort) ou l'enlever et marquer le test
  `skipif` sans réseau.
- **Fragilité assumée** : `ccc_bridge` parse le format texte de `ccc search`
  (pas de `--json` dans la version installée). Si `ccc` change son affichage,
  le parsing retourne une liste vide silencieuse — traiter « stdout non vide mais
  0 blocs parsés » comme `CccUnavailable` pour déclencher le fallback existant.

## Ordre d'exécution recommandé

```
R1 → R2 (complétude d'index, la valeur du produit en dépend)
   → R5 → R6 (robustesse indexation)
   → R4 + R3 + N2 (perf MCP + hygiène embedder, même chantier)
   → R7 → R10 → R9 → R8 → N1 → N3
```
