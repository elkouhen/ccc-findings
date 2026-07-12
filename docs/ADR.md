# Architecture Decision Records — ccc-findings (`cccf`)

> Une entrée par décision structurante : contexte, décision, conséquences.
> Les ADR-1 à ADR-6 sont les décisions actées avant l'implémentation (issues
> de `archive/BACKLOG.md` §« Décisions d'architecture », non rediscutées
> pendant le développement). Les ADR-7 à ADR-11 ont été prises en cours de
> route face à des écarts entre la spécification et le comportement réel des
> outils externes (Semgrep, `ccc`) ou de l'environnement d'exécution.

---

## ADR-1 — Package compagnon Python, pas un fork de `cocoindex-code`

**Statut** : Acté.

**Contexte** : le PRD (§13, question ouverte 1) hésitait entre contribuer en
amont à `cocoindex-code` ou livrer un package séparé.

**Décision** : `ccc-findings` (CLI `cccf`) est un package Python indépendant,
sans dépendance aux API internes de `ccc`. La jointure avec `ccc` se fait à
la requête, via subprocess (`ccc search ...`) et recouvrement
fichier + plage de lignes — jamais d'import de code interne de `ccc`.

**Conséquences** : zéro risque de casse si `ccc` change ses API internes ;
en contrepartie, la jointure dépend du format de sortie **texte** de `ccc`
(voir ADR-10) plutôt que d'une API stable.

---

## ADR-2 — Store SQLite unique, cosinus brute-force

**Statut** : Superseded par ADR-17 (le stockage reste SQLite unique, mais le
calcul de similarité n'est plus du brute-force NumPy).

**Contexte** : un repo compte au plus quelques milliers de findings.

**Décision** : un seul fichier `.cccf/findings.db` (SQLite), embeddings
stockés en `BLOB` (`float32.tobytes()`), similarité cosinus calculée en
Python/NumPy par force brute (chargement de tous les embeddings, produit
scalaire).

**Conséquences** : latence < 50 ms pour quelques milliers de findings, zéro
dépendance à un index vectoriel externe (LMDB/ANN). Ne passera pas à
l'échelle au-delà de ~50-100k findings — non traité, hors échelle cible V1.

---

## ADR-3 — Embeddings via `sentence-transformers`, modèle par défaut Snowflake arctic-embed-xs

**Statut** : Acté.

**Contexte** : cohérence avec `ccc`, contrainte local-first.

**Décision** : `sentence-transformers`, modèle par défaut
`Snowflake/snowflake-arctic-embed-xs` (même défaut que `ccc`), configurable
via `config.embedding_model`.

**Conséquences** : téléchargement du modèle au premier usage (accès réseau
one-shot, voir note environnement dans `SPEC-TECH.md` §8) ; un changement de
modèle déclenche un ré-embedding complet de la base (`indexer.index_repo`,
comparaison `meta.embedding_model` vs `config.embedding_model`).

---

## ADR-4 — Règles Semgrep locales dans les tests, jamais de pack registry

**Statut** : Acté.

**Contexte** : déterminisme et exécution hors-ligne des tests.

**Décision** : les fixtures de test (`tests/fixtures/vuln_repo/rules/rules.yml`)
définissent des règles Semgrep locales ; aucun test n'utilise un pack
`p/...` du registry.

**Conséquences** : tests reproductibles sans connexion réseau ; en
contrepartie, ne couvre pas les particularités de comportement des packs
registry réels (versions, méta-données supplémentaires).

---

## ADR-5 — Identité stable d'un finding : hash règle + chemin + snippet normalisé

**Statut** : Acté.

**Contexte** : permettre le diff entre indexations et la déduplication sans
dépendre des numéros de ligne (qui bougent).

**Décision** :
`compute_finding_id = sha256(f"{rule_id}|{path}|{snippet_normalisé}")[:16]`,
où `snippet_normalisé = " ".join(snippet.split())`.

**Conséquences** : survit aux décalages de lignes causés par des édits
ailleurs dans le fichier. Trade-off accepté puis identifié comme limite
réelle en revue : deux findings de même règle/chemin avec un snippet
identique (ligne dupliquée, ou snippet vide sur fichier illisible)
collisionnent — voir défaut connu R6 dans `archive/BACKLOG-2.md`, non corrigé
à ce jour.

---

## ADR-6 — Python ≥ 3.10, `uv`, `pytest`

**Statut** : Acté.

**Décision** : alignement sur l'écosystème `cocoindex-code` — gestion de
projet `uv`, tests `pytest`, lint `ruff`.

---

## ADR-7 — `.semgrepignore` racine pour neutraliser l'exclusion par défaut de `tests/`

**Statut** : Acté (limité au repo `ccc-findings` lui-même — voir limite
ci-dessous).

**Contexte** : Semgrep (v1.168, celle installée dans l'environnement de
développement) embarque un motif d'ignore par défaut `tests/` — tout chemin
contenant un composant de répertoire nommé `tests` est silencieusement exclu
du scan, y compris quand il est explicitement passé en cible. Or D4 (ADR-4)
impose des fixtures sous `tests/fixtures/vuln_repo/`, et ce repo est lui-même
un dépôt git — la commande de vérification F0.2 (`semgrep scan --config
tests/fixtures/vuln_repo/rules/rules.yml tests/fixtures/vuln_repo/app --json`)
retournait 0 findings au lieu de 2, exactement à cause de ce défaut.

**Décision** : ajout d'un fichier `.semgrepignore` à la racine du repo
`ccc-findings`, contenant `!tests/`, pour ré-inclure explicitement l'arbre
`tests/` dans les scans de ce projet. Décision validée avec l'utilisateur
avant application (sortait du périmètre `Fichiers` déclaré de la tâche F0.2).

**Conséquences** : corrige le repo `ccc-findings` lui-même. **Ne corrige
PAS** le cas général — dans tout repo cible d'un utilisateur de `cccf`, le
même défaut Semgrep s'applique : ses répertoires `tests/` sont silencieusement
absents de l'index, sans erreur ni avertissement (voir défaut connu R2 dans
`archive/BACKLOG-2.md`, non résolu pour les repos utilisateurs).

---

## ADR-8 — Snippet lu depuis le fichier source, pas depuis `extra.lines` de Semgrep

**Statut** : Acté.

**Contexte** : la spécification F1.2 prévoyait de mapper `extra.lines` (champ
JSON de Semgrep) directement vers `Finding.snippet`. En pratique, la version
de Semgrep installée retourne la chaîne littérale `"requires login"` pour ce
champ tant que l'utilisateur n'est pas authentifié sur semgrep.dev — un
changement de comportement de l'OSS CLI, gating une fonctionnalité derrière
un compte.

**Décision** : `scanner._read_snippet` relit directement les lignes
`[start_line, end_line]` du fichier source sur disque (`repo_root / path`)
plutôt que d'utiliser `extra.lines`. Décision prise sans consultation
préalable car imposée par les contraintes déjà actées D4/NF4 (tests
hors-ligne, local-first) — exiger un `semgrep login` aurait violé ces deux
contraintes non-négociables.

**Conséquences** : fonctionne hors-ligne, sans compte, et donne un snippet
non tronqué (contrairement à `extra.lines` qui a une limite de lignes/
caractères côté Semgrep). Introduit une dépendance à la lisibilité du fichier
au moment du parsing (`OSError` → snippet vide, voir défaut connu R6).

---

## ADR-9 — `run_semgrep` cible `"."` (et non le chemin absolu du repo) pour un scan complet

**Statut** : Acté.

**Contexte** : Semgrep préfixe le `check_id` retourné avec les composants de
répertoire de l'argument `--config` **tel qu'il est passé sur la ligne de
commande** (pas relatif au répertoire de travail réel). Avec
`config.rules = ["rules/rules.yml"]` et `cwd=repo_root`, cela produit
`rules.custom.sql-fstring` plutôt que `custom.sql-fstring`. Par ailleurs,
scanner avec une cible en chemin absolu fait ressortir des chemins absolus
dans les résultats JSON, ce qui rend les fixtures de test (committées) non
portables d'une machine à l'autre.

**Décision** : `run_semgrep` invoque toujours Semgrep avec `cwd=repo_root` et
une cible relative (`"."` pour un scan complet, chemins relatifs pour un
scan ciblé), jamais de chemin absolu en argument.

**Conséquences** : les fixtures JSON committées (`tests/fixtures/semgrep_output.json`)
sont portables entre machines. Le préfixe de `rule_id` reste un effet de bord
accepté (documenté dans `SPEC-TECH.md` §4) plutôt que masqué — le contrat
n'exige pas que `rule_id` soit strictement identique à l'`id` déclaré dans le
fichier de règles.

---

## ADR-10 — `ccc_bridge` parse la sortie texte de `ccc search`, pas du JSON

**Statut** : Acté.

**Contexte** : la spécification F5.2 prévoyait `ccc search "<query>" --json
--limit N`. La version de `ccc` installée dans l'environnement de
développement n'expose **aucun** flag `--json` sur sa commande `search`
(vérifié via `ccc search --help` et confirmé par un code de sortie 2 et
« No such option: --json » à l'exécution).

**Décision** : `ccc_bridge.search_code` invoque `ccc search <query> --limit
N` sans `--json` et parse le format texte réel de sortie (blocs
`--- Result N (score: X) ---` / `File: chemin:début-fin [langage]`).

**Conséquences** : fonctionne avec la version de `ccc` réellement installée.
Contrat fragile par nature — un changement de format d'affichage de `ccc`
casse le parsing silencieusement (bloc ignoré, pas d'erreur — voir
`archive/BACKLOG-2.md`, note « fragilité assumée »). Piste de durcissement
identifiée mais non implémentée : détecter l'absence de blocs parsés sur une
sortie non vide et basculer sur `CccUnavailable` pour déclencher le fallback
existant.

---

## ADR-11 — Exclusion par défaut des tests `@pytest.mark.slow`

**Statut** : Acté — à réévaluer (voir note).

**Contexte** : le test vérifiant `Embedder.embed_texts` avec le vrai modèle
sentence-transformers télécharge ~100 Mo depuis Hugging Face. Dans
l'environnement de développement, ce téléchargement échouait par défaut
(interception TLS d'un proxy d'entreprise, `CERTIFICATE_VERIFY_FAILED`) et
n'est pas garanti disponible dans tous les environnements d'exécution
(sandboxes sans réseau, CI restreinte).

**Décision** : `pyproject.toml` déclare `addopts = "-m 'not slow'"` — `uv run
pytest` sans argument n'exécute jamais les tests marqués `slow`. Le test a
été exécuté et vérifié manuellement (`uv run pytest -m slow`, avec un accès
réseau correctement configuré) : passe (shape correcte, normes ≈ 1).

**Conséquences** : `uv run pytest` (sans argument) ne couvre plus ce test à
chaque exécution — un affaiblissement de la DoD « `uv run pytest` passe
entièrement », documenté dans le commit F3.1 et dans `archive/BACKLOG-2.md`.
Alternative non retenue : `pytest.mark.skipif` conditionné à la présence
réseau, qui aurait gardé le test dans le run par défaut tout en le
neutralisant proprement en environnement isolé.

---

## ADR-12 — Le skill Claude Code est distribué hors du repo `ccc-findings`

**Statut** : Acté (sur demande explicite de l'utilisateur).

**Contexte** : F6.1 avait livré `skills/cccf/SKILL.md` comme partie du
package `ccc-findings`. L'utilisateur a demandé de déplacer ce fichier vers
`~/cocoindex-ext-skill/SKILL.md`, en dehors du repo, avec suppression de la
copie versionnée (pas une simple copie de commodité).

**Décision** : `skills/cccf/SKILL.md` est retiré du repo `ccc-findings` ;
le skill vit désormais uniquement dans `~/cocoindex-ext-skill/SKILL.md`
(fichier `SKILL.md` à la racine de ce répertoire, convention Claude Code
d'un dossier = un skill). `docs/SPEC-FONC.md` §4 et le `README.md` sont mis à
jour pour pointer vers ce nouvel emplacement plutôt que documenter un chemin
qui n'existe plus dans ce repo.

**Conséquences** : le package `ccc-findings` (pip/uv) ne contient plus le
skill — quiconque installe seulement `ccc-findings` doit récupérer le
`SKILL.md` séparément pour l'activer dans Claude Code. `archive/BACKLOG.md`
(tâche F6.1, historique figé) continue de mentionner `skills/cccf/SKILL.md`
comme périmètre de fichiers : exact au moment de son exécution, plus exact
aujourd'hui — ne pas corriger un document archivé, seuls les documents
vivants (`docs/`, `README.md`) reflètent l'état courant.

---

## ADR-13 — `cccf init` se replie sur un pack registry par défaut

**Statut** : Acté (sur demande explicite de l'utilisateur — revient sur un
choix antérieur).

**Contexte** : le PRD initial (§12, question ouverte 2) avait tranché pour
une config Semgrep explicite obligatoire, afin d'éviter le bruit d'un pack
par défaut mal calibré. L'utilisateur a demandé, après usage, de pouvoir
utiliser les bibliothèques de règles standard de Semgrep sans avoir à
définir de `rules` explicitement.

**Décision** : quand `cccf init` ne reçoit ni `--rules` ni ne détecte de
config Semgrep locale (`.semgrep.yml`/`semgrep.yml`/`.semgrep`), il se
replie sur le pack registry `p/security-audit` plutôt que d'échouer. Un
message informatif (stdout, code de sortie 0) indique le pack utilisé et
comment le personnaliser via `--rules`. Choix de `p/security-audit` plutôt
que `p/default` : cohérent avec le positionnement sécurité du produit (CWE/
OWASP dans le modèle de données, cas d'usage centrés vulnérabilités). Ordre
de priorité inchangé : `--rules` explicite > config locale détectée > pack
par défaut.

**Conséquences** : lève la friction de démarrage (plus besoin d'écrire des
règles custom pour essayer `cccf`) au prix du bruit que le choix initial
voulait éviter — un pack généraliste peut remonter des findings peu
pertinents pour un projet donné. Vérifié manuellement : le pack se
télécharge et s'exécute avec succès dans l'environnement de développement
(`semgrep scan --config p/security-audit`, ~225 règles Python chargées) ;
sa couverture réelle sur un cas donné dépend du contenu du registry Semgrep,
hors du contrôle de `cccf`. `docs/PRD.md` §12 point 2 est mis à jour pour
refléter que cette question n'est plus ouverte.

---

## ADR-14 — Le périmètre `cccf` prime sur les ignores Semgrep

**Statut** : Acté.

**Contexte** : la revue architecture a confirmé deux trous d'index silencieux :
`include: ["**/*"]` ne matchait pas les fichiers à la racine avec `fnmatch`, et
Semgrep pouvait exclure des répertoires `tests/` via ses mécanismes d'ignore
avant même que `cccf` ne parse les résultats.

**Décision** : `cccf` traite explicitement `**/*` comme « tout fichier du repo »
pendant la phase de hashing, et invoque Semgrep avec
`--x-ignore-semgrepignore-files` pour que le périmètre sélectionné par
`.cccf/config.yml` reste la source de vérité.

**Conséquences** : les fichiers racine et les répertoires `tests/` ne sont plus
silencieusement absents de l'index. Le choix repose sur un flag Semgrep interne
non garanti comme API stable ; si Semgrep le retire, `run_semgrep` échouera
bruyamment plutôt que de produire un index incomplet sans signal.

---

## ADR-15 — L'identité d'un finding inclut sa localisation

**Statut** : Acté.

**Contexte** : l'identité historique `hash(rule_id|path|snippet_normalisé)`
résistait aux décalages de lignes, mais fusionnait deux occurrences identiques
de la même règle dans un même fichier, et fusionnait encore plus facilement des
findings au snippet vide.

**Décision** : l'identité calculée par `compute_finding_id` inclut désormais la
plage `start_line:end_line` en plus de la règle, du chemin et du snippet
normalisé.

**Conséquences** : deux occurrences identiques restent distinctes en base et ne
s'écrasent plus via la clé primaire. En contrepartie, un finding dont le code ne
change pas mais dont la ligne se décale reçoit un nouvel identifiant ; c'est
accepté pour privilégier l'absence de sous-rapportage silencieux.

---

## ADR-16 — Signature et dimension des embeddings stockées dans l'index

**Statut** : Acté.

**Contexte** : le hook `CCCF_FAKE_EMBEDDER=1` utilisé en test pouvait créer une
base avec des vecteurs 8 dimensions tout en enregistrant seulement le nom du
modèle réel, puis une recherche avec le vrai modèle échouait tardivement dans
NumPy.

**Décision** : chaque embedder expose une `signature` qui encode son type et son
modèle. `index_repo` stocke `embedding_signature` et `embedding_dim` dans la
table `meta`, ré-embedde tout lorsque la signature change, et la recherche
vérifie explicitement la dimension des vecteurs avant le produit scalaire.

**Conséquences** : les index mixtes ou corrompus produisent une erreur
actionnable demandant une réindexation complète, au lieu d'un traceback brut ou
de scores incohérents. Le fake embedder reste disponible pour les tests, mais sa
signature distincte empêche de le confondre avec le modèle de production.

---

## ADR-17 — Recherche vectorielle via `sqlite-vec` (`vec0`), plus de brute-force NumPy

**Statut** : Acté. Supersede ADR-2.

**Contexte** : `ccc` (cocoindex-code) — dont `cccf` réutilise déjà le modèle
d'embedding par défaut (ADR-3) — stocke son propre index dans
`.cocoindex_code/target_sqlite.db` via le connector `cocoindex.connectors.sqlite`,
qui s'appuie sur l'extension `sqlite-vec` (tables virtuelles `vec0`, distance
SIMD) plutôt que sur un calcul brute-force. `cccf` restait sur du SQLite
« nu » avec cosinus calculé en Python/NumPy (ADR-2) : correct à l'échelle
cible mais incohérent avec l'outil dont il hérite déjà le choix de format
d'embedding, et moins performant sans bénéfice de simplicité additionnel
(`sqlite-vec` est déjà une dépendance transitive de l'écosystème `ccc`).

**Décision** : les embeddings ne sont plus stockés en `BLOB` dans la table
`findings`, mais dans une table virtuelle `vec0` dédiée (`vec_findings`,
colonne `embedding float[N] distance_metric=cosine`, colonne auxiliaire
`+finding_id TEXT` pour la jointure retour). `Store.knn_search` délègue le
calcul de similarité à `sqlite-vec` (`... WHERE embedding MATCH ? AND k = ?`)
au lieu d'itérer en Python. Comme `vec0` ne supporte ni `ALTER TABLE` ni clé
primaire arbitraire, la dimension du vecteur double comme signal de
recréation de table (`meta.embedding_dim`), et le filtrage par
sévérité/règle/chemin reste fait en amont côté SQL classique sur `findings`
(le filtrage post-KNN se fait ensuite en Python sur l'ensemble trié renvoyé
par `vec0`, sans borne artificielle puisque `k` = nombre total de vecteurs).

**Migration** : à l'ouverture d'une base créée par une version antérieure de
`cccf` (`schema_version` = 1, colonne `findings.embedding` présente), `Store`
supprime cette colonne (`ALTER TABLE ... DROP COLUMN`), efface
`embedding_signature`/`embedding_dim` de `meta`, et passe `schema_version` à
2. Le prochain `cccf index` détecte la signature manquante et ré-embedde
automatiquement — aucune commande de migration dédiée n'est nécessaire, mais
un premier `cccf index` (potentiellement complet) est requis après mise à
jour.

**Conséquences** : format de stockage aligné avec `ccc`, calcul de similarité
accéléré SIMD au lieu d'une boucle Python, mais une dépendance de plus
(`sqlite-vec`, déjà présente transitivement dans l'écosystème `ccc`). Le
choix de conserver SQLite comme unique backend (plutôt que Postgres/pgvector
ou un store vectoriel dédié) reste celui d'ADR-2 : la cible V1 (quelques
milliers de findings par repo) ne justifie pas une dépendance externe.

---

## ADR-18 — Sortie MCP structurée (`TypedDict`/dataclass), erreurs via exception

**Statut** : Acté.

**Contexte** : les 4 tools de `mcp_server.py` étaient annotés `-> str` et
renvoyaient `json.dumps(...)`. FastMCP dérive pourtant un `outputSchema` de
l'annotation de retour même dans ce cas (`str` → type primitif, wrappé) : les
4 tools annonçaient `{"result": {"type": "string"}}` — un schema qui promet
une structure sans en fournir une, vérifié empiriquement via
`mcp.list_tools()`. `ccc` (cocoindex-code), à titre de comparaison, retourne
un vrai `pydantic.BaseModel` (`SearchResultModel`) pour son tool `search`,
avec un schema par champ. Séparément, les 4 tools interceptaient toute
exception et la transformaient en `{"error": "<message>"}` — un résultat
renvoyé comme un succès, sans signal protocolaire permettant à un client de
distinguer un échec d'une réponse valide sans convention ad hoc.

**Décision** : chaque tool est annoté avec son vrai type de retour —
`TypedDict` (`FindingHit`, `FindingsSummary`, `CodeSearchResult`, définis
dans `render.py`/`ccc_bridge.py`/`mcp_server.py`) ou dataclass existante
(`IndexReport`, réutilisée telle quelle depuis `indexer.py`, sans
duplication). FastMCP en dérive un `outputSchema` par champ et renvoie à la
fois le texte JSON habituel (`content`, pour les clients qui l'ignorent) et
le contenu structuré (`structuredContent`) — additif, aucune régression pour
un client existant. Les `try/except Exception` qui avalaient les erreurs sont
supprimés : une exception remonte telle quelle, FastMCP la convertit en
`ToolError`, exposé au client comme `isError: true`. Le cas `ccc`
indisponible dans `search_code_with_findings` (`CccUnavailable`) reste un
repli **volontaire**, pas une erreur : plutôt qu'une forme
`{"error": ..., "fallback": ...}` distincte du cas succès, `CodeSearchResult`
a un schema unique et stable (`results`, `findings_only_fallback`,
`warning`), rempli différemment selon le cas — l'`outputSchema` reste valide
dans les deux branches.

**Conséquences** : les 4 tools sont maintenant symétriques avec `ccc mcp` sur
la forme de sortie (schema riche, pas de string à re-parser), sans ajouter de
dépendance directe (`pydantic` est déjà transitif via `mcp`, mais `TypedDict`
suffit ici — pas de validation runtime nécessaire côté `cccf`, qui contrôle
déjà les deux bouts). Effet de bord positif : `search_findings`,
`findings_summary` et `search_code_with_findings` ne dupliquent plus
manuellement la sérialisation `Finding → dict` (voir N3 dans
`archive/BACKLOG-2.md`, désormais partagée via les `TypedDict` de
`render.py`/`ccc_bridge.py` plutôt que des dicts construits inline). Le
skill (`~/ccc-findings-skill/SKILL.md`) ne dépend d'aucun parsing strict de
la clé `"error"` — vérifié avant ce changement — donc aucune mise à jour n'y
était nécessaire.

---

## ADR-19 — `search_code_with_findings` : classement pondéré par sévérité, pas seulement une annotation

**Statut** : Acté.

**Contexte** : `search_code_with_findings` composait la recherche sémantique
de `ccc` avec les findings `cccf` en pur post-traitement — les findings
étaient attachés à chaque résultat mais n'influençaient jamais leur ordre. Un
chunk avec un finding `ERROR` et un chunk sans finding pouvaient ressortir
dans n'importe quel ordre, uniquement piloté par la pertinence sémantique de
`ccc`. Un deuxième axe d'amélioration du couplage `ccc`↔`cccf` (traduire un
finding en pattern `ccc grep` pour trouver des occurrences structurellement
similaires) a été évalué en parallèle et écarté pour l'instant : testé
empiriquement sur les 4 règles de `tests/fixtures/vuln_repo/rules/rules.yml`,
seules les règles sans `...`/pattern composé (2 sur 4) se traduisent
correctement — les règles avec ellipsis mêlée à un kwarg littéral
(`subprocess.run(..., shell=True, ...)`) perdent leur contrainte de sécurité
une fois traduites (`ccc grep` matche alors *tous* les appels à la fonction).

**Décision** : `ccc_bridge.rank_by_severity` ré-ordonne les résultats déjà
annotés en ajoutant un boost additif à `score` selon `max_severity` (`ERROR`
+0.15, `WARNING` +0.05, `INFO`/aucun +0.0), sans modifier `score` lui-même
(qui continue de refléter la pertinence sémantique brute de `ccc`). Comme
`ccc search` tronque déjà à `--limit` avant que `cccf` ne voie les résultats,
un résultat juste hors du top `N` ne pourrait jamais bénéficier du boost —
`ccc_bridge.overfetch_limit` sur-demande donc `limit × 3` (plafonné à 50)
avant l'annotation, le classement et la troncature finale.

**Conséquences** : les poids de boost sont un choix heuristique initial
(volontairement petits devant l'écart typique des scores `ccc`, pour ne
réordonner que les cas proches et ne jamais faire remonter un résultat
nettement hors-sujet) — à ajuster si l'usage réel montre un besoin différent.
Le sur-fetch ajoute un coût (jusqu'à 3× plus de résultats demandés à `ccc`
par appel), négligeable à l'échelle cible (recherche interactive, pas de
volumétrie). L'idée de traduction finding → `ccc grep` reste ouverte mais
hors scope : voir `archive/BACKLOG-6.md` pour le compte-rendu de faisabilité,
à reprendre uniquement restreinte aux règles sans ellipsis si elle est un
jour priorisée.
