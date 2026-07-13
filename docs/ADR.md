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
`ToolError`, exposé au client comme `isError: true`. Depuis ADR-22,
`CccUnavailable` dans `search_code_with_findings` est également une vraie erreur
et non plus un repli success-shaped.

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

---

## ADR-20 — `cccf search` = sur-ensemble de `ccc search` ; la recherche findings devient `cccf findings`

**Statut** : Acté.

**Contexte** : depuis la V1, `cccf search` cherchait *dans les findings*
(embeddings des findings Semgrep), et la composition code + findings n'était
exposée que côté MCP (`search_code_with_findings`). Ce positionnement ne
correspondait pas à l'intention produit : `cccf` doit **étendre** `ccc` —
même question, même genre de réponse. Attendu : `ccc search "user
authentication flow"` décrit le flux ; `cccf search "user authentication
flow"` décrit le même flux **et** remonte les findings Semgrep dessus.

**Décision** : `cccf search` devient la recherche code + findings —
l'orchestration (sur-fetch `ccc`, annotation, classement par sévérité, modes
dégradés), auparavant dans `mcp_server.py`, est extraite dans
`code_search.py` et partagée par la CLI et le tool MCP (comportements
garantis identiques). Le rendu texte reproduit **exactement** le format de
`ccc search` (`--- Result N (score) --- / File: path:l1-l2 [lang]`), suivi
d'un bloc findings sous chaque résultat concerné — un utilisateur de `ccc`
garde ses repères, `cccf` ajoute la couche findings. Le parseur de
`ccc_bridge` capture désormais le langage pour reproduire la ligne `File:` à
l'identique. L'ancienne recherche findings-only déménage telle quelle
(mêmes flags, même contrat JSON) sous `cccf findings`.

**Modes dégradés** : index findings absent → résultats `ccc` bruts avec
avertissement (plutôt que des findings silencieusement vides, et sans créer
`.cccf/` par effet de bord dans un repo non initialisé). Depuis ADR-22, `ccc`
indisponible ou en erreur n'est plus un mode dégradé réussi : l'erreur remonte
au CLI/MCP.

**Conséquences** : rupture du contrat CLI (`cccf search` change de
sémantique ; les usages findings-only doivent migrer vers `cccf findings`) —
acceptée, le package n'étant pas encore distribué au-delà de ce poste. Les
tools MCP sont inchangés (`search_findings` = `cccf findings`,
`search_code_with_findings` = `cccf search`). Au passage, les fixtures de
faux `ccc` sont mutualisées dans `tests/conftest.py` (première étape de N2,
`archive/BACKLOG-2.md`).

---

## ADR-21 — Prototype d'extension native CocoIndex sans abandonner le package compagnon

**Statut** : Acté expérimental.

**Contexte** : la revue de `../cocoindex/examples` a montré que l'indexation
actuelle de `cccf` réimplémente à la main plusieurs primitives fournies par
CocoIndex : état cible déclaratif (`TargetState = Transform(SourceState)`),
invalidation incrémentale, suppression automatique des orphelins, mémoïsation
des transformations et mode live. Le pont actuel vers `ccc` reste en outre
fragile car `ccc search` ne fournit pas de JSON stable dans la version utilisée
localement (ADR-10) : `cccf` parse une sortie humaine.

**Décision** : `cccf` reste un package compagnon distinct (ADR-1 n'est pas
annulé) mais introduit un mode expérimental `cccf index --engine cocoindex`.
Ce mode prépare une extension native CocoIndex en modélisant les findings et
les chunks de code comme des états cibles typés dans le store local. Il ne
dépend pas encore d'API internes de `cocoindex-code` et ne rend pas `cocoindex`
obligatoire à l'installation : le backend stable reste `--engine manual`.

Quand l'index expérimental existe (`meta.index_engine = "cocoindex-prototype"`),
`cccf search` et le tool MCP `search_code_with_findings` interrogent d'abord les
chunks de code indexés localement (`vec_code_chunks`) puis annotent ces résultats
avec les findings. Le fallback `ccc search` + parsing texte reste disponible
pour les index manuels ou les repos non migrés.

Options rejetées pour l'instant :
- contribuer directement dans `cocoindex-code` / `ccc` : meilleur alignement à
  terme, mais trop couplé pour une correction locale rapide ;
- remplacer immédiatement `cccf` par un nouvel index unifié : trop risqué pour
  les commandes MCP/CLI existantes ;
- rendre `cocoindex` dépendance obligatoire : prématuré tant que le prototype ne
  couvre pas les mêmes garanties que l'indexer manuel.

**Conséquences** : X2/X4 diminuent le risque d'ADR-10 sans rupture : les
utilisateurs gardent les commandes actuelles, et l'expérimental est opt-in. Le
prototype n'est pas encore un flow CocoIndex complet avec `live=True` ni une
migration de backend ; ces étapes restent à traiter (X3/X5/X6). Le store passe
en `schema_version = 3` pour ajouter `code_chunks` et `vec_code_chunks`.

---

## ADR-22 — Une panne `ccc` fait échouer `cccf search`

**Statut** : Acté.

**Contexte** : le fallback historique de `search_code_with_findings` masquait
une panne de `ccc` (`ccc` absent ou code retour non nul) en retournant une
recherche findings-only dans `findings_only_fallback`. Ce comportement rendait
la sortie ambiguë : l'appelant pouvait croire avoir obtenu une recherche code +
findings valide alors que le service code sous-jacent était en erreur.

**Décision** : quand `cccf search` doit passer par le pont `ccc`, toute
`CccUnavailable` est convertie en erreur (`RuntimeError`) et remonte au CLI
(code de sortie 2) ou au MCP (`ToolError` / `isError: true`). Le message conserve
la cause initiale : `ccc introuvable dans le PATH` ou
`ccc a échoué (code N) : <stderr>`.

Le mode expérimental `--engine cocoindex` reste indépendant : si un index code
local existe, `cccf search` l'utilise sans appeler `ccc`.

**Conséquences** : `findings_only_fallback` reste présent dans
`CodeSearchResult` pour compatibilité de schema, mais il n'est plus utilisé pour
masquer une panne `ccc`. Un utilisateur qui veut chercher uniquement dans les
findings doit appeler explicitement `cccf findings` ou le tool MCP
`search_findings`.

---

## ADR-23 — Le tool MCP de recherche code prend le même nom et les mêmes
paramètres que `ccc search`

**Statut** : Acté.

**Contexte** : le tool MCP `search_code_with_findings` était déjà un
sur-ensemble de `ccc search` (ADR-20/21) mais n'exposait que `query` et
`limit`, alors que `ccc search` accepte aussi `--offset`, `--lang`, `--path`
et `--refresh` (voir `ccc search --help`). Un agent qui connaît déjà `ccc`
devait donc deviner que ces options n'existaient pas côté `cccf`, ou basculer
vers `ccc` pour les usages paginés/filtrés — cassant le positionnement
« `cccf search` = `ccc search` + findings ».

**Décision** :
1. Le tool MCP est renommé `search_code_with_findings` → `search`, même nom
   que le tool exposé par `ccc mcp`. Comme les tools MCP sont préfixés par
   serveur côté client (`mcp__cccf__search` vs `mcp__ccc__search`), il n'y a
   pas de collision réelle même si les deux serveurs sont enregistrés
   simultanément.
2. `search`/`cccf search` acceptent désormais `offset`, `lang`, `path`,
   `refresh` — mêmes noms que les flags `ccc search --offset/--lang/--path/
   --refresh`.
3. Quand le pont `ccc` est utilisé (pas d'index code expérimental), ces
   paramètres sont transmis tels quels au binaire `ccc` (`ccc_bridge.
   search_code`), sans transformation.
4. Quand l'index code expérimental (`--engine cocoindex`) est utilisé,
   `lang`/`path` filtrent et `offset` pagine `Store.knn_search_code_chunks`
   (post-filtrage, `vec0` n'ayant pas de filtre de métadonnées natif — sur-
   demande `(offset + top_k) × 3`, plafonné à 200, même schéma que l'over-
   fetch de `rank_by_severity`) ; `refresh=True` déclenche une réindexation
   incrémentale locale (`coco_indexer.index_repo_with_cocoindex`) avant la
   recherche, mais seulement si le repo utilise déjà ce moteur — un
   `refresh=True` n'active pas silencieusement le moteur expérimental sur un
   repo indexé en mode `manual`.

**Conséquences** : le nom Python de la fonction partagée CLI/MCP,
`code_search.search_code_with_findings`, ne change pas — seul le nom du tool
MCP exposé change. Les tests et docs qui référençaient le tool par son ancien
nom sont mis à jour (`tests/test_mcp_server.py`,
`tests/test_ccc_bridge.py`).

## ADR-24 — Les packs de règles vivent dans le repo skill, jamais dans
`cccf`, et ne sont jamais référencés par un chemin absolu

**Statut** : Acté.

**Contexte** : BACKLOG-10 K8 a d'abord livré un premier pack (liveness
Python) embarqué dans le package `cccf` lui-même
(`src/cccf/rules/liveness/rules.yml`) — jusque-là, `rules:` ne contenait que
des chemins projet ou des packs registry (ADR-4, ADR-13). En expérimentant
l'usage direct via `--config /chemin/absolu/vers/.venv/.../rules/
liveness.yml`, le `check_id` Semgrep sorti (donc `Finding.rule_id`, et son
identité — ADR-5/ADR-15) se révèle préfixé par les composants du chemin
passé à `--config` tels quels : deux machines avec le paquet installé à des
chemins différents (ou un dev checkout vs une install `uv tool`) obtiennent
des `rule_id` différents pour la même règle. Par ailleurs, le repo
`ccc-findings-skill` s'est révélé être *déjà* le point de distribution
naturel de ce type de contenu : il porte son propre pack de règles Java
(`skills/cccf/rules/plateforme-agree/`, spécifique à la plateforme cible
analysée), avec la même règle déjà énoncée dans `SKILL.md` — copier le
pack dans le repo cible avant de le déclarer dans `rules:`.

**Décision** :
1. Les packs de règles ne sont **jamais embarqués dans `cccf`**
   (`src/cccf/rules/` n'existe pas) — `cccf` reste un exécuteur de Semgrep
   générique, agnostique du contenu des règles (cohérent ADR-1 : package
   compagnon, pas de logique métier propre à une plateforme).
2. Ils vivent dans `ccc-findings-skill` sous `skills/cccf/rules/<pack>/`
   (ex. `liveness/{python,java}.yaml`, `plateforme-agree/*.yaml`), aux côtés
   de la documentation d'usage dans `SKILL.md`.
3. Ils sont documentés comme des fichiers de référence à **copier dans le
   repo cible** (ex. `.cccf/rules/liveness/`) et à déclarer dans `rules:`
   par un chemin **relatif au repo scanné** — jamais un chemin absolu vers
   le repo skill ou vers un package installé, exactement comme une règle
   locale ordinaire (ADR-4).

**Conséquences** : `rule_id` reste stable et prévisible (`rules.<id>` quand
la règle vit dans `<repo>/rules/…`), indépendamment de l'endroit où `cccf`
ou le repo skill sont installés. `ccc-findings` garde une copie de test
(`tests/fixtures/liveness_repo/rules/`, `tests/test_liveness_rules.py`) qui
valide le *comportement* des règles (positif/négatif sur fixtures réelles)
mais n'est plus la source de vérité — celle-ci est `ccc-findings-skill`, qui
n'a pas d'infra de test propre ; la synchronisation entre les deux copies
est manuelle, pas vérifiée automatiquement (les deux repos sont versionnés
indépendamment). Si ça devient un point de friction, une vérification
inter-repos ou un script de sync pourra être ajouté.

## ADR-25 — `MessageEndpoint` : identité sans le snippet dans le hash,
un endpoint par site plutôt qu'un flux

**Statut** : Acté.

**Contexte** : BACKLOG-10 K1 introduit `MessageEndpoint`, l'entité qui
modélise un site statique d'échange entre services (production/consommation
Kafka, exposition/appel REST — K2/K11), pour permettre à un agent de
répondre à « qui produit/consomme ce topic ? » ou « qui appelle cette
route ? » sans connexion runtime (principe directeur de BACKLOG-10).

**Décision** :
1. `compute_endpoint_id(role, topic, path, start_line, end_line)` — pas de
   snippet dans le hash, contrairement à `compute_finding_id`. Un `Finding`
   distingue deux occurrences du même problème par leur texte ; un endpoint
   se distingue par *où* il est (site de code ou entrée de manifeste), la
   forme exacte de l'appel important peu pour répondre à « qui parle à
   qui ? ». Ça rend aussi l'identité insensible à un renommage de variable
   qui ne change ni le topic/route ni la position.
2. Un endpoint représente un **site**, pas un flux : deux appels
   `producer.send("orders.created", ...)` à deux lignes différentes du même
   fichier sont deux `MessageEndpoint` distincts (même topic, `path`
   identique, `start_line`/`end_line` différents) — cohérent avec
   `replace_endpoints_for_files` qui raisonne par fichier, comme
   `replace_findings_for_files`.
3. `source: code`/`manifest` (K10) coexistent pour le même topic sans champ
   dédié dans le hash : leurs `path` diffèrent naturellement (fichier de
   code vs `TOPICS.md`), donc leurs identités aussi. Pas besoin d'ajouter
   `source` à la fonction de hash pour éviter une collision qui ne peut pas
   se produire.
4. Aucune table `vec0`/embedding associée à `endpoints` pour l'instant — K1
   ne couvre que le modèle et le stockage ; la vectorisation (recherche NL
   sur les endpoints, si un jour utile) resterait à spécifier séparément,
   hors périmètre K1/K3.
5. `remove_files` purge aussi `endpoints` (comme `findings` et
   `code_chunks`) : un fichier supprimé du disque ne doit laisser aucun
   endpoint fantôme.

**Conséquences** : schema v3 → v4 (`docs/SPEC-TECH.md`), migration purement
additive (`CREATE TABLE IF NOT EXISTS`, pas de table vectorielle à
recréer). `tests/test_store.py` fixe le contrat : round-trip, remplacement
par fichier, stabilité/variation de l'identité, coexistence code/manifeste,
filtres (`system`/`role`/`topic`/`path_glob`), purge par `remove_files`.

## ADR-26 — Extraction du chemin REST par regex sur le snippet, pas par
métavariable Semgrep

**Statut** : Acté.

**Contexte** : BACKLOG-10 K11 doit extraire la méthode HTTP et le chemin
d'une route/d'un appel REST capturés par une règle Semgrep (ex.
`@GetMapping("/orders/{id}")`). L'approche naturelle serait de lire
`extra.metavars` dans la sortie JSON de Semgrep (la valeur exacte capturée
par une métavariable comme `$PATH`). En expérimentation (semgrep 1.168.0,
CLI OSS non authentifié), `extra.metavars` est **absent** de la sortie JSON,
et les champs `fingerprint`/`lines` sont remplacés par le texte littéral
`"requires login"` — ce comportement ne dépend pas d'un flag `--metrics`,
seulement (a priori) d'une session `semgrep login` active, ce qui violerait
NF4 (local-first, aucune dépendance à un compte externe pour indexer).

**Décision** : chaque règle d'inventaire fixe la méthode HTTP dans ses
propres métadonnées (`metadata.http_method`, une règle = une méthode, ex.
`@GetMapping`/`@PostMapping` sont deux règles distinctes plutôt qu'une seule
avec une métavariable de méthode) ; seul le **chemin** varie et doit être
extrait du texte. `cccf` relit déjà le snippet depuis le fichier source
(ADR-8) — `_extract_rest_path` y cherche par regex le premier littéral entre
guillemets de la première ligne. Si ce littéral est suivi d'une
concaténation (`+ variable`) ou qu'aucun littéral n'existe, le chemin est
marqué `topic_dynamic=True` (même politique que `topic_dynamic` en K2 :
jamais résolu silencieusement). Une f-string Python (`f"...{id}..."`) est
traitée comme littéral **résolu** : les accolades d'interpolation sont
indiscernables, à l'extraction, d'un gabarit d'URI façon `{id}` — et se lisent
d'ailleurs naturellement comme tel.

**Conséquences** : extraction best-effort et non sémantique — une
concaténation au milieu d'une expression (`base + "/orders/" + id`) peut
faire remonter un fragment de chemin qui n'est pas le préfixe réel. Documenté
et testé tel quel (`tests/test_rest_endpoints.py`), cohérent avec le
« best-effort » déjà assumé pour l'appariement de chemins en K12. Si Semgrep
expose un jour les métavariables sans connexion (ou via un flag dédié),
cette décision pourra être révisée pour une extraction exacte.

## ADR-27 — Le graphe d'interactions est dérivé à la requête, jamais persisté

**Statut** : Acté.

**Contexte** : BACKLOG-10 K12 doit détecter des cycles d'appels
inter-services et des hotspots (site sur un cycle + finding liveness K8) à
partir des endpoints indexés (K1/K11). Une option aurait été de matérialiser
le graphe (arêtes, cycles) dans des tables SQLite dédiées, recalculées à
chaque `cccf index` — cohérent avec le reste du store (findings,
code_chunks, endpoints).

**Décision** : `src/cccf/graph.py` ne touche pas au schéma SQLite.
`build_graph`/`find_cycles`/`find_outbound_calls_in_consumers`/
`find_hotspots` sont des fonctions pures qui prennent des `MessageEndpoint`/
`Finding` déjà en mémoire (lus du store par l'appelant) et retournent des
structures en mémoire (`GraphEdge`, `Cycle`, `Hotspot`) — jamais écrites en
base. Raisons :
1. Le graphe dépend de **plusieurs projets** dès que K7 (fédération
   multi-dépôts) est en jeu — il n'a pas de « propriétaire » naturel parmi
   les stores SQLite d'un seul repo.
2. C'est une vue dérivée bon marché à recalculer (quelques centaines
   d'endpoints par projet, pas des millions) : pas de gain de performance
   qui justifie la complexité d'un cache invalidé à chaque réindexation.
3. Cohérent avec le principe directeur de BACKLOG-10 : « la vue distribuée
   est une jointure à la requête », déjà appliqué à
   `search_code_with_findings` (ADR-19) et à `cccf flow`/K10.

**Conséquences** : `cccf graph` (CLI/MCP) ne peut aujourd'hui rapporter que
`find_outbound_calls_in_consumers` (K1/K11 suffisent, un seul repo) ; les
champs `cycles`/`hotspots` de sa sortie sont vides tant que K7 n'alimente
pas `build_graph`/`find_hotspots` avec les endpoints/findings de plusieurs
projets — la limitation est explicite dans la sortie (`note`), pas cachée.
`tests/test_graph.py` vérifie qu'aucune table `*graph*`/`*cycle*` n'existe
dans le schéma (CA5).

## ADR-28 — Un topic Kafka donné comme propriété Spring est résolu
localement contre `application.yml`/`.properties`, jamais deviné

**Statut** : Acté.

**Contexte** : BACKLOG-10 K2 doit extraire le nom du topic dans
`@KafkaListener(topics = "...")`/`KafkaTemplate.send(...)`. En pratique
(cible Java + Spring + Maven), le topic n'est presque jamais un littéral
brut : il est externalisé en configuration —
`@KafkaListener(topics = "${app.kafka.topics.orders}")`, la valeur réelle
vivant dans `application.yml`/`.properties`. Le texte capturé par
extraction regex (ADR-26) est alors `${app.kafka.topics.orders}` — une clé
de configuration, pas un nom de topic. Le marquer simplement
`topic_dynamic=True` comme un cas non résolu (variable, concaténation)
aurait été correct mais peu utile : la clé est presque toujours résolvable
statiquement, dans le même repo, sans aucune connexion runtime.

**Décision** : `resolve_spring_property(repo_root, property_key)` cherche
`property_key` (syntaxe `prop` ou `prop:défaut`, comme Spring) dans les
fichiers de configuration Spring Boot conventionnels du repo (Maven/Gradle
standard layout : `src/main/resources/application.{yml,yaml,properties}`,
puis les mêmes noms à la racine), dans cet ordre — premier fichier qui
définit la clé gagne. YAML imbriqué est aplati en clés pointées
(`app.kafka.topics.orders`) ; `.properties` est déjà plat. Si la clé n'est
trouvée dans aucun fichier, le défaut Spring (`${prop:défaut}`) s'applique ;
sinon, le placeholder est conservé tel quel et marqué `topic_dynamic=True`
— jamais résolu au hasard, même politique que ADR-26 pour les chemins REST
non littéraux.

**Conséquences** : une variable qui reçoit une valeur `@Value("${...}")`
puis est passée à `.send(topic, ...)` n'est **pas** résolue (pas d'analyse
de flux de données à travers les statements — hors périmètre, cohérent
avec l'absence de métavariables/taint dans ADR-26) : seul le cas où le
placeholder apparaît **textuellement** dans l'annotation/l'appel est
couvert. Les profils Spring (`application-prod.yml`) ne sont pas
consultés — seul le fichier de base. `tests/test_kafka_endpoints.py` fixe
le contrat : résolution YAML et `.properties`, valeur par défaut, clé
introuvable, priorité YAML > `.properties` quand les deux existent.

## ADR-29 — `cccf index` fait un seul scan Semgrep pour les findings et les
endpoints, discriminés par `metadata.category`

**Statut** : Acté.

**Contexte** : BACKLOG-11 A1 branche l'extraction d'endpoints (K2/K11) dans
`cccf index`, jusque-là dédié aux findings (`run_semgrep`). Les deux types
de règles (findings d'un côté, inventaire d'endpoints de l'autre) peuvent
cohabiter dans `config.rules` (ex. `default.yaml` + `liveness.yaml` +
`rest/java.yaml` + `kafka/java.yaml`). Lancer `run_semgrep` puis
`run_semgrep_endpoints` séparément aurait scanné les mêmes fichiers deux
fois avec Semgrep — le poste le plus coûteux du pipeline (NF2).

**Décision** : `indexer.index_repo` appelle `scanner.invoke_semgrep_raw`
(renommée depuis l'ancien `_invoke_semgrep` privé, désormais partagée)
**une seule fois** par indexation, puis passe la même sortie JSON à
`parse_semgrep_json` (findings) et `parse_semgrep_endpoints` (endpoints).
Chaque parseur ignore ce qui ne le concerne pas via
`extra.metadata.category` : `parse_semgrep_json` saute désormais les
résultats `category: endpoint-inventory` (sinon ils deviendraient de faux
findings INFO — contraire à K8 CA2, « traités comme des endpoints, pas
comme des findings filtrés par `min_severity` ») ; `parse_semgrep_endpoints`
ne garde que ceux-là. Le filtre `min_severity` (auparavant dans
`run_semgrep`) est appliqué dans `index_repo` sur la liste de findings
déjà parsée, pour ne pas dupliquer la logique dans les deux fonctions
`run_semgrep`/`run_semgrep_endpoints` (conservées telles quelles, utilisées
par les tests et un futur usage CLI direct hors indexation).

**Conséquences** : `IndexReport` gagne `endpoints_added`/`endpoints_removed`
(défauts à `0`, compatible avec toute construction positionnelle
existante). `tests/test_indexer.py` fixe le contrat : un scan mélangeant
une règle de finding et deux règles d'inventaire produit 1 finding et 2
endpoints, sans fuite dans un sens ni dans l'autre ; suppression de fichier
purge aussi les endpoints (déjà vrai depuis K1 via `Store.remove_files`).

## ADR-30 — Fédération multi-services : découverte Maven par `pom.xml`,
lecture strictement read-only des bases pairs

**Statut** : Acté.

**Contexte** : BACKLOG-11 A2 doit permettre à `cccf` de raisonner sur
plusieurs microservices à la fois (graphe REST/Kafka inter-services, K12),
sans dépendre d'une configuration manuelle de « workspace nommé » (le plan
initial de K7, `~/.cccf/workspaces/<nom>.yml`) — la cible réelle est un
répertoire parent contenant tous les microservices et des modules Maven
partagés d'un même produit (voir `archive/BACKLOG-PRIORITY.md`, cadrage
2026-07-13), pas des dépôts indépendants sans lien.

**Décision** :
1. **Découverte** (`workspace.discover_maven_services`) : chaque `pom.xml`
   trouvé sous le répertoire donné est un module. Le nom logique stable
   vient de l'`artifactId` du pom (repli : nom du répertoire si le pom est
   illisible ou sans `artifactId` — un module cassé ne bloque jamais les
   autres). Un module est classé `microservice` si son pom référence
   `spring-boot-maven-plugin` (il produit un jar exécutable), `shared-module`
   sinon — recherche textuelle simple dans le XML, pas une résolution
   complète du modèle Maven (héritage de parent POM, profils) : suffisant
   pour distinguer un service déployable d'une bibliothèque interne dans
   l'immense majorité des repos Spring Boot réels, documenté comme
   heuristique et non comme garantie.
2. **Lecture read-only** (`Store(path, readonly=True)`) : ouverture SQLite
   via `file:...?mode=ro` (URI), sans `_create_schema()` (aucune écriture de
   schéma/migration dans la base d'un autre projet), sans `commit()` en
   sortie. Base absente → `StoreError` explicite avant même la tentative de
   connexion ; schéma incompatible (`schema_version` différent, ou table
   manquante) → `StoreError` explicite plutôt qu'une lecture partielle
   silencieuse (K7 CA2/A2 CA8). SQLite refuse lui-même toute écriture sur
   une connexion `mode=ro` — double garantie, pas seulement une convention
   côté code.
3. **Robustesse par service** (`workspace.load_federation`) : un module non
   indexé ou dont la base est incompatible ajoute un avertissement et
   n'interrompt pas la fédération des autres services — jamais un échec
   global pour un seul module en défaut.
4. **Modules partagés vs microservices** (A2 CA5) : `load_federation`
   inclut les findings d'un `shared-module` (une bibliothèque interne porte
   du code, donc potentiellement des findings pertinents pour les
   hotspots), mais jamais ses endpoints — un module partagé n'est pas un
   producteur/consommateur runtime, même si un scan y a par erreur détecté
   un endpoint-inventory.

**Conséquences** : `src/cccf/workspace.py` (nouveau), pas de dépendance à
un parseur Maven tiers (juste `xml.etree.ElementTree`, stdlib). CLI `cccf
workspace <root>` et tool MCP `list_workspace_services` exposent la
découverte + le comptage endpoints/findings par service, en amont de K12
qui consommera `load_federation` pour construire le graphe et les hotspots
réels. `tests/test_workspace.py` fixe le contrat : noms/classification,
détection d'indexation, avertissement sur service non indexé ou base
incompatible, non-fuite des endpoints d'un module partagé, et non-écriture
effective d'une connexion read-only.

## ADR-31 — `metavariable-regex` sur un littéral Java doit tenir compte des
guillemets échappés dans le texte source

**Statut** : Acté.

**Contexte** : BACKLOG-10 K8 (volet sécurité) doit distinguer un
`sasl.jaas.config` avec un mot de passe **littéral** (`password="secret"`,
en dur dans le source) d'un mot de passe **construit** (`password="` +
variable + `"`, injecté depuis l'extérieur). `metavariable-regex` applique
la regex au texte source brut capturé par la métavariable — pour un
littéral Java contenant des guillemets internes, ce texte porte les
guillemets **échappés** (`\"`), pas des guillemets nus, puisque c'est ainsi
qu'ils apparaissent dans le fichier `.java` lui-même. Une regex du genre
`password\s*=\s*"[^"]+"` (guillemets nus) ne matche donc **jamais**, y
compris sur le cas qu'elle est censée détecter — testé et confirmé en
expérimentation (voir aussi ADR-26 : `extra.metavars` n'apparaît pas dans
la sortie JSON sans session `semgrep login`, ce qui a rendu ce piège plus
long à diagnostiquer, faute de pouvoir inspecter directement le texte
capturé).

**Décision** : la regex doit chercher le guillemet échappé explicitement —
`password\s*=\s*\\"[^"]*\\"` (un littéral backslash-quote, pas de backslash
dans le contenu). Un mot de passe concaténé avec une variable ne produit
qu'**un seul** guillemet échappé suivi du nom de la variable (pas de
second guillemet fermant dans la même sous-chaîne), donc ne matche pas —
c'est exactement la distinction recherchée.

**Conséquences** : `cccf.kafka-security.sasl-plaintext-credentials`
(`skills/cccf/rules/kafka-security/java.yaml`) encode cette regex ;
`tests/test_kafka_security_rules.py` fixe le contrat sur les deux formes
(littéral pur vs concaténation) pour éviter une régression silencieuse si
quelqu'un « simplifie » la regex vers des guillemets nus. Tout futur usage
de `metavariable-regex` visant le contenu d'un littéral de chaîne Java (ou
d'un langage à guillemets échappables similaire) doit garder ce piège en
tête plutôt que de le redécouvrir.
