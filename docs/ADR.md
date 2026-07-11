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

**Statut** : Acté.

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
