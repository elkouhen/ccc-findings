# Backlog 4 — Propositions issues de la revue architecture (2026-07-12)

> Objectif : transformer la revue architecture/produit en tâches autonomes,
> assez détaillées pour être traitées ultérieurement sans relire la conversation
> d'origine. Les tâches ci-dessous complètent `archive/BACKLOG-2.md` : elles
> reprennent les priorités de stabilisation quand elles conditionnent la valeur
> produit, puis ajoutent les chantiers d'architecture, de mesure et de
> distribution nécessaires pour passer du MVP à une V1 robuste.
>
> Convention proposée : une tâche = un commit (`A<n>: <titre>`). DoD globale
> inchangée : `uv run pytest` vert, `uv run ruff check .` propre, documentation
> vivante mise à jour si le comportement observable ou l'architecture changent.

## Phase 1 — Fiabiliser la promesse de sécurité

### [x] A1 — Garantir que le périmètre configuré est réellement indexé
- **Priorité** : CRITIQUE
- **Fichiers** : `src/cccf/indexer.py`, `src/cccf/config.py`,
  `src/cccf/scanner.py`, `tests/fixtures/vuln_repo/`, `tests/test_indexer.py`,
  `tests/test_scanner.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`,
  `docs/ADR.md` si une décision Semgrep est actée.
- **Description** : corriger les trous d'index silencieux qui faussent la
  confiance dans l'outil. La configuration par défaut `include: ["**/*"]` doit
  inclure aussi les fichiers à la racine du repo (`setup.py`, `app.py`,
  `pyproject.toml`, etc.), et les répertoires `tests/` d'un repo utilisateur ne
  doivent pas être exclus silencieusement par les règles d'ignore par défaut de
  Semgrep. Choisir explicitement une stratégie pour Semgrep : ignorer les
  `.semgrepignore` par défaut si supporté par la version cible, générer/mettre à
  jour une ignore locale maîtrisée, ou au minimum exposer les chemins ignorés en
  avertissement exploitable.
- **Critères d'acceptation** :
  - Un fichier vulnérable placé à la racine d'un fixture est scanné et ses
    findings apparaissent dans `cccf search`.
  - Un fichier vulnérable placé sous `tests/` dans un repo cible est scanné ou,
    si la décision produit est de respecter l'ignore Semgrep, l'utilisateur
    reçoit un avertissement explicite indiquant que le fichier est hors index.
  - Les règles `include`/`exclude` documentées dans `.cccf/config.yml` ont une
    sémantique cohérente entre la liste des fichiers hashés et les fichiers
    réellement envoyés à Semgrep.
  - Les specs décrivent clairement la relation entre `include`/`exclude`,
    `.semgrepignore` et les ignores par défaut de Semgrep.

### [x] A2 — Rendre l'identité des findings non ambiguë
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/models.py`, `src/cccf/scanner.py`,
  `src/cccf/store.py`, `tests/test_models.py`, `tests/test_scanner.py`,
  `tests/test_store.py`, `docs/SPEC-TECH.md`, `docs/ADR.md`.
- **Description** : éviter le sous-rapportage silencieux quand deux findings de
  même règle et même chemin ont un snippet identique ou vide. L'identifiant
  actuel dépend de `rule_id`, `path` et du snippet normalisé, ce qui peut
  fusionner deux occurrences distinctes. Faire évoluer l'identité pour inclure
  une information de localisation stable ou suffisamment discriminante
  (`start_line`, plage de lignes, empreinte Semgrep si disponible), et rendre
  toute collision restante visible plutôt que masquée par un `UPSERT`.
- **Critères d'acceptation** :
  - Deux occurrences identiques de la même règle dans le même fichier produisent
    deux lignes distinctes en base.
  - Un snippet vide ne peut plus écraser silencieusement un autre finding.
  - Les tests documentent le comportement attendu en cas de collision.
  - L'ADR existante sur l'identité des findings est mise à jour ou remplacée par
    une nouvelle ADR expliquant le compromis retenu.

### [x] A3 — Dégrader proprement quand l'index est périmé
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/search.py`, `src/cccf/render.py`,
  `src/cccf/mcp_server.py`, `tests/test_search.py`, `tests/test_cli.py`,
  `tests/test_mcp_server.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`.
- **Description** : `cccf search --context` et le tool MCP `search_findings` ne
  doivent pas perdre tous les résultats si un fichier indexé a été supprimé,
  renommé ou rendu illisible avant réindexation. Le contexte doit être une
  information optionnelle par résultat : un finding valide doit rester retourné
  même si son contexte source ne peut plus être relu.
- **Critères d'acceptation** :
  - Si un fichier indexé disparaît, `cccf search --json --context` retourne le
    finding avec un champ d'erreur de contexte explicite, sans traceback.
  - Via MCP, un échec de contexte sur un hit ne transforme pas toute la réponse
    en `{"error": ...}`.
  - Le rendu texte reste lisible et signale le contexte indisponible sans cacher
    le finding.
  - Le contrat JSON documente le champ ajouté ou la valeur `null` retenue.

## Phase 2 — Stabiliser le runtime agent/MCP

### [x] A4 — Centraliser et cacher la factory d'embedder
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/embedder.py`, `src/cccf/cli.py`,
  `src/cccf/mcp_server.py`, `tests/conftest.py`, `tests/test_embedder.py`,
  `tests/test_cli.py`, `tests/test_mcp_server.py`, `docs/SPEC-TECH.md`.
- **Description** : supprimer l'inversion de dépendance où `mcp_server.py`
  importe une fonction privée de `cli.py`, éviter de recharger le modèle
  d'embedding à chaque appel MCP, et isoler les fakes de test du code de
  production. Introduire une factory publique dans `embedder.py`, idéalement
  cachée par nom de modèle dans un processus long, utilisée par CLI et MCP.
- **Critères d'acceptation** :
  - `mcp_server.py` n'importe plus `cccf.cli`.
  - Deux appels MCP successifs avec le même modèle réutilisent la même instance
    d'embedder ou le même modèle chargé.
  - Le fake embedder utilisé par les tests est injecté depuis les tests plutôt
    que déclenché par une variable d'environnement de production, ou bien la
    variable est explicitement marquée et stockée en meta pour empêcher un index
    mixte.
  - Les tests d'intégration restent déterministes sans téléchargement du modèle.

### [x] A5 — Détecter les embeddings incompatibles avant la recherche
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/store.py`, `src/cccf/indexer.py`,
  `src/cccf/search.py`, `src/cccf/embedder.py`, `tests/test_indexer.py`,
  `tests/test_search.py`, `docs/SPEC-TECH.md`.
- **Description** : empêcher qu'un index contienne des vecteurs de dimensions ou
  de modèles différents, ce qui provoque aujourd'hui des erreurs NumPy tardives
  ou des résultats incohérents. Stocker en base les métadonnées nécessaires
  (`embedding_model`, dimension, éventuellement provider/type d'embedder) et
  vérifier leur compatibilité au moment de l'indexation et de la recherche.
- **Critères d'acceptation** :
  - Si le modèle ou la dimension change, l'indexation ré-embedde tous les
    findings ou refuse explicitement de chercher tant qu'un réindex complet n'a
    pas été fait.
  - Une base contenant un vecteur de dimension inattendue produit un message
    actionnable, pas un traceback brut.
  - Les tests couvrent un changement de modèle et un vecteur corrompu ou
    incompatible.

### [ ] A6 — Durcir le pont `ccc` contre les changements de format
- **Priorité** : MOYENNE-HAUTE
- **Fichiers** : `src/cccf/ccc_bridge.py`, `src/cccf/mcp_server.py`,
  `tests/test_ccc_bridge.py`, `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`.
- **Description** : le pont `ccc` parse une sortie texte non contractuelle. Si
  `ccc search` retourne une sortie non vide mais qu'aucun bloc ne matche le
  format attendu, considérer cela comme une indisponibilité de `ccc` plutôt que
  comme une recherche sans résultats. Le fallback MCP vers `search_findings`
  doit alors s'activer pour préserver une réponse utile.
- **Critères d'acceptation** :
  - Une sortie `ccc` non vide mais non parsable déclenche `CccUnavailable`.
  - `search_code_with_findings` retourne un objet JSON avec
    `"error": "ccc non disponible"` et un `fallback` findings dans ce cas.
  - Une sortie vide reste interprétée comme zéro résultat, sans erreur.
  - Les tests couvrent les trois cas : sortie valide, sortie vide, sortie non
    vide non parsable.

## Phase 3 — Préparer le passage à l'échelle raisonnable

### [ ] A7 — Batcher les opérations SQLite dépendantes du nombre de fichiers
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/store.py`, `src/cccf/indexer.py`,
  `tests/test_store.py`, `tests/test_indexer.py`, `docs/SPEC-TECH.md`.
- **Description** : éviter l'erreur SQLite `too many SQL variables` sur les
  repos de plusieurs dizaines de milliers de fichiers. Les méthodes qui
  construisent des clauses `IN (?, ?, ...)` doivent traiter les chemins par
  tranches bornées, avec un helper partagé et testé.
- **Critères d'acceptation** :
  - `remove_files` et `replace_findings_for_files` acceptent au moins 40 000
    chemins sans erreur SQLite.
  - Le calcul des compteurs de findings supprimés ne fait plus un scan complet
    des findings pour chaque fichier.
  - Le comportement reste identique pour les petits repos.

### [ ] A8 — Rendre les filtres de lecture cohérents avec la configuration courante
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/config.py`, `src/cccf/store.py`,
  `src/cccf/search.py`, `src/cccf/indexer.py`, `tests/test_config.py`,
  `tests/test_search.py`, `tests/test_indexer.py`, `docs/SPEC-FONC.md`,
  `docs/SPEC-TECH.md`.
- **Description** : quand `min_severity`, `include`, `exclude` ou les règles
  changent, l'index existant peut continuer à servir des findings qui ne
  correspondent plus à la configuration. Définir une politique explicite :
  appliquer certains filtres à la lecture, stocker un hash de configuration et
  forcer une réindexation complète quand il change, ou refuser la recherche tant
  que l'index n'est pas à jour.
- **Critères d'acceptation** :
  - Durcir `min_severity` de `INFO` à `ERROR` ne laisse plus apparaître les
    findings `WARNING` dans `search` et `summary`, ou force une action claire de
    réindexation avant de répondre.
  - Modifier `include`/`exclude` ne laisse pas indéfiniment des findings hors
    périmètre visibles.
  - La politique choisie est documentée côté CLI et technique.

### [ ] A9 — Ajouter une commande de diagnostic de santé de l'index
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/cli.py`, `src/cccf/store.py`,
  `src/cccf/config.py`, `src/cccf/search.py`, `tests/test_cli.py`,
  `docs/SPEC-FONC.md`, `docs/SPEC-TECH.md`, `README.md`.
- **Description** : créer une commande `cccf doctor` ou `cccf status` qui
  vérifie rapidement si l'index est utilisable : présence de la config,
  présence de la base, version de schéma, modèle/dimension d'embeddings,
  fraîcheur approximative par rapport aux fichiers modifiés, disponibilité de
  Semgrep, disponibilité optionnelle de `ccc`.
- **Critères d'acceptation** :
  - La commande retourne un code 0 si l'index est cohérent et interrogeable.
  - Elle retourne un code non nul et des messages actionnables si la config est
    absente, la base absente, les embeddings incompatibles, ou Semgrep
    introuvable.
  - Une option `--json` expose les mêmes informations pour un agent MCP/CLI.
  - Le README documente quand lancer cette commande.

## Phase 4 — Mesurer la valeur produit

### [ ] A10 — Transformer l'évaluation de pertinence en garde-fou exploitable
- **Priorité** : MOYENNE
- **Fichiers** : `eval/run_eval.py`, `eval/queries.yml`, `pyproject.toml`,
  `tests/` si une intégration légère est ajoutée, `docs/SPEC-TECH.md`,
  `README.md`.
- **Description** : l'évaluation actuelle mesure la pertinence sur un petit jeu
  de requêtes, mais elle n'est pas intégrée comme signal régulier. Stabiliser un
  mode d'exécution documenté qui peut être lancé volontairement, produit un
  résultat lisible et échoue si le seuil minimal n'est pas atteint. Ajouter des
  requêtes qui couvrent français/anglais, règles différentes et formulations
  non triviales.
- **Critères d'acceptation** :
  - Une commande documentée lance l'évaluation et affiche le hit-rate top-k, le
    seuil attendu et les échecs détaillés.
  - Le seuil de passage est explicite et versionné.
  - Les requêtes couvrent au moins les quatre types de vulnérabilités du fixture
    existant avec plusieurs formulations.
  - L'évaluation reste séparée des tests unitaires rapides si elle nécessite le
    vrai modèle ou le réseau.

### [ ] A11 — Mesurer latence et coût token des réponses principales
- **Priorité** : MOYENNE
- **Fichiers** : `eval/`, `docs/PRD.md`, `docs/SPEC-TECH.md`, éventuellement
  `README.md`.
- **Description** : les objectifs produit annoncent p95 < 1 s et une économie de
  tokens vs `semgrep scan --json`, mais le repo ne fournit pas encore de mesure
  reproductible. Ajouter un script d'évaluation qui compare `cccf search`,
  `cccf summary` et `semgrep scan --json` sur un fixture ou un repo échantillon,
  puis publie les métriques utiles : durée, taille de sortie, nombre de tokens
  approximatif ou nombre de caractères.
- **Critères d'acceptation** :
  - Le script produit une sortie JSON ou tableau avec latence, taille de sortie
    et ratio de réduction.
  - Le script peut être lancé localement sans modifier la base réelle d'un
    utilisateur.
  - Les résultats attendus ou les seuils cibles sont documentés comme indicatifs
    si l'environnement influence fortement les temps.

## Phase 5 — Clarifier distribution et documentation

### [x] A12 — Corriger les incohérences de documentation fonctionnelle
- **Priorité** : MOYENNE
- **Fichiers** : `docs/SPEC-FONC.md`, `README.md`, éventuellement
  `docs/ADR.md`.
- **Description** : aligner les documents vivants sur le comportement réel. En
  particulier, `cccf init` se replie désormais sur `p/security-audit` quand
  aucune config Semgrep n'est détectée, mais le tableau de synthèse des erreurs
  mentionne encore une erreur dans ce cas. Relire les sections CLI/MCP pour
  supprimer les contradictions similaires.
- **Critères d'acceptation** :
  - `SPEC-FONC.md` ne contient plus de comportement contradictoire pour
    `cccf init` sans `--rules`.
  - README, SPEC-FONC et ADR racontent la même politique de configuration par
    défaut.
  - Aucune modification de code n'est nécessaire pour cette tâche sauf si la
    relecture révèle un écart réel entre spec et implémentation.

### [ ] A13 — Définir la stratégie de distribution du skill séparé
- **Priorité** : MOYENNE
- **Fichiers** : `README.md`, `docs/SPEC-FONC.md`, `docs/ADR.md`,
  éventuellement un script ou une commande d'installation si le choix retenu le
  nécessite.
- **Description** : le skill Claude Code est documenté comme distribué hors du
  repo, dans `~/cocoindex-ext-skill/SKILL.md`. Cette séparation doit être
  clarifiée pour un utilisateur externe : où récupérer le skill, comment le
  mettre à jour, quelle version du skill correspond à quelle version de
  `ccc-findings`, et ce qui est garanti par le package Python seul.
- **Critères d'acceptation** :
  - Le README explique explicitement si `uv tool install ccc-findings` installe
    ou non le skill.
  - Une procédure d'installation/mise à jour du skill existe ou la décision de
    ne pas le distribuer est justifiée.
  - Une ADR consigne la stratégie retenue si elle change le modèle actuel.

### [ ] A14 — Préparer une politique de versionnement du schéma SQLite
- **Priorité** : MOYENNE
- **Fichiers** : `src/cccf/store.py`, `docs/SPEC-TECH.md`, `docs/ADR.md`,
  `tests/test_store.py`.
- **Description** : plusieurs tâches proposées peuvent modifier le schéma
  SQLite (`schema_version`, identité des findings, métadonnées d'embeddings,
  diagnostics). Définir avant ces changements une politique de migration :
  migration automatique, erreur demandant `cccf index --full`, suppression
  contrôlée de la base, ou compatibilité ascendante. Éviter que le premier
  changement de schéma casse silencieusement les bases existantes.
- **Critères d'acceptation** :
  - Ouvrir une base avec une version de schéma inconnue produit un comportement
    explicite et testé.
  - Les migrations supportées sont documentées.
  - La stratégie indique comment préserver ou reconstruire les embeddings.

## Ordre recommandé

```text
A1 → A2 → A3
   → A4 → A5 → A6
   → A7 → A8 → A9
   → A10 → A11
   → A12 → A13 → A14
```

`archive/BACKLOG-2.md` contient déjà des remédiations détaillées qui recoupent
plusieurs tâches ci-dessus. Si une tâche `R<n>` et une tâche `A<n>` couvrent le
même changement, traiter le sujet une seule fois et cocher/mettre à jour les deux
backlogs dans le commit correspondant.
