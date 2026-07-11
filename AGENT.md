# AGENT.md — Comment naviguer et maintenir la documentation de ce projet

> Ce fichier s'adresse à tout agent (Claude Code ou autre) qui intervient sur
> `ccc-findings`. Il décrit où vit chaque type de documentation et la règle
> non négociable : **tout changement se documente dans un fichier BACKLOG**.

## Carte des documents

| Document | Contenu | Quand le lire |
|---|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Problème, vision, personas, cas d'usage, métriques de succès | Pour comprendre *pourquoi* le produit existe et ce qu'il doit accomplir |
| [`docs/SPEC-FONC.md`](docs/SPEC-FONC.md) | Comportement observable : commandes CLI, flags, messages d'erreur/codes de sortie, tools MCP, workflows du skill | Avant de modifier tout ce qu'un utilisateur ou un agent voit (CLI, MCP, skill) |
| [`docs/SPEC-TECH.md`](docs/SPEC-TECH.md) | Modules, modèle de données, schéma SQLite, algorithmes, contrat JSON | Avant de modifier l'architecture interne (`src/cccf/*.py`) |
| [`docs/ADR.md`](docs/ADR.md) | Décisions d'architecture : contexte, choix, conséquences | Avant de revenir sur un choix déjà tranché — pour savoir si c'est une décision D1-D6 « ne pas rediscuter » ou une adaptation ADR-7+ documentée |
| `archive/BACKLOG*.md` | Tâches de travail (implémentation initiale, remédiations) — voir ci-dessous | Pour tout travail nouveau ou en cours |

`README.md` reste le point d'entrée court (installation, démarrage) et
renvoie vers ces documents ; il ne duplique pas leur contenu.

## Règle d'or : tout changement se documente dans un BACKLOG

Aucune tâche (feature, fix, refactor, changement de doc) ne doit être menée
sans une entrée correspondante dans un fichier `archive/BACKLOG-<n>.md` :

1. **Avant de commencer** : vérifier si la tâche existe déjà dans un backlog
   en cours (`archive/BACKLOG-2.md` ou le plus récent). Sinon, l'ajouter avec
   le même gabarit que l'existant : titre, `Fichiers` (périmètre exact),
   `Description`, `CA` (critères d'acceptation vérifiables).
2. **Pendant** : une tâche = un commit (`F<epic>.<n>: <titre>` pour le
   backlog d'implémentation d'origine, `R<n>: <titre>` pour les
   remédiations, `N<n>: <titre>` pour le nettoyage transverse — voir
   `archive/BACKLOG-2.md`).
3. **Après** : cocher la case (`[ ]` → `[x]`) dans le fichier BACKLOG
   correspondant dans le même commit (ou un commit dédié explicite) — ne
   jamais laisser le fichier mentir sur l'état réel du repo.
4. **Si le changement révèle une décision d'architecture** (nouvelle,
   ou déviation d'une décision existante) : ajouter une entrée à
   `docs/ADR.md` (contexte / décision / conséquences), ne pas la laisser
   implicite dans un message de commit.
5. **Si le changement modifie le comportement observable ou l'architecture
   interne** : mettre à jour `docs/SPEC-FONC.md` et/ou `docs/SPEC-TECH.md`
   dans le même commit que le code — ces documents décrivent le code
   *tel qu'il est*, pas tel qu'il était prévu.

## Cycle de vie des fichiers BACKLOG

- Tous les backlogs (terminés ou en cours) vivent dans `archive/`, numérotés
  séquentiellement : `BACKLOG.md` (plan d'implémentation initial, terminé),
  `BACKLOG-2.md` (findings de revue de code, en cours), `BACKLOG-3.md`, etc.
- Un nouveau chantier de travail (feature notable, campagne de
  remédiation) crée un nouveau `archive/BACKLOG-<n>.md` plutôt que de
  rallonger indéfiniment un fichier existant déjà clos.
- Un backlog existant et encore ouvert (cases non cochées) reçoit les
  nouvelles tâches qui prolongent son sujet.

## Conventions héritées (ne pas rediscuter)

Reprises d'`archive/BACKLOG.md` §« Conventions pour l'agent exécutant » —
valables pour tout fichier BACKLOG présent ou futur :

1. Traiter les tâches dans l'ordre ; ne commencer une tâche que si ses
   dépendances déclarées sont `DONE`.
2. Une tâche est `DONE` uniquement quand tous ses critères d'acceptation
   passent, plus la DoD globale.
3. **DoD globale** : `uv run pytest` passe entièrement, `uv run ruff check .`
   sans erreur, aucun fichier hors du périmètre `Fichiers` de la tâche n'est
   modifié (toute exception à cette règle doit être signalée et approuvée
   avant d'être appliquée — voir `docs/ADR.md` ADR-7 pour un précédent), pas
   de `TODO` laissé dans le code livré.
4. Si un critère d'acceptation est impossible à satisfaire tel quel :
   s'arrêter et signaler, ne pas réinterpréter silencieusement (voir
   `docs/ADR.md` pour les précédents où cette règle a été appliquée).
