# PRD — ccc-findings : enrichissement de cocoindex-code par les résultats Semgrep

| | |
|---|---|
| **Produit** | ccc-findings (nom de travail) — extension de [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) |
| **Auteur** | Mehdi El-Kouhen |
| **Statut** | Draft v0.1 — vision produit d'origine, en partie antérieure aux décisions d'architecture |
| **Date** | 2026-07-11 |

> **Note de lecture** : ce document capture la vision produit et les cas d'usage
> tels que formulés au démarrage du projet. Certains détails de mécanique (ex. `ccc
> findings`/`ccc index --with-findings` intégrés à `ccc`, store LMDB+SQLite unique)
> ont été **remplacés** par les décisions d'architecture actées dans
> [`ADR.md`](./ADR.md) (notamment ADR-1 : package compagnon `cccf` plutôt que fork
> de `ccc`). Pour ce qui a été **effectivement livré**, se référer à
> [`SPEC-FONC.md`](./SPEC-FONC.md) (comportement utilisateur) et
> [`SPEC-TECH.md`](./SPEC-TECH.md) (architecture technique réelle). Ce PRD reste la
> référence pour : le problème, la vision, les personas/cas d'usage, et les
> métriques de succès — qui n'ont pas changé.

---

## 1. Contexte et problème

`cocoindex-code` (CLI `ccc`) offre aux agents de codage une recherche **sémantique** (embeddings sur chunks AST) et **structurelle** (pattern matching AST) du code, exposée via skill Claude Code, serveur MCP et hooks. Il répond bien à la question *« où est le code qui fait X ? »*.

Il ne répond pas aux questions de **qualité et de sécurité** que se posent quotidiennement développeurs et agents :

- *« Quelles injections SQL potentielles dans ce module ? »*
- *« Ce fichier que je m'apprête à modifier porte-t-il des findings connus ? »*
- *« Corrige toutes les violations de la règle `no-raw-sql` dans `src/api/`. »*

Aujourd'hui, un agent qui veut ces réponses doit lancer Semgrep lui-même à chaque question : lent (scan complet), coûteux en tokens (sortie JSON verbeuse, non filtrée sémantiquement), et déconnecté du contexte code que `ccc` sait déjà restituer. Les findings ne sont ni persistés, ni incrémentaux, ni interrogeables en langage naturel.

**Opportunité** : Semgrep produit des résultats structurés (règle, sévérité, message, localisation précise) qui se marient naturellement avec l'index AST de `ccc`. En indexant les findings *avec* le code, on donne à l'agent une réponse complète en une requête : le code, ses problèmes connus, et le contexte pour les corriger.

## 2. Vision et objectif

> **Un agent de codage interroge en langage naturel un index unifié « code + analyse statique » et obtient des réponses pertinentes, sourcées et économes en tokens.**

Objectifs produit :

1. **Indexer** les résultats de règles Semgrep (règles configurées par le projet : registry semgrep, packs custom, règles maison) dans un pipeline incrémental.
2. **Lier** chaque finding au code concerné (chunk AST via `ccc`, ou a minima fichier + plage de lignes), pour que toute réponse combine finding + code.
3. **Exposer** cette connaissance aux LLM via les mêmes types de surfaces que `ccc` : CLI, skill, serveur MCP.

Non-objectifs (voir §5) : remplacer Semgrep CI/CD, faire du triage de vulnérabilités, réécrire un moteur d'analyse.

## 3. Personas et cas d'usage

### Personas

- **P1 — Agent de codage** (Claude Code, agent MCP) : consommateur principal. Interroge l'index avant/pendant une modification, corrige des findings à la demande.
- **P2 — Développeur** : utilise le CLI directement pour explorer la dette sécurité/qualité de son périmètre.
- **P3 — Tech lead / AppSec** : configure les règles Semgrep du projet, suit l'évolution des findings, définit les seuils.

### Cas d'usage prioritaires

| ID | Cas d'usage | Persona | Priorité |
|----|-------------|---------|----------|
| UC1 | Recherche en langage naturel sur les findings : *« problèmes de désérialisation non sûre »* → findings pertinents + code + explication de la règle | P1, P2 | Must |
| UC2 | Contexte pré-édition : avant de modifier un fichier, l'agent récupère les findings qui le concernent (via hook ou requête MCP) | P1 | Must |
| UC3 | Correction guidée : *« corrige les findings ERROR de `src/api/` »* → l'agent itère sur les findings, avec le chunk de code et le `fix`/message Semgrep comme contexte | P1 | Must |
| UC4 | Recherche croisée code ↔ findings : *« montre le code de gestion des sessions et ses findings associés »* | P1, P2 | Should |
| UC5 | Synthèse : *« état des findings par sévérité/règle sur le repo »* (vue agrégée, faible coût tokens) | P2, P3 | Should |
| UC6 | Diff de findings : findings apparus/résolus depuis la dernière indexation | P3 | Could |

## 4. Proposition de valeur et différenciation

- **vs `semgrep scan` à la demande** : réponses en < 1 s (index persistant, pas de re-scan), sortie filtrée sémantiquement et compacte (objectif : 70 %+ d'économie de tokens).
- **vs SAST plateformes (Semgrep AppSec Platform, SonarQube)** : local-first, sans serveur, conçu pour la boucle interne de l'agent, pas pour la gouvernance.
- **vs index code seul (`ccc` actuel)** : chaque réponse peut porter la dimension « problèmes connus », ce qu'aucun embedding de code seul ne capture.

## 5. Périmètre

### Inclus (V1)

- Exécution de Semgrep pilotée par la configuration de règles du projet (fichier de règles locales ou pack registry).
- Indexation incrémentale des findings : re-scan limité aux fichiers modifiés.
- Modèle de données finding : règle (id, message, sévérité, catégorie/CWE/OWASP si présents), localisation (fichier, lignes), extrait, `fix` suggéré.
- Embedding des findings (message de règle + métadonnées + extrait) dans un store vectoriel dédié.
- CLI de recherche/filtres/agrégats en langage naturel.
- MCP : tools de recherche findings + recherche croisée code ↔ findings.
- Skill Claude Code (workflow d'interrogation + correction guidée).

### Exclus (V1)

- Autres moteurs que Semgrep (extensibilité prévue dans l'architecture, non livrée).
- Triage/workflow de findings (assignation, faux positifs persistés, SLA) — hors boucle agent.
- Exécution de Semgrep Pro / règles interfile taint cross-repo.
- Application automatique des fixes sans agent (les `fix` Semgrep sont du contexte fourni à l'agent, pas un autofix produit).
- UI web / dashboards.

## 6. Exigences fonctionnelles (vision d'origine)

> Le détail fonctionnel réellement livré (commandes, flags, formats) est dans
> [`SPEC-FONC.md`](./SPEC-FONC.md). Les IDs F1-F4 ci-dessous sont conservés pour la
> traçabilité avec les cas d'usage §3, mais la mécanique décrite (`ccc findings`,
> `.cocoindex_code/settings.yml`, `ccc search --with-findings`) est celle du
> draft initial, antérieure à ADR-1.

### F1 — Configuration
- F1.1 : la config projet accepte une section dédiée : sources de règles (chemins, packs registry `p/...`), inclusions/exclusions, sévérité minimale indexée, timeout.
- F1.2 : l'initialisation détecte une config Semgrep existante et propose de l'activer.
- F1.3 : absence de Semgrep installé → message actionnable, le reste de l'outil fonctionne inchangé (feature strictement additive).

### F2 — Indexation
- F2.1 : l'indexation exécute le scan Semgrep sur les fichiers nouveaux/modifiés uniquement et met à jour les findings de ces fichiers (suppression des findings obsolètes incluse).
- F2.2 : chaque finding est rattaché au code concerné (chunk AST si disponible, sinon fichier).
- F2.3 : les findings sont vectorisés avec un modèle d'embedding (texte embeddé : message règle + id + catégories + extrait normalisé).
- F2.4 : identité stable d'un finding (hash règle + chemin + empreinte du code concerné) pour permettre le diff entre indexations (UC6) et éviter les doublons.
- F2.5 : un scan complet reste possible en complément de l'incrémental.

### F3 — Requêtage
- F3.1 : recherche en langage naturel → top-k findings par similarité, avec filtres sévérité/règle/chemin/langue, pagination.
- F3.2 : sortie compacte par défaut (règle, sévérité, fichier:lignes, message court) ; option pour ajouter le contexte de code lié.
- F3.3 : la recherche de code peut être annotée du nombre et de la sévérité max des findings de chaque résultat.
- F3.4 : agrégats par règle/sévérité/répertoire (UC5), format tableau court.
- F3.5 : sortie JSON sur toutes les commandes pour consommation machine.

### F4 — Intégrations agent
- F4.1 : tool MCP de recherche findings retournant le format compact F3.2.
- F4.2 : tool MCP de recherche croisée code ↔ findings.
- F4.3 : skill décrivant : quand interroger les findings, comment mener une correction guidée (récupérer finding → lire contexte → patcher → réindexer → vérifier disparition du finding).
- F4.4 : hook (optionnel) de rafraîchissement de l'index et de signalement des findings des fichiers touchés (UC2), désactivable.

## 7. Exigences non fonctionnelles

- **NF1 — Performance requête** : p95 < 1 s sur un repo de 500k LOC déjà indexé.
- **NF2 — Performance indexation** : surcoût Semgrep incrémental < 10 s pour un changement de 20 fichiers avec les packs par défaut ; jamais bloquant pour la recherche code.
- **NF3 — Économie de tokens** : une réponse recherche top-5 ≤ ~1 200 tokens.
- **NF4 — Local-first & confidentialité** : aucun code, chemin, finding ni requête envoyé à l'extérieur (hors provider d'embedding cloud si explicitement configuré).
- **NF5 — Robustesse** : échec ou timeout Semgrep → l'index existant reste valide et interrogeable ; les findings ne sont jamais supprimés silencieusement suite à une erreur.
- **NF6 — Compatibilité** : Python 3.10+.

## 8. Expérience cible (exemples)

```bash
# Setup
cccf init                              # détecte .semgrep.yml, ou --rules explicite
cccf index                             # findings, incrémental

# Développeur
cccf search "injection sql" --severity ERROR
cccf summary
```

```text
# Agent (via MCP / skill)
Utilisateur : « corrige les problèmes de sécurité du module paiements »
Agent : search_findings("sécurité", path_glob="src/payments/*", severity="ERROR")
      → findings compacts + contexte
      → patch fichier par fichier, reindex_findings, re-vérifie que les findings ont disparu
```

## 9. Métriques de succès

| Métrique | Cible V1 |
|----------|----------|
| Pertinence : % de requêtes NL findings où le bon finding est dans le top-5 (jeu d'éval interne) | ≥ 85 % |
| Économie de tokens vs `semgrep scan --json` brut pour répondre à la même question | ≥ 70 % |
| Latence requête p95 (repo 500k LOC) | < 1 s |
| Surcoût d'indexation incrémentale (20 fichiers) | < 10 s |
| Boucle de correction agent : % de findings corrigés dont le finding disparaît à la réindexation | ≥ 90 % |
| Adoption : % d'utilisateurs activant la feature à 3 mois | ≥ 25 % |

## 10. Risques et mitigations

| Risque | Impact | Mitigation |
|--------|--------|------------|
| Faux positifs Semgrep → l'agent « corrige » du code sain | Confiance, régressions | Sévérité min configurable ; le skill impose de valider le finding avant patch ; support des `# nosemgrep` existants |
| Coût du scan sur gros repos / packs lourds | Indexation lente | Incrémental par fichier, timeout par règle |
| Dérive de version Semgrep (format JSON, comportement des règles) | Casse silencieuse | Contrat de parsing testé sur fixtures (voir ADR-8) |
| Embeddings de findings peu discriminants (messages de règles répétitifs) | Pertinence UC1 | Texte embeddé enrichi (extrait de code + catégories) ; jeu d'éval dès le MVP |
| Dépendance amont `cocoindex-code` (API interne non stable) | Maintenance | Package compagnon plutôt que fork (ADR-1) |

## 11. Jalons

| Jalon | Contenu | Critère de sortie |
|-------|---------|-------------------|
| **M1 — MVP CLI** | Configuration, indexation, recherche/résumé CLI ; jeu d'éval pertinence | UC1 utilisable au quotidien ; métriques pertinence/latence mesurées |
| **M2 — Intégration agent** | MCP (findings + jointure code), skill | UC2/UC3 démontrés dans Claude Code de bout en bout |
| **M3 — V1** | Documentation, éval de bout en bout | Cibles §9 atteintes sur le jeu d'éval interne |

Statut réel (voir `archive/BACKLOG.md`) : M1, M2 et M3 sont atteints — l'ensemble
des tâches F0.1 à F7.2 du plan d'implémentation initial est livré.

## 12. Questions ouvertes restantes

1. Les findings **supprimés** doivent-ils être conservés en historique (audit, UC6 étendu) ou purgés ? V1 a retenu : purge (`replace_findings_for_files` supprime puis réinsère), pas de diff persistant — UC6 (Could) n'est pas livré en V1.
2. ~~Faut-il embarquer un **pack de règles par défaut** quand le projet n'a pas de config Semgrep ?~~ Tranché (ADR-13) : `cccf init` se replie sur le pack registry `p/security-audit` quand rien n'est détecté ni passé en `--rules` — revient sur le choix initial « config explicite obligatoire » pour réduire la friction de démarrage (voir `SPEC-FONC.md`, commande `init`).
3. Politique sur **Semgrep Pro** (règles interfile) : toujours hors scope, non traité.
