# PRD — ccc-findings : enrichissement de cocoindex-code par les résultats Semgrep

| | |
|---|---|
| **Produit** | ccc-findings (nom de travail) — extension de [cocoindex-code](https://github.com/cocoindex-io/cocoindex-code) |
| **Auteur** | Mehdi El-Kouhen |
| **Statut** | Draft v0.1 |
| **Date** | 2026-07-11 |

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

1. **Indexer** les résultats de règles Semgrep (règles configurées par le projet : registry semgrep, packs custom, règles maison) dans le même pipeline incrémental que le code.
2. **Lier** chaque finding au chunk AST correspondant, pour que toute réponse combine finding + code concerné.
3. **Exposer** cette connaissance aux LLM via les mêmes surfaces que `ccc` : CLI, skill, serveur MCP — dans l'esprit du skill `cocoindex` existant, mais avec les résultats d'analyse en plus.

Non-objectifs (voir §5) : remplacer Semgrep CI/CD, faire du triage de vulnérabilités, réécrire un moteur d'analyse.

## 3. Personas et cas d'usage

### Personas

- **P1 — Agent de codage** (Claude Code, agent MCP) : consommateur principal. Interroge l'index avant/pendant une modification, corrige des findings à la demande.
- **P2 — Développeur** : utilise le CLI `ccc` directement pour explorer la dette sécurité/qualité de son périmètre.
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

- **vs `semgrep scan` à la demande** : réponses en < 1 s (index persistant, pas de re-scan), sortie filtrée sémantiquement et compacte (objectif : 70 %+ d'économie de tokens, aligné sur la promesse de `ccc`).
- **vs SAST plateformes (Semgrep AppSec Platform, SonarQube)** : local-first, sans serveur, conçu pour la boucle interne de l'agent, pas pour la gouvernance.
- **vs index code seul (`ccc` actuel)** : chaque réponse peut porter la dimension « problèmes connus », ce qu'aucun embedding de code seul ne capture.

## 5. Périmètre

### Inclus (V1)

- Exécution de Semgrep pilotée par `ccc` avec la **configuration de règles du projet** (fichier `.semgrep.yml`, dossier de règles, packs registry — configurable dans `.cocoindex_code/settings.yml`).
- Indexation incrémentale des findings : re-scan limité aux fichiers modifiés (aligné sur le mécanisme incrémental cocoindex existant).
- Modèle de données finding : règle (id, message, sévérité, catégorie/CWE/OWASP si présents), localisation (fichier, lignes), extrait, `fix` suggéré, lien vers le chunk AST.
- Embedding des findings (message de règle + métadonnées + extrait) dans le même store vectoriel, avec espace de noms distinct.
- CLI : `ccc findings` (recherche, filtres, agrégats), extension de `ccc search --with-findings`.
- MCP : nouveaux tools `search_findings` et enrichissement du tool `search` existant.
- Skill Claude Code mis à jour (workflow d'interrogation + correction guidée).

### Exclus (V1)

- Autres moteurs que Semgrep (extensibilité prévue dans l'architecture, non livrée).
- Triage/workflow de findings (assignation, faux positifs persistés, SLA) — hors boucle agent.
- Exécution de Semgrep Pro / règles interfile taint cross-repo.
- Application automatique des fixes sans agent (les `fix` Semgrep sont du contexte fourni à l'agent, pas un autofix produit).
- UI web / dashboards.

## 6. Exigences fonctionnelles

### F1 — Configuration

- F1.1 : la config projet (`.cocoindex_code/settings.yml`) accepte une section `semgrep` : sources de règles (chemins, packs registry `p/...`), inclusions/exclusions, sévérité minimale indexée, timeout.
- F1.2 : `ccc init` détecte une config Semgrep existante (`.semgrep.yml`, `semgrep.yml`) et propose de l'activer.
- F1.3 : absence de Semgrep installé → message actionnable, le reste de `ccc` fonctionne inchangé (feature strictement additive).

### F2 — Indexation

- F2.1 : `ccc index` exécute le scan Semgrep sur les fichiers nouveaux/modifiés uniquement et met à jour les findings de ces fichiers (suppression des findings obsolètes incluse).
- F2.2 : chaque finding est rattaché au chunk AST englobant ; si aucun chunk (fichier non parsable), rattachement au fichier.
- F2.3 : les findings sont vectorisés avec le même modèle d'embedding que le code (texte embeddé : message règle + id + catégories + extrait normalisé).
- F2.4 : identité stable d'un finding (hash règle + chemin + empreinte du code concerné) pour permettre le diff entre indexations (UC6) et éviter les doublons.
- F2.5 : un scan complet reste possible (`ccc index --full-scan` ou équivalent existant).

### F3 — Requêtage

- F3.1 : `ccc findings "<requête NL>"` → top-k findings par similarité, avec filtres `--severity`, `--rule`, `--path`, `--lang`, pagination.
- F3.2 : sortie compacte par défaut (règle, sévérité, fichier:lignes, message court) ; `--context` ajoute le chunk de code lié.
- F3.3 : `ccc search --with-findings` annote chaque résultat code du nombre et de la sévérité max de ses findings.
- F3.4 : `ccc findings --summary` → agrégats par règle/sévérité/répertoire (UC5), format tableau court.
- F3.5 : sortie `--json` sur toutes les commandes pour consommation machine.

### F4 — Intégrations agent

- F4.1 : tool MCP `search_findings(query, filters)` retournant le format compact F3.2.
- F4.2 : le tool MCP `search` existant accepte `with_findings: true`.
- F4.3 : skill mis à jour décrivant : quand interroger les findings, comment mener une correction guidée (récupérer finding → lire chunk → patcher → réindexer → vérifier disparition du finding).
- F4.4 : hook (optionnel) SessionStart/PreToolUse qui rafraîchit l'index et peut signaler les findings des fichiers touchés (UC2), désactivable.

## 7. Exigences non fonctionnelles

- **NF1 — Performance requête** : p95 < 1 s sur un repo de 500k LOC déjà indexé.
- **NF2 — Performance indexation** : surcoût Semgrep incrémental < 10 s pour un changement de 20 fichiers avec les packs par défaut ; jamais bloquant pour la recherche code (indexation findings asynchrone ou tolérante à l'échec).
- **NF3 — Économie de tokens** : une réponse `search_findings` top-5 ≤ ~1 200 tokens ; mesurée et suivie via `rtk gain`-like / télémétrie interne.
- **NF4 — Local-first & confidentialité** : aucun code, chemin, finding ni requête envoyé à l'extérieur (hors provider d'embedding cloud si explicitement configuré) ; télémétrie anonyme opt-out, alignée sur la politique `ccc` existante.
- **NF5 — Robustesse** : échec ou timeout Semgrep → l'index code reste valide et interrogeable ; les findings sont marqués périmés, pas supprimés silencieusement.
- **NF6 — Compatibilité** : Python 3.10+, mêmes plateformes que `ccc` ; images Docker slim/full étendues avec le binaire Semgrep.

## 8. Architecture cible (vue produit)

```
                    ┌──────────────────────────────┐
   fichiers   ──►   │  Flow cocoindex (incrémental) │
   modifiés         │                              │
                    │  ┌────────┐   ┌────────────┐ │
                    │  │ chunks │   │  semgrep    │ │
                    │  │  AST   │   │  scan (JSON)│ │
                    │  └───┬────┘   └─────┬──────┘ │
                    │      │   liaison    │        │
                    │      └──── chunk ◄──┘        │
                    │            ▼                 │
                    │   embeddings (code+findings) │
                    └───────────┬──────────────────┘
                                ▼
                    LMDB (vecteurs) + SQLite (findings, liens)
                                ▲
              ┌─────────────────┼──────────────────┐
         CLI ccc            MCP server           skill/hooks
      (findings, search)  (search_findings)    (Claude Code)
```

Décisions structurantes :

1. **Semgrep comme transformation dans le flow cocoindex** (pas un post-traitement séparé) : on hérite gratuitement de l'incrémental, du cache et de la cohérence code/findings à chaque indexation.
2. **Un seul store, deux espaces de noms** : les findings vivent dans le même LMDB/SQLite que le code — pas de deuxième infrastructure à gérer.
3. **Interface moteur abstraite** (`AnalysisEngine`) même si seul Semgrep est livré en V1, pour ouvrir la porte à d'autres analyseurs (bandit, ruff, gitleaks…) en V2 sans refonte.

## 9. Expérience cible (exemples)

```bash
# Setup
ccc init                        # détecte .semgrep.yml, propose l'activation
ccc index                       # code + findings, incrémental

# Développeur
ccc findings "injection sql" --severity ERROR
# ▸ python.lang.security.audit.formatted-sql-query  ERROR
#   src/api/orders.py:42-45 — Detected formatted string in SQL statement…
#   (2 autres findings, --limit pour paginer)

ccc findings --summary
# ERROR 4 | WARNING 12 | INFO 31   — top règles : formatted-sql-query (4)…
```

```text
# Agent (via MCP / skill)
Utilisateur : « corrige les problèmes de sécurité du module paiements »
Agent : search_findings("sécurité", path="src/payments/*", severity="ERROR")
      → 3 findings compacts + chunks liés
      → patch fichier par fichier, ccc index, re-vérifie que les findings ont disparu
```

## 10. Métriques de succès

| Métrique | Cible V1 |
|----------|----------|
| Pertinence : % de requêtes NL findings où le bon finding est dans le top-5 (jeu d'éval interne) | ≥ 85 % |
| Économie de tokens vs `semgrep scan --json` brut pour répondre à la même question | ≥ 70 % |
| Latence requête p95 (repo 500k LOC) | < 1 s |
| Surcoût d'indexation incrémentale (20 fichiers) | < 10 s |
| Boucle de correction agent : % de findings corrigés dont le finding disparaît à la réindexation | ≥ 90 % |
| Adoption : % d'utilisateurs `ccc` activant la feature à 3 mois | ≥ 25 % |

## 11. Risques et mitigations

| Risque | Impact | Mitigation |
|--------|--------|------------|
| Faux positifs Semgrep → l'agent « corrige » du code sain | Confiance, régressions | Sévérité min configurable ; le skill impose de valider le finding avant patch ; support des `# nosemgrep` existants |
| Coût du scan sur gros repos / packs lourds | Indexation lente | Incrémental par fichier, timeout par règle, scan asynchrone non bloquant (NF2/NF5) |
| Dérive de version Semgrep (format JSON, comportement des règles) | Casse silencieuse | Pin de version testée + contrat de parsing testé sur fixtures |
| Embeddings de findings peu discriminants (messages de règles répétitifs) | Pertinence UC1 | Texte embeddé enrichi (extrait de code + catégories) ; fallback filtres exacts ; jeu d'éval dès le MVP |
| Dépendance amont `cocoindex-code` (API interne non stable) | Maintenance | Contribution upstream discutée tôt ; sinon extension par points d'entrée publics (custom chunkers/flows) |

## 12. Jalons

| Jalon | Contenu | Critère de sortie |
|-------|---------|-------------------|
| **M0 — Spike** (2 sem.) | Flow cocoindex exécutant Semgrep incrémental sur un repo test ; findings liés aux chunks en SQLite | Démo : requête vectorielle retourne un finding pertinent |
| **M1 — MVP CLI** | F1, F2, F3.1–F3.2 ; jeu d'éval pertinence | UC1 utilisable au quotidien ; métriques pertinence/latence mesurées |
| **M2 — Intégration agent** | F3.3–F3.5, F4 (MCP + skill + hook) | UC2/UC3 démontrés dans Claude Code de bout en bout |
| **M3 — V1 GA** | NF durcies, Docker, docs, télémétrie, diff findings (UC6 si budget) | Cibles §10 atteintes sur 3 repos pilotes |

## 13. Questions ouvertes

1. **Distribution** : contribution upstream à `cocoindex-io/cocoindex-code` ou package compagnon (`cocoindex-code-findings`) ? Impacte M0.
2. Les findings **supprimés** doivent-ils être conservés en historique (audit, UC6 étendu) ou purgés ? V1 propose : purge + diff éphémère.
3. Faut-il embarquer un **pack de règles par défaut** (`p/default`, `p/security-audit`) quand le projet n'a pas de config Semgrep, ou exiger une config explicite ? Recommandation : config explicite en V1 (éviter le bruit).
4. Politique sur **Semgrep Pro** (règles interfile) : hors scope V1, mais la config doit-elle déjà l'accepter en passthrough ?
