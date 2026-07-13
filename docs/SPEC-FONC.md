# Spécification fonctionnelle — ccc-findings (`cccf`)

> Décrit le comportement observable des trois surfaces livrées : CLI, serveur
> MCP, skill Claude Code. Pour l'architecture interne (schémas, algorithmes),
> voir [`SPEC-TECH.md`](./SPEC-TECH.md). Pour le pourquoi des choix, voir
> [`ADR.md`](./ADR.md).

## 1. Configuration du projet

Fichier `.cccf/config.yml`, à la racine du repo cible :

```yaml
rules:                  # requis — chemins ou identifiants de config Semgrep
  - rules/rules.yml
include:                 # défaut : ["**/*"]
  - "**/*"
exclude:                  # défaut : [".git/**", ".venv/**", "node_modules/**", ".cccf/**"]
  - ".git/**"
  - ".venv/**"
  - "node_modules/**"
  - ".cccf/**"
min_severity: INFO        # INFO | WARNING | ERROR
embedding_model: Snowflake/snowflake-arctic-embed-xs
semgrep_timeout_s: 120
```

- `rules` est le seul champ obligatoire ; son absence ou sa vacuité est une
  erreur bloquante (`ConfigError`).
- `min_severity` invalide (hors `INFO`/`WARNING`/`ERROR`) est une erreur
  bloquante.
- Tous les autres champs ont une valeur par défaut appliquée silencieusement
  si absents du fichier.

## 2. CLI `cccf`

### `cccf version`
Affiche la version du package (`0.1.0`).

### `cccf init [--rules PATH]...`
Crée `.cccf/config.yml`.

- `--rules` répétable : chemins ou identifiants de config Semgrep (ex.
  `rules/rules.yml`, `p/security-audit`).
- Sans `--rules` : détection automatique dans l'ordre `.semgrep.yml` →
  `semgrep.yml` → `.semgrep`. Si rien n'est trouvé, repli sur le pack
  registry Semgrep par défaut `p/security-audit` (pas d'erreur) : message
  informatif sur stdout précisant le pack utilisé et comment le changer,
  code de sortie 0. Ordre de priorité : `--rules` explicite > config locale
  détectée > pack par défaut.
- Si `.cccf/config.yml` existe déjà : erreur explicite, code de sortie 1, le
  fichier existant n'est jamais écrasé.

### `cccf index [--full] [--engine manual|cocoindex]`
Indexe le projet (findings Semgrep **et** endpoints REST/Kafka —
BACKLOG-11 A1).

- Par défaut : incrémental — ne re-scanne que les fichiers ajoutés ou
  modifiés depuis la dernière indexation (hash SHA-256 par fichier) ; les
  fichiers supprimés du disque voient leurs findings et endpoints purgés.
- `--full` : force un scan complet, comme si tous les fichiers étaient
  modifiés (les fichiers supprimés du disque sont quand même purgés).
- `--engine manual` (défaut) : indexe les findings et les endpoints, avec le
  moteur incrémental historique.
- `--engine cocoindex` : mode expérimental inspiré de CocoIndex. Il indexe les
  mêmes findings et endpoints, et ajoute un index local de chunks de code
  (`code_chunks` + embeddings) utilisé ensuite par `cccf search` avant de
  retomber sur `ccc`.
- Un seul scan Semgrep par indexation : `config.rules` peut mélanger règles
  de findings (`default`, `liveness`) et règles d'inventaire d'endpoints
  (`rest`, `kafka`, `metadata.category: endpoint-inventory`) — chacune
  finit dans la bonne table, sans se marcher dessus (voir
  `docs/SPEC-TECH.md#3-pipeline-dindexation-indexerindex_repo`). Les règles
  d'inventaire ne sont pas filtrées par `min_severity`.
- Sortie sur une ligne :
  `scanned=<N> skipped=<N> +findings=<N> -findings=<N> +endpoints=<N> -endpoints=<N>`
  - `scanned` : nombre de fichiers (re)scannés.
  - `skipped` : nombre de fichiers inchangés, non re-scannés.
  - `+findings`/`-findings` : findings (ré)insérés / supprimés pour les
    fichiers scannés ou supprimés du disque.
  - `+endpoints`/`-endpoints` : endpoints (ré)insérés / supprimés, même
    logique.
- Code de sortie 0 en cas de succès.
- Échec Semgrep (timeout, crash, code retour inattendu) : message d'erreur sur
  stderr, **code de sortie 2**, la base `.cccf/findings.db` reste inchangée
  (aucune écriture partielle, findings et endpoints compris).
- `.cccf/config.yml` absent ou invalide : message d'erreur sur stderr, code de
  sortie 1.

### `cccf search "<requête>" [--limit N] [--offset N] [--lang L] [--path GLOB] [--refresh] [--json]`
Recherche sémantique de code enrichie des findings Semgrep qui recouvrent
chaque résultat, puis classée en tenant compte de leur sévérité (voir §3,
`rank_by_severity`). Mêmes options, mêmes noms, que `ccc search` :

| Option | Effet |
|---|---|
| `--limit N` | nombre maximum de résultats (défaut 5) |
| `--offset N` | pagination (défaut 0) |
| `--lang L` | ne garde que les résultats du langage `L` (égalité exacte) |
| `--path GLOB` | ne garde que les résultats dont le chemin matche le glob (style `fnmatch`) |
| `--refresh` | réindexe (incrémental) avant de chercher |

Deux sources de code sont possibles :
- si le repo a été indexé avec `cccf index --engine cocoindex`, `cccf search`
  interroge d'abord l'index local de chunks de code (`vec_code_chunks`) et ne
  dépend pas du format texte de `ccc search` — `--lang`/`--path`/`--offset`
  filtrent et paginent localement, `--refresh` déclenche une réindexation
  incrémentale locale (`cccf index --engine cocoindex`) avant la recherche ;
- sinon, `cccf search` reste un **sur-ensemble de `ccc search`** : mêmes
  résultats (mêmes extraits, même format d'affichage), enrichis des findings,
  et toutes les options sont transmises telles quelles au binaire `ccc`.

Rendu texte — format identique à `ccc search`, plus un bloc findings sous
chaque résultat concerné :
```
--- Result 1 (score: 0.850) ---
File: src/auth.py:12-34 [python]
def login(user, password):
    ...

  ⚠ findings (max: ERROR):
  [ERROR] custom.sql-fstring  src/auth.py:18-18
    Une requête SQL construite par f-string permet une injection SQL.
```
Le `score` affiché reste la pertinence sémantique brute de `ccc` ; le boost
par sévérité n'affecte que l'ordre.

Rendu `--json` : objet `CodeSearchResult` (schéma unique et stable, voir §3).

Dégradations :
- **Index code expérimental absent** : comportement normal ; fallback sur
  `ccc search`.
- **`ccc` indisponible** (absent du PATH, ou en erreur) : erreur explicite,
  stderr conserve la cause (`ccc introuvable...` ou code retour/stderr de
  `ccc`), code de sortie 2. `cccf` ne retourne pas de résultat findings-only
  success-shaped dans ce cas.
- **Index findings absent** (mais `ccc` disponible) : résultats de code
  bruts, précédés de l'avertissement
  `index findings absent (lancez: cccf index) : résultats sans findings`,
  code de sortie 0.

### `cccf findings "<requête>" [options]`
Recherche en langage naturel dans les findings indexés **seuls** (sans
recherche de code) — l'ancienne `cccf search`, renommée quand `search` est
devenue le sur-ensemble de `ccc search`.

| Option | Effet |
|---|---|
| `--severity S` | ne garde que les findings de sévérité ≥ S (S ∈ INFO/WARNING/ERROR) |
| `--rule R` | ne garde que les findings de la règle `R` (égalité exacte sur `rule_id`) |
| `--path GLOB` | ne garde que les findings dont le chemin matche le glob (style `fnmatch`) |
| `--limit N` | nombre maximum de résultats (défaut 5) |
| `--offset N` | pagination (défaut 0) |
| `--context` | ajoute le contexte de code (5 lignes avant/après, bornées au fichier) |
| `--json` | sortie JSON structurée au lieu du rendu texte |

Rendu texte, un bloc par résultat :
```
1. [ERROR] custom.sql-fstring  app/db.py:12-14  (0.83)
   Une requête SQL construite par f-string permet une injection SQL.
```
Avec `--context`, le bloc de code numéroté est ajouté à la suite (format
`{n:>5}| {ligne}`). Si le fichier source a disparu ou n'est plus lisible depuis
la dernière indexation, le finding reste affiché et le contexte est signalé
comme indisponible pour ce résultat uniquement.

Rendu `--json` de `cccf findings` : liste d'objets — **contrat stable**
(`FindingHit`, `render.py`), consommé aussi par le serveur MCP
(`search_findings`) :
```json
{
  "id": "...", "rule_id": "...", "severity": "...", "message": "...",
  "path": "...", "start_line": 0, "end_line": 0, "score": 0.0,
  "fix": null, "cwe": [], "owasp": [],
  "context": null,        // toujours présent ; string si --context a réussi
  "context_error": null   // toujours présent ; string si --context a échoué
}
```
`context`/`context_error` sont toujours présents (valeur `null` par défaut) —
schéma stable, plutôt que des clés apparaissant/disparaissant selon `--context`
(nécessaire pour un `outputSchema` MCP correct, voir §3).

Si l'index n'existe pas (`.cccf/findings.db` absent) : message exact sur
stderr `Index absent. Lancez d'abord: cccf index`, code de sortie 2.

### `cccf summary [--json]`
Vue agrégée des findings.

Rendu texte, 3 lignes : totaux par sévérité, top 10 des règles avec compte,
compte par répertoire de premier niveau.

Rendu `--json` :
```json
{
  "by_severity": {"ERROR": 2, "WARNING": 2},
  "top_rules": [{"rule_id": "...", "count": 2}, ...],
  "by_top_level_dir": {"app": 4}
}
```

Mêmes règles d'index absent que `findings` (message identique, code 2).

### `cccf endpoints [--system S] [--role R] [--topic T] [--path GLOB] [--json]`
Liste les endpoints REST/Kafka indexés (BACKLOG-10 K1, BACKLOG-11 A1).
Filtres optionnels combinables :

| Option | Effet |
|---|---|
| `--system` | `rest` ou `kafka` |
| `--role` | `serve`/`call` (rest) ou `produce`/`consume` (kafka) |
| `--topic` | égalité exacte sur `topic` (ex. `"GET /orders/{id}"`, `"orders.created"`) |
| `--path` | motif de chemin (`fnmatch`), même style que `cccf search --path` |

Rendu texte, une ligne par endpoint :
`[<system>/<role>] <topic>[ (dynamique)]  <path>:<start>-<end>`

Rendu `--json` : liste de `EndpointHit` (`id`, `role`, `system`, `topic`,
`topic_dynamic`, `source`, `framework`, `path`, `start_line`, `end_line`).

Mêmes règles d'index absent que `findings` (message identique, code 2) —
`endpoints` vit dans la même base que `findings`.

### `cccf graph [--json]`
Points de blocage probables à partir des endpoints indexés (BACKLOG-10 K12) :
appels REST synchrones détectés dans un handler de consommation Kafka (même
fichier, site d'appel dans la plage de lignes du handler). Les cycles
d'appels inter-services et les hotspots (site sur un cycle + finding
liveness K8) nécessitent plusieurs projets indexés — fédération multi-dépôts
K7, pas encore livrée — donc toujours vides pour l'instant (voir ADR-27) :
la réponse le dit explicitement plutôt que de laisser deviner une absence
de résultat.

Rendu `--json` :
```json
{
  "outbound_calls_in_consumers": [
    {"consumer": {"path": "...", "start_line": 15, "end_line": 25, "topic": "orders.created"},
     "call": {"path": "...", "start_line": 20, "end_line": 20, "topic": "POST /payments"}}
  ],
  "cycles": [],
  "hotspots": [],
  "note": "Cycles et hotspots inter-services nécessitent plusieurs projets indexés (...)"
}
```

Mêmes règles d'index absent que `findings`/`summary` (message identique,
code 2) — `endpoints` vit dans la même base que `findings` (`.cccf/
findings.db`).

### `cccf mcp`
Lance le serveur MCP (stdio) sur le repo courant (répertoire d'exécution).
`cccf mcp --help` documente le bloc d'enregistrement client :
```json
{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}
```

## 3. Serveur MCP

Six tools, chacun annoté avec un type de retour concret (`TypedDict` ou
dataclass, jamais `str`) — FastMCP en dérive un `outputSchema` par champ,
exposé aux clients MCP en plus du texte JSON habituel (`structuredContent`
*et* `content` texte, les deux dans la même réponse ; un client qui ignore le
premier retombe sur le second, aucune régression pour les clients existants).
Une exception levée dans un tool **n'est plus interceptée** : elle remonte
telle quelle, FastMCP la convertit en `ToolError` puis en `isError: true`
côté protocole — le signal standard qu'un client MCP peut détecter sans
parser le texte de réponse (avant : `{"error": "<message>"}` retourné comme
un résultat normal, indiscernable d'un succès sans convention côté client).

| Tool | Type de retour | Rôle | Notes |
|---|---|---|---|
| `search_findings(query, severity=None, rule=None, path_glob=None, limit=5, include_context=False)` | `list[FindingHit]` | Recherche en langage naturel — même contrat que `cccf findings --json` | Pas de pagination (`offset`) côté MCP |
| `findings_summary()` | `FindingsSummary` | Vue agrégée à faible coût | Même structure que `cccf summary --json` |
| `reindex_findings()` | `IndexReport` (dataclass de `indexer.py`, réutilisée telle quelle) | Réindexation incrémentale | Champs `scanned, skipped, findings_added, findings_removed, deleted_files` |
| `search(query, limit=5, offset=0, lang=None, path=None, refresh=False)` | `CodeSearchResult` | Recherche de code annotée des findings qui recouvrent chaque résultat — même nom de tool, mêmes paramètres et même comportement que le `search` de ccc, et équivalent à la CLI `cccf search` (implémentation partagée, `code_search.py`) | Utilise l'index code expérimental s'il existe, sinon `ccc` |
| `list_endpoints(system=None, role=None, topic=None, path_glob=None)` | `list[EndpointHit]` | Liste filtrable des endpoints REST/Kafka indexés — équivalent à la CLI `cccf endpoints` | BACKLOG-10 K1, BACKLOG-11 A1 |
| `graph()` | `GraphResult` | Points de blocage probables (BACKLOG-10 K12) — équivalent à la CLI `cccf graph` | `cycles`/`hotspots` vides tant que K7 (fédération) n'est pas livré (ADR-27) |

`search` ajoute à chaque résultat de code :
- `findings` : liste des findings dont `path` est identique et dont la plage
  `[start_line, end_line]` chevauche celle du résultat de code (chevauchement
  inclusif — une seule ligne commune suffit) — même contrat que `findings`,
  sans le champ `context`.
- `max_severity` : la sévérité la plus haute parmi les findings joints, ou
  `null` si aucun.

**Classement pondéré par sévérité** (`ccc_bridge.rank_by_severity`) : l'ordre
de `ccc search` (pertinence sémantique pure) est ré-ordonné en ajoutant un
boost additif à `score` selon `max_severity` (`ERROR` +0.15, `WARNING` +0.05,
`INFO`/aucun +0.0), puis tronqué à `limit`. `score` lui-même n'est pas modifié
— seul l'ordre en tient compte. Pour que ce boost puisse faire remonter un
résultat juste hors du top `limit` de `ccc`, l'appel sous-jacent sur-demande
(`overfetch_limit` : `limit × 3`, plafonné à 50) avant de trier et tronquer.

`CodeSearchResult` a un schéma **unique et stable** pour les réponses réussies
(nominales ou index findings absent) — pas de forme alternative selon le cas,
pour que l'`outputSchema` reste valide :
```json
{
  "results": [...],                 // sans findings si index absent
  "findings_only_fallback": [],     // conservé vide pour compatibilité de schema
  "warning": null                   // string explicative en mode dégradé, null sinon
}
```
Si `ccc` échoue ou est absent : exception (`ccc introuvable...` ou
`ccc a échoué...`) → `isError: true` côté MCP, code de sortie 2 côté CLI.

## 4. Skill Claude Code (distribué séparément — `~/cocoindex-ext-skill/SKILL.md`)

Déclencheurs : vulnérabilité, sécurité, semgrep, finding, dette, audit.

Règle d'or UX : commencer par la requête la moins coûteuse qui répond à la
question, puis demander plus de contexte seulement quand il faut agir. Le skill
choisit donc entre :
1. **Vue d'ensemble** — `findings_summary()` pour un état court.
2. **Recherche ciblée** — `search_findings(...)` pour un problème ou un fichier.
3. **Recherche code + dette** — `search(...)` quand la question porte
   d'abord sur du code.
4. **Boucle de correction** — `search_findings(..., include_context=true)` →
   patch → scan Semgrep frais sur le fichier si le MCP officiel est disponible
   → `reindex_findings()` → même `search_findings(...)` pour confirmer la
   disparition ; abandon et signalement après 2 tentatives infructueuses.

Anti-patterns explicites : ne pas scanner tout le repo via le MCP Semgrep
officiel (préférer l'index `cccf`), ne pas corriger sans avoir lu le contexte,
ne pas supprimer un commentaire `# nosemgrep` existant, ne pas exposer le JSON
brut à l'utilisateur sauf demande explicite, et utiliser les fallbacks MCP
existants plutôt que bloquer inutilement.

## 5. Comportements d'erreur — résumé

| Situation | Surface | Comportement |
|---|---|---|
| `.cccf/config.yml` absent | `cccf index` | stderr + code 1 |
| Pas de config Semgrep détectée et pas de `--rules` | `cccf init` | repli sur `p/security-audit`, message informatif stdout + code 0 |
| `.cccf/config.yml` déjà existant | `cccf init` | stderr + code 1, fichier non modifié |
| Semgrep échoue ou dépasse le timeout | `cccf index` | stderr + code 2, base inchangée |
| `.cccf/findings.db` absent | `cccf findings` / `cccf summary` (et `cccf search` si `ccc` est aussi indisponible) | stderr (message exact) + code 2 |
| Embeddings incompatibles avec la requête | `cccf findings` (ou repli findings de `cccf search`) | stderr actionnable + code 2 |
| Toute exception | tools MCP | remonte telle quelle → `ToolError` FastMCP → `isError: true` côté protocole ; le serveur reste utilisable pour l'appel suivant |
| `ccc` absent ou en erreur | `cccf search` / `search` (MCP) | stderr/exception explicite, code 2 côté CLI, `isError: true` côté MCP |

## 6. Pack de règles liveness (BACKLOG-10 K8)

Le pack de règles vit dans le repo skill, pas dans ce repo : voir
[`ccc-findings-skill`](https://github.com/elkouhen/ccc-findings-skill)
`skills/cccf/rules/liveness/java.yaml`, aux côtés du pack `default` déjà
distribué par le skill (ADR-24). `cccf` lui-même ne livre plus aucun
fichier de règles (`src/cccf/rules/` n'existe pas) — il ne fait qu'exécuter
Semgrep avec les chemins déclarés dans `rules:`. Ce repo garde une copie de
test dans `tests/fixtures/liveness_repo/rules/`
(`tests/test_liveness_rules.py`), tenue à jour manuellement avec la copie
du skill.

Cible d'analyse : **Java + Spring + Maven uniquement** — décision de
périmètre, pas un manque temporaire (voir « Périmètre » ci-dessous).

| Règle | Langage | Sévérité | Détecte |
|---|---|---|---|
| `cccf.liveness.java.new-resttemplate-no-timeout` | Java | WARNING | `new RestTemplate()` sans configuration de timeout (vs `RestTemplateBuilder`) |
| `cccf.liveness.java.blocking-join-no-timeout` | Java | WARNING | `.join()` sans argument (`Thread` ou `CompletableFuture`) |
| `cccf.liveness.java.blocking-future-get-no-timeout` | Java | WARNING | `.get()` sans argument sur une variable déclarée `Future<T>`/`CompletableFuture<T>` |
| `cccf.liveness.java.rest-call-in-kafka-listener` | Java | ERROR | Appel `RestTemplate` dans une méthode `@KafkaListener` |
| `cccf.liveness.java.network-call-inside-synchronized` | Java | ERROR | Appel `RestTemplate` à l'intérieur d'un bloc `synchronized` |

**Usage** : comme le pack `default`, le copier dans le repo cible
(ex. `.cccf/rules/liveness/`) et le déclarer dans `rules:` — jamais de
chemin absolu vers le repo skill (ADR-24) :

```yaml
rules:
  - .cccf/rules/liveness/java.yaml
```

Périmètre : Java (`RestTemplate`, Spring Kafka `@KafkaListener`,
`synchronized`, `Future`/`CompletableFuture`) — la stack cible de l'analyse
est Java + Spring + Maven ; Python/JS/TS ne sont pas des cibles (voir K8
dans `archive/BACKLOG-10.md`). Le volet sécurité (SASL en clair,
`PLAINTEXT`, désérialisation non sûre) n'est pas encore livré.

## 7. Pack de règles d'inventaire REST (BACKLOG-10 K11)

Comme le pack liveness, vit dans `ccc-findings-skill`
(`skills/cccf/rules/rest/java.yaml`, ADR-24) — copie de test dans
`tests/fixtures/rest_repo/`. Contrairement aux packs liveness/`default`, ce
pack n'est **pas un pack de findings** : `metadata.severity` (`INFO`) n'a
pas de sens à seuiller, et `cccf` ne l'exécute pas encore automatiquement à
`cccf init`/`cccf index` — K1/K11 livrent le modèle de données
(`MessageEndpoint`) et l'extraction (`run_semgrep_endpoints`,
`parse_semgrep_endpoints` dans `scanner.py`), pas encore le branchement dans
le pipeline d'indexation ni une commande CLI/MCP (K3, K5/K6, non livrés).

| Règle | Langage | Rôle | Détecte |
|---|---|---|---|
| `cccf.rest.java.serve-{get,post,put,delete,patch}` | Java | `serve` | Route Spring exposée (`@GetMapping`/`@PostMapping`/`@PutMapping`/`@DeleteMapping`/`@PatchMapping`, ou `@RequestMapping(method=...)` pour GET) |
| `cccf.rest.java.call-{get,post,put,delete}` | Java | `call` | Appel `RestTemplate` (`getForObject`/`getForEntity`, `postForObject`/`postForEntity`, `put`, `delete`) |

Chaque résultat porte `metadata.category: endpoint-inventory`,
`metadata.role`, `metadata.http_method`, `metadata.framework` — le contrat
que lit `parse_semgrep_endpoints` (voir `docs/SPEC-TECH.md#4bis-extraction-
dendpoints-rest--kafka-run_semgrep_endpoints-backlog-10-k11k2`). Le chemin
est extrait du texte du site (regex sur le snippet, pas de métavariable
Semgrep — ADR-26) : un chemin non littéral, ou concaténé à une variable,
est marqué `topic_dynamic=True` plutôt que résolu au hasard.
`@RequestMapping` avec méthode explicite autre que GET reste à couvrir.
Périmètre : Java uniquement — la stack cible de l'analyse est Java +
Spring + Maven (voir K8/K11 dans `archive/BACKLOG-10.md`).

## 8. Pack de règles d'inventaire Kafka (BACKLOG-10 K2)

Comme le pack REST, vit dans `ccc-findings-skill`
(`skills/cccf/rules/kafka/java.yaml`, ADR-24) — copie de test dans
`tests/fixtures/kafka_repo/`. Pas un pack de findings, pas exécuté
automatiquement (mêmes raisons que K11).

| Règle | Rôle | Détecte |
|---|---|---|
| `cccf.kafka.java.consume` | `consume` | Méthode `@KafkaListener(topics = "...")` |
| `cccf.kafka.java.produce-template` | `produce` | `KafkaTemplate.send(topic, valeur, ...)` (au moins 2 arguments — exclut `send(ProducerRecord)`, déjà couvert ci-dessous) ou `KafkaTemplate.sendDefault(...)` (topic implicite, toujours dynamique) |
| `cccf.kafka.java.produce-record` | `produce` | `new ProducerRecord(topic, ...)` |

Le topic est extrait comme pour REST (`extra.metadata.role`, pas de
`http_method` ici), avec un cas supplémentaire propre à Kafka/Spring : un
littéral de la forme `${propriete.imbriquee}` — un topic externalisé en
configuration (`@KafkaListener(topics = "${app.kafka.topics.orders}")`) —
n'est **pas** traité comme un nom de topic littéral. `cccf` tente de le
résoudre contre `application.yml`/`.yaml`/`.properties` du repo
(`src/main/resources/` puis la racine, layout standard Maven/Gradle,
support de la syntaxe de défaut Spring `${prop:défaut}`) via
`resolve_spring_property` — voir ADR-28. Résolu → `topic_dynamic=False`,
topic = la valeur trouvée (ou le défaut) ; introuvable et sans défaut →
`topic_dynamic=True`, le placeholder est conservé tel quel (jamais résolu
au hasard). Une variable alimentée par un `@Value("${...}")` ailleurs dans
la classe n'est pas suivie (pas d'analyse de flux de données entre
statements) : seul le placeholder textuel dans l'annotation/l'appel est
résolu.

Périmètre : Java uniquement (voir note en tête de `archive/BACKLOG-10.md`).
