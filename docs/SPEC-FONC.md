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
- Indépendamment de `include`/`exclude` : tout fichier sous un répertoire
  `src/<jeu-de-sources>` où `<jeu-de-sources>` suit la convention
  Maven/Gradle de nommage des source sets de test (`test`, `componentTest`,
  `contractTest`, `endToEndTest`, ... — nom égal à `test` ou terminant par
  `Test`) est **toujours** exclu du scan, findings et endpoints confondus
  (BACKLOG-15 H2, ADR-34 ; règle resserrée en BACKLOG-16 P1) — ni
  configurable, ni contournable via `include`. Un layout `src/<package>`
  générique (Python, JS, Rust, ...) n'est **pas** concerné : `<package>`
  ne suit pas cette convention. Un fichier déjà indexé qui devient exclu
  par cette règle est purgé au prochain `cccf index`, comme un fichier
  supprimé du disque.

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
- Ce fallback `p/security-audit` est le comportement **générique** du CLI.
  Pour le workflow d'audit Java/Spring/Maven porté par le skill
  `ccc-findings-skill`, l'initialisation recommandée consiste à copier puis
  déclarer explicitement les packs `.cccf/rules/default/`,
  `.cccf/rules/liveness/`, `.cccf/rules/rest/` et `.cccf/rules/kafka/`, afin
  que `cccf index` produise findings **et** inventaire d'endpoints.
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

### `cccf endpoints [--system S] [--role R] [--topic T] [--path GLOB] [--module M] [--json]`
Liste les endpoints REST/Kafka indexés (BACKLOG-10 K1, BACKLOG-11 A1).
Filtres optionnels combinables :

| Option | Effet |
|---|---|
| `--system` | `rest` ou `kafka` |
| `--role` | `serve`/`call` (rest) ou `produce`/`consume` (kafka) |
| `--topic` | égalité exacte sur `topic` (ex. `"GET /orders/{id}"`, `"orders.created"`) |
| `--path` | motif de chemin (`fnmatch`), même style que `cccf search --path` |
| `--module` | nom du module Maven (artifactId, BACKLOG-13) ou du service Gradle détecté (BACKLOG-15 H1) — `None` si ni l'un ni l'autre ne s'applique |

Rendu texte, une ligne par endpoint :
`[<system>/<role>] <topic>[ (dynamique)][ [<module>]]  <path>:<start>-<end>`

Pour les endpoints REST, `topic` est toujours canonique côté graphe :
`METHOD /path`. Les URLs absolues appelantes (`http://service/orders`) sont
normalisées en route (`/orders`) ; query string et fragment sont ignorés.
Un appel concaténé à une variable reste `topic_dynamic=True`, mais conserve
son préfixe de route normalisé.

Rendu `--json` : liste de `EndpointHit` (`id`, `role`, `system`, `topic`,
`topic_dynamic`, `source`, `framework`, `path`, `start_line`, `end_line`,
`module`, `qualified_name`). `module` vient d'abord du `pom.xml` Maven le
plus proche (artifactId, BACKLOG-13) ; si le repo n'a aucun `pom.xml`,
repli sur la détection Gradle (BACKLOG-15 H1, ADR-33) — le répertoire de
premier niveau qui contient, quelque part dans son arbre, une classe Java
avec un `main()` démarrant Spring Boot (`SpringApplication.run(...)`),
regroupant ainsi tous les sous-projets Gradle d'un même microservice.
`qualified_name` (package + classe Java) est `None` pour un fichier
non-Java.

Mêmes règles d'index absent que `findings` (message identique, code 2) —
`endpoints` vit dans la même base que `findings`.

### `cccf graph [--workspace ROOT] [--json] [--drawio FICHIER]`
Points de blocage probables à partir des endpoints indexés (BACKLOG-10 K12).
Toujours : les appels REST synchrones détectés dans un handler de
consommation Kafka **du projet courant** (même fichier, site d'appel dans
la plage de lignes du handler).

Pour les cycles/hotspots inter-services, deux sources possibles, essayées
dans cet ordre :
1. **Sans `--workspace`** : si l'index couvre un répertoire multi-modules
   Maven (`cccf index` lancé au répertoire parent, endpoints/findings
   attribués à un module par l'indexation — BACKLOG-13), les endpoints/
   findings sont groupés par module et le graphe est construit directement
   à partir de cet unique index — pas de fédération nécessaire pour un
   monorepo.
2. **Avec `--workspace ROOT`** : fédère aussi les microservices Maven sous
   `ROOT`, indexés **séparément** (BACKLOG-11 A2, lecture seule —
   `discover_maven_services`/`load_federation`) — le chemin pour des
   services qui vivent dans des dépôts réellement distincts.

Les deux sources alimentent le même algorithme (`graph.build_graph`) et
rapportent :
- **cycles** : cycles simples contenant au moins une arête REST synchrone
  (une arête `WebClient`, non bloquante par nature, ne compte pas — K11),
  avec les sites (fichier:lignes) de chaque arête ;
- **hotspots** : sites sur un cycle recouverts par un finding (fichier+lignes
  qui se chevauchent, même module/service), classés par sévérité décroissante.

Si ni l'un ni l'autre n'est disponible (repo non-Maven sans `--workspace`,
ou aucun module Maven détecté), `cycles`/`hotspots` restent vides, avec une
`note` qui le dit explicitement (voir ADR-27) plutôt que de laisser deviner
une absence de résultat.

Rendu `--json` :
```json
{
  "outbound_calls_in_consumers": [
    {"consumer": {"path": "...", "start_line": 15, "end_line": 25, "topic": "orders.created"},
     "call": {"path": "...", "start_line": 20, "end_line": 20, "topic": "POST /payments"}}
  ],
  "cycles": [
    {"services": ["service-x", "service-y", "service-z", "service-x"],
     "has_synchronous_rest": true,
     "edges": [{"kind": "rest", "from_service": "service-x", "to_service": "service-y",
                "from_site": {"path": "...", "start_line": 13, "end_line": 13, "topic": "GET /y-status"},
                "to_site": {"path": "...", "start_line": 9, "end_line": 11, "topic": "GET /y-status"}}]}
  ],
  "hotspots": [
    {"service": "service-x", "site": {"path": "...", "start_line": 13, "end_line": 13, "topic": "GET /y-status"},
     "finding_rule_id": "rules.cccf.liveness.java.new-resttemplate-no-timeout", "finding_severity": "WARNING"}
  ],
  "note": ""
}
```
`note` est vide dès qu'une source de données inter-modules (module Maven ou
`--workspace`) a produit un résultat ; avec `--workspace`, elle porte aussi
les avertissements de fédération (service non indexé, base incompatible —
préfixés `⚠`).

Mêmes règles d'index absent que `findings`/`summary` (message identique,
code 2) — `endpoints` vit dans la même base que `findings` (`.cccf/
findings.db`). `--workspace` ne fait jamais échouer la commande : un
service fédéré manquant ou incompatible est signalé dans `note`, pas une
erreur (K7 CA2).

`--drawio FICHIER` (BACKLOG-14 G1) : plutôt que le rendu JSON/texte, écrit
le graphe complet services ↔ services (pas seulement les arêtes des
cycles) au format `.drawio` (XML mxGraph, ouvrable directement dans
diagrams.net) à `FICHIER`, et affiche une confirmation courte (nombre de
services/arêtes). Un nœud par service connu de la même source de données
que `--json` (module Maven groupé, ou fédération `--workspace`) — y
compris un service sans aucune arête. Une arête par appel REST apparié
(call → serve) ou événement Kafka apparié (produce → consume) : trait
plein pour REST, pointillé pour Kafka, libellé = route/topic. Les arêtes
qui appartiennent à un cycle synchrone (`has_synchronous_rest: true`,
c'est-à-dire au moins une arête REST hors `WebClient`) sont mises en
évidence en rouge — même signal que le marqueur `[synchrone]` du rendu
texte. Sans donnée inter-modules disponible, écrit un document valide mais
sans nœud/arête et affiche la même `note` explicative que `--json`
(jamais d'échec silencieux). Incompatible avec `--json` : `--drawio` a
priorité s'il est fourni. Pas de tool MCP équivalent — un fichier
`.drawio` n'est pas un résultat exploitable par un agent, contrairement au
JSON déjà renvoyé par `graph`.

### `cccf workspace <root> [--json]`
Découvre les modules Maven sous `root` (BACKLOG-11 A2, ADR-30) : un module
par `pom.xml` trouvé, nommé d'après son `artifactId`, classé
`microservice` (le pom référence `spring-boot-maven-plugin`) ou
`shared-module` sinon. Pour chaque module déjà indexé (`cccf index` y a été
lancé), lit sa base **en lecture seule** (jamais d'écriture dans la base
d'un autre projet) pour compter ses endpoints et findings.

Rendu `--json` :
```json
{
  "services": [
    {"name": "order-service", "path": "/repo/order-service", "kind": "microservice",
     "indexed": true, "endpoint_count": 4, "finding_count": 2},
    {"name": "common-lib", "path": "/repo/common-lib", "kind": "shared-module",
     "indexed": true, "endpoint_count": 0, "finding_count": 1}
  ],
  "warnings": ["payment-service (/repo/payment-service) : non indexé, ignoré (lancez cccf index sur ce projet)."]
}
```

`endpoint_count` d'un `shared-module` est toujours `0` : un module partagé
n'est jamais traité comme producteur/consommateur runtime, même si des
endpoints y ont été détectés par erreur (A2 CA5). Un module non indexé, à
la base introuvable ou au schéma incompatible ne fait pas échouer la
commande : il apparaît dans `warnings`, absent des comptages. Aucun module
Maven trouvé → message informatif, code de sortie 0 (pas une erreur —
`root` peut légitimement ne pas être un répertoire Maven).

### `cccf flow <requête> [--workspace ROOT] [--json]`
Résout `<requête>` en topic Kafka ou route REST (BACKLOG-10 K5) : nom exact
d'abord, sinon sous-chaîne insensible à la casse **si elle désigne un
unique topic/route** parmi les endpoints indexés — une correspondance
ambiguë (plusieurs topics contiennent la sous-chaîne) échoue plutôt que de
choisir arbitrairement.

Sans `--workspace` uniquement : si la résolution textuelle échoue, un
dernier recours par **similarité vectorielle** (BACKLOG-10 K3) cherche le
plus proche voisin parmi les endpoints déjà embeddés par `cccf index`
(`cccf endpoints`/`cccf graph` en dépendent aussi indirectement, même
pipeline d'indexation) — utile pour une requête en langage naturel qui ne
contient aucun nom de topic/route littéral. En dessous d'un seuil de
similarité minimal, aucun résultat n'est retenu (même politique que
`topic_dynamic` : jamais résolu au hasard) et l'échec reste le même message
que pour une résolution textuelle infructueuse. Ce repli n'est pas
disponible avec `--workspace` (fédération multi-services).

Sans `--workspace` : ne cherche que dans le projet courant, mais `service`
reflète désormais le module Maven de chaque site (`endpoint.module`,
BACKLOG-13) quand l'index couvre un répertoire multi-modules — `null`
seulement pour un repo non-Maven ou un site hors arborescence Maven,
jamais pour dissimuler la fédération. Avec `--workspace ROOT` : fédère en
plus les microservices Maven indexés séparément sous `ROOT` (BACKLOG-11
A2, lecture seule). Dans les deux cas, chaque site du flux (producteur/
consommateur Kafka, ou serveur/appelant REST) apparaît attribué à son
service, et pour chaque site, les findings Semgrep qui le recouvrent
(fichier + lignes qui se chevauchent, même service — esprit ADR-19) sont
listés par `rule_id`.

Rendu `--json` :
```json
{
  "query": "orders.created",
  "resolved_topic": "orders.created",
  "sites": [
    {"service": "order-service", "role": "produce", "system": "kafka",
     "framework": "spring-kafka", "path": "app/OrderProducer.java",
     "start_line": 14, "end_line": 14, "topic_dynamic": false,
     "finding_rule_ids": ["rules.cccf.demo.kafka-send-fire-and-forget"]},
    {"service": "payment-service", "role": "consume", "system": "kafka",
     "framework": "spring-kafka", "path": "app/OrderConsumer.java",
     "start_line": 7, "end_line": 10, "topic_dynamic": false,
     "finding_rule_ids": []}
  ],
  "warnings": []
}
```

Requête sans correspondance, ou ambiguë (plusieurs topics correspondent en
sous-chaîne) : message explicite sur stderr, code de sortie 2. Mêmes règles
d'index absent que `findings`/`summary` (message identique, code 2) quand
`--workspace` n'est pas fourni ; avec `--workspace`, un service fédéré
manquant ou incompatible ne fait jamais échouer `flow` (mêmes garanties que
`cccf graph --workspace`/`cccf workspace`, K7 CA2), mais n'est **pas** non
plus absorbé silencieusement : il apparaît dans `warnings` — un site
manquant à cause d'un service non fédéré doit rester visible, pas confondu
avec l'absence réelle d'un producteur/consommateur.

### `cccf mcp`
Lance le serveur MCP (stdio) sur le repo courant (répertoire d'exécution).
`cccf mcp --help` documente le bloc d'enregistrement client :
```json
{"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}
```

## 3. Serveur MCP

Huit tools, chacun annoté avec un type de retour concret (`TypedDict` ou
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
| `graph(workspace_root=None)` | `GraphResult` | Points de blocage probables (BACKLOG-10 K12) — équivalent à la CLI `cccf graph`/`cccf graph --workspace` | `cycles`/`hotspots` vides sans `workspace_root` (ADR-27) ; réels sinon (fédération A2) |
| `list_workspace_services(root)` | `WorkspaceResult` | Découverte de modules Maven + comptage endpoints/findings par service — équivalent à la CLI `cccf workspace` | Lecture seule (ADR-30) ; BACKLOG-11 A2 |
| `trace_message_flow(query, workspace_root=None)` | `FlowResultInfo` | Résout un topic/route et liste ses sites (producteurs/consommateurs, ou serveurs/appelants) avec les findings qui les recouvrent — équivalent à la CLI `cccf flow`/`cccf flow --workspace` | Requête sans correspondance ou ambiguë → `ToolError` (BACKLOG-10 K5/K6) |

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
| `cccf.liveness.java.mongo-lock-busy-wait-poll` | Java | ERROR | Verrou pessimiste MongoDB (`findAndModify`/`findOneAndUpdate`) acquis par sondage bloquant — boucle `while`/`for` contenant aussi un `Thread.sleep(...)` |
| `cccf.liveness.java.mongo-lock-inside-synchronized` | Java | ERROR | Appel `findAndModify`/`findOneAndUpdate` (verrou pessimiste MongoDB) à l'intérieur d'un bloc `synchronized` |

**Usage** : comme le pack `default`, le copier dans le repo cible
(ex. `.cccf/rules/liveness/`) et le déclarer dans `rules:` — jamais de
chemin absolu vers le repo skill (ADR-24) :

```yaml
rules:
  - .cccf/rules/liveness/java.yaml
```

Périmètre : Java (`RestTemplate`, Spring Kafka `@KafkaListener`,
`synchronized`, `Future`/`CompletableFuture`, verrous pessimistes MongoDB
`findAndModify`/`findOneAndUpdate`) — la stack cible de l'analyse est Java +
Spring + Maven ; Python/JS/TS ne sont pas des cibles (voir K8 dans
`archive/BACKLOG-10.md`). Le volet sécurité (SASL en clair, `PLAINTEXT`,
désérialisation non sûre) n'est pas encore livré.

**Verrous pessimistes MongoDB** — MongoDB n'a pas de verrou pessimiste
natif façon `SELECT ... FOR UPDATE` ; le motif observé dans ce type de code
est une écriture atomique (`findAndModify`/`findOneAndUpdate`) sur un champ
« verrouillé », combinée à une boucle de sondage ou un moniteur JVM :
- `mongo-lock-busy-wait-poll` flague l'appel Mongo dès lors qu'il vit dans
  une boucle `while`/`for` qui contient aussi un `Thread.sleep(...)` —
  co-occurrence structurelle (pas de dépendance au nom du champ de verrou),
  signal fort d'un sondage sans timeout ni backoff visible.
- `mongo-lock-inside-synchronized` flague le même appel Mongo à l'intérieur
  d'un bloc `synchronized` — le round-trip réseau se fait moniteur JVM
  tenu, même risque que `network-call-inside-synchronized`.
- Les deux règles ne présument rien du nom du champ « verrouillé » (aucune
  hypothèse `locked`/`lockedAt`/etc.) : c'est la structure (boucle+sleep, ou
  synchronized) autour de l'écriture atomique qui signale l'usage en
  verrou, pas une convention de nommage.

## 7. Pack de règles d'inventaire REST (BACKLOG-10 K11)

Comme le pack liveness, vit dans `ccc-findings-skill`
(`skills/cccf/rules/rest/java.yaml`, ADR-24) — copie de test dans
`tests/fixtures/rest_repo/`. Contrairement aux packs liveness/`default`, ce
pack n'est **pas un pack de findings** : `metadata.severity` (`INFO`) n'a
pas de sens à seuiller. En revanche, il est désormais exécuté pendant
`cccf index` dès qu'il figure dans `rules:` (workflow d'audit microservices du
skill), et alimente `cccf endpoints` / `cccf graph`.

| Règle | Langage | Rôle | Détecte |
|---|---|---|---|
| `cccf.rest.java.serve-{get,post,put,delete,patch}` | Java | `serve` | Route Spring exposée (`@GetMapping`/`@PostMapping`/`@PutMapping`/`@DeleteMapping`/`@PatchMapping`, ou `@RequestMapping(method=...)` pour n'importe quel verbe) |
| `cccf.rest.java.call-{get,post,put,delete}` | Java | `call` | Appel `RestTemplate` (`getForObject`/`getForEntity`, `postForObject`/`postForEntity`, `put`, `delete`) |
| `cccf.rest.java.feign-{get,post,put,delete,patch}` | Java | `call` | Méthode d'une interface `@FeignClient` annotée `@GetMapping`/.../`@RequestMapping(method=...)` (signature sans corps — un client déclaratif, pas une route exposée) |
| `cccf.rest.java.webclient-{get,post,put,delete,patch}` | Java | `call` | Appel `WebClient` fluent (`.get().uri(...)`, `.post().uri(...)`, ...) |

Chaque résultat porte `metadata.category: endpoint-inventory`,
`metadata.role`, `metadata.http_method`, `metadata.framework` — le contrat
que lit `parse_semgrep_endpoints` (voir `docs/SPEC-TECH.md#4bis-extraction-
dendpoints-rest--kafka-run_semgrep_endpoints-backlog-10-k11k2`). Le chemin
est extrait du texte du site (regex sur le snippet, pas de métavariable
Semgrep — ADR-26) : un chemin non littéral, ou concaténé à une variable,
est marqué `topic_dynamic=True` plutôt que résolu au hasard. Une URL absolue
appelante est normalisée en route canonique (`GET http://svc/orders` →
`GET /orders`) pour rester comparable aux routes exposées. Une interface
`@FeignClient` n'est jamais classée `serve` : les règles `serve-*` exigent un
corps de méthode (`{ ... }`), absent des signatures déclaratives Feign — pas
besoin d'exclusion explicite. Périmètre : Java uniquement — la stack cible
de l'analyse est Java + Spring + Maven (voir K8/K11 dans
`archive/BACKLOG-10.md`). Reste à couvrir : chaîne `WebClient` répartie sur
plusieurs lignes (`.get()` et `.uri(...)` non sur la même ligne dans le
snippet — `_find_first_literal` ne cherche que sur la première ligne).

## 8. Pack de règles d'inventaire Kafka (BACKLOG-10 K2)

Comme le pack REST, vit dans `ccc-findings-skill`
(`skills/cccf/rules/kafka/java.yaml`, ADR-24) — copie de test dans
`tests/fixtures/kafka_repo/`. Pas un pack de findings, mais exécuté pendant
`cccf index` dès qu'il figure dans `rules:` (workflow d'audit microservices du
skill).

| Règle | Rôle | Détecte |
|---|---|---|
| `cccf.kafka.java.consume` | `consume` | Méthode `@KafkaListener(topics = "...")` |
| `cccf.kafka.java.produce-template` | `produce` | `KafkaTemplate.send(topic, valeur, ...)` (au moins 2 arguments — exclut `send(ProducerRecord)`, déjà couvert ci-dessous) ou `KafkaTemplate.sendDefault(...)` (topic implicite, toujours dynamique) |
| `cccf.kafka.java.produce-record` | `produce` | `new ProducerRecord(topic, ...)` (API bas niveau `kafka-clients` **et** Spring, mêmes classes) |
| `cccf.kafka.java.consume-raw` | `consume` | `KafkaConsumer.subscribe(Collections.singletonList(...))`/`Arrays.asList(...)`/`List.of(...)` — API bas niveau (confluent-kafka), hors `@KafkaListener` |

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
au hasard).

Une variable alimentée par un `@Value("${...}")` ailleurs dans la classe
(`@KafkaListener(topics = ordersTopic)`, `kafkaTemplate.send(ordersTopic,
...)`) **est** désormais suivie, best-effort : `_extract_kafka_topic`
retrouve le nom de la variable dans le snippet, puis cherche une
déclaration de champ `@Value("${clé}") ... ordersTopic;` dans le même
fichier source (regex sur le texte, pas d'AST Java ni d'analyse de flux de
données entre statements — même esprit ADR-26) ; la clé trouvée est
résolue comme un placeholder normal (`resolve_spring_property`). Variable
non alimentée par un `@Value` dans le même fichier (paramètre de méthode,
champ initialisé autrement) → toujours `<dynamic>`, jamais résolu au
hasard. `KafkaConsumer.subscribe(...)` est volontairement restreint aux
trois formes de collection usuelles (`Collections.singletonList`/
`Arrays.asList`/`List.of`) pour ne jamais confondre un `.subscribe(...)`
RxJava/Reactor (lambda/Observer, jamais une `Collection<String>`) avec un
abonnement Kafka — `subscribe(Pattern.compile(...))` (abonnement par motif
de nom) n'est pas couvert.

## 9. Pack de règles sécurité Kafka (BACKLOG-10 K8, volet sécurité)

Vit dans `ccc-findings-skill` (`skills/cccf/rules/kafka-security/
java.yaml`, ADR-24) — copie de test dans
`tests/fixtures/kafka_security_repo/`. Contrairement aux packs `rest`/
`kafka` (inventaire), ce sont de vraies règles de **findings**, comme
`default`/`liveness` — indexées et interrogeables via `cccf findings`.

| Règle | Sévérité | Détecte |
|---|---|---|
| `cccf.kafka-security.sasl-plaintext-credentials` | ERROR | `sasl.jaas.config` avec un mot de passe **littéral** (`password="..."` en dur, pas construit depuis une variable) |
| `cccf.kafka-security.plaintext-protocol` | ERROR | `security.protocol` réglé sur `PLAINTEXT` (littéral ou constante `CommonClientConfigs.SECURITY_PROTOCOL_CONFIG`) |
| `cccf.kafka-security.json-deserializer-trusts-all-packages` | ERROR | `JsonDeserializer`/`ErrorHandlingDeserializer` Spring Kafka configuré avec `trusted.packages` = `"*"` (désérialisation non sûre — instanciation de classe arbitraire depuis un message) |
| `cccf.kafka-security.unsafe-java-deserialization` | ERROR | `ObjectInputStream(...).readObject()` — désérialisation Java native sur des données potentiellement issues d'un message non fiable |

`cccf.kafka-security.sasl-plaintext-credentials` distingue un mot de passe
en dur d'un mot de passe injecté par variable via `metavariable-regex` sur
le texte source du littéral — qui porte des guillemets **échappés**
(`\"`), pas nus, puisque c'est un littéral Java imbriqué dans un autre
littéral (voir ADR-31, un piège non évident à connaître avant d'écrire ce
genre de règle).

**Ce qui n'est délibérément pas dupliqué ici** : producteur non idempotent,
`enable.auto.commit` risqué et handler sans DLQ/retry étaient dans le
périmètre initial de K8 mais sont déjà couverts par le pack `default`
(`skills/cccf/rules/default/b-kafka.yaml`, règles R7 et R10) — voir
`archive/BACKLOG-10.md` K8. `max.poll.interval.ms` risqué reste un
écart documenté (pas de règle, le seuil/l'intention « risqué » n'étant pas
assez univoque pour une détection fiable sans faux positifs).

Périmètre : Java uniquement (voir note en tête de `archive/BACKLOG-10.md`).
