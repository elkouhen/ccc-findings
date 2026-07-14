# Prompt : audit croisé graphe microservices (cccr vs analyse directe)

## Contexte
Tu travailles dans le repo `ccc-radar` (outils `cccr`). Le but est de
mesurer la qualité de la détection d'endpoints et de construction de graphe
de `cccr` en la confrontant à une lecture directe du code, sur un repo
d'exemple représentatif d'une architecture microservices HTTP + Kafka.

Repo cible à analyser : `~/examples/<nom du repo>`

## Étape 1 — Analyse outillée (cccr)
1. Vérifie si le repo cible est déjà indexé (présence de `.cccr/`) ;
   sinon lance l'indexation nécessaire
   (`cccr init` / `cccr index`, puis l'équivalent `cccr` — vérifie
   `cccr --help` pour la commande exacte si tu ne l'as pas déjà en mémoire).
2. Utilise les commandes/tools `cccr` disponibles (`list_workspace_services`,
   `list_endpoints`, `graph`, `trace_message_flow`, etc. côté MCP, ou leurs
   équivalents CLI) pour extraire :
   - la liste des microservices détectés,
   - leurs endpoints HTTP (méthode + chemin, exposés ET appelés),
   - leurs endpoints Kafka (topic + rôle producer/consumer),
   - les arêtes du graphe qui en résultent (qui appelle/publie vers qui).
3. Génère un diagramme **drawio** (`.drawio`/XML) représentant ce graphe :
   un nœud par service, une arête par relation HTTP (avec méthode+chemin en
   label) et par relation Kafka (avec topic + sens producer/consumer en
   label, flèche distincte des appels HTTP).

## Étape 2 — Analyse directe (sans cccr)
Sans t'appuyer sur les résultats de l'étape 1 (ne les relis pas avant
d'avoir terminé celle-ci) :
1. Explore le repo cible toi-même (lecture de code, grep sur les annotations
   Spring/Kafka type `@RequestMapping`,
   `@GetMapping`/`@PostMapping`/etc., `@KafkaListener`, `KafkaTemplate.send`,
   `builder.stream(...).to(...)` pour Kafka Streams, clients HTTP sortants
   type `RestTemplate`/`WebClient`/`Feign`).
2. Reconstruis manuellement le même inventaire : services, endpoints HTTP
   exposés/appelés, topics Kafka produits/consommés, arêtes du graphe.
3. Génère un second diagramme **drawio** avec la même convention visuelle
   que celui de l'étape 1, pour permettre une comparaison visuelle directe.

## Étape 3 — Comparaison
Produit un tableau de diff structuré :
- Services : présents dans les deux / uniquement cccr / uniquement analyse
  directe.
- Endpoints HTTP : idem, avec pour chaque écart la raison probable
  (annotation non reconnue, préfixe de classe non fusionné, endpoint
  dynamique/réflexif, etc.).
- Endpoints Kafka : idem (topic non résolu, DSL Kafka Streams non
  couvert, nom de topic dynamique/config-driven non résolu, etc.).
- Arêtes du graphe : relations manquantes ou en trop d'un côté par rapport
  à l'autre.

## Sorties attendues
- 1 rapport d'execution dans le répertoire reports
- Le rapport porte nom du dépot analysé 
- Le rapport contient le tableau de diff
- La rapport contient liste d'axes d'amélioration priorisée.
- une copie d'écran du graph généré en drawio (obtenu par export drawio).

## Remarque 

Sur les dépots analysés, 
- il devrait y avoir un consumer et un producer par endpoint kafka
- il devrait y avoir un client HTTP pour chaque endpoint HTTP