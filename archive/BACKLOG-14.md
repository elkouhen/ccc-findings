# Backlog 14 — Export visuel du graphe d'interactions (2026-07-13)

> Objectif : retour utilisateur direct — `cccf graph` calcule déjà le
> graphe complet services ↔ services (REST + Kafka, cycles, hotspots,
> BACKLOG-10 K12) mais ne le restitue qu'en JSON/texte (listes d'arêtes et
> de cycles). Pour un usage « comprendre l'architecture microservices d'un
> coup d'œil », il manque un rendu visuel ouvrable directement dans
> diagrams.net (drawio), sans outillage supplémentaire côté utilisateur.
>
> Convention : une tâche = un commit (`G<n>: <titre>`), DoD globale
> inchangée (voir `AGENT.md`).

## Tâches

### [x] G1 — `cccf graph --drawio FICHIER` : export du graphe en `.drawio`
- **Priorité** : HAUTE
- **Fichiers** : `src/cccf/render.py`, `src/cccf/cli.py`, `tests/test_render.py`
  (nouveau), `tests/test_k12_graph_workspace_e2e.py`, `docs/SPEC-FONC.md`,
  `docs/SPEC-TECH.md`
- **Description** : nouvelle fonction `render_graph_drawio(services, edges,
  cycles)` dans `render.py` qui produit un document XML mxGraph (format
  natif diagrams.net/drawio) : un nœud par service (toutes les clés du
  dict `endpoints_by_service`/fédération déjà utilisé par `build_graph`,
  y compris les services sans arête), une arête par `GraphEdge` renvoyé
  par `build_graph` (REST en trait plein, Kafka en pointillé, libellé =
  route/topic), les arêtes appartenant à un cycle avec
  `has_synchronous_rest=True` mises en évidence (couleur dédiée). Toute
  valeur dérivée du code source (nom de service, route, topic) est
  échappée XML via `xml.sax.saxutils.quoteattr` — jamais interpolée
  brute dans le document produit. Câblé sur `cccf graph` via une nouvelle
  option `--drawio FICHIER`, compatible avec `--workspace` et le mode
  monorepo (M3) exactement comme `--json`/le rendu texte actuel ; écrit le
  fichier et imprime une confirmation courte (nombre de services/arêtes),
  jamais les deux formats en même temps que `--json`. Pas d'exposition
  MCP : un fichier `.drawio` n'est pas un résultat exploitable par un
  agent (contrairement au JSON déjà renvoyé par le tool `graph`).
- **CA** :
  1. `cccf graph --workspace ROOT --drawio out.drawio` sur la fixture à
     cycle REST (`rest_cycle_workspace`, déjà utilisée par K12) produit un
     fichier XML mxGraph valide avec 3 nœuds et au moins 3 arêtes, les
     arêtes du cycle marquées différemment des autres.
  2. Sans donnée inter-modules disponible (ni `--workspace`, ni module
     Maven détecté), la commande n'échoue pas : elle écrit un document
     mxGraph vide (aucun nœud/arête) et affiche la même note explicative
     que le rendu JSON/texte (`_NO_CROSS_MODULE_DATA_NOTE`).
  3. Un nom de service/route/topic contenant des caractères spéciaux XML
     (`<`, `&`, `"`) produit un document XML toujours valide (parsable),
     jamais de corruption du fichier de sortie.
  4. `render_graph_drawio` testée unitairement (`tests/test_render.py`) :
     nœuds/arêtes attendus, styles REST vs Kafka, mise en évidence des
     arêtes de cycle, échappement XML.
  5. `cccf graph --drawio` testée de bout en bout (`tests/test_cli.py`) :
     fichier écrit sur disque, message de confirmation, non-régression du
     rendu `--json`/texte existant (comportement inchangé sans `--drawio`).
- **Statut** : livré. `render_graph_drawio` (nouveau, `render.py`) : nœud
  par service (grille `ceil(sqrt(n))` colonnes), arête par `GraphEdge`
  (pointillé Kafka, trait plein REST, libellé = topic/route), arêtes d'un
  cycle `has_synchronous_rest=True` identifiées par `id(edge)` et
  coloriées en rouge (`strokeColor=#d32f2f`). Toute valeur dérivée du code
  source passe par `xml.sax.saxutils.quoteattr` (CA3). `cccf graph
  --drawio FICHIER` (`cli.py`) : réutilise exactement le même calcul
  `services_by_name`/`edges`/`cycles` que `--json` (branchement
  `--workspace`/regroupement par module inchangé), écrit le fichier,
  affiche une confirmation puis la `note` de `render_graph_json` si non
  vide (CA2) ; prioritaire sur `--json` s'ils sont fournis ensemble. Pas de
  tool MCP (fichier non exploitable par un agent). Testé unitairement
  (`tests/test_render.py`, nouveau : 8 tests — nœuds, arêtes REST/Kafka,
  mise en évidence de cycle, absence de mise en évidence hors cycle,
  services sans arête, graphe vide, échappement XML) et de bout en bout
  (`tests/test_k12_graph_workspace_e2e.py`, réutilise la fixture
  `rest_cycle_workspace` déjà indexée pour K12 : cycle des 3 services
  rendu en `.drawio` valide avec les 3 arêtes en rouge — CA1 ; sans donnée
  inter-modules, fichier vide + note affichée — CA2). `uv run pytest`
  (214 passed avant cette tâche, +18 tests ajoutés par K13/G1, tous verts ;
  8 échecs préexistants et sans rapport — SSL manquant en sandbox pour le
  téléchargement du modèle d'embedding HuggingFace, non liés à ce
  changement) et `uv run ruff check .` passent.
