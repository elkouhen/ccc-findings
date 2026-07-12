# Backlog 6 — Sortie MCP structurée (2026-07-12)

> Objectif : remplacer les 4 tools MCP `-> str` (JSON sérialisé à la main) par
> des types de retour concrets (`TypedDict`/dataclass), pour un `outputSchema`
> réellement exploitable par un client MCP, et faire remonter les erreurs comme
> de vraies erreurs MCP (`isError`) plutôt que comme un payload `{"error": ...}`
> indiscernable d'un succès. Convention : une tâche = un commit (`S<n>: <titre>`),
> DoD globale inchangée.

### [x] S1 — Types de retour structurés pour les 4 tools MCP + erreurs via exception
- **Fichiers** : `src/cccf/render.py`, `src/cccf/ccc_bridge.py`,
  `src/cccf/mcp_server.py`, `tests/test_mcp_server.py`,
  `tests/test_ccc_bridge.py`, `docs/SPEC-FONC.md`, `docs/ADR.md`,
  `archive/BACKLOG-6.md`
- **Contexte** : chaque tool était annoté `-> str` et renvoyait
  `json.dumps(...)`. FastMCP génère quand même un `outputSchema` à partir de
  l'annotation (`str` → primitive à wrapper), produisant
  `{"result": {"type": "string"}}` pour les 4 tools — un schema qui promet une
  structure sans en fournir une (vérifié empiriquement via
  `mcp.list_tools()`). Toute exception était en outre avalée et transformée en
  `{"error": "<message>"}`, un résultat renvoyé comme un succès, sans signal
  protocolaire distinguant échec et réussite.
- **Description** :
  1. `render.py` : `FindingHit`/`RuleCount`/`FindingsSummary` (`TypedDict`),
     `render_search_json`/`render_summary_json` retournent ces types au lieu de
     `dict` non typés. `context`/`context_error` toujours présents (défaut
     `None`) plutôt que des clés conditionnelles, pour un schema stable.
  2. `ccc_bridge.py` : `FindingRef`/`CodeHitWithFindings` (`TypedDict`),
     `annotate_with_findings` retourne `list[CodeHitWithFindings]`.
  3. `mcp_server.py` : les 4 tools annotés avec leur vrai type de retour
     (`list[FindingHit]`, `FindingsSummary`, `IndexReport` — réutilisation
     directe de la dataclass de `indexer.py` — et `CodeSearchResult`, nouveau
     `TypedDict` local). Suppression des `try/except Exception` qui
     avalaient les erreurs : les exceptions remontent, FastMCP les convertit en
     `ToolError` → `isError: true` côté protocole.
  4. `search_code_with_findings` : le fallback `ccc` indisponible n'est plus
     une forme `{"error": ..., "fallback": ...}` distincte du cas succès — un
     seul schema stable (`results`, `findings_only_fallback`, `warning`),
     rempli différemment selon le cas, pour que l'`outputSchema` reste valide
     dans les deux branches.
- **CA** :
  1. `mcp.list_tools()` montre un `outputSchema` par champ (pas
     `{"result": {"type": "string"}}`) pour les 4 tools — vérifié.
  2. Un appel à un tool sur un repo non indexé lève une exception ; via
     `mcp.call_tool(...)`, elle remonte en `ToolError` — vérifié
     (`test_search_findings_tool_on_unindexed_repo_surfaces_as_mcp_tool_error`).
  3. `search_code_with_findings` sans `ccc` disponible retourne
     `results=[]`, `findings_only_fallback` peuplé, `warning` non nul — plus
     de forme `{"error": ...}` séparée.
  4. `docs/SPEC-FONC.md` §3 et le tableau d'erreurs §5 reflètent le nouveau
     contrat. `docs/ADR.md` documente la décision (ADR-18).
  5. `uv run pytest` (62 tests) et `uv run ruff check .` passent.
