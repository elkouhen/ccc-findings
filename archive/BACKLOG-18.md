# BACKLOG-18 — Rendre `cccr search` utilisable sans timeout MCP

## [x] N1 : Faire échouer vite le bridge `ccc` quand le search n’est pas prêt

**Files**: `src/ccc_radar/ccc_bridge.py`, `tests/conftest.py`,
`tests/test_ccc_bridge.py`, `tests/test_cli.py`, `README.md`,
`docs/SPEC-FONC.md`.

**Description**: `cccr search` pouvait rester bloqué côté bridge `ccc` quand le
repo n’avait pas d’index `.cocoindex_code/target_sqlite.db`, ce qui rendait le
tool MCP `search` inutilisable (`Request timed out`). Le bridge doit désormais
échouer vite avec un message actionnable quand l’index `ccc` manque, et aussi
borner les appels `ccc search` qui restent bloqués malgré un index présent.

**AC**:
- sans index `ccc` prêt, `cccr search` échoue immédiatement avec un message
  expliquant de lancer `ccc index` ;
- un `ccc search` bloqué remonte une erreur explicite de timeout au lieu de
  laisser l’appelant MCP expirer ;
- les chemins nominals existants (`fake ccc`, propagation des flags, erreur
  `ccc`) restent couverts par les tests.
