# Backlog 3 — Pack Semgrep par défaut sans config explicite (2026-07-12)

> Revient sur une décision actée dans `docs/PRD.md` §12 point 2 (« V1 exige
> une config explicite, éviter le bruit ») à la demande explicite de
> l'utilisateur : `cccf init` doit pouvoir fonctionner sans qu'aucune règle
> Semgrep ne soit définie explicitement, en repliant sur un pack registry
> standard. Conventions identiques à `archive/BACKLOG.md` (une tâche = un
> commit `S<n>: <titre>`, DoD : `pytest` vert, `ruff` propre).

### [x] S1 — `cccf init` se replie sur un pack registry par défaut
- **Fichiers** : `src/cccf/cli.py`, `tests/test_cli.py`, `docs/SPEC-FONC.md`,
  `docs/PRD.md`, `docs/ADR.md`, `~/cocoindex-ext-skill/SKILL.md`
- **Description** : quand `cccf init` ne reçoit pas de `--rules` ET
  qu'aucune config Semgrep locale n'est détectée (`.semgrep.yml`,
  `semgrep.yml`, `.semgrep`), utiliser un pack registry Semgrep par défaut
  (`p/security-audit`) au lieu d'échouer. Afficher un message informatif sur
  stdout précisant que le pack par défaut est utilisé et comment le changer
  (`--rules`). L'ordre de priorité reste : `--rules` explicite > config
  locale détectée > pack par défaut.
- **CA** :
  1. `cccf init` (sans `--rules`, sans config locale détectée) réussit
     (code 0), crée `.cccf/config.yml` avec `rules: [p/security-audit]`, et
     affiche un message mentionnant le pack utilisé et `--rules`.
  2. `cccf init --rules <chemin>` et la détection de config locale restent
     inchangés (priorité conservée).
  3. `cccf index` fonctionne avec ce pack par défaut (vérifié manuellement :
     `semgrep scan --config p/security-audit` télécharge et exécute le pack
     avec succès dans l'environnement de dev).
  4. Documentation à jour : `docs/SPEC-FONC.md`, `docs/PRD.md` (§12 point 2
     n'est plus une question ouverte), `docs/ADR.md` (nouvelle entrée),
     `~/cocoindex-ext-skill/SKILL.md`.
