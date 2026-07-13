import json
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from cccf.config import Config
from cccf.models import Finding, MessageEndpoint, compute_endpoint_id, compute_finding_id

SEVERITY_ORDER = ["INFO", "WARNING", "ERROR"]

_SEVERITY_MAP = {
    "INFO": "INFO",
    "WARNING": "WARNING",
    "ERROR": "ERROR",
    "LOW": "INFO",
    "MEDIUM": "WARNING",
    "HIGH": "ERROR",
    "CRITICAL": "ERROR",
}


class SemgrepError(Exception):
    pass


def _normalize_severity(raw_severity: str) -> str:
    severity = _SEVERITY_MAP.get(str(raw_severity).upper())
    if severity is None:
        raise SemgrepError(f"Sévérité Semgrep inconnue : {raw_severity!r}")
    return severity


def _normalize_str_or_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _read_snippet(repo_root: Path, rel_path: str, start_line: int, end_line: int) -> str:
    try:
        lines = (repo_root / rel_path).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except (OSError, UnicodeError):
        return ""
    start_idx = max(start_line - 1, 0)
    end_idx = min(end_line, len(lines))
    return "\n".join(lines[start_idx:end_idx])


def _relative_path(raw_path: str, repo_root: Path) -> str:
    path = Path(raw_path)
    if path.is_absolute():
        path = path.relative_to(repo_root.resolve())
    return path.as_posix()


def parse_semgrep_json(raw: str, repo_root: Path) -> list[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"Sortie Semgrep JSON invalide : {exc}") from exc

    try:
        results = data["results"]
    except (KeyError, TypeError) as exc:
        raise SemgrepError(
            f"Sortie Semgrep JSON invalide : champ 'results' manquant ({exc})"
        ) from exc

    findings: list[Finding] = []
    for result in results:
        try:
            rule_id = result["check_id"]
            extra = result["extra"]
            severity = _normalize_severity(extra["severity"])
            path = _relative_path(result["path"], repo_root)
            start_line = result["start"]["line"]
            end_line = result["end"]["line"]
        except (KeyError, TypeError) as exc:
            raise SemgrepError(
                f"Sortie Semgrep JSON invalide : champ manquant ({exc})"
            ) from exc

        metadata = extra.get("metadata") or {}
        if metadata.get("category") == "endpoint-inventory":
            # Règle d'inventaire d'endpoints (K2/K11) : ce n'est pas un
            # finding, même si elle a tourné dans le même scan Semgrep que
            # les règles de findings (cccf index les exécute ensemble) —
            # voir parse_semgrep_endpoints.
            continue

        snippet = _read_snippet(repo_root, path, start_line, end_line)
        findings.append(
            Finding(
                id=compute_finding_id(rule_id, path, snippet, start_line, end_line),
                rule_id=rule_id,
                severity=severity,
                message=extra.get("message", ""),
                path=path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet,
                fix=extra.get("fix"),
                cwe=_normalize_str_or_list(metadata.get("cwe")),
                owasp=_normalize_str_or_list(metadata.get("owasp")),
            )
        )

    return findings


# BACKLOG-10 K2/K11 : règles d'inventaire d'endpoints (`metadata.category:
# endpoint-inventory`) — le rôle/système/méthode HTTP viennent des métadonnées
# de la règle (fixes par construction, une règle = une méthode), le
# topic/chemin vient d'une extraction best-effort sur le snippet
# (métavariables Semgrep indisponibles sans compte connecté, voir ADR-26).
_QUOTED_STRING_RE = re.compile(r"f?[\"']([^\"']*)[\"']")
_PROPERTY_PLACEHOLDER_RE = re.compile(r"^\$\{([^}]+)\}$")

# BACKLOG-11 A1 / K2 : emplacements conventionnels des fichiers de
# configuration Spring Boot (Maven/Gradle standard layout), essayés dans
# l'ordre — le premier fichier qui définit la clé gagne.
_SPRING_PROPERTY_FILES = [
    "src/main/resources/application.yml",
    "src/main/resources/application.yaml",
    "src/main/resources/application.properties",
    "application.yml",
    "application.yaml",
    "application.properties",
]


def _find_first_literal(snippet: str) -> tuple[str | None, bool]:
    """Cherche le premier texte entre guillemets sur la première ligne du
    snippet (annotation ou appel). Renvoie (littéral, concaténé) ;
    concaténé=True si immédiatement suivi de `+` (avant la virgule/
    parenthèse fermante), ou si aucun littéral n'est trouvé."""
    first_line = snippet.splitlines()[0] if snippet else ""
    match = _QUOTED_STRING_RE.search(first_line)
    if match is None:
        return None, True
    literal = match.group(1)
    remainder = first_line[match.end() :].lstrip()
    return literal, remainder.startswith("+")


def _extract_rest_path(snippet: str) -> tuple[str, bool]:
    """Renvoie (chemin, dynamique) — jamais résolu silencieusement (même
    esprit que `topic_dynamic` en K2)."""
    literal, dynamic = _find_first_literal(snippet)
    if literal is None:
        return "<dynamic>", True
    return literal, dynamic


def _flatten_properties(data: object, prefix: str = "") -> dict[str, str]:
    flat: dict[str, str] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            flat.update(_flatten_properties(value, full_key))
    elif isinstance(data, (str, int, float, bool)):
        flat[prefix] = str(data)
    return flat


def _parse_dotted_properties_file(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        sep_index = min(
            (i for i in (stripped.find("="), stripped.find(":")) if i != -1), default=-1
        )
        if sep_index == -1:
            continue
        key, value = stripped[:sep_index], stripped[sep_index + 1 :]
        result[key.strip()] = value.strip()
    return result


def resolve_spring_property(repo_root: Path, property_key: str) -> str | None:
    """Cherche `property_key` (ex. `app.kafka.topics.orders`, ou
    `prop:default` — syntaxe de valeur par défaut Spring) dans les fichiers
    de configuration Spring Boot conventionnels du repo (Maven/Gradle
    standard layout). `None` si introuvable et sans défaut — jamais résolu
    au hasard (ADR-26/28)."""
    key, _, default = property_key.partition(":")
    for rel_path in _SPRING_PROPERTY_FILES:
        path = repo_root / rel_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if rel_path.endswith(".properties"):
            flat = _parse_dotted_properties_file(text)
        else:
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError:
                continue
            flat = _flatten_properties(data or {})

        if key in flat:
            return flat[key]

    return default or None


def _extract_kafka_topic(snippet: str, repo_root: Path) -> tuple[str, bool]:
    """Renvoie (topic, dynamique). Un littéral `${propriete.imbriquee}`
    (placeholder Spring, ex. `@KafkaListener(topics = "${app.kafka.topics.
    orders}")`) n'est pas un nom de topic mais une clé de configuration :
    tentative de résolution via `resolve_spring_property` avant de retomber
    sur dynamique si la clé est introuvable — jamais résolu au hasard."""
    literal, dynamic = _find_first_literal(snippet)
    if literal is None:
        return "<dynamic>", True

    placeholder = _PROPERTY_PLACEHOLDER_RE.match(literal)
    if placeholder is not None:
        resolved = resolve_spring_property(repo_root, placeholder.group(1))
        if resolved is not None:
            return resolved, False
        return literal, True

    return literal, dynamic


def parse_semgrep_endpoints(raw: str, repo_root: Path) -> list[MessageEndpoint]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"Sortie Semgrep JSON invalide : {exc}") from exc

    try:
        results = data["results"]
    except (KeyError, TypeError) as exc:
        raise SemgrepError(
            f"Sortie Semgrep JSON invalide : champ 'results' manquant ({exc})"
        ) from exc

    endpoints: list[MessageEndpoint] = []
    for result in results:
        extra = result["extra"]
        metadata = extra.get("metadata") or {}
        if metadata.get("category") != "endpoint-inventory":
            continue

        system = metadata.get("system", "rest")
        if system not in ("rest", "kafka"):
            continue

        try:
            path = _relative_path(result["path"], repo_root)
            start_line = result["start"]["line"]
            end_line = result["end"]["line"]
            role = metadata["role"]
        except (KeyError, TypeError) as exc:
            raise SemgrepError(
                f"Règle d'inventaire d'endpoints mal formée : champ manquant ({exc})"
            ) from exc

        snippet = _read_snippet(repo_root, path, start_line, end_line)

        if system == "rest":
            try:
                http_method = metadata["http_method"]
            except KeyError as exc:
                raise SemgrepError(
                    f"Règle d'inventaire d'endpoints mal formée : champ manquant ({exc})"
                ) from exc
            route, dynamic = _extract_rest_path(snippet)
            topic = f"{http_method} {route}"
        else:
            topic, dynamic = _extract_kafka_topic(snippet, repo_root)

        endpoints.append(
            MessageEndpoint(
                id=compute_endpoint_id(role, topic, path, start_line, end_line),
                role=role,
                system=system,
                topic=topic,
                topic_dynamic=dynamic,
                source="code",
                framework=metadata.get("framework"),
                path=path,
                start_line=start_line,
                end_line=end_line,
                snippet=snippet,
            )
        )

    return endpoints


def invoke_semgrep_raw(
    repo_root: Path, config: Config, files: list[str] | None = None
) -> str:
    """Sortie JSON brute d'un seul scan Semgrep sur `config.rules` (findings
    et règles d'inventaire d'endpoints mélangées — `parse_semgrep_json` et
    `parse_semgrep_endpoints` filtrent chacun ce qui les concerne sur la
    même sortie). Public : `indexer.index_repo` (BACKLOG-11 A1) l'appelle
    une seule fois par indexation plutôt que de scanner deux fois."""
    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--quiet",
        "--x-ignore-semgrepignore-files",
        "--timeout",
        str(config.semgrep_timeout_s),
    ]
    for rule in config.rules:
        cmd += ["--config", rule]
    cmd += files if files else ["."]

    proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        raise SemgrepError(
            f"Semgrep a échoué (code {proc.returncode}) : {proc.stderr.strip()}"
        )
    return proc.stdout


def run_semgrep(
    repo_root: Path, config: Config, files: list[str] | None = None
) -> list[Finding]:
    raw = invoke_semgrep_raw(repo_root, config, files)
    findings = parse_semgrep_json(raw, repo_root)
    min_index = SEVERITY_ORDER.index(config.min_severity)
    return [f for f in findings if SEVERITY_ORDER.index(f.severity) >= min_index]


def run_semgrep_endpoints(
    repo_root: Path, config: Config, files: list[str] | None = None
) -> list[MessageEndpoint]:
    """Comme `run_semgrep`, mais pour les règles d'inventaire d'endpoints
    (BACKLOG-10 K11) — pas de filtre `min_severity` : ce ne sont pas des
    findings, la sévérité INFO qu'elles portent n'a pas de sens à seuiller."""
    raw = invoke_semgrep_raw(repo_root, config, files)
    return parse_semgrep_endpoints(raw, repo_root)
