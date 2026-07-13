import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from cccf.config import Config
from cccf.gradle import gradle_service_for_path
from cccf.maven import module_name_for_path
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


# BACKLOG-13 M1 : module Maven + nom qualifié Java attribués à chaque
# finding/endpoint indexé, en plus de `path` — permet de grouper par module
# sans fédération multi-dépôts (voir `graph.group_endpoints_by_module`).
_JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)


@lru_cache(maxsize=2048)
def _java_qualified_name(repo_root_str: str, rel_path: str) -> str | None:
    if not rel_path.endswith(".java"):
        return None
    class_name = Path(rel_path).stem
    try:
        text = (Path(repo_root_str) / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return class_name
    match = _JAVA_PACKAGE_RE.search(text)
    if match is None:
        return class_name
    return f"{match.group(1)}.{class_name}"


def _module_for_path(repo_root: Path, rel_path: str) -> str | None:
    """Module Maven (`pom.xml`) en priorité (choix explicite, ADR-32) ;
    repli sur la détection de service Gradle (BACKLOG-15 H1, ADR-33) quand
    aucun `pom.xml` n'est trouvé — un repo purement Maven ou purement
    Gradle n'a jamais les deux à interroger, un repo mixte essaie les deux
    dans cet ordre par fichier."""
    return module_name_for_path(repo_root, rel_path) or gradle_service_for_path(
        repo_root, rel_path
    )


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
                module=_module_for_path(repo_root, path),
                qualified_name=_java_qualified_name(str(repo_root), path),
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
_MULTI_SLASH_RE = re.compile(r"/{2,}")

# BACKLOG-10 K2 (reliquat) : `@KafkaListener(topics = someVar)` ou
# `kafkaTemplate.send(someVar, ...)` où `someVar` n'est pas un littéral mais
# une variable alimentée ailleurs dans la classe par `@Value("${...}")` —
# retrouver le nom de variable en jeu (pas son contenu, absent du snippet)
# avant de la résoudre contre les champs `@Value` du fichier source.
_BARE_TOPIC_VAR_RE = re.compile(
    r"(?:topics\s*=\s*|\.send\(\s*|ProducerRecord\(\s*)([A-Za-z_]\w*)\s*[,)]"
)
_VALUE_FIELD_RE = re.compile(
    r'@Value\(\s*"\$\{([^}]+)\}"\s*\)\s*'
    r"(?:private\s+|protected\s+|public\s+|final\s+|static\s+)*"
    r"[\w.<>\[\],\s]+?\s+"
    r"(\w+)\s*[;=]"
)

_SPRING_BASE_FILENAMES = (
    "application.yml",
    "application.yaml",
    "application.properties",
    "bootstrap.yml",
    "bootstrap.yaml",
    "bootstrap.properties",
)
_SPRING_PROFILE_PATTERNS = (
    "application-*.yml",
    "application-*.yaml",
    "application-*.properties",
    "bootstrap-*.yml",
    "bootstrap-*.yaml",
    "bootstrap-*.properties",
)


def _find_first_literal(snippet: str) -> tuple[str | None, bool]:
    """Cherche le premier texte entre guillemets dans le snippet (annotation
    ou appel), en parcourant ses lignes dans l'ordre — une chaîne fluent
    `WebClient` peut répartir `.get()` et `.uri(...)` sur deux lignes
    (BACKLOG-10 K13) ; le snippet est de toute façon borné exactement par
    `start_line`/`end_line` du match Semgrep, jamais de code hors de
    l'appel. Renvoie (littéral, concaténé) ; concaténé=True si
    immédiatement suivi de `+` sur la même ligne (avant la virgule/
    parenthèse fermante), ou si aucun littéral n'est trouvé."""
    for line in snippet.splitlines():
        match = _QUOTED_STRING_RE.search(line)
        if match is not None:
            literal = match.group(1)
            remainder = line[match.end() :].lstrip()
            return literal, remainder.startswith("+")
    return None, True


def _extract_rest_path(snippet: str) -> tuple[str, bool]:
    """Renvoie (chemin, dynamique) — jamais résolu silencieusement (même
    esprit que `topic_dynamic` en K2)."""
    literal, dynamic = _find_first_literal(snippet)
    if literal is None:
        return "<dynamic>", True
    return _normalize_rest_path(literal), dynamic


def _normalize_rest_path(literal: str) -> str:
    normalized = literal.strip()
    if not normalized:
        return "/"
    if normalized.startswith("//"):
        normalized = urlsplit(f"http:{normalized}").path or "/"
    elif "://" in normalized:
        normalized = urlsplit(normalized).path or "/"
    normalized = normalized.split("?", 1)[0].split("#", 1)[0]
    normalized = _MULTI_SLASH_RE.sub("/", normalized)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized or "/"


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


def _candidate_spring_roots(repo_root: Path, source_path: str | None) -> list[Path]:
    if source_path is None:
        return [repo_root]
    source_abs = (repo_root / source_path).resolve()
    roots: list[Path] = []
    for candidate in [source_abs.parent, *source_abs.parents]:
        if candidate == repo_root or repo_root in candidate.parents:
            roots.append(candidate)
        if candidate == repo_root:
            break
    if repo_root not in roots:
        roots.append(repo_root)
    return roots


def _discover_spring_property_files(
    repo_root_str: str, source_path: str | None
) -> tuple[str, ...]:
    repo_root = Path(repo_root_str)
    discovered: list[str] = []
    seen: set[Path] = set()

    for root in _candidate_spring_roots(repo_root, source_path):
        for config_dir in (root / "src" / "main" / "resources", root):
            for filename in _SPRING_BASE_FILENAMES:
                candidate = config_dir / filename
                if candidate.is_file() and candidate not in seen:
                    seen.add(candidate)
                    discovered.append(str(candidate))
            for pattern in _SPRING_PROFILE_PATTERNS:
                for candidate in sorted(config_dir.glob(pattern)):
                    if candidate.is_file() and candidate not in seen:
                        seen.add(candidate)
                        discovered.append(str(candidate))
    return tuple(discovered)


@lru_cache(maxsize=512)
def _load_flat_spring_properties(path_str: str) -> dict[str, str]:
    path = Path(path_str)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    if path.suffix == ".properties":
        return _parse_dotted_properties_file(text)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    return _flatten_properties(data or {})


def resolve_spring_property(
    repo_root: Path, property_key: str, source_path: str | None = None
) -> str | None:
    """Cherche `property_key` (ex. `app.kafka.topics.orders`, ou
    `prop:default` — syntaxe de valeur par défaut Spring) dans les fichiers
    de configuration Spring Boot conventionnels du repo. La recherche est
    best-effort mais orientée microservice : on essaie d'abord les configs du
    module contenant `source_path`, puis celles du repo parent ; les fichiers
    sont parsés une seule fois par process via cache."""
    key, _, default = property_key.partition(":")
    for path_str in _discover_spring_property_files(str(repo_root), source_path):
        flat = _load_flat_spring_properties(path_str)
        if key in flat:
            return flat[key]
    return default or None


@lru_cache(maxsize=512)
def _load_value_annotated_fields(path_str: str) -> dict[str, str]:
    """Champs `@Value("${clé}")` d'un fichier source Java — variable ->
    clé de propriété (avec éventuel `:défaut`, laissé tel quel pour
    `resolve_spring_property`). Best-effort par regex sur le texte source,
    même esprit que le reste de l'extraction (ADR-26) : pas d'AST Java."""
    path = Path(path_str)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return {match.group(2): match.group(1) for match in _VALUE_FIELD_RE.finditer(text)}


def _resolve_value_annotated_variable(
    repo_root: Path, source_path: str, var_name: str
) -> str | None:
    fields = _load_value_annotated_fields(str(repo_root / source_path))
    property_key = fields.get(var_name)
    if property_key is None:
        return None
    return resolve_spring_property(repo_root, property_key, source_path)


def _extract_kafka_topic(
    snippet: str, repo_root: Path, source_path: str | None = None
) -> tuple[str, bool]:
    """Renvoie (topic, dynamique). Un littéral `${propriete.imbriquee}`
    (placeholder Spring, ex. `@KafkaListener(topics = "${app.kafka.topics.
    orders}")`) n'est pas un nom de topic mais une clé de configuration :
    tentative de résolution via `resolve_spring_property` avant de retomber
    sur dynamique si la clé est introuvable — jamais résolu au hasard. Une
    variable (pas de littéral du tout, ex. `topics = ordersTopic`) est
    tentée contre les champs `@Value("${...}")` du même fichier source
    (`_resolve_value_annotated_variable`) avant d'abandonner en dynamique."""
    literal, dynamic = _find_first_literal(snippet)
    if literal is None:
        if source_path is not None:
            first_line = snippet.splitlines()[0] if snippet else ""
            var_match = _BARE_TOPIC_VAR_RE.search(first_line)
            if var_match is not None:
                resolved = _resolve_value_annotated_variable(
                    repo_root, source_path, var_match.group(1)
                )
                if resolved is not None:
                    return resolved, False
        return "<dynamic>", True

    placeholder = _PROPERTY_PLACEHOLDER_RE.match(literal)
    if placeholder is not None:
        resolved = resolve_spring_property(repo_root, placeholder.group(1), source_path)
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
            topic, dynamic = _extract_kafka_topic(snippet, repo_root, path)

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
                module=_module_for_path(repo_root, path),
                qualified_name=_java_qualified_name(str(repo_root), path),
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
