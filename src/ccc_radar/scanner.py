import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from ccc_radar.config import Config
from ccc_radar import gradle as gradle_module
from ccc_radar import maven as maven_module
from ccc_radar.gradle import gradle_service_for_path
from ccc_radar.maven import module_name_for_path
from ccc_radar.models import Finding, MessageEndpoint, compute_endpoint_id, compute_finding_id

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
            # les règles de findings (cccr index les exécute ensemble) —
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
# BACKLOG Q25 : `KStream.to("topic")`/`.to("topic", Produced.with(...))` —
# le topic suit directement `.to(`, contrairement au premier littéral
# quelconque du snippet (qui peut appartenir à un `.peek(...)` chaîné avant).
_KAFKA_STREAMS_TO_RE = re.compile(r'\.to\(\s*"([^"]*)"\s*(\+)?')
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
_SPRING_CLOUD_CONFIG_DIR_PATTERNS = (
    "src/main/resources/configurations",
    "configurations",
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


# BACKLOG Q24 : une règle Semgrep `endpoint-inventory` est bornée à la
# méthode annotée (`pattern: @GetMapping(...) $RET $METHOD(...) { ... }`) —
# elle ne voit jamais le `@RequestMapping` porté par la classe englobante,
# alors que Spring MVC le préfixe silencieusement au chemin de la méthode.
# Conséquence observée sur des repos réels (spring-petclinic-microservices,
# microservices-kafka-mq) : soit le chemin sort sous-qualifié (méthode avec
# valeur explicite, préfixe de classe ignoré), soit il sort `<dynamic>`
# (méthode sans valeur explicite : `@GetMapping` seul hérite du chemin de
# classe côté Spring, mais Semgrep n'a aucun littéral à extraire) — dans les
# deux cas, la corrélation caller/callee de `graph.paths_match` échoue sur
# des appels réels. Best-effort ligne par ligne (ADR-26, pas d'AST) : la
# classe/interface la plus proche au-dessus de la méthode, avec ses lignes
# d'annotation contiguës.
_CLASS_DECL_RE = re.compile(
    r"^\s*(?:public\s+|private\s+|protected\s+|final\s+|abstract\s+|static\s+)*"
    r"(?:class|interface|record)\s+\w+"
)
_MAPPING_ANNOTATION_RE = re.compile(r"@\w+Mapping\s*(?:\(([^)]*)\))?")
_REQUEST_MAPPING_RE = re.compile(r"@RequestMapping\s*(?:\(([^)]*)\))?")
_REQUEST_MAPPING_BLOCK_RE = re.compile(r"@RequestMapping\s*(?:\((.*?)\))?", re.DOTALL)
_NON_PATH_MAPPING_ATTRS = {"method", "produces", "consumes", "headers", "params", "name"}
_REPOSITORY_REST_RESOURCE_RE = re.compile(r"@RepositoryRestResource\s*(?:\(([^)]*)\))?")
_FEIGN_CLIENT_RE = re.compile(r"@FeignClient\s*\((.*?)\)", re.DOTALL)
_NAMED_STRING_ARG_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_ENABLE_SWAGGER2_RE = re.compile(r"@EnableSwagger2\b")
_METHOD_DECL_RE = re.compile(
    r"^\s*(?:public|private|protected)?(?:\s+static)?(?:\s+final)?[\w<>\[\], ?]+\s+\w+\s*\([^;]*\)\s*\{?"
)
_MESSAGE_BUILDER_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:[\w<>\[\], ?]+|var)\s+(\w+)\s*=\s*MessageBuilder\b"
)
_MESSAGE_BUILDER_TOPIC_RE = re.compile(
    r"\.setHeader\(\s*(?:TOPIC|KafkaHeaders\.TOPIC)\s*,\s*([^)]+?)\s*\)"
)
_MESSAGE_SEND_RE = re.compile(r"\.send\(\s*(\w+)\s*\)\s*;")
_REST_TEMPLATE_CALL_RE = re.compile(
    r"\.(getForObject|getForEntity|postForObject|postForEntity|put|delete)\(\s*(.+?)\s*(?:,|\))",
    re.DOTALL,
)
_REST_TEMPLATE_EXCHANGE_RE = re.compile(
    r"\.exchange\(\s*(.+?)\s*,\s*(?:HttpMethod\.)?([A-Z]+)\s*,",
    re.DOTALL,
)


def _mapping_args_have_only_non_path_attrs(args: str) -> bool:
    """`True` si les arguments d'une annotation `@XMapping(...)` ne portent
    aucun chemin explicite (vide, ou uniquement `method=`/`produces=`/...) —
    dans ce cas le chemin effectif de la méthode est vide (hérite du préfixe
    de classe), pas inconnu."""
    args = args.strip()
    if not args:
        return True
    for part in args.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            return False  # argument positionnel : c'est le chemin lui-même
        key = part.split("=", 1)[0].strip()
        if key not in _NON_PATH_MAPPING_ATTRS:
            return False
    return True


def _mapping_args_have_http_method(args: str) -> bool:
    return "method" in args


def _next_declaration_line(lines: list[str], start_idx: int) -> int | None:
    for idx in range(start_idx, len(lines)):
        stripped = lines[idx].strip()
        if not stripped or stripped.startswith("@"):
            continue
        return idx
    return None


def _named_string_arg(args: str, key: str) -> str | None:
    for match in _NAMED_STRING_ARG_RE.finditer(args):
        if match.group(1) == key:
            return match.group(2)
    return None


def _split_java_concat(expr: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in expr:
        if quote is not None:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            current.append(ch)
            continue
        if ch == "+":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _resolve_rest_path_expression(
    expr: str, repo_root: Path, source_path: str
) -> tuple[str, bool]:
    resolved_parts: list[str] = []
    dynamic = False
    for part in _split_java_concat(expr.strip()):
        if len(part) >= 2 and part[0] == part[-1] == '"':
            literal = part[1:-1]
            placeholder = _PROPERTY_PLACEHOLDER_RE.match(literal)
            if placeholder is not None:
                resolved = resolve_spring_property(repo_root, placeholder.group(1), source_path)
                if resolved is None:
                    dynamic = True
                    continue
                resolved_parts.append(resolved)
                continue
            resolved_parts.append(literal)
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", part):
            resolved = _resolve_value_annotated_variable(repo_root, source_path, part)
            if resolved is None:
                dynamic = True
                continue
            resolved_parts.append(resolved)
            continue
        dynamic = True
    raw = "".join(resolved_parts).strip()
    if not raw:
        return "<dynamic>", True
    return _normalize_rest_path(raw), dynamic


def _annotation_block_before_declaration(lines: list[str], decl_idx: int) -> str:
    block: list[str] = []
    idx = decl_idx - 1
    while idx >= 0:
        stripped = lines[idx].strip()
        if not stripped:
            if block:
                break
            idx -= 1
            continue
        if stripped.startswith("@"):
            block.append(lines[idx])
            idx -= 1
            continue
        if block:
            if _CLASS_DECL_RE.match(lines[idx]) or _METHOD_DECL_RE.match(lines[idx]):
                break
            block.append(lines[idx])
            idx -= 1
            continue
        if stripped.endswith(("(", ")", ",")) or "=" in stripped:
            block.append(lines[idx])
            idx -= 1
            continue
        break
    annotation_block = "\n".join(reversed(block))
    return annotation_block if "@" in annotation_block else ""


@lru_cache(maxsize=1024)
def _class_base_path(repo_root_str: str, source_path: str, start_line: int) -> tuple[str, bool]:
    """Chemin `@RequestMapping` de la classe/interface qui englobe la
    méthode trouvée à `start_line` — renvoie (préfixe, dynamique) ;
    (`""`, `False`) si aucune classe englobante ou aucun `@RequestMapping`
    de classe (rien à préfixer, pas une valeur inconnue)."""
    path = Path(repo_root_str) / source_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "", False

    class_line_idx: int | None = None
    for idx in range(min(start_line - 1, len(lines) - 1), -1, -1):
        if _CLASS_DECL_RE.match(lines[idx]):
            class_line_idx = idx
            break
    if class_line_idx is None:
        return "", False

    annotation_block = _annotation_block_before_declaration(lines, class_line_idx)
    if not annotation_block:
        return "", False

    request_mapping = _REQUEST_MAPPING_BLOCK_RE.search(annotation_block)
    if request_mapping is not None:
        args = request_mapping.group(1) or ""
        literal, _ = _find_first_literal(args)
        if literal is not None:
            return literal, False
        return "", True  # @RequestMapping de classe présent mais valeur non littérale

    feign_client = _FEIGN_CLIENT_RE.search(annotation_block)
    if feign_client is not None:
        args = feign_client.group(1) or ""
        prefix = ""
        dynamic = False
        for key in ("url", "path"):
            value = _named_string_arg(args, key)
            if value is None:
                continue
            resolved, part_dynamic = _resolve_rest_path_expression(
                f'"{value}"', Path(repo_root_str), source_path
            )
            dynamic = dynamic or part_dynamic
            if resolved == "<dynamic>":
                continue
            prefix = _join_rest_paths(prefix, resolved) if prefix else resolved
        if prefix:
            return prefix, dynamic
        if dynamic:
            return "", True

    return "", False


def _extract_rest_path(
    snippet: str,
    repo_root: Path | None = None,
    source_path: str | None = None,
    start_line: int | None = None,
) -> tuple[str, bool]:
    """Renvoie (chemin, dynamique) — jamais résolu silencieusement (même
    esprit que `topic_dynamic` en K2). Fusionne le préfixe `@RequestMapping`
    de la classe englobante (Q24) quand `repo_root`/`source_path`/
    `start_line` sont fournis."""
    prefix, prefix_dynamic = "", False
    if repo_root is not None and source_path is not None and start_line is not None:
        prefix, prefix_dynamic = _class_base_path(str(repo_root), source_path, start_line)

    literal, method_dynamic = _find_first_literal(snippet)
    if literal is None:
        first_line = snippet.splitlines()[0] if snippet else ""
        match = _MAPPING_ANNOTATION_RE.search(first_line)
        if match is None or not _mapping_args_have_only_non_path_attrs(match.group(1) or ""):
            return "<dynamic>", True
        literal, method_dynamic = "", False  # annotation sans valeur : hérite du préfixe

    if prefix_dynamic:
        return "<dynamic>", True

    method_path = _normalize_rest_path(literal) if literal else "/"
    if not prefix:
        return method_path, method_dynamic
    return _join_rest_paths(_normalize_rest_path(prefix), method_path), method_dynamic


def _join_rest_paths(prefix: str, suffix: str) -> str:
    """Assemble deux chemins déjà normalisés (slash de tête unique) sans
    jamais repasser par l'heuristique d'URL protocole-relatif de
    `_normalize_rest_path` : une simple concaténation `"" + "/" +
    "/orders/{id}"` produit `"//orders/{id}"`, que `urlsplit` interprète à
    tort comme `http://orders/{id}` (`orders` avalé comme nom d'hôte)."""
    segments = [s for s in (prefix.strip("/"), suffix.strip("/")) if s]
    return "/" + "/".join(segments) if segments else "/"


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


def _build_endpoint(
    repo_root: Path,
    rel_path: str,
    start_line: int,
    end_line: int,
    role: str,
    system: str,
    topic: str,
    framework: str,
    snippet: str,
    topic_dynamic: bool = False,
) -> MessageEndpoint:
    return MessageEndpoint(
        id=compute_endpoint_id(role, topic, rel_path, start_line, end_line),
        role=role,
        system=system,
        topic=topic,
        topic_dynamic=topic_dynamic,
        source="code",
        framework=framework,
        path=rel_path,
        start_line=start_line,
        end_line=end_line,
        snippet=snippet,
        module=_module_for_path(repo_root, rel_path),
        qualified_name=_java_qualified_name(str(repo_root), rel_path),
    )


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
    for candidate in _discover_spring_cloud_config_files(repo_root, source_path):
        if candidate not in seen:
            seen.add(candidate)
            discovered.append(str(candidate))
    return tuple(discovered)


def _local_spring_application_names(repo_root: Path, source_path: str | None) -> tuple[str, ...]:
    names: list[str] = []
    seen: set[str] = set()
    for root in _candidate_spring_roots(repo_root, source_path):
        for config_dir in (root / "src" / "main" / "resources", root):
            for filename in _SPRING_BASE_FILENAMES:
                candidate = config_dir / filename
                if not candidate.is_file():
                    continue
                name = _load_flat_spring_properties(str(candidate)).get("spring.application.name")
                if name and name not in seen:
                    seen.add(name)
                    names.append(name)
            for pattern in _SPRING_PROFILE_PATTERNS:
                for candidate in sorted(config_dir.glob(pattern)):
                    if not candidate.is_file():
                        continue
                    name = _load_flat_spring_properties(str(candidate)).get("spring.application.name")
                    if name and name not in seen:
                        seen.add(name)
                        names.append(name)
    return tuple(names)


def _discover_spring_cloud_config_files(
    repo_root: Path, source_path: str | None
) -> tuple[Path, ...]:
    discovered: list[Path] = []
    seen: set[Path] = set()
    for app_name in _local_spring_application_names(repo_root, source_path):
        for config_dir_pattern in _SPRING_CLOUD_CONFIG_DIR_PATTERNS:
            for suffix in (".yml", ".yaml", ".properties"):
                for candidate in sorted(
                    repo_root.glob(f"**/{config_dir_pattern}/{app_name}{suffix}")
                ):
                    if candidate.is_file() and candidate not in seen:
                        seen.add(candidate)
                        discovered.append(candidate)
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


def _infer_generic_request_mapping_endpoints(repo_root: Path, rel_path: str) -> list[MessageEndpoint]:
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    endpoints: list[MessageEndpoint] = []
    for idx, line in enumerate(lines):
        match = _REQUEST_MAPPING_RE.search(line)
        if match is None:
            continue
        args = match.group(1) or ""
        if _mapping_args_have_http_method(args):
            continue
        decl_idx = _next_declaration_line(lines, idx + 1)
        if decl_idx is None or _CLASS_DECL_RE.match(lines[decl_idx]):
            continue
        if not _METHOD_DECL_RE.match(lines[decl_idx]):
            continue
        snippet = "\n".join(lines[idx : decl_idx + 1])
        route, dynamic = _extract_rest_path(snippet, repo_root, rel_path, decl_idx + 1)
        endpoints.append(
            _build_endpoint(
                repo_root,
                rel_path,
                decl_idx + 1,
                decl_idx + 1,
                "serve",
                "rest",
                f"ANY {route}",
                "spring",
                snippet,
                topic_dynamic=dynamic,
            )
        )
    return endpoints


def _infer_spring_data_rest_endpoints(repo_root: Path, rel_path: str) -> list[MessageEndpoint]:
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    endpoints: list[MessageEndpoint] = []
    for idx, line in enumerate(lines):
        match = _REPOSITORY_REST_RESOURCE_RE.search(line)
        if match is None:
            continue
        rest_path = _named_string_arg(match.group(1) or "", "path")
        if not rest_path:
            continue
        base_path = _normalize_rest_path(rest_path)
        for topic in (
            f"GET {base_path}",
            f"POST {base_path}",
            f"GET {base_path}/{{id}}",
            f"PUT {base_path}/{{id}}",
            f"PATCH {base_path}/{{id}}",
            f"DELETE {base_path}/{{id}}",
        ):
            endpoints.append(
                _build_endpoint(
                    repo_root,
                    rel_path,
                    idx + 1,
                    idx + 1,
                    "serve",
                    "rest",
                    topic,
                    "spring-data-rest",
                    line.strip(),
                )
            )
    return endpoints


def _infer_swagger_endpoint(repo_root: Path, rel_path: str) -> list[MessageEndpoint]:
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for idx, line in enumerate(lines):
        if _ENABLE_SWAGGER2_RE.search(line):
            return [
                _build_endpoint(
                    repo_root,
                    rel_path,
                    idx + 1,
                    idx + 1,
                    "serve",
                    "rest",
                    "GET /swagger-ui.html",
                    "swagger-ui",
                    line.strip(),
                )
            ]
    return []


def _infer_actuator_endpoint(repo_root: Path, rel_path: str) -> list[MessageEndpoint]:
    path = repo_root / rel_path
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    value = _load_flat_spring_properties(str(path)).get("management.endpoints.web.exposure.include")
    if value is None or "*" not in value:
        return []
    start_line = 1
    for idx, line in enumerate(text.splitlines(), start=1):
        if "management.endpoints.web.exposure.include" in line:
            start_line = idx
            break
    return [
        _build_endpoint(
            repo_root,
            rel_path,
            start_line,
            start_line,
            "serve",
            "rest",
            "GET /actuator/**",
            "spring-actuator",
            "management.endpoints.web.exposure.include=*",
        )
    ]


@lru_cache(maxsize=512)
def _file_uses_resttemplate(repo_root_str: str, rel_path: str) -> bool:
    path = Path(repo_root_str) / rel_path
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return (
        "org.springframework.web.client.RestTemplate" in text
        or "new RestTemplate(" in text
        or " RestTemplate " in text
    )


def _extract_resttemplate_path(
    snippet: str, repo_root: Path, source_path: str
) -> tuple[str, bool] | None:
    match = _REST_TEMPLATE_CALL_RE.search(snippet)
    if match is not None:
        return _resolve_rest_path_expression(match.group(2), repo_root, source_path)
    exchange_match = _REST_TEMPLATE_EXCHANGE_RE.search(snippet)
    if exchange_match is not None:
        return _resolve_rest_path_expression(exchange_match.group(1), repo_root, source_path)
    return None


def _infer_resttemplate_exchange_endpoints(
    repo_root: Path, rel_path: str
) -> list[MessageEndpoint]:
    if not _file_uses_resttemplate(str(repo_root), rel_path):
        return []
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    inferred: list[MessageEndpoint] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if ".exchange(" not in line:
            idx += 1
            continue
        block_lines = [line]
        block_end = idx
        while block_end + 1 < len(lines):
            if ");" in lines[block_end]:
                break
            block_end += 1
            block_lines.append(lines[block_end])
            if ");" in lines[block_end]:
                break
        snippet = "\n".join(block_lines)
        match = _REST_TEMPLATE_EXCHANGE_RE.search(snippet)
        if match is not None:
            http_method = match.group(2).split(".")[-1]
            route, dynamic = _resolve_rest_path_expression(match.group(1), repo_root, rel_path)
            inferred.append(
                _build_endpoint(
                    repo_root,
                    rel_path,
                    idx + 1,
                    block_end + 1,
                    "call",
                    "rest",
                    f"{http_method} {route}",
                    "resttemplate",
                    snippet,
                    topic_dynamic=dynamic,
                )
            )
        idx = block_end + 1
    return inferred


def _resolve_topic_expression(
    expr: str, repo_root: Path, source_path: str
) -> tuple[str, bool]:
    expr = expr.strip()
    if len(expr) >= 2 and expr[0] == expr[-1] == '"':
        literal = expr[1:-1]
        placeholder = _PROPERTY_PLACEHOLDER_RE.match(literal)
        if placeholder is not None:
            resolved = resolve_spring_property(repo_root, placeholder.group(1), source_path)
            if resolved is not None:
                return resolved, False
            return literal, True
        return literal, False
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        resolved = _resolve_value_annotated_variable(repo_root, source_path, expr)
        if resolved is not None:
            return resolved, False
    return "<dynamic>", True


def _infer_message_builder_kafka_producers(
    repo_root: Path, rel_path: str
) -> list[MessageEndpoint]:
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    builders: dict[str, list[tuple[str, bool, int, str]]] = {}
    inferred: list[MessageEndpoint] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = _MESSAGE_BUILDER_ASSIGNMENT_RE.match(line)
        if match is None:
            idx += 1
            continue
        var_name = match.group(1)
        block_lines = [line]
        block_end = idx
        while block_end + 1 < len(lines):
            if ".build()" in lines[block_end]:
                break
            block_end += 1
            block_lines.append(lines[block_end])
            if ".build()" in lines[block_end]:
                break
        block_snippet = "\n".join(block_lines)
        topic_match = _MESSAGE_BUILDER_TOPIC_RE.search(block_snippet)
        if topic_match is not None:
            topic, dynamic = _resolve_topic_expression(
                topic_match.group(1), repo_root, rel_path
            )
            builders.setdefault(var_name, []).append((topic, dynamic, idx + 1, block_snippet))
        idx = block_end + 1

    for line_no, line in enumerate(lines, start=1):
        send_match = _MESSAGE_SEND_RE.search(line)
        if send_match is None:
            continue
        candidates = builders.get(send_match.group(1), [])
        built_message = None
        for candidate in candidates:
            if candidate[2] <= line_no:
                built_message = candidate
        if built_message is None:
            continue
        topic, dynamic, _, builder_snippet = built_message
        inferred.append(
            _build_endpoint(
                repo_root,
                rel_path,
                line_no,
                line_no,
                "produce",
                "kafka",
                topic,
                "spring-kafka",
                f"{builder_snippet}\n{line.strip()}",
                topic_dynamic=dynamic,
            )
        )
    return inferred


def infer_framework_endpoints(repo_root: Path, files: list[str] | None = None) -> list[MessageEndpoint]:
    if files is None:
        candidate_files = [
            path.relative_to(repo_root).as_posix() for path in repo_root.rglob("*") if path.is_file()
        ]
    else:
        candidate_files = sorted(files)

    inferred: dict[str, MessageEndpoint] = {}
    for rel_path in candidate_files:
        if rel_path.endswith(".java"):
            for endpoint in (
                _infer_generic_request_mapping_endpoints(repo_root, rel_path)
                + _infer_spring_data_rest_endpoints(repo_root, rel_path)
                + _infer_swagger_endpoint(repo_root, rel_path)
                + _infer_resttemplate_exchange_endpoints(repo_root, rel_path)
                + _infer_message_builder_kafka_producers(repo_root, rel_path)
            ):
                inferred[endpoint.id] = endpoint
        elif rel_path.endswith((".properties", ".yml", ".yaml")):
            for endpoint in _infer_actuator_endpoint(repo_root, rel_path):
                inferred[endpoint.id] = endpoint
    return list(inferred.values())


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
    (`_resolve_value_annotated_variable`) avant d'abandonner en dynamique.

    BACKLOG Q25 : `KStream.to("topic")` (Kafka Streams) est souvent chaîné
    après un `.peek(...)` dont le lambda peut lui-même contenir un littéral
    (message de log) — le premier littéral du snippet n'est alors pas le
    topic. Un `.to("...")` capté explicitement prime sur la recherche
    générique du premier littéral."""
    streams_to_match = _KAFKA_STREAMS_TO_RE.search(snippet)
    if streams_to_match is not None:
        return streams_to_match.group(1), streams_to_match.group(2) is not None

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
            framework = metadata.get("framework")
            if framework == "resttemplate":
                if not _file_uses_resttemplate(str(repo_root), path):
                    continue
                extracted = _extract_resttemplate_path(snippet, repo_root, path)
                if extracted is not None:
                    route, dynamic = extracted
                else:
                    route, dynamic = _extract_rest_path(snippet, repo_root, path, start_line)
            else:
                route, dynamic = _extract_rest_path(snippet, repo_root, path, start_line)
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
    endpoints = parse_semgrep_endpoints(raw, repo_root)
    endpoints.extend(infer_framework_endpoints(repo_root, files))
    return endpoints


def clear_analysis_caches() -> None:
    """BACKLOG-16 P2 : vide tous les `lru_cache` d'analyse best-effort
    (package/qualified-name Java, propriétés Spring, champs `@Value`,
    module Maven, service Gradle) — à appeler en tête de chaque
    indexation. Ces caches accélèrent une indexation en cours (un même
    fichier de config lu plusieurs fois), mais un serveur MCP est un
    process long-vivant : sans purge, `reindex_findings` reservirait des
    valeurs résolues avant la modification des fichiers qui a motivé la
    réindexation."""
    _java_qualified_name.cache_clear()
    _load_flat_spring_properties.cache_clear()
    _load_value_annotated_fields.cache_clear()
    _class_base_path.cache_clear()
    _file_uses_resttemplate.cache_clear()
    maven_module.clear_caches()
    gradle_module.clear_caches()
