import json
import re
import subprocess
from pathlib import Path
from typing import Any

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

        snippet = _read_snippet(repo_root, path, start_line, end_line)
        metadata = extra.get("metadata") or {}
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


# BACKLOG-10 K11 : règles d'inventaire d'endpoints (`metadata.category:
# endpoint-inventory`) — le rôle/système/méthode HTTP viennent des métadonnées
# de la règle (fixes par construction, une règle = une méthode), le chemin
# vient d'une extraction best-effort sur le snippet (métavariables Semgrep
# indisponibles sans compte connecté, voir ADR-26).
_QUOTED_STRING_RE = re.compile(r"f?[\"']([^\"']*)[\"']")


def _extract_rest_path(snippet: str) -> tuple[str, bool]:
    """Renvoie (chemin, dynamique). Cherche le premier littéral entre
    guillemets sur la première ligne du snippet (annotation ou appel) ; si
    ce littéral est suivi d'une concaténation (`+`) ou qu'aucun littéral
    n'est trouvé, le chemin est marqué dynamique (jamais résolu
    silencieusement, même esprit que `topic_dynamic` en K2)."""
    first_line = snippet.splitlines()[0] if snippet else ""
    match = _QUOTED_STRING_RE.search(first_line)
    if match is None:
        return "<dynamic>", True
    path = match.group(1)
    remainder = first_line[match.end() :].lstrip()
    is_dynamic = remainder.startswith("+")
    return path, is_dynamic


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
        if metadata.get("system", "rest") != "rest":
            continue  # K2 (kafka) a sa propre extraction, hors périmètre K11

        try:
            path = _relative_path(result["path"], repo_root)
            start_line = result["start"]["line"]
            end_line = result["end"]["line"]
            role = metadata["role"]
            http_method = metadata["http_method"]
        except (KeyError, TypeError) as exc:
            raise SemgrepError(
                f"Règle d'inventaire d'endpoints mal formée : champ manquant ({exc})"
            ) from exc

        snippet = _read_snippet(repo_root, path, start_line, end_line)
        route, dynamic = _extract_rest_path(snippet)
        topic = f"{http_method} {route}"

        endpoints.append(
            MessageEndpoint(
                id=compute_endpoint_id(role, topic, path, start_line, end_line),
                role=role,
                system="rest",
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


def _invoke_semgrep(
    repo_root: Path, config: Config, files: list[str] | None = None
) -> str:
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
    raw = _invoke_semgrep(repo_root, config, files)
    findings = parse_semgrep_json(raw, repo_root)
    min_index = SEVERITY_ORDER.index(config.min_severity)
    return [f for f in findings if SEVERITY_ORDER.index(f.severity) >= min_index]


def run_semgrep_endpoints(
    repo_root: Path, config: Config, files: list[str] | None = None
) -> list[MessageEndpoint]:
    """Comme `run_semgrep`, mais pour les règles d'inventaire d'endpoints
    (BACKLOG-10 K11) — pas de filtre `min_severity` : ce ne sont pas des
    findings, la sévérité INFO qu'elles portent n'a pas de sens à seuiller."""
    raw = _invoke_semgrep(repo_root, config, files)
    return parse_semgrep_endpoints(raw, repo_root)
