"""Détection de microservices Gradle Spring Boot (BACKLOG-15 H1, ADR-33)."""

import re
from functools import lru_cache
from pathlib import Path

_MAIN_METHOD_RE = re.compile(r"\bstatic\s+void\s+main\s*\(")
_SPRING_APPLICATION_RUN_RE = re.compile(r"SpringApplication\.run\(")
_GRADLE_ARTIFACT_RE = re.compile(
    r"(?:archiveBaseName|archivesBaseName|archivesName)\s*(?:\.set\s*\()?\s*=\s*['\"]([^'\"]+)['\"]"
)
_GRADLE_ARTIFACT_SET_RE = re.compile(
    r"(?:archiveBaseName|archivesBaseName|archivesName)\s*\.set\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
)
_ROOT_PROJECT_NAME_RE = re.compile(r"rootProject\.name\s*=\s*['\"]([^'\"]+)['\"]")


def _is_spring_boot_main_class(text: str) -> bool:
    return bool(_MAIN_METHOD_RE.search(text)) and bool(_SPRING_APPLICATION_RUN_RE.search(text))


def _first_gradle_match(paths: list[Path], patterns: tuple[re.Pattern[str], ...]) -> str | None:
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match is not None:
                return match.group(1)
    return None


@lru_cache(maxsize=128)
def _gradle_artifact_name(service_dir_str: str, fallback: str) -> str:
    """Nom d'artefact Gradle, ou nom de projet si Gradle utilise son défaut."""
    service_dir = Path(service_dir_str)
    build_files = [service_dir / "build.gradle", service_dir / "build.gradle.kts"]
    artifact_name = _first_gradle_match(
        build_files, (_GRADLE_ARTIFACT_RE, _GRADLE_ARTIFACT_SET_RE)
    )
    if artifact_name is not None:
        return artifact_name

    settings_files = [service_dir / "settings.gradle", service_dir / "settings.gradle.kts"]
    project_name = _first_gradle_match(settings_files, (_ROOT_PROJECT_NAME_RE,))
    return project_name or fallback


@lru_cache(maxsize=8)
def _service_root_artifacts(repo_root_str: str) -> tuple[tuple[str, str], ...]:
    """Paires ``(racine relative, nom d'artefact)`` des services détectés."""
    repo_root = Path(repo_root_str)
    roots: dict[str, str] = {}
    for java_file in repo_root.rglob("*.java"):
        rel_parts = java_file.relative_to(repo_root).parts
        if len(rel_parts) < 2:
            continue
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _is_spring_boot_main_class(text):
            continue

        relative_root = "" if rel_parts[:3] == ("src", "main", "java") else rel_parts[0]
        service_dir = repo_root if not relative_root else repo_root / relative_root
        fallback = repo_root.name if not relative_root else relative_root
        roots[relative_root] = _gradle_artifact_name(str(service_dir), fallback)
    return tuple(sorted(roots.items()))


def clear_caches() -> None:
    """Vide les caches de détection Gradle avant une nouvelle indexation."""
    _gradle_artifact_name.cache_clear()
    _service_root_artifacts.cache_clear()


def discover_gradle_services(repo_root: Path) -> list[tuple[str, Path]]:
    """Services Gradle détectés sous la forme ``(artefact, répertoire)``."""
    root = repo_root.resolve()
    return [
        (artifact, root if not relative_root else root / relative_root)
        for relative_root, artifact in _service_root_artifacts(str(root))
    ]


def discover_gradle_service_roots(repo_root: Path) -> list[str]:
    """Noms d'artefacts des microservices Gradle détectés, triés."""
    return sorted(artifact for artifact, _ in discover_gradle_services(repo_root))


def gradle_service_for_path(repo_root: Path, rel_path: str) -> str | None:
    """Nom d'artefact du service Gradle auquel appartient ``rel_path``.

    Un projet mono-service avec ``src/main/java`` à la racine est rattaché à
    son propre artefact. Pour un workspace, tous les sous-projets du même
    répertoire de premier niveau reçoivent le nom d'artefact déclaré par le
    projet Gradle de ce service.
    """
    parts = Path(rel_path).parts
    if not parts:
        return None
    relative_root = "" if parts[:3] == ("src", "main", "java") else parts[0]
    for root, artifact in _service_root_artifacts(str(repo_root.resolve())):
        if root == relative_root:
            return artifact
    return None
