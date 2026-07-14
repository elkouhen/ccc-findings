"""Lecture minimale de `pom.xml` (artifactId, détection Spring Boot) partagée
entre `workspace.py` (fédération multi-services, BACKLOG-11 A2) et `scanner.py`
(attribution d'un module à chaque finding/endpoint indexé, BACKLOG-13 M1)."""

import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path
import re

_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"
_SPRING_BOOT_PLUGIN_MARKER = "spring-boot-maven-plugin"
_MAIN_METHOD_RE = re.compile(r"\bstatic\s+void\s+main\s*\(")
_SPRING_APPLICATION_RUN_RE = re.compile(r"SpringApplication\.run\(")


def _pom_child_text(root: ET.Element, tag: str) -> str | None:
    element = root.find(f"{_MAVEN_NS}{tag}")
    if element is None:
        element = root.find(tag)  # pom sans espace de noms déclaré (rare)
    return element.text.strip() if element is not None and element.text else None


def _is_spring_boot_main_class(text: str) -> bool:
    return bool(_MAIN_METHOD_RE.search(text)) and bool(_SPRING_APPLICATION_RUN_RE.search(text))


@lru_cache(maxsize=256)
def _module_has_spring_boot_main_class(module_dir_str: str) -> bool:
    module_dir = Path(module_dir_str)
    source_root = module_dir / "src" / "main" / "java"
    if not source_root.is_dir():
        return False
    for java_file in source_root.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _is_spring_boot_main_class(text):
            return True
    return False


def parse_pom(pom_path: Path) -> tuple[str | None, bool, str | None]:
    """Renvoie (artifactId, is_spring_boot_app, packaging). Un pom.xml illisible ou mal
    formé renvoie (None, False, None) plutôt que de faire échouer toute la
    découverte — un seul module cassé ne doit pas bloquer les autres."""
    try:
        text = pom_path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text)
    except (ET.ParseError, OSError):
        return None, False, None
    artifact_id = _pom_child_text(root, "artifactId")
    packaging = _pom_child_text(root, "packaging")
    is_spring_boot_app = _SPRING_BOOT_PLUGIN_MARKER in text or _module_has_spring_boot_main_class(
        str(pom_path.parent)
    )
    return artifact_id, is_spring_boot_app, packaging


def is_runtime_service(packaging: str | None, is_spring_boot_app: bool) -> bool:
    """Un parent/agrégateur Maven `packaging=pom` n'est jamais un service
    runtime, même s'il déclare le plugin Spring Boot pour ses enfants."""
    return packaging != "pom" and is_spring_boot_app


@lru_cache(maxsize=512)
def _cached_module_name(pom_path_str: str) -> str:
    pom_path = Path(pom_path_str)
    artifact_id, _, _ = parse_pom(pom_path)
    return artifact_id or pom_path.parent.name


def clear_caches() -> None:
    """BACKLOG-16 P2 : à appeler en tête de chaque indexation dans un
    process long-vivant (serveur MCP) — `_cached_module_name` est caché par
    chemin de pom.xml pour toute la durée du process, un artifactId modifié
    entre deux `cccr index` resterait sinon périmé."""
    _cached_module_name.cache_clear()
    _module_has_spring_boot_main_class.cache_clear()


def module_name_for_path(repo_root: Path, rel_path: str) -> str | None:
    """Nom de module Maven (artifactId, repli sur le nom du répertoire) du
    plus proche `pom.xml` en remontant depuis le répertoire de `rel_path`
    jusqu'à `repo_root` inclus (BACKLOG-13 M1). `None` si aucun `pom.xml`
    n'est trouvé sur ce chemin — repo non-Maven, ou fichier hors
    arborescence Maven. Résultat caché par `pom.xml` (mêmes garanties que
    `resolve_spring_property`/`_load_flat_spring_properties` : un pom lu une
    seule fois par process). Même bornage que `_candidate_spring_roots`
    (`scanner.py`) : jamais de remontée au-delà de `repo_root`."""
    source_abs = (repo_root / rel_path).resolve()
    repo_root_resolved = repo_root.resolve()
    candidates = [source_abs.parent, *source_abs.parent.parents]
    for candidate in candidates:
        if candidate == repo_root_resolved or repo_root_resolved in candidate.parents:
            pom_path = candidate / "pom.xml"
            if pom_path.is_file():
                return _cached_module_name(str(pom_path))
        if candidate == repo_root_resolved:
            break
    return None
