"""Détection de microservice pour un repo Gradle sans `pom.xml`, en
complément de `maven.py` (BACKLOG-15 H1, ADR-33). Contrairement à Maven, un
`build.gradle` n'a pas de marqueur universel équivalent à
`spring-boot-maven-plugin` (plugins de convention custom via `buildSrc`,
souvent utilisés pour masquer le plugin Spring Boot standard derrière un
nom maison) — le signal fiable est la classe Java qui démarre réellement
l'application (`main()` qui appelle `SpringApplication.run(...)`), au
niveau du code plutôt que du build.
"""

import re
from functools import lru_cache
from pathlib import Path

_MAIN_METHOD_RE = re.compile(r"\bstatic\s+void\s+main\s*\(")
_SPRING_APPLICATION_RUN_RE = re.compile(r"SpringApplication\.run\(")


def _is_spring_boot_main_class(text: str) -> bool:
    return bool(_MAIN_METHOD_RE.search(text)) and bool(_SPRING_APPLICATION_RUN_RE.search(text))


@lru_cache(maxsize=8)
def _service_roots(repo_root_str: str) -> frozenset[str]:
    """Premier segment de chemin (sous `repo_root`) de chaque classe Java
    munie d'un `main()` qui démarre Spring Boot — un seul parcours du repo,
    mis en cache par process (même esprit que
    `scanner._discover_spring_property_files`)."""
    repo_root = Path(repo_root_str)
    roots: set[str] = set()
    for java_file in repo_root.rglob("*.java"):
        rel_parts = java_file.relative_to(repo_root).parts
        if len(rel_parts) < 2:
            continue
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _is_spring_boot_main_class(text):
            roots.add(rel_parts[0])
    return frozenset(roots)


def gradle_service_for_path(repo_root: Path, rel_path: str) -> str | None:
    """Service Gradle (BACKLOG-15 H1) : premier segment de `rel_path` s'il
    correspond à un répertoire qui contient, quelque part dans son
    arborescence, une classe Java avec un `main()` démarrant Spring Boot —
    signal indépendant du système de build, contrairement à Maven où
    `spring-boot-maven-plugin` est cherché dans le texte du pom. Un
    microservice Gradle réparti sur plusieurs sous-projets (`<service>/
    <service>-domain`, `<service>-restapi`, ... `<service>-main`) est ainsi
    regroupé sous un seul nom, celui du répertoire de premier niveau — même
    granularité que ce qu'un seul `pom.xml` Maven produirait pour un
    microservice équivalent. `None` si aucun segment ne correspond à un
    service connu (répertoire hors service, ou fichier directement à la
    racine du repo)."""
    parts = Path(rel_path).parts
    if not parts:
        return None
    first = parts[0]
    return first if first in _service_roots(str(repo_root.resolve())) else None
