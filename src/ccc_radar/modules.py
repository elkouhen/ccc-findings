"""Inventaire de tous les modules Maven et Gradle d'un workspace."""

from dataclasses import dataclass
from pathlib import Path

from ccc_radar.gradle import discover_gradle_modules, discover_gradle_services
from ccc_radar.maven import is_runtime_service, parse_pom, pom_version
from ccc_radar.configuration import service_configuration_example


@dataclass(frozen=True)
class DiscoveredModule:
    name: str
    path: Path
    build_system: str  # maven | gradle
    version: str | None
    kind: str  # microservice | library | aggregator
    configuration_example: str


def discover_modules(root: Path) -> list[DiscoveredModule]:
    """Discover build modules, including libraries and aggregators."""
    root = root.resolve()
    modules: list[DiscoveredModule] = []
    seen_paths: set[Path] = set()
    for pom_path in sorted(root.rglob("pom.xml")):
        module_dir = pom_path.parent.resolve()
        artifact_id, spring_boot, packaging = parse_pom(pom_path)
        kind = (
            "microservice"
            if is_runtime_service(packaging, spring_boot)
            else "aggregator"
            if packaging == "pom"
            else "library"
        )
        modules.append(
            DiscoveredModule(
                name=artifact_id or module_dir.name,
                path=module_dir,
                build_system="maven",
                version=pom_version(pom_path),
                kind=kind,
                configuration_example=service_configuration_example(module_dir),
            )
        )
        seen_paths.add(module_dir)
    runtime_paths = {path.resolve() for _, path in discover_gradle_services(root)}
    for name, module_dir, version in discover_gradle_modules(root):
        module_dir = module_dir.resolve()
        if module_dir in seen_paths:
            continue
        has_build_file = any(
            (module_dir / filename).is_file() for filename in ("build.gradle", "build.gradle.kts")
        )
        modules.append(
            DiscoveredModule(
                name=name,
                path=module_dir,
                build_system="gradle",
                version=version,
                kind=(
                    "microservice"
                    if module_dir in runtime_paths
                    else "library"
                    if has_build_file
                    else "aggregator"
                ),
                configuration_example=service_configuration_example(module_dir),
            )
        )
    return sorted(modules, key=lambda module: str(module.path))
