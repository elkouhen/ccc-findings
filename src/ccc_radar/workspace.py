"""Fédération read-only d'un répertoire multi-services Maven/Gradle (BACKLOG-11 A2).

Découvre les services d'un répertoire parent : modules Maven (`pom.xml`) ou
microservices Gradle détectés via leur classe Spring Boot principale. Puis
lit — en lecture seule, jamais d'écriture (ADR-30) — les `.cccr/findings.db`
déjà indexés pour construire une vue fédérée
(`endpoints_by_service`/`findings_by_service`) consommable par `graph.py`.
"""

from dataclasses import dataclass
from pathlib import Path

from ccc_radar.gradle import discover_gradle_service_roots
from ccc_radar.inventory_freshness import endpoint_inventory_warning
from ccc_radar.maven import is_runtime_service, parse_pom
from ccc_radar.models import Finding, MessageEndpoint
from ccc_radar.paths import db_path
from ccc_radar.store import Store, StoreError


@dataclass(frozen=True)
class DiscoveredService:
    name: str
    path: Path
    kind: str  # "microservice" | "shared-module"
    indexed: bool
    index_root: Path


@dataclass(frozen=True)
class FederationResult:
    endpoints_by_service: dict[str, list[MessageEndpoint]]
    findings_by_service: dict[str, list[Finding]]
    warnings: list[str]


def _dedupe_by_id(items: list[Finding] | list[MessageEndpoint]) -> list[Finding] | list[MessageEndpoint]:
    deduped: list[Finding] | list[MessageEndpoint] = []
    seen: set[str] = set()
    for item in items:
        if item.id in seen:
            continue
        seen.add(item.id)
        deduped.append(item)
    return deduped


def _service_index_state(root: Path, service_dir: Path) -> tuple[bool, Path]:
    root = root.resolve()
    root_indexed = db_path(root).is_file()
    direct_indexed = db_path(service_dir).is_file()
    parent_indexed = root_indexed and service_dir != root
    indexed = direct_indexed or parent_indexed
    index_root = service_dir if direct_indexed or service_dir == root else root
    return indexed, index_root


def _discover_maven_services(root: Path) -> list[DiscoveredService]:
    """Découvre les modules Maven runtime ou partagés sous `root`."""
    services: list[DiscoveredService] = []
    for pom_path in sorted(root.rglob("pom.xml")):
        module_dir = pom_path.parent
        artifact_id, is_spring_boot_app, packaging = parse_pom(pom_path)
        if packaging == "pom" and not is_runtime_service(packaging, is_spring_boot_app):
            continue
        name = artifact_id or module_dir.name
        kind = "microservice" if is_runtime_service(packaging, is_spring_boot_app) else "shared-module"
        indexed, index_root = _service_index_state(root, module_dir)
        services.append(
            DiscoveredService(
                name=name,
                path=module_dir,
                kind=kind,
                indexed=indexed,
                index_root=index_root,
            )
        )
    return services


def _discover_gradle_services(root: Path, seen_paths: set[Path]) -> list[DiscoveredService]:
    """Découvre les microservices Gradle de premier niveau sous `root`.

    Contrairement à Maven, on ne tente pas de modéliser des `shared-module`
    Gradle ici : le besoin utilisateur porte sur les services runtime
    visibles via `cccr microservices`.
    """
    services: list[DiscoveredService] = []
    for service_name in discover_gradle_service_roots(root):
        service_dir = (root / service_name).resolve()
        if service_dir in seen_paths or not service_dir.is_dir():
            continue
        indexed, index_root = _service_index_state(root, service_dir)
        services.append(
            DiscoveredService(
                name=service_name,
                path=service_dir,
                kind="microservice",
                indexed=indexed,
                index_root=index_root,
            )
        )
    return services


def discover_workspace_services(root: Path) -> list[DiscoveredService]:
    """Découvre les services fédérables sous `root`.

    - Maven : un service/module par `pom.xml` runtime.
    - Gradle : un microservice par répertoire de premier niveau contenant une
      classe Java Spring Boot exécutable, directement ou dans un sous-projet.
    """
    root = root.resolve()
    services = _discover_maven_services(root)
    seen_paths = {service.path.resolve() for service in services}
    services.extend(_discover_gradle_services(root, seen_paths))
    return sorted(services, key=lambda service: str(service.path))


def discover_maven_services(root: Path) -> list[DiscoveredService]:
    """Compatibilité historique : alias vers `discover_workspace_services`."""
    return discover_workspace_services(root)


def load_federation(services: list[DiscoveredService]) -> FederationResult:
    """Lit, en lecture seule, les bases déjà indexées des services
    découverts. Un service non indexé, dont la base est introuvable ou
    incompatible, génère un avertissement (`warnings`) plutôt que de faire
    échouer la fédération entière (K7 CA2). Les modules partagés
    (`shared-module`) contribuent leurs findings, mais pas leurs endpoints :
    ce ne sont pas des producteurs/consommateurs runtime (A2 CA5)."""
    endpoints_by_service: dict[str, list[MessageEndpoint]] = {}
    findings_by_service: dict[str, list[Finding]] = {}
    warnings: list[str] = []

    for service in services:
        if not service.indexed:
            warnings.append(
                f"{service.name} ({service.path}) : non indexé, ignoré "
                "(lancez cccr index sur ce projet)."
            )
            continue
        try:
            with Store(service.index_root, readonly=True) as store:
                if service.index_root == service.path:
                    findings = store.all_findings()
                    endpoints = store.all_endpoints()
                else:
                    findings = [f for f in store.all_findings() if f.module == service.name]
                    endpoints = [e for e in store.all_endpoints() if e.module == service.name]
                findings = _dedupe_by_id(findings)
                endpoints = _dedupe_by_id(endpoints)
                findings_by_service[service.name] = findings
                if service.kind == "microservice":
                    endpoints_by_service[service.name] = endpoints
                stale_warning = endpoint_inventory_warning(
                    store.get_meta("endpoint_inventory_signature"), scope=service.name
                )
                if stale_warning is not None:
                    warnings.append(stale_warning)
        except StoreError as exc:
            warnings.append(f"{service.name} ({service.path}) : {exc}")

    return FederationResult(endpoints_by_service, findings_by_service, warnings)
