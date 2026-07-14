"""Fédération read-only d'un répertoire multi-services Maven (BACKLOG-11 A2).

Découvre les modules Maven d'un répertoire parent (chaque `pom.xml` est un
module), leur donne un nom logique stable (`artifactId`), les classe en
microservice déployable ou module partagé, puis lit — en lecture seule,
jamais d'écriture (ADR-30) — les `.cccr/findings.db` déjà indexés pour
construire une vue fédérée (`endpoints_by_service`/`findings_by_service`)
consommable par `graph.py`.
"""

from dataclasses import dataclass
from pathlib import Path

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


def discover_maven_services(root: Path) -> list[DiscoveredService]:
    """Explore `root` pour des `pom.xml` — chaque répertoire qui en porte un
    est un module. Nom de service : `artifactId` du pom (repli : nom du
    répertoire, si le pom est absent d'artifactId ou illisible). Classé
    `microservice` si le pom référence `spring-boot-maven-plugin` (produit
    un jar exécutable), `shared-module` sinon (bibliothèque interne) — voir
    ADR-30. Triés par chemin pour un ordre stable et déterministe."""
    root = root.resolve()
    root_indexed = db_path(root).is_file()
    services: list[DiscoveredService] = []
    for pom_path in sorted(root.rglob("pom.xml")):
        module_dir = pom_path.parent
        artifact_id, is_spring_boot_app, packaging = parse_pom(pom_path)
        if packaging == "pom" and not is_runtime_service(packaging, is_spring_boot_app):
            continue
        name = artifact_id or module_dir.name
        kind = "microservice" if is_runtime_service(packaging, is_spring_boot_app) else "shared-module"
        direct_indexed = db_path(module_dir).is_file()
        parent_indexed = root_indexed and module_dir != root
        indexed = direct_indexed or parent_indexed
        index_root = module_dir if direct_indexed or module_dir == root else root
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


def load_federation(services: list[DiscoveredService]) -> FederationResult:
    """Lit, en lecture seule, les bases déjà indexées des services
    découverts. Un service non indexé, dont la base est introuvable ou
    incompatible, génère un avertissement (`warnings`) plutôt que de faire
    échouer la fédération entière (K7 CA2). Les modules partagés
    (`shared-module`) contribuent leurs findings (pour les hotspots) mais
    pas leurs endpoints : ce ne sont pas des producteurs/consommateurs
    runtime (A2 CA5)."""
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
