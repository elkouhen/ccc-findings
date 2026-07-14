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

from ccc_radar.maven import parse_pom
from ccc_radar.models import Finding, MessageEndpoint
from ccc_radar.paths import db_path
from ccc_radar.store import Store, StoreError


@dataclass(frozen=True)
class DiscoveredService:
    name: str
    path: Path
    kind: str  # "microservice" | "shared-module"
    indexed: bool


@dataclass(frozen=True)
class FederationResult:
    endpoints_by_service: dict[str, list[MessageEndpoint]]
    findings_by_service: dict[str, list[Finding]]
    warnings: list[str]


def discover_maven_services(root: Path) -> list[DiscoveredService]:
    """Explore `root` pour des `pom.xml` — chaque répertoire qui en porte un
    est un module. Nom de service : `artifactId` du pom (repli : nom du
    répertoire, si le pom est absent d'artifactId ou illisible). Classé
    `microservice` si le pom référence `spring-boot-maven-plugin` (produit
    un jar exécutable), `shared-module` sinon (bibliothèque interne) — voir
    ADR-30. Triés par chemin pour un ordre stable et déterministe."""
    services: list[DiscoveredService] = []
    for pom_path in sorted(root.rglob("pom.xml")):
        module_dir = pom_path.parent
        artifact_id, is_spring_boot_app = parse_pom(pom_path)
        name = artifact_id or module_dir.name
        kind = "microservice" if is_spring_boot_app else "shared-module"
        indexed = db_path(module_dir).is_file()
        services.append(
            DiscoveredService(name=name, path=module_dir, kind=kind, indexed=indexed)
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
            with Store(service.path, readonly=True) as store:
                findings_by_service[service.name] = store.all_findings()
                if service.kind == "microservice":
                    endpoints_by_service[service.name] = store.all_endpoints()
        except StoreError as exc:
            warnings.append(f"{service.name} ({service.path}) : {exc}")

    return FederationResult(endpoints_by_service, findings_by_service, warnings)
