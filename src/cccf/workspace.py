"""Fédération read-only d'un répertoire multi-services Maven (BACKLOG-11 A2).

Découvre les modules Maven d'un répertoire parent (chaque `pom.xml` est un
module), leur donne un nom logique stable (`artifactId`), les classe en
microservice déployable ou module partagé, puis lit — en lecture seule,
jamais d'écriture (ADR-30) — les `.cccf/findings.db` déjà indexés pour
construire une vue fédérée (`endpoints_by_service`/`findings_by_service`)
consommable par `graph.py`.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

from cccf.models import Finding, MessageEndpoint
from cccf.store import Store, StoreError

_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"
_SPRING_BOOT_PLUGIN_MARKER = "spring-boot-maven-plugin"


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


def _pom_child_text(root: ET.Element, tag: str) -> str | None:
    element = root.find(f"{_MAVEN_NS}{tag}")
    if element is None:
        element = root.find(tag)  # pom sans espace de noms déclaré (rare)
    return element.text.strip() if element is not None and element.text else None


def _parse_pom(pom_path: Path) -> tuple[str | None, bool]:
    """Renvoie (artifactId, is_spring_boot_app). Un pom.xml illisible ou mal
    formé renvoie (None, False) plutôt que de faire échouer toute la
    découverte — un seul module cassé ne doit pas bloquer les autres."""
    try:
        text = pom_path.read_text(encoding="utf-8", errors="replace")
        root = ET.fromstring(text)
    except (ET.ParseError, OSError):
        return None, False
    artifact_id = _pom_child_text(root, "artifactId")
    is_spring_boot_app = _SPRING_BOOT_PLUGIN_MARKER in text
    return artifact_id, is_spring_boot_app


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
        artifact_id, is_spring_boot_app = _parse_pom(pom_path)
        name = artifact_id or module_dir.name
        kind = "microservice" if is_spring_boot_app else "shared-module"
        indexed = (module_dir / ".cccf" / "findings.db").is_file()
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
                "(lancez cccf index sur ce projet)."
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
