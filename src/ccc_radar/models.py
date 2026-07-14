import hashlib
from dataclasses import dataclass


def compute_finding_id(
    rule_id: str,
    path: str,
    snippet: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    normalized_snippet = " ".join(snippet.split())
    location = "" if start_line is None else f"|{start_line}:{end_line or start_line}"
    digest = hashlib.sha256(
        f"{rule_id}|{path}{location}|{normalized_snippet}".encode()
    ).hexdigest()
    return digest[:16]


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int
    snippet: str
    fix: str | None
    cwe: list[str]
    owasp: list[str]
    # BACKLOG-13 M1 : module Maven (artifactId du pom.xml le plus proche) et
    # nom qualifié Java (package + classe) du fichier — None si non
    # applicable (repo non-Maven, fichier non-Java). Permet de grouper par
    # module sans fédération multi-dépôts (voir graph.py).
    module: str | None = None
    qualified_name: str | None = None


def compute_endpoint_id(
    role: str,
    topic: str,
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
) -> str:
    location = "" if start_line is None else f"|{start_line}:{end_line or start_line}"
    digest = hashlib.sha256(f"{role}|{topic}|{path}{location}".encode()).hexdigest()
    return digest[:16]


@dataclass(frozen=True)
class MessageEndpoint:
    """Un site statique d'échange entre services — production/consommation
    d'un topic Kafka, ou exposition/appel d'une route REST (BACKLOG-10 K1).

    `topic` porte le nom du topic Kafka, ou "METHODE /chemin" pour REST (ex.
    "GET /orders/{id}"). `path`/`start_line`/`end_line` localisent le site :
    pour `source="manifest"`, `path` est le chemin du manifeste (`TOPICS.md`,
    K10) et `start_line`/`end_line` pointent l'entrée déclarative, pas un
    site de code.
    """

    id: str
    role: str  # produce | consume (kafka) ; serve | call (rest)
    system: str  # kafka | rest
    topic: str
    topic_dynamic: bool
    source: str  # code | manifest
    framework: str | None
    path: str
    start_line: int
    end_line: int
    snippet: str
    # BACKLOG-13 M1 : voir Finding.module/qualified_name — même principe.
    module: str | None = None
    qualified_name: str | None = None
