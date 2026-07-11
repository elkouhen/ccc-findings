import hashlib
from dataclasses import dataclass


def compute_finding_id(rule_id: str, path: str, snippet: str) -> str:
    normalized_snippet = " ".join(snippet.split())
    digest = hashlib.sha256(f"{rule_id}|{path}|{normalized_snippet}".encode()).hexdigest()
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
