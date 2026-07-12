import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from cccf.models import Finding
from cccf.store import Store

_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}


class FindingRef(TypedDict):
    """A finding attached to a code hit — no `score`, that belongs to the code match."""

    id: str
    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int
    fix: str | None
    cwe: list[str]
    owasp: list[str]


class CodeHitWithFindings(TypedDict):
    """Shape returned by the `search_code_with_findings` MCP tool."""

    path: str
    start_line: int
    end_line: int
    score: float
    content: str
    findings: list[FindingRef]
    max_severity: str | None

# Sortie réelle de `ccc search` (cette version n'expose pas de flag --json) :
#
# --- Result 1 (score: 0.657) ---
# File: src/mailer.py:1-6 [python]
# <contenu...>
_RESULT_HEADER_RE = re.compile(r"^--- Result \d+ \(score: ([\d.]+)\) ---$")
_FILE_LINE_RE = re.compile(r"^File: (.+):(\d+)-(\d+) \[[^\]]*\]$")


class CccUnavailable(Exception):
    pass


@dataclass
class CodeHit:
    path: str
    start_line: int
    end_line: int
    score: float
    content: str


def _parse_ccc_search_output(raw: str) -> list[CodeHit]:
    stripped = raw.strip()
    if not stripped:
        return []

    blocks = re.split(r"\n(?=--- Result \d+ )", stripped)
    hits = []
    for block in blocks:
        lines = block.splitlines()
        if len(lines) < 2:
            continue
        header_match = _RESULT_HEADER_RE.match(lines[0])
        file_match = _FILE_LINE_RE.match(lines[1])
        if not header_match or not file_match:
            continue
        hits.append(
            CodeHit(
                path=file_match.group(1),
                start_line=int(file_match.group(2)),
                end_line=int(file_match.group(3)),
                score=float(header_match.group(1)),
                content="\n".join(lines[2:]),
            )
        )
    return hits


def search_code(repo_root: Path, query: str, limit: int = 5) -> list[CodeHit]:
    try:
        proc = subprocess.run(
            ["ccc", "search", query, "--limit", str(limit)],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CccUnavailable("ccc introuvable dans le PATH") from exc

    if proc.returncode != 0:
        raise CccUnavailable(
            f"ccc a échoué (code {proc.returncode}) : {proc.stderr.strip()}"
        )

    return _parse_ccc_search_output(proc.stdout)


def _finding_to_ref(finding: Finding) -> FindingRef:
    return FindingRef(
        id=finding.id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        message=finding.message,
        path=finding.path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        fix=finding.fix,
        cwe=finding.cwe,
        owasp=finding.owasp,
    )


def annotate_with_findings(code_hits: list[CodeHit], store: Store) -> list[CodeHitWithFindings]:
    findings_by_path: dict[str, list[Finding]] = {}
    for finding in store.all_findings():
        findings_by_path.setdefault(finding.path, []).append(finding)

    results: list[CodeHitWithFindings] = []
    for hit in code_hits:
        matched = [
            f
            for f in findings_by_path.get(hit.path, [])
            if f.start_line <= hit.end_line and f.end_line >= hit.start_line
        ]
        max_severity = (
            max(matched, key=lambda f: _SEVERITY_RANK[f.severity]).severity
            if matched
            else None
        )
        results.append(
            CodeHitWithFindings(
                path=hit.path,
                start_line=hit.start_line,
                end_line=hit.end_line,
                score=hit.score,
                content=hit.content,
                findings=[_finding_to_ref(f) for f in matched],
                max_severity=max_severity,
            )
        )
    return results
