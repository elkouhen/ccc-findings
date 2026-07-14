import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

from ccc_radar.models import Finding
from ccc_radar.store import Store

_SEVERITY_RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}

# Additive ranking boost for search_code_with_findings: small relative to the
# typical spread of ccc's semantic scores, so it reorders close calls (a
# borderline-relevant chunk with a critical finding overtakes a
# slightly-more-relevant, finding-free one) without burying clearly more
# relevant results under a distant one that merely shares a risky line.
_SEVERITY_BOOST: dict[str | None, float] = {
    None: 0.0,
    "INFO": 0.0,
    "WARNING": 0.05,
    "ERROR": 0.15,
}

# ccc truncates to --limit before cccr ever sees the results, so a relevant
# hit just outside the top N would never be considered for the severity
# boost. Over-fetch, boost, re-sort, then truncate to the caller's limit.
_OVERFETCH_FACTOR = 3
_OVERFETCH_CAP = 50
_CCC_INDEX_PATH = Path(".cocoindex_code") / "target_sqlite.db"
_DEFAULT_CCC_SEARCH_TIMEOUT_S = 20


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
    """Shape returned by `cccr search` (--json) and the `search_code_with_findings` MCP tool."""

    path: str
    start_line: int
    end_line: int
    language: str
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
_FILE_LINE_RE = re.compile(r"^File: (.+):(\d+)-(\d+) \[([^\]]*)\]$")


class CccUnavailable(Exception):
    pass


@dataclass
class CodeHit:
    path: str
    start_line: int
    end_line: int
    language: str
    score: float
    content: str


def _ccc_search_timeout_s() -> int:
    raw = os.environ.get("CCCR_CCC_SEARCH_TIMEOUT_S")
    if raw is None:
        return _DEFAULT_CCC_SEARCH_TIMEOUT_S
    try:
        timeout_s = int(raw)
    except ValueError:
        return _DEFAULT_CCC_SEARCH_TIMEOUT_S
    return timeout_s if timeout_s > 0 else _DEFAULT_CCC_SEARCH_TIMEOUT_S


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
                language=file_match.group(4),
                score=float(header_match.group(1)),
                content="\n".join(lines[2:]),
            )
        )
    return hits


def overfetch_limit(limit: int) -> int:
    return min(limit * _OVERFETCH_FACTOR, _OVERFETCH_CAP)


def search_code(
    repo_root: Path,
    query: str,
    limit: int = 5,
    offset: int = 0,
    lang: str | None = None,
    path: str | None = None,
    refresh: bool = False,
) -> list[CodeHit]:
    cmd = ["ccc", "search", query, "--limit", str(limit)]
    if offset:
        cmd += ["--offset", str(offset)]
    if lang:
        cmd += ["--lang", lang]
    if path:
        cmd += ["--path", path]
    if refresh:
        cmd.append("--refresh")

    if shutil.which("ccc") is None:
        raise CccUnavailable("ccc introuvable dans le PATH")
    if not refresh and not (repo_root / _CCC_INDEX_PATH).is_file():
        raise CccUnavailable(
            "index code ccc absent (.cocoindex_code/target_sqlite.db). "
            "Lancez d'abord: ccc index"
        )

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
            timeout=_ccc_search_timeout_s(),
        )
    except subprocess.TimeoutExpired as exc:
        raise CccUnavailable(
            f"ccc search a expiré après {_ccc_search_timeout_s()}s"
        ) from exc

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
    if not code_hits:
        return []
    findings_by_path: dict[str, list[Finding]] = {}
    for finding in store.all_findings_for_paths(sorted({hit.path for hit in code_hits})):
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
                language=hit.language,
                score=hit.score,
                content=hit.content,
                findings=[_finding_to_ref(f) for f in matched],
                max_severity=max_severity,
            )
        )
    return results


def without_findings(code_hits: list[CodeHit]) -> list[CodeHitWithFindings]:
    """Wrap raw ccc hits when no findings index exists to join against."""
    return [
        CodeHitWithFindings(
            path=hit.path,
            start_line=hit.start_line,
            end_line=hit.end_line,
            language=hit.language,
            score=hit.score,
            content=hit.content,
            findings=[],
            max_severity=None,
        )
        for hit in code_hits
    ]


def rank_by_severity(
    hits: list[CodeHitWithFindings], limit: int
) -> list[CodeHitWithFindings]:
    """Re-rank ccc's semantic order, boosting hits that carry a known finding.

    `score` is left untouched — it still reports ccc's raw semantic
    similarity. Only the ordering (and truncation to `limit`) accounts for
    severity; ties keep ccc's original relative order (stable sort).
    """
    ranked = sorted(
        hits,
        key=lambda hit: hit["score"] + _SEVERITY_BOOST[hit["max_severity"]],
        reverse=True,
    )
    return ranked[:limit]
