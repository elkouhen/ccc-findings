"""Résultats de `ccc search`, complétés par les findings indexés.

La recherche et son classement restent intégralement ceux de `ccc`; `cccr`
ne fait qu'ajouter les findings de la classe/fichier retourné.
"""

from pathlib import Path
from typing import TypedDict

from ccc_radar.ccc_bridge import (
    CccUnavailable,
    CodeHitWithFindings,
    annotate_with_findings,
    search_code,
    without_findings,
)
from ccc_radar.paths import db_path
from ccc_radar.render import FindingHit
from ccc_radar.store import Store

WARNING_NO_FINDINGS_INDEX = (
    "index findings absent (lancez: cccr index) : résultats sans findings"
)


class CodeSearchResult(TypedDict):
    """Shape returned by `cccr search --json` and the MCP tool `search`.

    A single stable schema for nominal results and findings-index-missing
    degraded mode (`results` without findings), `warning` telling the caller
    which degraded mode applies. If the underlying `ccc` command fails, the
    function raises instead of returning a success-shaped fallback.
    """

    results: list[CodeHitWithFindings]
    findings_only_fallback: list[FindingHit]
    warning: str | None


def _has_findings_index(repo_root: Path) -> bool:
    return db_path(repo_root).is_file()


def search_code_with_findings(
    repo_root: Path,
    query: str,
    limit: int = 5,
    offset: int = 0,
    lang: str | None = None,
    path: str | None = None,
    refresh: bool = False,
) -> CodeSearchResult:
    """Recherche `ccc search` et annote sans modifier ses résultats.

    Tous les paramètres sont transmis tels quels à `ccc`, dont `limit`,
    `offset`, filtres et `refresh`. L'ordre, les scores et les extraits de
    `ccc` sont conservés.

    Dégradations :
    - `ccc` indisponible ou en erreur → RuntimeError.
    - index findings absent → résultats `ccc` bruts, sans annotation.
    """
    try:
        code_hits = search_code(
            repo_root,
            query,
            limit,
            offset=offset,
            lang=lang,
            path=path,
            refresh=refresh,
        )
    except CccUnavailable as exc:
        raise RuntimeError(str(exc)) from exc

    if not _has_findings_index(repo_root):
        annotated = without_findings(code_hits)
        warning: str | None = WARNING_NO_FINDINGS_INDEX
    else:
        with Store(repo_root) as store:
            annotated = annotate_with_findings(code_hits, store)
        warning = None

    return CodeSearchResult(results=annotated, findings_only_fallback=[], warning=warning)
