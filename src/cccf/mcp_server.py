from pathlib import Path
from typing import TypedDict

from mcp.server.fastmcp import FastMCP

from cccf.ccc_bridge import CccUnavailable, CodeHitWithFindings, annotate_with_findings, search_code
from cccf.config import load_config
from cccf.embedder import make_embedder
from cccf.indexer import IndexReport, index_repo
from cccf.render import FindingHit, FindingsSummary, render_search_json, render_summary_json
from cccf.search import search_findings as run_search_findings
from cccf.search import summary as compute_summary
from cccf.store import Store

mcp = FastMCP("cccf")


class CodeSearchResult(TypedDict):
    """Shape returned by `search_code_with_findings`.

    `results` is empty and `findings_only_fallback` populated when `ccc` is
    unreachable — a single stable schema instead of two differently-shaped
    payloads, so structured output stays valid either way.
    """

    results: list[CodeHitWithFindings]
    findings_only_fallback: list[FindingHit]
    warning: str | None


def _repo_root() -> Path:
    return Path.cwd()


def _require_index(repo_root: Path) -> None:
    if not (repo_root / ".cccf" / "findings.db").is_file():
        raise RuntimeError("Index absent. Lancez d'abord: cccf index")


@mcp.tool()
def search_findings(
    query: str,
    severity: str | None = None,
    rule: str | None = None,
    path_glob: str | None = None,
    limit: int = 5,
    include_context: bool = False,
) -> list[FindingHit]:
    """Recherche en langage naturel dans les findings Semgrep indexés du repo.
    Utiliser AVANT de modifier du code pour connaître les problèmes connus,
    et pour localiser des vulnérabilités par description.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    config = load_config(repo_root)
    embedder = make_embedder(config.embedding_model)

    with Store(repo_root) as store:
        hits = run_search_findings(
            store,
            embedder,
            query,
            severity=severity,
            rule=rule,
            path_glob=path_glob,
            limit=limit,
        )
        return render_search_json(hits, repo_root, include_context)


@mcp.tool()
def findings_summary() -> FindingsSummary:
    """Vue agrégée des findings (sévérités, top règles).
    Utiliser pour une vue d'ensemble à faible coût.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    with Store(repo_root) as store:
        result = compute_summary(store)
    return render_summary_json(result)


@mcp.tool()
def reindex_findings() -> IndexReport:
    """Met à jour l'index des findings après modification de fichiers.
    Appeler après un patch pour vérifier la disparition d'un finding.
    """
    repo_root = _repo_root()
    config = load_config(repo_root)
    embedder = make_embedder(config.embedding_model)
    with Store(repo_root) as store:
        return index_repo(repo_root, config, store, embedder)


@mcp.tool()
def search_code_with_findings(query: str, limit: int = 5) -> CodeSearchResult:
    """Recherche sémantique de code (via ccc) annotée des findings Semgrep connus
    sur chaque résultat. Outil à privilégier pour explorer du code en tenant
    compte de sa dette sécurité.
    """
    repo_root = _repo_root()
    try:
        code_hits = search_code(repo_root, query, limit)
    except CccUnavailable:
        _require_index(repo_root)
        config = load_config(repo_root)
        embedder = make_embedder(config.embedding_model)
        with Store(repo_root) as store:
            hits = run_search_findings(store, embedder, query, limit=limit)
            fallback = render_search_json(hits, repo_root, include_context=False)
        return CodeSearchResult(
            results=[],
            findings_only_fallback=fallback,
            warning="ccc indisponible : recherche restreinte aux findings Semgrep",
        )

    with Store(repo_root) as store:
        annotated = annotate_with_findings(code_hits, store)
    return CodeSearchResult(results=annotated, findings_only_fallback=[], warning=None)
