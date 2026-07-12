"""Recherche de code (via `ccc`) enrichie des findings Semgrep indexés.

C'est le comportement « sur-ensemble de ccc » exposé à la fois par la CLI
(`cccf search`) et par le tool MCP `search_code_with_findings` : mêmes
résultats que `ccc search`, annotés des findings qui les chevauchent et
classés en tenant compte de leur sévérité.
"""

from pathlib import Path
from typing import TypedDict

from cccf.ccc_bridge import (
    CccUnavailable,
    CodeHit,
    CodeHitWithFindings,
    annotate_with_findings,
    overfetch_limit,
    rank_by_severity,
    search_code,
    without_findings,
)
from cccf.coco_indexer import ENGINE_META_VALUE
from cccf.config import ConfigError, load_config
from cccf.embedder import make_embedder
from cccf.render import FindingHit, render_search_json
from cccf.search import search_findings
from cccf.store import Store

WARNING_CCC_UNAVAILABLE = "ccc indisponible : recherche restreinte aux findings Semgrep"
WARNING_NO_FINDINGS_INDEX = (
    "index findings absent (lancez: cccf index) : résultats sans findings"
)
ERROR_NOTHING_AVAILABLE = "Index absent. Lancez d'abord: cccf index"


class CodeSearchResult(TypedDict):
    """Shape returned by `cccf search --json` and `search_code_with_findings`.

    A single stable schema for every case — nominal, ccc unreachable
    (`results` empty, `findings_only_fallback` populated), findings index
    missing (`results` without findings) — so structured output stays valid
    in all branches, `warning` telling the caller which degraded mode applies.
    """

    results: list[CodeHitWithFindings]
    findings_only_fallback: list[FindingHit]
    warning: str | None


def _has_findings_index(repo_root: Path) -> bool:
    return (repo_root / ".cccf" / "findings.db").is_file()


def _search_indexed_code(
    store: Store, embedder: object, query: str, limit: int
) -> list[CodeHit]:
    if store.get_meta("index_engine") != ENGINE_META_VALUE:
        return []
    if store.code_chunk_embedding_count() == 0:
        return []
    query_vec = embedder.embed_query(query)
    return [
        CodeHit(
            path=chunk.path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            language=chunk.language,
            score=score,
            content=chunk.content,
        )
        for chunk, score in store.knn_search_code_chunks(query_vec, top_k=overfetch_limit(limit))
    ]


def search_code_with_findings(
    repo_root: Path, query: str, limit: int = 5
) -> CodeSearchResult:
    """Recherche `ccc search` + annotation findings + classement par sévérité.

    Dégradations (jamais les deux surfaces en panne sans erreur claire) :
    - `ccc` indisponible → recherche dans les findings seuls (nécessite
      l'index `cccf`, sinon RuntimeError).
    - index findings absent → résultats `ccc` bruts, sans annotation.
    """
    if _has_findings_index(repo_root):
        try:
            config = load_config(repo_root)
        except ConfigError:
            config = None
        if config is not None:
            embedder = make_embedder(config.embedding_model)
            with Store(repo_root) as store:
                indexed_hits = _search_indexed_code(store, embedder, query, limit)
                if indexed_hits:
                    annotated = annotate_with_findings(indexed_hits, store)
                    ranked = rank_by_severity(annotated, limit)
                    return CodeSearchResult(
                        results=ranked,
                        findings_only_fallback=[],
                        warning=None,
                    )

    try:
        # Sur-demande à ccc : le classement par sévérité a besoin de plus de
        # candidats que `limit` pour pouvoir faire remonter un résultat
        # légèrement moins pertinent sémantiquement mais porteur d'un finding.
        code_hits = search_code(repo_root, query, overfetch_limit(limit))
    except CccUnavailable:
        if not _has_findings_index(repo_root):
            raise RuntimeError(ERROR_NOTHING_AVAILABLE) from None
        config = load_config(repo_root)
        embedder = make_embedder(config.embedding_model)
        with Store(repo_root) as store:
            hits = search_findings(store, embedder, query, limit=limit)
            fallback = render_search_json(hits, repo_root, include_context=False)
        return CodeSearchResult(
            results=[],
            findings_only_fallback=fallback,
            warning=WARNING_CCC_UNAVAILABLE,
        )

    if not _has_findings_index(repo_root):
        annotated = without_findings(code_hits)
        warning: str | None = WARNING_NO_FINDINGS_INDEX
    else:
        with Store(repo_root) as store:
            annotated = annotate_with_findings(code_hits, store)
        warning = None

    ranked = rank_by_severity(annotated, limit)
    return CodeSearchResult(results=ranked, findings_only_fallback=[], warning=warning)
