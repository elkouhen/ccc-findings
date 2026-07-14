"""Recherche de code (via `ccc`) enrichie des findings Semgrep indexés.

C'est le comportement « sur-ensemble de ccc » exposé à la fois par la CLI
(`cccr search`) et par le tool MCP `search` : mêmes résultats et mêmes
paramètres que `ccc search`, annotés des findings qui les chevauchent et
classés en tenant compte de leur sévérité.
"""

from pathlib import Path
from typing import TypedDict

from ccc_radar.ccc_bridge import (
    CccUnavailable,
    CodeHit,
    CodeHitWithFindings,
    annotate_with_findings,
    overfetch_limit,
    rank_by_severity,
    search_code,
    without_findings,
)
from ccc_radar.coco_indexer import ENGINE_META_VALUE, index_repo_with_cocoindex
from ccc_radar.config import ConfigError, load_config
from ccc_radar.embedder import make_embedder
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


def _search_indexed_code(
    store: Store,
    embedder: object,
    query: str,
    limit: int,
    offset: int,
    lang: str | None,
    path: str | None,
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
        for chunk, score in store.knn_search_code_chunks(
            query_vec,
            top_k=overfetch_limit(limit),
            offset=offset,
            language=lang,
            path_glob=path,
        )
    ]


def search_code_with_findings(
    repo_root: Path,
    query: str,
    limit: int = 5,
    offset: int = 0,
    lang: str | None = None,
    path: str | None = None,
    refresh: bool = False,
) -> CodeSearchResult:
    """Recherche `ccc search` + annotation findings + classement par sévérité.

    Mêmes paramètres que `ccc search` (`--limit`, `--offset`, `--lang`,
    `--path`, `--refresh`) : sur l'index code expérimental (`--engine
    cocoindex`), `lang`/`path`/`offset` filtrent et paginent localement, et
    `refresh` réindexe (incrémental) avant de chercher ; sinon ils sont
    transmis tels quels au binaire `ccc`.

    Dégradations :
    - `ccc` indisponible ou en erreur → RuntimeError.
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
                if refresh and store.get_meta("index_engine") == ENGINE_META_VALUE:
                    index_repo_with_cocoindex(repo_root, config, store, embedder)
                indexed_hits = _search_indexed_code(
                    store, embedder, query, limit, offset, lang, path
                )
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
        code_hits = search_code(
            repo_root,
            query,
            overfetch_limit(limit),
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

    ranked = rank_by_severity(annotated, limit)
    return CodeSearchResult(results=ranked, findings_only_fallback=[], warning=warning)
