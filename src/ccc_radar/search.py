from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import re

import numpy as np

from ccc_radar.config import VALID_SEVERITIES
from ccc_radar.embedder import EmbeddingError
from ccc_radar.models import Finding
from ccc_radar.store import Store

_KNN_OVERFETCH_FACTOR = 3
_KNN_MIN_FETCH = 20
_HYBRID_RESULT_WINDOW_FACTOR = 5
_RRF_K = 60
_WORD_RE = re.compile(r"\w+")


class SearchError(Exception):
    """Paramètre de recherche invalide (BACKLOG-16 P4) — distinct
    d'`EmbeddingError` (incompatibilité de modèle/dimension) : ici la
    requête elle-même est mal formée, indépendamment de l'index."""


class EmbedderLike(Protocol):
    def embed_query(self, text: str) -> np.ndarray: ...


@dataclass
class SearchHit:
    finding: Finding
    score: float


@dataclass
class Summary:
    by_severity: dict[str, int]
    top_rules: list[tuple[str, int]]
    by_top_level_dir: dict[str, int]


def _tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.casefold())


def _normalize_for_match(text: str) -> str:
    return " ".join(_tokenize(text))


def _severity_rank(severity: str) -> int:
    return VALID_SEVERITIES.index(severity)


def _finding_sort_key(finding: Finding) -> tuple[int, str, int, int, str]:
    return (-_severity_rank(finding.severity), finding.path, finding.start_line, finding.end_line, finding.id)


def _keyword_fields(finding: Finding) -> list[tuple[str, float]]:
    return [
        (finding.rule_id, 6.0),
        (finding.message, 4.0),
        (finding.path, 3.0),
        (" ".join(finding.cwe), 5.0),
        (" ".join(finding.owasp), 5.0),
        (finding.snippet, 2.0),
        (finding.severity, 1.0),
    ]


def _keyword_score(finding: Finding, query: str) -> float:
    query_casefold = query.strip().casefold()
    query_tokens = set(_tokenize(query))
    normalized_query = _normalize_for_match(query)
    if not query_casefold and not query_tokens:
        return 0.0

    score = 0.0
    for value, weight in _keyword_fields(finding):
        if not value:
            continue
        raw_value = value.casefold()
        normalized_value = _normalize_for_match(value)
        if query_casefold:
            if raw_value == query_casefold:
                score += weight * 8.0
            elif query_casefold in raw_value:
                score += weight * 4.0
        if normalized_query:
            if normalized_value == normalized_query:
                score += weight * 6.0
            elif normalized_query in normalized_value:
                score += weight * 3.0
        if query_tokens:
            field_tokens = set(_tokenize(value))
            score += weight * sum(1.0 for token in query_tokens if token in field_tokens)
    return score


def _keyword_hits(candidates: list[Finding], query: str) -> list[SearchHit]:
    hits = [
        SearchHit(finding=finding, score=score)
        for finding in candidates
        if (score := _keyword_score(finding, query)) > 0.0
    ]
    hits.sort(key=lambda hit: (-hit.score, *_finding_sort_key(hit.finding)))
    return hits


def _semantic_hits(
    store: Store,
    embedder: EmbedderLike,
    candidates: list[Finding],
    query: str,
    requested: int,
) -> list[SearchHit]:
    total_vectors = store.embedding_count()
    if total_vectors == 0:
        return []

    query_vec = embedder.embed_query(query)
    stored_dim = store.get_embedding_dim()
    if stored_dim is not None and query_vec.shape[0] != stored_dim:
        raise EmbeddingError(
            f"Dimension d'embedding incompatible : index={stored_dim}, "
            f"requête={query_vec.shape[0]}. Relancez: cccr index --full"
        )

    by_id = {finding.id: finding for finding in candidates}
    semantic_needed = min(
        len(by_id),
        max(requested * _HYBRID_RESULT_WINDOW_FACTOR, _KNN_MIN_FETCH),
    )
    fetch_k = min(total_vectors, max(requested * _KNN_OVERFETCH_FACTOR, _KNN_MIN_FETCH))

    while True:
        hits: list[SearchHit] = []
        for finding_id, score in store.knn_search(query_vec, top_k=fetch_k):
            finding = by_id.get(finding_id)
            if finding is None:
                continue
            hits.append(SearchHit(finding=finding, score=score))
            if len(hits) >= semantic_needed:
                return hits
        if fetch_k >= total_vectors:
            return hits
        next_fetch_k = min(total_vectors, max(fetch_k * 2, requested))
        if next_fetch_k == fetch_k:
            return hits
        fetch_k = next_fetch_k


def _hybrid_hits(
    candidates: list[Finding],
    semantic_hits: list[SearchHit],
    keyword_hits: list[SearchHit],
    limit: int,
    offset: int,
) -> list[SearchHit]:
    semantic_rank = {hit.finding.id: index for index, hit in enumerate(semantic_hits, start=1)}
    semantic_score = {hit.finding.id: hit.score for hit in semantic_hits}
    keyword_rank = {hit.finding.id: index for index, hit in enumerate(keyword_hits, start=1)}
    keyword_score = {hit.finding.id: hit.score for hit in keyword_hits}
    by_id = {finding.id: finding for finding in candidates}

    ranked_ids = set(semantic_rank) | set(keyword_rank)
    ranked = []
    for finding_id in ranked_ids:
        fused_score = 0.0
        if finding_id in semantic_rank:
            fused_score += 1.0 / (_RRF_K + semantic_rank[finding_id])
        if finding_id in keyword_rank:
            fused_score += 1.0 / (_RRF_K + keyword_rank[finding_id])
        ranked.append(
            (
                fused_score,
                semantic_score.get(finding_id, 0.0),
                keyword_score.get(finding_id, 0.0),
                by_id[finding_id],
            )
        )

    ranked.sort(
        key=lambda item: (-item[0], -item[1], -item[2], *_finding_sort_key(item[3]))
    )
    return [
        SearchHit(finding=finding, score=fused_score)
        for fused_score, _, _, finding in ranked[offset : offset + limit]
    ]


def search_findings(
    store: Store,
    embedder: EmbedderLike,
    query: str,
    severity: str | None = None,
    rule: str | None = None,
    path_glob: str | None = None,
    limit: int = 5,
    offset: int = 0,
) -> list[SearchHit]:
    if severity is not None and severity not in VALID_SEVERITIES:
        raise SearchError(
            f"Sévérité invalide : {severity!r}. Valeurs autorisées : {VALID_SEVERITIES}."
        )

    candidates = store.all_findings(
        severity_at_least=severity, rule_id=rule, path_glob=path_glob
    )
    if not candidates:
        return []

    stored_signature = store.get_meta("embedding_signature")
    query_signature = getattr(embedder, "signature", None)
    if stored_signature and query_signature and stored_signature != query_signature:
        raise EmbeddingError(
            f"Signature d'embedding incompatible : index={stored_signature}, "
            f"requête={query_signature}. Relancez: cccr index --full"
        )

    requested = offset + limit
    semantic_hits = _semantic_hits(store, embedder, candidates, query, requested)
    keyword_hits = _keyword_hits(candidates, query)
    return _hybrid_hits(candidates, semantic_hits, keyword_hits, limit=limit, offset=offset)


def summary(store: Store) -> Summary:
    by_severity = store.counts_by("severity")
    rule_counts = store.counts_by("rule_id")
    top_rules = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]

    dir_counts: dict[str, int] = {}
    for finding in store.all_findings():
        top_dir = finding.path.split("/", 1)[0]
        dir_counts[top_dir] = dir_counts.get(top_dir, 0) + 1

    return Summary(by_severity=by_severity, top_rules=top_rules, by_top_level_dir=dir_counts)


def get_context(repo_root: Path, finding: Finding, before: int = 5, after: int = 5) -> str:
    lines = (repo_root / finding.path).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines()
    start_line = max(finding.start_line - before, 1)
    end_line = min(finding.end_line + after, len(lines))
    return "\n".join(f"{n:>5}| {lines[n - 1]}" for n in range(start_line, end_line + 1))
