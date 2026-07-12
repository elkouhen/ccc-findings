from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

from cccf.embedder import EmbeddingError
from cccf.models import Finding
from cccf.store import Store


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
            f"requête={query_signature}. Relancez: cccf index --full"
        )

    query_vec = embedder.embed_query(query)
    stored_dim = store.get_embedding_dim()
    if stored_dim is not None and query_vec.shape[0] != stored_dim:
        raise EmbeddingError(
            f"Dimension d'embedding incompatible : index={stored_dim}, "
            f"requête={query_vec.shape[0]}. Relancez: cccf index --full"
        )

    total_vectors = store.embedding_count()
    if total_vectors == 0:
        return []

    by_id = {finding.id: finding for finding in candidates}
    hits: list[SearchHit] = []
    for finding_id, score in store.knn_search(query_vec, top_k=total_vectors):
        finding = by_id.get(finding_id)
        if finding is None:
            continue
        hits.append(SearchHit(finding=finding, score=score))
        if len(hits) >= offset + limit:
            break
    return hits[offset : offset + limit]


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
