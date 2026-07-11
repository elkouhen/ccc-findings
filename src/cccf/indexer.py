import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

from cccf.config import Config
from cccf.embedder import finding_to_text
from cccf.models import Finding
from cccf.scanner import run_semgrep
from cccf.store import Store


class EmbedderLike(Protocol):
    def embed_texts(self, texts: list[str]) -> np.ndarray: ...


@dataclass
class IndexReport:
    scanned: int
    skipped: int
    findings_added: int
    findings_removed: int
    deleted_files: int


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _matches_any(rel_path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


def _list_repo_files(repo_root: Path, config: Config) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(repo_root).as_posix()
        if config.exclude and _matches_any(rel_path, config.exclude):
            continue
        if config.include and not _matches_any(rel_path, config.include):
            continue
        hashes[rel_path] = _sha256_file(path)
    return hashes


def _embed_findings(embedder: EmbedderLike, store: Store, findings: list[Finding]) -> None:
    if not findings:
        return
    vectors = embedder.embed_texts([finding_to_text(f) for f in findings])
    for finding, vector in zip(findings, vectors, strict=True):
        store.set_embedding(finding.id, vector)


def index_repo(
    repo_root: Path,
    config: Config,
    store: Store,
    embedder: EmbedderLike,
    full: bool = False,
) -> IndexReport:
    current_hashes = _list_repo_files(repo_root, config)
    previous_hashes = store.get_file_hashes()

    current_paths = set(current_hashes)
    previous_paths = set(previous_hashes)

    deleted = sorted(previous_paths - current_paths)

    if full:
        changed = sorted(current_paths)
    else:
        added = current_paths - previous_paths
        modified = {
            p
            for p in current_paths & previous_paths
            if current_hashes[p] != previous_hashes[p]
        }
        changed = sorted(added | modified)
    unchanged = current_paths - set(changed)

    findings_removed = sum(len(store.all_findings(path_glob=p)) for p in deleted)
    store.remove_files(deleted)

    findings_added = 0
    findings: list[Finding] = []
    if changed:
        findings_removed += sum(len(store.all_findings(path_glob=p)) for p in changed)

        findings = run_semgrep(repo_root, config, files=changed)
        store.replace_findings_for_files(changed, findings)
        findings_added = len(findings)

        for path in changed:
            store.set_file_hash(path, current_hashes[path])

    if store.get_meta("embedding_model") != config.embedding_model:
        _embed_findings(embedder, store, store.all_findings())
        store.set_meta("embedding_model", config.embedding_model)
    else:
        embedded_ids = {finding_id for finding_id, _ in store.iter_embeddings()}
        _embed_findings(embedder, store, [f for f in findings if f.id not in embedded_ids])

    return IndexReport(
        scanned=len(changed),
        skipped=len(unchanged),
        findings_added=findings_added,
        findings_removed=findings_removed,
        deleted_files=len(deleted),
    )
