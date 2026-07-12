import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

from cccf.config import Config
from cccf.embedder import EmbeddingError, finding_to_text
from cccf.models import Finding
from cccf.scanner import run_semgrep
from cccf.store import CodeChunk, Store


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
    return any(pattern == "**/*" or fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


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


def _embedder_signature(embedder: EmbedderLike, config: Config) -> str:
    return str(getattr(embedder, "signature", config.embedding_model))


def _embed_findings(
    embedder: EmbedderLike, store: Store, findings: list[Finding]
) -> int | None:
    if not findings:
        return None
    vectors = embedder.embed_texts([finding_to_text(f) for f in findings])
    dim = int(vectors.shape[1]) if vectors.ndim == 2 else int(vectors.shape[0])
    stored_dim = store.get_embedding_dim()
    if stored_dim is not None and stored_dim != dim:
        raise EmbeddingError(
            f"Dimension d'embedding incompatible : index={stored_dim}, nouveau={dim}. "
            "Relancez un ré-embedding complet."
        )
    for finding, vector in zip(findings, vectors, strict=True):
        store.set_embedding(finding.id, vector)
    return dim


_LANG_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".md": "markdown",
    ".mdx": "markdown",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
}


def _detect_language(path: str) -> str:
    return _LANG_BY_SUFFIX.get(Path(path).suffix.lower(), "text")


def _chunk_code_file(repo_root: Path, rel_path: str, max_lines: int = 80) -> list[CodeChunk]:
    path = repo_root / rel_path
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if not lines:
        return []
    chunks: list[CodeChunk] = []
    language = _detect_language(rel_path)
    for start_idx in range(0, len(lines), max_lines):
        chunk_lines = lines[start_idx : start_idx + max_lines]
        start_line = start_idx + 1
        end_line = start_idx + len(chunk_lines)
        content = "\n".join(chunk_lines)
        digest = hashlib.sha256(
            f"{rel_path}|{start_line}:{end_line}|{content}".encode()
        ).hexdigest()[:16]
        chunks.append(
            CodeChunk(
                id=digest,
                path=rel_path,
                start_line=start_line,
                end_line=end_line,
                language=language,
                content=content,
            )
        )
    return chunks


def _embed_code_chunks(
    embedder: EmbedderLike, store: Store, chunks: list[CodeChunk]
) -> int | None:
    if not chunks:
        return None
    vectors = embedder.embed_texts([chunk.content for chunk in chunks])
    dim = int(vectors.shape[1]) if vectors.ndim == 2 else int(vectors.shape[0])
    for chunk, vector in zip(chunks, vectors, strict=True):
        store.set_code_chunk_embedding(chunk.id, vector)
    return dim


def index_repo(
    repo_root: Path,
    config: Config,
    store: Store,
    embedder: EmbedderLike,
    full: bool = False,
    index_code_chunks: bool = False,
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

    if index_code_chunks:
        chunk_paths = changed
        if not chunk_paths and store.code_chunk_embedding_count() == 0:
            chunk_paths = sorted(current_paths)
        if chunk_paths:
            chunks = [
                chunk
                for path in chunk_paths
                for chunk in _chunk_code_file(repo_root, path)
            ]
            store.replace_code_chunks_for_files(chunk_paths, chunks)
            _embed_code_chunks(embedder, store, chunks)

    signature = _embedder_signature(embedder, config)
    if store.get_meta("embedding_signature") != signature:
        store.set_meta("embedding_signature", signature)
        store.set_meta("embedding_model", config.embedding_model)
        store.set_meta("embedding_dim", "")
        dim = _embed_findings(embedder, store, store.all_findings())
        if dim is not None:
            store.set_meta("embedding_dim", str(dim))
    else:
        embedded_ids = {finding_id for finding_id, _ in store.iter_embeddings()}
        dim = _embed_findings(
            embedder, store, [f for f in findings if f.id not in embedded_ids]
        )
        if dim is not None and store.get_meta("embedding_dim") != str(dim):
            store.set_meta("embedding_dim", str(dim))

    return IndexReport(
        scanned=len(changed),
        skipped=len(unchanged),
        findings_added=findings_added,
        findings_removed=findings_removed,
        deleted_files=len(deleted),
    )
