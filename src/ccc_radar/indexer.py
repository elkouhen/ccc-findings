import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import numpy as np

from ccc_radar.config import Config
from ccc_radar.embedder import EmbeddingError, endpoint_to_text, finding_to_text
from ccc_radar.models import Finding, MessageEndpoint
from ccc_radar.scanner import (
    SEVERITY_ORDER,
    clear_analysis_caches,
    invoke_semgrep_raw,
    parse_semgrep_endpoints,
    parse_semgrep_json,
)
from ccc_radar.store import CodeChunk, Store


class EmbedderLike(Protocol):
    def embed_texts(self, texts: list[str]) -> np.ndarray: ...


@dataclass
class IndexReport:
    scanned: int
    skipped: int
    findings_added: int
    findings_removed: int
    deleted_files: int
    endpoints_added: int = 0
    endpoints_removed: int = 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matches_any(rel_path: str, patterns: list[str]) -> bool:
    return any(pattern == "**/*" or fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


def _is_maven_or_gradle_test_source_set(source_set: str) -> bool:
    """`main` est le seul nom de source set universel en Maven/Gradle ;
    ses variants de test suivent tous la convention `test` ou
    `<prefixe>Test` (`componentTest`, `contractTest`, `endToEndTest`, ...).
    BACKLOG-16 P1 : restreint `_is_test_source` à cette convention, plutôt
    qu'à « tout ce qui suit `src/` et n'est pas `main` » — cette dernière
    règle confondait n'importe quel layout `src/<package>` (Python, JS,
    Rust, y compris ce projet lui-même) avec un jeu de sources de test."""
    return source_set == "test" or source_set.endswith("Test")


def _is_test_source(rel_path: str) -> bool:
    """BACKLOG-15 H2 (ADR-34) : tout fichier sous un dossier `src/<jeu-de-
    sources>` où `<jeu-de-sources>` suit la convention Maven/Gradle de
    nommage des source sets de test (voir
    `_is_maven_or_gradle_test_source_set`) est exclu du scan, findings et
    endpoints confondus. Décision explicite qui revient sur BACKLOG-2 R2/
    ADR-14 (« ne jamais exclure silencieusement les tests ») — voir ADR-34.
    Basé sur les segments du chemin, pas un pattern glob : un `fnmatch`
    avec `*` ne respecte pas les frontières de répertoire et confondrait un
    paquet nommé `testutils` sous `src/main/...` avec un vrai jeu de
    sources de test."""
    segments = rel_path.split("/")
    return any(
        segment == "src"
        and i + 1 < len(segments)
        and _is_maven_or_gradle_test_source_set(segments[i + 1])
        for i, segment in enumerate(segments)
    )


def _list_repo_files(repo_root: Path, config: Config) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        rel_path = path.relative_to(repo_root).as_posix()
        if _is_test_source(rel_path):
            continue
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


def _embed_endpoints(
    embedder: EmbedderLike, store: Store, endpoints: list[MessageEndpoint]
) -> int | None:
    if not endpoints:
        return None
    vectors = embedder.embed_texts([endpoint_to_text(e) for e in endpoints])
    dim = int(vectors.shape[1]) if vectors.ndim == 2 else int(vectors.shape[0])
    for endpoint, vector in zip(endpoints, vectors, strict=True):
        store.set_endpoint_embedding(endpoint.id, vector)
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
    # BACKLOG-16 P2 : purge les lru_cache d'analyse best-effort (package
    # Java, propriétés Spring, module Maven/Gradle) avant de relire le
    # repo — nécessaire dans un process long-vivant (serveur MCP) où
    # `reindex_findings` doit voir les fichiers tels qu'ils sont maintenant,
    # pas tels qu'un `cccr index` précédent les avait mémorisés.
    clear_analysis_caches()

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

    findings_removed = store.count_findings_for_paths(deleted)
    endpoints_removed = store.count_endpoints_for_paths(deleted)
    store.remove_files(deleted)  # purge aussi les endpoints (K1)

    findings_added = 0
    endpoints_added = 0
    findings: list[Finding] = []
    endpoints: list[MessageEndpoint] = []
    if changed:
        findings_removed += store.count_findings_for_paths(changed)
        endpoints_removed += store.count_endpoints_for_paths(changed)

        # Un seul scan Semgrep pour findings (K8/`default`) et règles
        # d'inventaire d'endpoints (K2/K11) mélangées dans config.rules ;
        # chaque parseur filtre ce qui le concerne sur la même sortie
        # (BACKLOG-11 A1) — pas de min_severity pour les endpoints (K8 CA2).
        raw = invoke_semgrep_raw(repo_root, config, files=changed)
        min_index = SEVERITY_ORDER.index(config.min_severity)
        findings = [
            f
            for f in parse_semgrep_json(raw, repo_root)
            if SEVERITY_ORDER.index(f.severity) >= min_index
        ]
        endpoints = parse_semgrep_endpoints(raw, repo_root)

        store.replace_findings_for_files(changed, findings)
        store.replace_endpoints_for_files(changed, endpoints)
        findings_added = len(findings)
        endpoints_added = len(endpoints)

        for path in changed:
            store.set_file_hash(path, current_hashes[path])

    if index_code_chunks:
        chunk_paths = changed
        if not chunk_paths and store.code_chunk_embedding_count() == 0:
            chunk_paths = sorted(current_paths)
        chunks: list[CodeChunk] = []
        if chunk_paths:
            chunks = [
                chunk
                for path in chunk_paths
                for chunk in _chunk_code_file(repo_root, path)
            ]
            store.replace_code_chunks_for_files(chunk_paths, chunks)

        # BACKLOG-16 P5 : contrairement aux findings/endpoints (voir le
        # bloc `embedding_signature` ci-dessous), les chunks n'étaient
        # jamais ré-embeddés qu'au changement de *dimension* — un
        # changement de modèle à dimension égale laissait silencieusement
        # des vecteurs de modèles différents dans `vec_code_chunks`.
        code_signature = _embedder_signature(embedder, config)
        if store.get_meta("code_embedding_signature") != code_signature:
            store.set_meta("code_embedding_signature", code_signature)
            _embed_code_chunks(embedder, store, store.all_code_chunks())
        elif chunks:
            _embed_code_chunks(embedder, store, chunks)

    signature = _embedder_signature(embedder, config)
    if store.get_meta("embedding_signature") != signature:
        store.set_meta("embedding_signature", signature)
        store.set_meta("embedding_model", config.embedding_model)
        store.set_meta("embedding_dim", "")
        dim = _embed_findings(embedder, store, store.all_findings())
        if dim is not None:
            store.set_meta("embedding_dim", str(dim))
        endpoint_dim = _embed_endpoints(embedder, store, store.all_endpoints())
        if endpoint_dim is not None:
            store.set_meta("endpoint_embedding_dim", str(endpoint_dim))
    else:
        embedded_ids = {finding_id for finding_id, _ in store.iter_embeddings()}
        dim = _embed_findings(
            embedder, store, [f for f in findings if f.id not in embedded_ids]
        )
        if dim is not None and store.get_meta("embedding_dim") != str(dim):
            store.set_meta("embedding_dim", str(dim))

        embedded_endpoint_ids = {
            endpoint_id for endpoint_id, _ in store.iter_endpoint_embeddings()
        }
        endpoint_dim = _embed_endpoints(
            embedder, store, [e for e in endpoints if e.id not in embedded_endpoint_ids]
        )
        if endpoint_dim is not None and store.get_meta("endpoint_embedding_dim") != str(
            endpoint_dim
        ):
            store.set_meta("endpoint_embedding_dim", str(endpoint_dim))

    return IndexReport(
        scanned=len(changed),
        skipped=len(unchanged),
        findings_added=findings_added,
        findings_removed=findings_removed,
        deleted_files=len(deleted),
        endpoints_added=endpoints_added,
        endpoints_removed=endpoints_removed,
    )
