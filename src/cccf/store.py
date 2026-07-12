import fnmatch
import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

import numpy as np
import sqlite_vec

from cccf.models import Finding

SCHEMA_VERSION = "3"
SEVERITY_ORDER = ["INFO", "WARNING", "ERROR"]
_COUNTABLE_DIMENSIONS = ("rule_id", "severity")
_SQLITE_BIND_LIMIT = 900


def _chunked(items: list[str], size: int = _SQLITE_BIND_LIMIT) -> Iterator[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


@dataclass(frozen=True)
class CodeChunk:
    id: str
    path: str
    start_line: int
    end_line: int
    language: str
    content: str


class Store:
    def __init__(self, repo_root: Path) -> None:
        self._db_path = Path(repo_root) / ".cccf" / "findings.db"
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> "Store":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._load_vec_extension()
        self._create_schema()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self._conn is not None
        if exc_type is None:
            self._conn.commit()
        self._conn.close()
        self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        assert self._conn is not None, "Store doit être utilisé comme context manager"
        return self._conn

    def _load_vec_extension(self) -> None:
        self.conn.enable_load_extension(True)
        sqlite_vec.load(self.conn)
        self.conn.enable_load_extension(False)

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                indexed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                rule_id TEXT,
                severity TEXT,
                message TEXT,
                path TEXT,
                start_line INTEGER,
                end_line INTEGER,
                snippet TEXT,
                fix TEXT,
                cwe TEXT,
                owasp TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE TABLE IF NOT EXISTS code_chunks (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                language TEXT NOT NULL,
                content TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_code_chunks_path ON code_chunks(path);
            """
        )
        self._migrate_legacy_embeddings()
        if self.get_meta("schema_version") != SCHEMA_VERSION:
            self.set_meta("schema_version", SCHEMA_VERSION)
        self.conn.commit()

    def _migrate_legacy_embeddings(self) -> None:
        """Schema v1 stored embeddings as a BLOB column on `findings` (brute-force
        cosine in Python). v2 moves them to a `vec0` virtual table (sqlite-vec,
        SIMD-accelerated KNN) — same store ccc/cocoindex-code already uses for its
        own index. Dropping the old column forces a transparent full re-embed on
        the next `cccf index`, since embedding_signature no longer matches.
        """
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")}
        if "embedding" not in cols:
            return
        self.conn.execute("ALTER TABLE findings DROP COLUMN embedding")
        self.conn.execute(
            "DELETE FROM meta WHERE key IN ('embedding_signature', 'embedding_dim')"
        )
        self.set_meta("schema_version", SCHEMA_VERSION)

    # -- meta --

    def get_meta(self, key: str) -> str | None:
        cur = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def get_embedding_dim(self) -> int | None:
        raw = self.get_meta("embedding_dim")
        return int(raw) if raw else None

    # -- files --

    def set_file_hash(self, path: str, sha: str) -> None:
        self.conn.execute(
            "INSERT INTO files (path, sha256, indexed_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(path) DO UPDATE SET "
            "sha256 = excluded.sha256, indexed_at = excluded.indexed_at",
            (path, sha),
        )

    def get_file_hashes(self) -> dict[str, str]:
        cur = self.conn.execute("SELECT path, sha256 FROM files")
        return {row["path"]: row["sha256"] for row in cur.fetchall()}

    def remove_files(self, paths: list[str]) -> None:
        if not paths:
            return
        placeholders = ",".join("?" for _ in paths)
        self.conn.execute(f"DELETE FROM files WHERE path IN ({placeholders})", paths)
        removed_ids = self._finding_ids_for_paths(paths)
        self.conn.execute(f"DELETE FROM findings WHERE path IN ({placeholders})", paths)
        self._delete_embeddings(removed_ids)
        self.replace_code_chunks_for_files(paths, [])

    # -- findings --

    def _finding_ids_for_paths(self, paths: list[str]) -> list[str]:
        placeholders = ",".join("?" for _ in paths)
        cur = self.conn.execute(
            f"SELECT id FROM findings WHERE path IN ({placeholders})", paths
        )
        return [row["id"] for row in cur.fetchall()]

    def replace_findings_for_files(self, paths: list[str], findings: list[Finding]) -> None:
        if paths:
            removed_ids = self._finding_ids_for_paths(paths)
            placeholders = ",".join("?" for _ in paths)
            self.conn.execute(
                f"DELETE FROM findings WHERE path IN ({placeholders})", paths
            )
            self._delete_embeddings(removed_ids)
        for finding in findings:
            self.conn.execute(
                """
                INSERT INTO findings
                    (id, rule_id, severity, message, path, start_line, end_line,
                     snippet, fix, cwe, owasp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    severity = excluded.severity,
                    message = excluded.message,
                    path = excluded.path,
                    start_line = excluded.start_line,
                    end_line = excluded.end_line,
                    snippet = excluded.snippet,
                    fix = excluded.fix,
                    cwe = excluded.cwe,
                    owasp = excluded.owasp
                """,
                (
                    finding.id,
                    finding.rule_id,
                    finding.severity,
                    finding.message,
                    finding.path,
                    finding.start_line,
                    finding.end_line,
                    finding.snippet,
                    finding.fix,
                    json.dumps(finding.cwe),
                    json.dumps(finding.owasp),
                ),
            )

    # -- indexed code chunks (experimental CocoIndex-style target state) --

    def _code_chunk_ids_for_paths(self, paths: list[str]) -> list[str]:
        placeholders = ",".join("?" for _ in paths)
        cur = self.conn.execute(
            f"SELECT id FROM code_chunks WHERE path IN ({placeholders})", paths
        )
        return [row["id"] for row in cur.fetchall()]

    def replace_code_chunks_for_files(
        self, paths: list[str], chunks: list[CodeChunk]
    ) -> None:
        if paths:
            removed_ids = self._code_chunk_ids_for_paths(paths)
            placeholders = ",".join("?" for _ in paths)
            self.conn.execute(
                f"DELETE FROM code_chunks WHERE path IN ({placeholders})", paths
            )
            self._delete_code_chunk_embeddings(removed_ids)
        for chunk in chunks:
            self.conn.execute(
                """
                INSERT INTO code_chunks
                    (id, path, start_line, end_line, language, content)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    path = excluded.path,
                    start_line = excluded.start_line,
                    end_line = excluded.end_line,
                    language = excluded.language,
                    content = excluded.content
                """,
                (
                    chunk.id,
                    chunk.path,
                    chunk.start_line,
                    chunk.end_line,
                    chunk.language,
                    chunk.content,
                ),
            )

    def all_code_chunks(self) -> list[CodeChunk]:
        cur = self.conn.execute(
            "SELECT id, path, start_line, end_line, language, content FROM code_chunks"
        )
        return [_row_to_code_chunk(row) for row in cur.fetchall()]

    def all_findings(
        self,
        severity_at_least: str | None = None,
        rule_id: str | None = None,
        path_glob: str | None = None,
    ) -> list[Finding]:
        cur = self.conn.execute("SELECT * FROM findings")
        results = []
        for row in cur.fetchall():
            if severity_at_least and SEVERITY_ORDER.index(
                row["severity"]
            ) < SEVERITY_ORDER.index(severity_at_least):
                continue
            if rule_id and row["rule_id"] != rule_id:
                continue
            if path_glob and not fnmatch.fnmatch(row["path"], path_glob):
                continue
            results.append(_row_to_finding(row))
        return results

    # -- embeddings --
    #
    # Vectors live in `vec_findings`, a sqlite-vec `vec0` virtual table (same
    # extension ccc/cocoindex-code uses for its own `.cocoindex_code/target_sqlite.db`).
    # `embedding_dim` (in `meta`) doubles as "does the table exist, and at what
    # dimension" — vec0 tables can't ALTER, so a dimension change drops and
    # recreates it; that only happens on a full re-embed (model change), which
    # already touches every finding.

    def _ensure_vec_table(self, dim: int) -> None:
        if self.get_embedding_dim() == dim:
            return
        self.conn.execute("DROP TABLE IF EXISTS vec_findings")
        self.conn.execute(
            f"CREATE VIRTUAL TABLE vec_findings USING vec0("
            f"embedding float[{dim}] distance_metric=cosine, +finding_id TEXT)"
        )
        self.set_meta("embedding_dim", str(dim))

    def _ensure_code_vec_table(self, dim: int) -> None:
        raw_dim = self.get_meta("code_embedding_dim")
        if raw_dim and int(raw_dim) == dim:
            return
        self.conn.execute("DROP TABLE IF EXISTS vec_code_chunks")
        self.conn.execute(
            f"CREATE VIRTUAL TABLE vec_code_chunks USING vec0("
            f"embedding float[{dim}] distance_metric=cosine, +chunk_id TEXT)"
        )
        self.set_meta("code_embedding_dim", str(dim))

    def _delete_embeddings(self, finding_ids: list[str]) -> None:
        if not finding_ids or self.get_embedding_dim() is None:
            return
        for chunk in _chunked(finding_ids):
            placeholders = ",".join("?" for _ in chunk)
            self.conn.execute(
                f"DELETE FROM vec_findings WHERE finding_id IN ({placeholders})", chunk
            )

    def _delete_code_chunk_embeddings(self, chunk_ids: list[str]) -> None:
        if not chunk_ids or self.get_meta("code_embedding_dim") is None:
            return
        for chunk in _chunked(chunk_ids):
            placeholders = ",".join("?" for _ in chunk)
            self.conn.execute(
                f"DELETE FROM vec_code_chunks WHERE chunk_id IN ({placeholders})", chunk
            )

    def set_embedding(self, finding_id: str, vector: np.ndarray) -> None:
        vector = vector.astype(np.float32)
        self._ensure_vec_table(vector.shape[0])
        self.conn.execute("DELETE FROM vec_findings WHERE finding_id = ?", (finding_id,))
        self.conn.execute(
            "INSERT INTO vec_findings (embedding, finding_id) VALUES (?, ?)",
            (sqlite_vec.serialize_float32(vector.tolist()), finding_id),
        )

    def set_code_chunk_embedding(self, chunk_id: str, vector: np.ndarray) -> None:
        vector = vector.astype(np.float32)
        self._ensure_code_vec_table(vector.shape[0])
        self.conn.execute("DELETE FROM vec_code_chunks WHERE chunk_id = ?", (chunk_id,))
        self.conn.execute(
            "INSERT INTO vec_code_chunks (embedding, chunk_id) VALUES (?, ?)",
            (sqlite_vec.serialize_float32(vector.tolist()), chunk_id),
        )

    def iter_embeddings(self) -> Iterable[tuple[str, np.ndarray]]:
        if self.get_embedding_dim() is None:
            return
        cur = self.conn.execute("SELECT finding_id, embedding FROM vec_findings")
        for row in cur.fetchall():
            yield row["finding_id"], np.frombuffer(row["embedding"], dtype=np.float32)

    def embedding_count(self) -> int:
        if self.get_embedding_dim() is None:
            return 0
        return self.conn.execute("SELECT COUNT(*) AS c FROM vec_findings").fetchone()["c"]

    def code_chunk_embedding_count(self) -> int:
        if self.get_meta("code_embedding_dim") is None:
            return 0
        return self.conn.execute("SELECT COUNT(*) AS c FROM vec_code_chunks").fetchone()["c"]

    def knn_search(self, query_vec: np.ndarray, top_k: int) -> list[tuple[str, float]]:
        """Nearest neighbors by cosine similarity, best first.

        Returns (finding_id, score) pairs, score = 1 - cosine_distance so higher
        is more similar (matches the old brute-force dot-product convention).
        """
        if top_k <= 0 or self.get_embedding_dim() is None:
            return []
        query_blob = sqlite_vec.serialize_float32(query_vec.astype(np.float32).tolist())
        cur = self.conn.execute(
            "SELECT finding_id, distance FROM vec_findings "
            "WHERE embedding MATCH ? AND k = ? ORDER BY distance",
            (query_blob, top_k),
        )
        return [(row["finding_id"], 1.0 - row["distance"]) for row in cur.fetchall()]

    def knn_search_code_chunks(
        self, query_vec: np.ndarray, top_k: int
    ) -> list[tuple[CodeChunk, float]]:
        if top_k <= 0 or self.get_meta("code_embedding_dim") is None:
            return []
        query_blob = sqlite_vec.serialize_float32(query_vec.astype(np.float32).tolist())
        cur = self.conn.execute(
            "SELECT chunk_id, distance FROM vec_code_chunks "
            "WHERE embedding MATCH ? AND k = ? ORDER BY distance",
            (query_blob, top_k),
        )
        rows = cur.fetchall()
        if not rows:
            return []
        ids = [row["chunk_id"] for row in rows]
        placeholders = ",".join("?" for _ in ids)
        chunk_rows = self.conn.execute(
            f"SELECT * FROM code_chunks WHERE id IN ({placeholders})", ids
        ).fetchall()
        chunks_by_id = {row["id"]: _row_to_code_chunk(row) for row in chunk_rows}
        return [
            (chunks_by_id[row["chunk_id"]], 1.0 - row["distance"])
            for row in rows
            if row["chunk_id"] in chunks_by_id
        ]

    def counts_by(self, dim: str) -> dict[str, int]:
        if dim not in _COUNTABLE_DIMENSIONS:
            raise ValueError(f"Dimension inconnue : {dim!r}")
        cur = self.conn.execute(
            f"SELECT {dim} AS d, COUNT(*) AS c FROM findings GROUP BY {dim}"
        )
        return {row["d"]: row["c"] for row in cur.fetchall()}


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        id=row["id"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        message=row["message"],
        path=row["path"],
        start_line=row["start_line"],
        end_line=row["end_line"],
        snippet=row["snippet"],
        fix=row["fix"],
        cwe=json.loads(row["cwe"]) if row["cwe"] else [],
        owasp=json.loads(row["owasp"]) if row["owasp"] else [],
    )


def _row_to_code_chunk(row: sqlite3.Row) -> CodeChunk:
    return CodeChunk(
        id=row["id"],
        path=row["path"],
        start_line=row["start_line"],
        end_line=row["end_line"],
        language=row["language"],
        content=row["content"],
    )
