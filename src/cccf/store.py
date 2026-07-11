import fnmatch
import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType

import numpy as np

from cccf.models import Finding

SCHEMA_VERSION = "1"
SEVERITY_ORDER = ["INFO", "WARNING", "ERROR"]
_COUNTABLE_DIMENSIONS = ("rule_id", "severity")


class Store:
    def __init__(self, repo_root: Path) -> None:
        self._db_path = Path(repo_root) / ".cccf" / "findings.db"
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> "Store":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
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
                owasp TEXT,
                embedding BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            """
        )
        if self.get_meta("schema_version") is None:
            self.set_meta("schema_version", SCHEMA_VERSION)
        self.conn.commit()

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
        self.conn.execute(f"DELETE FROM findings WHERE path IN ({placeholders})", paths)

    # -- findings --

    def replace_findings_for_files(self, paths: list[str], findings: list[Finding]) -> None:
        if paths:
            placeholders = ",".join("?" for _ in paths)
            self.conn.execute(
                f"DELETE FROM findings WHERE path IN ({placeholders})", paths
            )
        for finding in findings:
            self.conn.execute(
                """
                INSERT INTO findings
                    (id, rule_id, severity, message, path, start_line, end_line,
                     snippet, fix, cwe, owasp, embedding)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
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

    def set_embedding(self, finding_id: str, vector: np.ndarray) -> None:
        self.conn.execute(
            "UPDATE findings SET embedding = ? WHERE id = ?",
            (vector.astype(np.float32).tobytes(), finding_id),
        )

    def iter_embeddings(self) -> Iterable[tuple[str, np.ndarray]]:
        cur = self.conn.execute(
            "SELECT id, embedding FROM findings WHERE embedding IS NOT NULL"
        )
        for row in cur.fetchall():
            yield row["id"], np.frombuffer(row["embedding"], dtype=np.float32)

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
