import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from cccf.ccc_bridge import CccUnavailable, annotate_with_findings, search_code
from cccf.cli import _make_embedder
from cccf.config import load_config
from cccf.indexer import index_repo
from cccf.render import render_search_json
from cccf.search import search_findings as run_search_findings
from cccf.search import summary as compute_summary
from cccf.store import Store

mcp = FastMCP("cccf")


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
) -> str:
    """Recherche en langage naturel dans les findings Semgrep indexés du repo.
    Utiliser AVANT de modifier du code pour connaître les problèmes connus,
    et pour localiser des vulnérabilités par description.
    """
    repo_root = _repo_root()
    try:
        _require_index(repo_root)
        config = load_config(repo_root)
        embedder = _make_embedder(config.embedding_model)

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
            result = render_search_json(hits, repo_root, include_context)
        return json.dumps(result)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def findings_summary() -> str:
    """Vue agrégée des findings (sévérités, top règles).
    Utiliser pour une vue d'ensemble à faible coût.
    """
    repo_root = _repo_root()
    try:
        _require_index(repo_root)
        with Store(repo_root) as store:
            result = compute_summary(store)
        return json.dumps(
            {
                "by_severity": result.by_severity,
                "top_rules": [{"rule_id": r, "count": c} for r, c in result.top_rules],
                "by_top_level_dir": result.by_top_level_dir,
            }
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def reindex_findings() -> str:
    """Met à jour l'index des findings après modification de fichiers.
    Appeler après un patch pour vérifier la disparition d'un finding.
    """
    repo_root = _repo_root()
    try:
        config = load_config(repo_root)
        embedder = _make_embedder(config.embedding_model)
        with Store(repo_root) as store:
            report = index_repo(repo_root, config, store, embedder)
        return json.dumps(
            {
                "scanned": report.scanned,
                "skipped": report.skipped,
                "findings_added": report.findings_added,
                "findings_removed": report.findings_removed,
                "deleted_files": report.deleted_files,
            }
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def search_code_with_findings(query: str, limit: int = 5) -> str:
    """Recherche sémantique de code (via ccc) annotée des findings Semgrep connus
    sur chaque résultat. Outil à privilégier pour explorer du code en tenant
    compte de sa dette sécurité.
    """
    repo_root = _repo_root()
    try:
        code_hits = search_code(repo_root, query, limit)
    except CccUnavailable:
        fallback = json.loads(search_findings(query, limit=limit))
        return json.dumps({"error": "ccc non disponible", "fallback": fallback})

    try:
        with Store(repo_root) as store:
            annotated = annotate_with_findings(code_hits, store)
        return json.dumps(annotated)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
