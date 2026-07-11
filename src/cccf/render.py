from pathlib import Path

from cccf.search import SearchHit, Summary, get_context


def render_search_text(hits: list[SearchHit], repo_root: Path, include_context: bool) -> str:
    lines = []
    for i, hit in enumerate(hits, start=1):
        finding = hit.finding
        lines.append(
            f"{i}. [{finding.severity}] {finding.rule_id}  "
            f"{finding.path}:{finding.start_line}-{finding.end_line}  ({hit.score:.2f})"
        )
        lines.append(f"   {finding.message}")
        if include_context:
            try:
                context = get_context(repo_root, finding)
            except OSError as exc:
                lines.append(f"   contexte indisponible : {exc}")
            else:
                for context_line in context.splitlines():
                    lines.append(f"   {context_line}")
    return "\n".join(lines)


def render_search_json(
    hits: list[SearchHit], repo_root: Path, include_context: bool
) -> list[dict]:
    results = []
    for hit in hits:
        finding = hit.finding
        entry = {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
            "path": finding.path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "score": hit.score,
            "fix": finding.fix,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
        }
        if include_context:
            try:
                entry["context"] = get_context(repo_root, finding)
            except OSError as exc:
                entry["context"] = None
                entry["context_error"] = str(exc)
        results.append(entry)
    return results


def render_summary_text(result: Summary) -> str:
    severities = " | ".join(f"{sev} {count}" for sev, count in result.by_severity.items())
    top_rules = ", ".join(f"{rule} ({count})" for rule, count in result.top_rules)
    top_dirs = ", ".join(f"{d} ({count})" for d, count in result.by_top_level_dir.items())
    return "\n".join(
        [
            severities,
            f"top règles : {top_rules}",
            f"top répertoires : {top_dirs}",
        ]
    )


def render_summary_json(result: Summary) -> dict:
    return {
        "by_severity": result.by_severity,
        "top_rules": [{"rule_id": r, "count": c} for r, c in result.top_rules],
        "by_top_level_dir": result.by_top_level_dir,
    }
