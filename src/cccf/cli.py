import json
from pathlib import Path
from typing import Literal, Optional

import typer

from cccf import __version__
from cccf.code_search import search_code_with_findings
from cccf.config import ConfigError, init_config, load_config
from cccf.embedder import EmbeddingError, make_embedder
from cccf.coco_indexer import index_repo_with_cocoindex
from cccf.graph import find_outbound_calls_in_consumers
from cccf.indexer import index_repo
from cccf.render import (
    render_code_search_text,
    render_endpoints_json,
    render_endpoints_text,
    render_fallback_findings_text,
    render_graph_json,
    render_graph_text,
    render_search_json,
    render_search_text,
    render_summary_json,
    render_summary_text,
    render_workspace_json,
    render_workspace_text,
)
from cccf.scanner import SemgrepError
from cccf.search import search_findings
from cccf.search import summary as compute_summary
from cccf.store import Store
from cccf.workspace import discover_maven_services, load_federation

app = typer.Typer(help="ccc-findings: index Semgrep interrogeable par LLM")

_SEMGREP_CONFIG_CANDIDATES = [".semgrep.yml", "semgrep.yml", ".semgrep"]
DEFAULT_REGISTRY_PACK = "p/security-audit"


@app.callback()
def main() -> None:
    """ccc-findings: index Semgrep interrogeable par LLM."""


@app.command()
def version() -> None:
    """Affiche la version du package."""
    typer.echo(__version__)


def _detect_semgrep_config(repo_root: Path) -> str | None:
    for candidate in _SEMGREP_CONFIG_CANDIDATES:
        if (repo_root / candidate).exists():
            return candidate
    return None


@app.command()
def init(
    rules: Optional[list[str]] = typer.Option(  # noqa: UP007 (Typer nécessite Optional)
        None, "--rules", help="Chemin ou pack de règles Semgrep (répétable)."
    ),
) -> None:
    """Initialise la configuration .cccf/config.yml du projet."""
    repo_root = Path.cwd()

    rules_paths = list(rules) if rules else None
    if not rules_paths:
        detected = _detect_semgrep_config(repo_root)
        if detected is not None:
            rules_paths = [detected]
        else:
            rules_paths = [DEFAULT_REGISTRY_PACK]
            typer.echo(
                f"Aucune config Semgrep détectée. Utilisation du pack par défaut "
                f"'{DEFAULT_REGISTRY_PACK}' (relancez avec --rules "
                "<chemin-ou-pack> pour le personnaliser)."
            )

    try:
        path = init_config(repo_root, rules_paths)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Configuration créée : {path}")


@app.command(name="index")
def index_cmd(
    full: bool = typer.Option(False, "--full", help="Force un scan complet."),
    engine: Literal["manual", "cocoindex"] = typer.Option(
        "manual",
        "--engine",
        help="Moteur d'indexation : manual (défaut) ou cocoindex (expérimental).",
    ),
) -> None:
    """Indexe le code et les findings du projet (incrémental par défaut)."""
    repo_root = Path.cwd()

    try:
        config = load_config(repo_root)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    embedder = make_embedder(config.embedding_model)

    try:
        with Store(repo_root) as store:
            if engine == "cocoindex":
                report = index_repo_with_cocoindex(
                    repo_root, config, store, embedder, full=full
                )
            else:
                report = index_repo(repo_root, config, store, embedder, full=full)
                store.set_meta("index_engine", "manual")
    except (SemgrepError, EmbeddingError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(
        f"scanned={report.scanned} skipped={report.skipped} "
        f"+findings={report.findings_added} -findings={report.findings_removed} "
        f"+endpoints={report.endpoints_added} -endpoints={report.endpoints_removed}"
    )


def _require_index(repo_root: Path) -> None:
    db_path = repo_root / ".cccf" / "findings.db"
    if not db_path.is_file():
        typer.echo("Index absent. Lancez d'abord: cccf index", err=True)
        raise typer.Exit(code=2)


@app.command()
def search(
    query: str,
    limit: int = typer.Option(5, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    lang: Optional[str] = typer.Option(None, "--lang"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    refresh: bool = typer.Option(False, "--refresh"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Recherche sémantique de code (mêmes résultats et mêmes paramètres que
    `ccc search`), enrichie des findings Semgrep qui recouvrent chaque
    résultat et classée en tenant compte de leur sévérité.
    """
    repo_root = Path.cwd()

    try:
        result = search_code_with_findings(
            repo_root, query, limit=limit, offset=offset, lang=lang, path=path, refresh=refresh
        )
    except (RuntimeError, ConfigError, EmbeddingError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(result))
        return

    if result["findings_only_fallback"]:
        typer.echo(f"⚠ {result['warning']}", err=True)
        typer.echo(render_fallback_findings_text(result["findings_only_fallback"]))
    else:
        typer.echo(render_code_search_text(result["results"], warning=result["warning"]))


@app.command(name="findings")
def findings_cmd(
    query: str,
    severity: Optional[str] = typer.Option(None, "--severity"),  # noqa: UP007
    rule: Optional[str] = typer.Option(None, "--rule"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    limit: int = typer.Option(5, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    context: bool = typer.Option(False, "--context"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Recherche en langage naturel dans les findings Semgrep indexés (seuls,
    sans recherche de code — pour la recherche code + findings, voir `search`).
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    config = load_config(repo_root)
    embedder = make_embedder(config.embedding_model)

    try:
        with Store(repo_root) as store:
            hits = search_findings(
                store,
                embedder,
                query,
                severity=severity,
                rule=rule,
                path_glob=path,
                limit=limit,
                offset=offset,
            )
    except EmbeddingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if json_output:
        typer.echo(json.dumps(render_search_json(hits, repo_root, context)))
    else:
        typer.echo(render_search_text(hits, repo_root, context))


@app.command(name="summary")
def summary_cmd(json_output: bool = typer.Option(False, "--json")) -> None:
    """Vue agrégée des findings (sévérités, top règles, top répertoires)."""
    repo_root = Path.cwd()
    _require_index(repo_root)

    with Store(repo_root) as store:
        result = compute_summary(store)

    if json_output:
        typer.echo(json.dumps(render_summary_json(result)))
    else:
        typer.echo(render_summary_text(result))


@app.command(name="endpoints")
def endpoints_cmd(
    system: Optional[str] = typer.Option(None, "--system"),  # noqa: UP007
    role: Optional[str] = typer.Option(None, "--role"),  # noqa: UP007
    topic: Optional[str] = typer.Option(None, "--topic"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Liste les endpoints REST/Kafka indexés (BACKLOG-10 K1, BACKLOG-11 A1),
    filtrable par système, rôle, topic exact ou motif de chemin.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints(
            system=system, role=role, topic=topic, path_glob=path
        )

    if json_output:
        typer.echo(json.dumps(render_endpoints_json(endpoints)))
    else:
        typer.echo(render_endpoints_text(endpoints))


@app.command(name="graph")
def graph_cmd(json_output: bool = typer.Option(False, "--json")) -> None:
    """Points de blocage probables à partir des endpoints indexés (BACKLOG-10
    K12) : appels REST synchrones détectés dans un handler de consommation
    Kafka. Les cycles d'appels inter-services et les hotspots nécessitent
    plusieurs projets indexés (fédération multi-dépôts, K7, pas encore
    livré) — cette commande ne les rapporte pas tant qu'un seul projet est
    indexé.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints()

    outbound_calls = find_outbound_calls_in_consumers(endpoints)

    if json_output:
        typer.echo(json.dumps(render_graph_json(outbound_calls)))
    else:
        typer.echo(render_graph_text(render_graph_json(outbound_calls)))


@app.command(name="workspace")
def workspace_cmd(
    root: Path = typer.Argument(..., help="Répertoire parent à explorer (multi-modules Maven)."),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Découvre les modules Maven sous `root` (BACKLOG-11 A2) : un module par
    `pom.xml`, nommé d'après son `artifactId`, classé `microservice`
    (référence `spring-boot-maven-plugin`) ou `shared-module`. Lit en
    lecture seule les projets déjà indexés (`cccf index`) pour compter
    endpoints/findings par service — n'écrit jamais dans leurs bases.
    Un module non indexé ou dont la base est incompatible est signalé en
    avertissement, sans faire échouer la commande.
    """
    services = discover_maven_services(root)
    federation = load_federation(services)
    result = render_workspace_json(services, federation)

    if json_output:
        typer.echo(json.dumps(result))
    else:
        typer.echo(render_workspace_text(result))


@app.command(name="mcp")
def mcp_cmd() -> None:
    """Lance le serveur MCP (stdio) exposant les findings du repo courant.

    Enregistrement client (ex. Claude Code), à ajouter à la config MCP :

    {"mcpServers": {"cccf": {"command": "cccf", "args": ["mcp"]}}}
    """
    from cccf.mcp_server import mcp as fastmcp_app

    fastmcp_app.run()


if __name__ == "__main__":
    app()
