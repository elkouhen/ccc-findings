import json
from pathlib import Path
from typing import Literal, Optional

import typer

from cccf import __version__
from cccf.code_search import search_code_with_findings
from cccf.config import ConfigError, init_config, load_config
from cccf.embedder import EmbeddingError, make_embedder
from cccf.coco_indexer import index_repo_with_cocoindex
from cccf.flow import (
    FlowError,
    group_endpoints_by_module_for_flow,
    group_findings_by_module_for_flow,
    resolve_topic_by_similarity,
    trace_flow,
)
from cccf.graph import (
    GraphEdge,
    build_graph,
    find_cycles,
    find_hotspots,
    find_outbound_calls_in_consumers,
    group_endpoints_by_module,
    group_findings_by_module,
    rank_hotspots,
)
from cccf.indexer import index_repo
from cccf.models import MessageEndpoint
from cccf.render import (
    render_code_search_text,
    render_endpoints_json,
    render_endpoints_text,
    render_fallback_findings_text,
    render_flow_json,
    render_flow_text,
    render_graph_drawio,
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
from cccf.search import SearchError, search_findings
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
    except (EmbeddingError, SearchError) as exc:
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
    module: Optional[str] = typer.Option(  # noqa: UP007
        None, "--module", help="Nom du module Maven (artifactId, BACKLOG-13)."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Liste les endpoints REST/Kafka indexés (BACKLOG-10 K1, BACKLOG-11 A1),
    filtrable par système, rôle, topic exact, motif de chemin, ou module Maven.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints(
            system=system, role=role, topic=topic, path_glob=path, module=module
        )

    if json_output:
        typer.echo(json.dumps(render_endpoints_json(endpoints)))
    else:
        typer.echo(render_endpoints_text(endpoints))


@app.command(name="graph")
def graph_cmd(
    workspace: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--workspace",
        help="Répertoire parent Maven à fédérer (BACKLOG-11 A2) pour les "
        "cycles/hotspots inter-services.",
    ),
    json_output: bool = typer.Option(False, "--json"),
    drawio: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--drawio",
        help="Écrit le graphe d'interactions services <-> services en "
        ".drawio (mxGraph, diagrams.net) à ce chemin, plutôt que le rendu "
        "JSON/texte (BACKLOG-14 G1).",
    ),
) -> None:
    """Points de blocage probables à partir des endpoints indexés (BACKLOG-10
    K12) : appels REST synchrones détectés dans un handler de consommation
    Kafka du projet courant. Sans `--workspace`, si l'index couvre un
    répertoire multi-modules Maven (`cccf index` lancé au parent, BACKLOG-13),
    les endpoints/findings attribués à un module sont automatiquement
    groupés pour rapporter de vrais cycles/hotspots inter-modules — pas
    besoin de fédération pour un monorepo. Avec `--workspace <root>`, fédère
    en plus les autres microservices indexés séparément (BACKLOG-11 A2,
    lecture seule).
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints()
        findings = store.all_findings()

    outbound_calls = find_outbound_calls_in_consumers(endpoints)

    services_by_name: dict[str, list[MessageEndpoint]] = {}
    edges: list[GraphEdge] = []
    cycles = []
    hotspots = []
    warnings: list[str] = []
    cross_module_data_available = False
    if workspace is not None:
        discovered = discover_maven_services(workspace)
        federation = load_federation(discovered)
        warnings = federation.warnings
        services_by_name = federation.endpoints_by_service
        edges = build_graph(services_by_name)
        cycles = find_cycles(edges)
        hotspots = rank_hotspots(find_hotspots(cycles, federation.findings_by_service))
        cross_module_data_available = True
    else:
        grouped_endpoints = group_endpoints_by_module(endpoints)
        if grouped_endpoints:
            services_by_name = grouped_endpoints
            edges = build_graph(grouped_endpoints)
            cycles = find_cycles(edges)
            grouped_findings = group_findings_by_module(findings)
            hotspots = rank_hotspots(find_hotspots(cycles, grouped_findings))
            cross_module_data_available = True

    result = render_graph_json(
        outbound_calls,
        cycles=cycles,
        hotspots=hotspots,
        warnings=warnings,
        cross_module_data_available=cross_module_data_available,
    )

    if drawio is not None:
        drawio.write_text(
            render_graph_drawio(list(services_by_name), edges, cycles), encoding="utf-8"
        )
        typer.echo(f"Graphe écrit dans {drawio} ({len(services_by_name)} services, {len(edges)} arêtes).")
        if result["note"]:
            typer.echo(result["note"])
        return

    if json_output:
        typer.echo(json.dumps(result))
    else:
        typer.echo(render_graph_text(result))


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


@app.command(name="flow")
def flow_cmd(
    query: str,
    workspace: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--workspace",
        help="Répertoire parent Maven à fédérer (BACKLOG-11 A2) pour tracer "
        "un flux inter-services.",
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Résout un topic Kafka ou une route REST (nom exact, sinon sous-chaîne
    non ambiguë parmi les endpoints indexés, sinon plus proche voisin par
    similarité vectorielle — BACKLOG-10 K3) et liste tous ses sites
    (producteurs/consommateurs Kafka, ou serveurs/appelants REST) avec les
    findings Semgrep qui les recouvrent (BACKLOG-10 K5). Sans `--workspace`,
    ne cherche que dans le projet courant (la similarité vectorielle n'est
    disponible que dans ce mode) — chaque site est attribué à son module
    Maven si l'index couvre un répertoire multi-modules (BACKLOG-13) ;
    avec `--workspace <root>`, fédère en plus les autres microservices
    indexés séparément (lecture seule, BACKLOG-11 A2).
    """
    repo_root = Path.cwd()

    if workspace is not None:
        services = discover_maven_services(workspace)
        federation = load_federation(services)
        endpoints_by_service = dict(federation.endpoints_by_service)
        findings_by_service = dict(federation.findings_by_service)
        try:
            result = trace_flow(
                query, endpoints_by_service, findings_by_service, federation.warnings
            )
        except FlowError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
    else:
        _require_index(repo_root)
        with Store(repo_root) as store:
            endpoints = store.all_endpoints()
            endpoints_by_service = group_endpoints_by_module_for_flow(endpoints)
            findings_by_service = group_findings_by_module_for_flow(store.all_findings())
            try:
                result = trace_flow(query, endpoints_by_service, findings_by_service)
            except FlowError as exc:
                fallback_topic = None
                try:
                    config = load_config(repo_root)
                    embedder = make_embedder(config.embedding_model)
                    fallback_topic = resolve_topic_by_similarity(
                        store, embedder, query, endpoints
                    )
                except (ConfigError, EmbeddingError):
                    pass
                if fallback_topic is None:
                    typer.echo(str(exc), err=True)
                    raise typer.Exit(code=2) from exc
                result = trace_flow(fallback_topic, endpoints_by_service, findings_by_service)

    rendered = render_flow_json(result)
    if json_output:
        typer.echo(json.dumps(rendered))
    else:
        typer.echo(render_flow_text(rendered))


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
