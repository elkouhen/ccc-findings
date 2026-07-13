from pathlib import Path

from mcp.server.fastmcp import FastMCP

from cccf.code_search import CodeSearchResult
from cccf.code_search import search_code_with_findings as run_code_search
from cccf.config import load_config
from cccf.embedder import make_embedder
from cccf.flow import trace_flow
from cccf.graph import build_graph, find_cycles, find_hotspots, find_outbound_calls_in_consumers, rank_hotspots
from cccf.indexer import IndexReport, index_repo
from cccf.render import (
    EndpointHit,
    FindingHit,
    FindingsSummary,
    FlowResultInfo,
    GraphResult,
    WorkspaceResult,
    render_endpoints_json,
    render_flow_json,
    render_graph_json,
    render_search_json,
    render_summary_json,
    render_workspace_json,
)
from cccf.search import search_findings as run_search_findings
from cccf.search import summary as compute_summary
from cccf.store import Store
from cccf.workspace import discover_maven_services, load_federation

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
) -> list[FindingHit]:
    """Recherche en langage naturel dans les findings Semgrep indexés du repo.
    Utiliser AVANT de modifier du code pour connaître les problèmes connus,
    et pour localiser des vulnérabilités par description.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    config = load_config(repo_root)
    embedder = make_embedder(config.embedding_model)

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
        return render_search_json(hits, repo_root, include_context)


@mcp.tool()
def findings_summary() -> FindingsSummary:
    """Vue agrégée des findings (sévérités, top règles).
    Utiliser pour une vue d'ensemble à faible coût.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    with Store(repo_root) as store:
        result = compute_summary(store)
    return render_summary_json(result)


@mcp.tool()
def reindex_findings() -> IndexReport:
    """Met à jour l'index des findings après modification de fichiers.
    Appeler après un patch pour vérifier la disparition d'un finding.
    """
    repo_root = _repo_root()
    config = load_config(repo_root)
    embedder = make_embedder(config.embedding_model)
    with Store(repo_root) as store:
        return index_repo(repo_root, config, store, embedder)


@mcp.tool()
def search(
    query: str,
    limit: int = 5,
    offset: int = 0,
    lang: str | None = None,
    path: str | None = None,
    refresh: bool = False,
) -> CodeSearchResult:
    """Recherche sémantique de code (via ccc) annotée des findings Semgrep connus
    sur chaque résultat. Le classement favorise légèrement les résultats
    portant un finding connu (plus fortement si sévérité ERROR) par rapport à
    un résultat de pertinence sémantique proche mais sans finding. Outil à
    privilégier pour explorer du code en tenant compte de sa dette sécurité.
    Même comportement, mêmes paramètres et même nom de tool que le `search`
    de ccc ; équivalent à la CLI `cccf search`.
    """
    return run_code_search(
        _repo_root(), query, limit=limit, offset=offset, lang=lang, path=path, refresh=refresh
    )


@mcp.tool()
def list_endpoints(
    system: str | None = None,
    role: str | None = None,
    topic: str | None = None,
    path_glob: str | None = None,
) -> list[EndpointHit]:
    """Liste les endpoints REST/Kafka indexés (BACKLOG-10 K1, BACKLOG-11 A1),
    filtrable par système (rest/kafka), rôle (serve/call/produce/consume),
    topic exact ou motif de chemin. Utiliser pour explorer l'inventaire des
    échanges entre services avant d'appeler `graph`.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    with Store(repo_root) as store:
        endpoints = store.all_endpoints(
            system=system, role=role, topic=topic, path_glob=path_glob
        )
    return render_endpoints_json(endpoints)


@mcp.tool()
def graph(workspace_root: str | None = None) -> GraphResult:
    """Points de blocage probables à partir des endpoints indexés
    (BACKLOG-10 K12) : appels REST synchrones dans un handler de
    consommation Kafka du projet courant. Utiliser pour localiser les
    endroits d'une architecture distribuée susceptibles de causer un
    verrouillage intermittent. Avec `workspace_root`, fédère aussi les
    autres microservices du répertoire donné (BACKLOG-11 A2, lecture
    seule) pour rapporter les cycles d'appels inter-services et les
    hotspots — sinon `cycles`/`hotspots` restent vides, voir `note`.
    """
    repo_root = _repo_root()
    _require_index(repo_root)
    with Store(repo_root) as store:
        endpoints = store.all_endpoints()
    outbound_calls = find_outbound_calls_in_consumers(endpoints)

    if workspace_root is None:
        return render_graph_json(outbound_calls)

    services = discover_maven_services(Path(workspace_root))
    federation = load_federation(services)
    edges = build_graph(federation.endpoints_by_service)
    cycles = find_cycles(edges)
    hotspots = rank_hotspots(find_hotspots(cycles, federation.findings_by_service))
    return render_graph_json(
        outbound_calls,
        cycles=cycles,
        hotspots=hotspots,
        workspace_warnings=federation.warnings,
        workspace_provided=True,
    )


@mcp.tool()
def list_workspace_services(root: str) -> WorkspaceResult:
    """Découvre les modules Maven sous `root` (BACKLOG-11 A2) : un module
    par `pom.xml`, classé `microservice` (référence
    `spring-boot-maven-plugin`) ou `shared-module`. Lit en lecture seule les
    projets déjà indexés (`cccf index`) pour compter endpoints/findings par
    service — n'écrit jamais dans leurs bases. Utiliser avant `graph` pour
    vérifier quels services d'un répertoire multi-services sont prêts à
    être fédérés.
    """
    services = discover_maven_services(Path(root))
    federation = load_federation(services)
    return render_workspace_json(services, federation)


@mcp.tool()
def trace_message_flow(query: str, workspace_root: str | None = None) -> FlowResultInfo:
    """Résout `query` en topic Kafka ou route REST (nom exact, sinon
    sous-chaîne non ambiguë parmi les endpoints indexés, BACKLOG-10 K5) et
    liste tous ses sites (producteurs/consommateurs Kafka, ou
    serveurs/appelants REST) avec les findings Semgrep qui les recouvrent.
    Utiliser pour comprendre qui produit/consomme un topic donné, ou qui
    appelle une route donnée, avant de plonger dans le code. Sans
    `workspace_root`, ne cherche que dans le projet courant ; avec, fédère
    les autres microservices du répertoire (BACKLOG-11 A2, lecture seule)
    pour un flux qui traverse plusieurs services. Requête sans
    correspondance, ou ambiguë, lève une erreur explicite plutôt que de
    deviner un topic au hasard.
    """
    repo_root = _repo_root()
    warnings: list[str] = []

    if workspace_root is None:
        _require_index(repo_root)
        with Store(repo_root) as store:
            endpoints_by_service: dict[str | None, list] = {None: store.all_endpoints()}
            findings_by_service: dict[str | None, list] = {None: store.all_findings()}
    else:
        services = discover_maven_services(Path(workspace_root))
        federation = load_federation(services)
        endpoints_by_service = dict(federation.endpoints_by_service)
        findings_by_service = dict(federation.findings_by_service)
        warnings = federation.warnings

    result = trace_flow(query, endpoints_by_service, findings_by_service, warnings)
    return render_flow_json(result)
