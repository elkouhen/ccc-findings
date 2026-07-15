import json
import os
import shutil
import hashlib
import sys
import time
from pathlib import Path
from typing import Literal, Optional

import typer

from ccc_radar import __version__
from ccc_radar.code_search import search_code_with_findings
from ccc_radar.audit import assess_architecture, render_audit_json, render_audit_text
from ccc_radar.config import ConfigError, init_config, load_config
from ccc_radar.embedder import EmbeddingError, make_embedder, resolve_embedding_model
from ccc_radar.coco_indexer import index_repo_with_cocoindex
from ccc_radar.flow import (
    FlowError,
    group_endpoints_by_module_for_flow,
    group_findings_by_module_for_flow,
    resolve_topic_by_similarity,
    trace_flow,
)
from ccc_radar.graph import (
    GraphEdge,
    build_graph,
    find_outbound_calls_in_consumers,
    group_endpoints_by_module,
)
from ccc_radar.indexer import index_repo
from ccc_radar.inventory_freshness import endpoint_inventory_warning
from ccc_radar.models import MessageEndpoint
from ccc_radar.render import (
    render_code_search_text,
    render_endpoints_json,
    render_endpoints_text,
    render_fallback_findings_text,
    render_flow_json,
    render_flow_text,
    render_graph_d2,
    render_graph_drawio,
    render_graph_json,
    render_graph_text,
    render_module_detail_json,
    render_module_detail_text,
    render_modules_list_json,
    render_modules_list_text,
    render_search_json,
    render_search_text,
    render_summary_json,
    render_summary_text,
    render_workspace_json,
    render_workspace_text,
    write_graph_d2,
)
from ccc_radar.scanner import SemgrepError
from ccc_radar.search import SearchError, search_findings
from ccc_radar.search import summary as compute_summary
from ccc_radar.paths import config_path, db_path, state_dir
from ccc_radar.store import Store, StoreError
from ccc_radar.workspace import discover_maven_services, load_federation
from ccc_radar.doctor import has_errors, run_doctor

app = typer.Typer(
    help="ccc-radar: indexe findings, code associé et signaux d'architecture exploitables par agent"
)

_SEMGREP_CONFIG_CANDIDATES = [".semgrep.yml", "semgrep.yml", ".semgrep"]
DEFAULT_REGISTRY_PACK = "p/security-audit"
DEFAULT_RULE_PACKS = ("default", "liveness", "rest", "kafka", "kafka-security")
_SKILL_RULES_ROOT_CANDIDATES = (
    ("ccc-radar-skill", "skills", "cccr", "rules"),
    ("cocoindex-ext-skill", "skills", "cccr", "rules"),
)


def _current_repo_endpoint_warning(store: Store) -> str | None:
    return endpoint_inventory_warning(
        store.get_meta("endpoint_inventory_signature"), scope="ce projet"
    )


def _echo_index_progress(message: str) -> None:
    typer.echo(message)


def _trace_index(stage: str, **fields: object) -> None:
    if os.environ.get("CCCR_TRACE") != "1":
        return
    details = " ".join(f"{name}={value}" for name, value in fields.items())
    print(f"CCCR_TRACE ts={time.monotonic():.6f} stage={stage} {details}".rstrip(), file=sys.stderr, flush=True)


@app.callback()
def main() -> None:
    """ccc-radar: indexe findings, code associé et signaux d'architecture."""


@app.command()
def version() -> None:
    """Affiche la version du package."""
    typer.echo(__version__)


@app.command(name="doctor")
def doctor_cmd(json_output: bool = typer.Option(False, "--json")) -> None:
    """Vérifie les prérequis d'un audit d'architecture, sans modifier le projet."""
    checks = run_doctor(Path.cwd())
    result = [
        {"name": check.name, "status": check.status, "detail": check.detail}
        for check in checks
    ]
    if json_output:
        typer.echo(json.dumps(result))
    else:
        for check in checks:
            marker = {"ok": "✓", "warning": "⚠", "error": "✗"}[check.status]
            typer.echo(f"{marker} {check.name}: {check.detail}")
    if has_errors(checks):
        raise typer.Exit(code=2)


def _detect_semgrep_config(repo_root: Path) -> str | None:
    for candidate in _SEMGREP_CONFIG_CANDIDATES:
        if (repo_root / candidate).exists():
            return candidate
    return None


def _find_skill_rules_root() -> Path | None:
    configured = os.environ.get("CCCR_RULES_ROOT")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_dir():
            return candidate
    home = Path.home()
    for parts in _SKILL_RULES_ROOT_CANDIDATES:
        candidate = home.joinpath(*parts)
        if candidate.is_dir():
            return candidate
    # Common skill installation roots. `CCCR_RULES_ROOT` remains the
    # deterministic escape hatch for other clients/installers.
    for candidate in (
        home / ".codex" / "skills" / "cccr" / "rules",
        home / ".agents" / "skills" / "cccr" / "rules",
        home / ".claude" / "skills" / "cccr" / "rules",
    ):
        if candidate.is_dir():
            return candidate
    return None


def _install_default_rule_packs(repo_root: Path, rules_root: Path) -> list[str]:
    missing = [pack for pack in DEFAULT_RULE_PACKS if not (rules_root / pack).is_dir()]
    if missing:
        raise ConfigError(
            "Packs de règles introuvables dans "
            f"{rules_root} : {', '.join(missing)}."
        )

    destination_root = state_dir(repo_root) / "rules"
    destination_root.mkdir(parents=True, exist_ok=True)
    installed_paths: list[str] = []
    for pack in DEFAULT_RULE_PACKS:
        source_dir = rules_root / pack
        target_dir = destination_root / pack
        shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)
        installed_paths.append(f".cccr/rules/{pack}")
    manifest = {
        "source": str(rules_root),
        "packs": {
            pack: {
                path.relative_to(rules_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted((rules_root / pack).rglob("*"))
                if path.is_file()
            }
            for pack in DEFAULT_RULE_PACKS
        },
    }
    (destination_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return installed_paths


@app.command()
def init(
    rules: Optional[list[str]] = typer.Option(  # noqa: UP007 (Typer nécessite Optional)
        None, "--rules", help="Chemin ou pack de règles Semgrep (répétable)."
    ),
    rules_root: Optional[Path] = typer.Option(
        None, "--rules-root", help="Répertoire contenant les packs cccr (default/, rest/, kafka/, ...)."
    ),
) -> None:
    """Initialise la configuration .cccr/config.yml du projet."""
    repo_root = Path.cwd()
    if config_path(repo_root).exists():
        typer.echo(f"Une configuration existe déjà : {config_path(repo_root)}.", err=True)
        raise typer.Exit(code=1)

    rules_paths = list(rules) if rules else None
    if not rules_paths:
        detected = _detect_semgrep_config(repo_root)
        if detected is not None:
            rules_paths = [detected]
        else:
            rules_root = rules_root or _find_skill_rules_root()
            if rules_root is not None:
                try:
                    rules_paths = _install_default_rule_packs(repo_root, rules_root)
                except ConfigError:
                    rules_paths = [DEFAULT_REGISTRY_PACK]
                    typer.echo(
                    "Aucune config Semgrep détectée et les packs d'architecture sont "
                    f"incomplets sous {rules_root}. Utilisation du pack par défaut "
                    f"'{DEFAULT_REGISTRY_PACK}' : `cccr doctor` signalera que le graphe REST/Kafka n'est pas prêt."
                    )
                else:
                    typer.echo(
                        "Aucune config Semgrep détectée. Packs du skill copiés dans "
                        f".cccr/rules/ : {', '.join(DEFAULT_RULE_PACKS)}."
                    )
            else:
                rules_paths = [DEFAULT_REGISTRY_PACK]
                typer.echo(
                    f"Aucune config Semgrep détectée et packs du skill introuvables. "
                    f"Utilisation du pack par défaut '{DEFAULT_REGISTRY_PACK}' "
                    "(pour un audit architecture, définissez CCCR_RULES_ROOT ou passez --rules-root)."
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
    disable: list[str] = typer.Option(
        None, "--disable", help="Type à désactiver : semgrep ou properties. Répétable."
    ),
) -> None:
    """Indexe le code et les findings du projet (incrémental par défaut)."""
    repo_root = Path.cwd()
    _trace_index("cli.index.begin", root=repo_root, full=full, engine=engine)
    disabled = frozenset(disable or [])
    unknown = disabled - {"semgrep", "properties"}
    if unknown:
        typer.echo(f"Type d'indexation inconnu : {', '.join(sorted(unknown))}. Valeurs : semgrep, properties.", err=True)
        raise typer.Exit(code=2)

    try:
        config = load_config(repo_root)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    resolved_model, model_warning = resolve_embedding_model(config.embedding_model)
    if model_warning is not None:
        typer.echo(f"⚠ {model_warning}")
    _trace_index("embedder.begin", model=resolved_model)
    embedder = make_embedder(resolved_model)
    _trace_index("embedder.end")

    try:
        _trace_index("store.open.begin")
        with Store(repo_root) as store:
            _trace_index("store.open.end")
            if engine == "cocoindex":
                report = index_repo_with_cocoindex(
                    repo_root, config, store, embedder, full=full,
                    progress=_echo_index_progress, disabled=disabled,
                )
            else:
                report = index_repo(
                    repo_root, config, store, embedder, full=full, progress=_echo_index_progress,
                    disabled=disabled,
                )
                store.set_meta("index_engine", "manual")
            _trace_index("store.close.begin")
    except (SemgrepError, EmbeddingError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(
        f"scanned={report.scanned} skipped={report.skipped} "
        f"+findings={report.findings_added} -findings={report.findings_removed} "
        f"+endpoints={report.endpoints_added} -endpoints={report.endpoints_removed}"
    )
    _trace_index("cli.index.end")


def _require_index(repo_root: Path) -> None:
    index_path = db_path(repo_root)
    if not index_path.is_file():
        typer.echo("Index absent. Lancez d'abord: cccr index", err=True)
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
    """Recherche de code via `ccc`, dans le même ordre et avec la même limite,
    annotée des findings du même fichier ou de la même classe.
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
    query: Optional[str] = typer.Argument(  # noqa: UP007 (Typer nécessite Optional)
        None, help="Requête précision-first. Omettre pour lister les findings."
    ),
    severity: Optional[str] = typer.Option(None, "--severity"),  # noqa: UP007
    rule: Optional[str] = typer.Option(None, "--rule"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    limit: int = typer.Option(5, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    context: bool = typer.Option(False, "--context"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Liste les findings indexés ou les filtre par requête précision-first,
    sans recherche de code — pour la recherche code + findings, voir `search`.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)

    try:
        with Store(repo_root) as store:
            hits = search_findings(
                store,
                object(),  # recherche findings lexicale ; aucun modèle requis
                query,
                severity=severity,
                rule=rule,
                path_glob=path,
                limit=limit,
                offset=offset,
            )
    except SearchError as exc:
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
        warning = _current_repo_endpoint_warning(store)

    if json_output:
        typer.echo(json.dumps(render_endpoints_json(endpoints)))
    else:
        typer.echo(render_endpoints_text(endpoints, [warning] if warning else []))


@app.command(name="graph")
def graph_cmd(
    workspace: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--workspace",
        help="Répertoire parent Maven/Gradle à fédérer (BACKLOG-11 A2) pour les "
        "arêtes inter-services.",
    ),
    json_output: bool = typer.Option(False, "--json"),
    drawio: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--drawio",
        help="Écrit le graphe d'interactions microservices + topics Kafka en "
        ".drawio (mxGraph, diagrams.net) à ce chemin, plutôt que le rendu "
        "JSON/texte (BACKLOG-14 G1).",
    ),
    d2: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--d2",
        help="Écrit le graphe en D2 : source `.d2` si l'extension vaut `.d2`, "
        "sinon rendu généré par la CLI D2 (`.svg`, etc.).",
    ),
    d2_layout: Literal["dagre", "elk"] = typer.Option(
        "elk",
        "--d2-layout",
        help="Moteur de layout D2 utilisé pour un rendu non-`.d2`.",
    ),
) -> None:
    """Graphe dérivé des endpoints indexés : nœuds = microservices + topics
    Kafka ; arêtes = appel HTTP, production Kafka, consommation Kafka, avec
    en plus les signaux de blocage probables (BACKLOG-10 K12) : appels REST
    synchrones détectés dans un handler de consommation Kafka du projet
    courant. Sans `--workspace`, si l'index couvre un répertoire
    multi-modules Maven ou Gradle (`cccr index` lancé au parent,
    BACKLOG-13/15), les endpoints attribués à un module/service sont automatiquement groupés
    pour rapporter de vraies arêtes inter-modules — pas besoin de
    fédération pour un monorepo. Avec `--workspace <root>`, fédère en plus
    les autres microservices indexés séparément
    (BACKLOG-11 A2, lecture seule).
    """
    repo_root = Path.cwd()
    _require_index(repo_root)
    if drawio is not None and d2 is not None:
        typer.echo("Choisissez soit --drawio, soit --d2.", err=True)
        raise typer.Exit(code=2)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints()
        repo_warning = _current_repo_endpoint_warning(store)

    outbound_calls = find_outbound_calls_in_consumers(endpoints)

    services_by_name: dict[str, list[MessageEndpoint]] = {}
    edges: list[GraphEdge] = []
    warnings: list[str] = [repo_warning] if repo_warning else []
    cross_module_data_available = False
    if workspace is not None:
        discovered = discover_maven_services(workspace)
        federation = load_federation(discovered)
        warnings.extend(federation.warnings)
        services_by_name = federation.endpoints_by_service
        edges = build_graph(services_by_name)
        cross_module_data_available = True
    else:
        grouped_endpoints = group_endpoints_by_module(endpoints)
        if grouped_endpoints:
            services_by_name = grouped_endpoints
            edges = build_graph(grouped_endpoints)
            cross_module_data_available = True

    result = render_graph_json(
        list(services_by_name),
        edges,
        outbound_calls,
        warnings=warnings,
        cross_module_data_available=cross_module_data_available,
    )

    if drawio is not None:
        drawio.write_text(
            render_graph_drawio(services_by_name, edges), encoding="utf-8"
        )
        typer.echo(f"Graphe écrit dans {drawio} ({len(services_by_name)} services, {len(edges)} arêtes).")
        if result["note"]:
            typer.echo(result["note"])
        return

    if d2 is not None:
        try:
            write_graph_d2(d2, render_graph_d2(services_by_name, edges), layout=d2_layout)
        except RuntimeError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from exc
        typer.echo(f"Graphe écrit dans {d2} ({len(services_by_name)} services, {len(edges)} arêtes).")
        if result["note"]:
            typer.echo(result["note"])
        return

    if json_output:
        typer.echo(json.dumps(result))
    else:
        typer.echo(render_graph_text(result))


@app.command(name="audit")
def audit_cmd(
    workspace: Optional[Path] = typer.Option(
        None, "--workspace", help="Workspace de services indexés séparément."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Signale les risques d'architecture statiquement démontrables.

    Les constats sont volontairement conservateurs : topics dynamiques,
    producteurs/consommateurs Kafka orphelins et cycles HTTP synchrones.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)
    if workspace is not None:
        federation = load_federation(discover_maven_services(workspace))
        endpoints_by_service = dict(federation.endpoints_by_service)
    else:
        with Store(repo_root, readonly=True) as store:
            endpoints_by_service = group_endpoints_by_module(store.all_endpoints())
    risks = assess_architecture(endpoints_by_service, build_graph(endpoints_by_service))
    typer.echo(json.dumps(render_audit_json(risks)) if json_output else render_audit_text(risks))


@app.command(name="microservices")
def microservices_cmd(
    arguments: list[str] = typer.Argument(
        None,
        help="Sous-commande et microservice, ou anciennement la racine du workspace.",
    ),
    root: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--root", help="Répertoire parent à explorer. Défaut : répertoire courant.",
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Découvre les services fédérables sous `root` (BACKLOG-11 A2) :
    modules Maven runtime/shared (`pom.xml`) et microservices Gradle
    Spring Boot. Lit en lecture seule les projets déjà indexés
    (`cccr index`) pour compter endpoints/findings par service — n'écrit
    jamais dans leurs bases. Un service non indexé ou dont la base est
    incompatible est signalé en avertissement, sans faire échouer la
    commande. Sous-commandes : `endpoints <service>`, `flow <service>`,
    `properties <service>` et `openapi <service>`, avec `--root <workspace>`.
    """
    arguments = arguments or []
    commands = {"endpoints", "flow", "properties", "openapi"}
    if arguments and arguments[0] in commands:
        if len(arguments) != 2:
            typer.echo(f"`microservices {arguments[0]}` requiert un nom de microservice.", err=True)
            raise typer.Exit(code=2)
        service = arguments[1]
        workspace_root = (root or Path.cwd()).resolve()
        if arguments[0] == "endpoints":
            _render_microservice_endpoints(service, workspace_root, json_output)
        elif arguments[0] == "flow":
            _render_microservice_flow(service, workspace_root, json_output)
        elif arguments[0] == "properties":
            _render_microservice_properties(service, workspace_root, json_output)
        else:
            _render_microservice_openapi(service, workspace_root, json_output)
        return
    if len(arguments) > 1:
        typer.echo("Usage : `cccr microservices [root]` ou `cccr microservices <endpoints|flow|properties|openapi> <service> --root <root>`.", err=True)
        raise typer.Exit(code=2)
    workspace_root = Path(arguments[0]) if arguments else (root or Path.cwd())
    services = discover_maven_services(workspace_root)
    federation = load_federation(services)
    result = render_workspace_json(services, federation)

    if json_output:
        typer.echo(json.dumps(result))
    else:
        typer.echo(render_workspace_text(result))


def _selected_microservice(name: str, root: Path):
    services = discover_maven_services(root)
    matches = [service for service in services if service.name == name and service.kind == "microservice"]
    if not matches:
        typer.echo(f"Microservice introuvable : {name}", err=True)
        raise typer.Exit(code=2)
    if len(matches) > 1:
        paths = ", ".join(str(service.path) for service in matches)
        typer.echo(f"Microservice ambigu : {name} ({paths})", err=True)
        raise typer.Exit(code=2)
    return matches[0], load_federation(services)


def _render_microservice_endpoints(service: str, root: Path, json_output: bool) -> None:
    """Liste les endpoints indexés d'un microservice du workspace."""
    _, federation = _selected_microservice(service, root)
    endpoints = federation.endpoints_by_service.get(service, [])
    typer.echo(
        json.dumps(render_endpoints_json(endpoints))
        if json_output
        else render_endpoints_text(endpoints, federation.warnings)
    )


def _render_microservice_flow(service: str, root: Path, json_output: bool) -> None:
    """Affiche les flux HTTP/Kafka entrants et sortants d'un microservice."""
    _, federation = _selected_microservice(service, root)
    edges = [
        edge for edge in build_graph(dict(federation.endpoints_by_service))
        if edge.from_service == service or edge.to_service == service
    ]
    involved_services = sorted({service} | {edge.from_service for edge in edges} | {edge.to_service for edge in edges})
    result = render_graph_json(
        involved_services, edges, [], warnings=federation.warnings,
        cross_module_data_available=True,
    )
    typer.echo(json.dumps(result) if json_output else render_graph_text(result))


def _render_microservice_properties(service: str, root: Path, json_output: bool) -> None:
    """Affiche l'exemple YAML de propriétés Spring d'un microservice."""
    selected, _ = _selected_microservice(service, root)
    from ccc_radar.configuration import service_configuration_example

    properties = service_configuration_example(selected.path)
    result = {"name": selected.name, "properties_example": properties}
    typer.echo(json.dumps(result) if json_output else properties.rstrip())


def _render_microservice_openapi(service: str, root: Path, json_output: bool) -> None:
    """Affiche les contrats OpenAPI/Swagger locaux d'un microservice."""
    selected, _ = _selected_microservice(service, root)
    _render_openapi_contracts(selected.name, selected.path, json_output)


def _render_openapi_contracts(name: str, root: Path, json_output: bool) -> None:
    """Rend les contrats OpenAPI/Swagger d'un module ou microservice."""
    names = {"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json"}
    contracts = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name.casefold() not in names:
            continue
        relative = path.relative_to(root)
        if any(part in {".git", ".cccr", "target", "build", "test"} for part in relative.parts):
            continue
        contracts.append({
            "path": relative.as_posix(),
            "content": path.read_text(encoding="utf-8", errors="replace"),
        })
    result = {"name": name, "contracts": contracts}
    if json_output:
        typer.echo(json.dumps(result))
    elif not contracts:
        typer.echo("Aucun contrat OpenAPI/Swagger local détecté.")
    else:
        typer.echo("\n\n".join(f"# {contract['path']}\n{contract['content'].rstrip()}" for contract in contracts))


@app.command(name="modules")
def modules_cmd(
    arguments: list[str] = typer.Argument(
        None, help="Sous-commande et module, ou nom de module à détailler."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Liste les modules indexés ou détaille l'un d'eux.

    `cccr modules` liste. `cccr modules <module>` détaille. Les sous-commandes
    `endpoints`, `flow`, `properties` et `openapi` prennent un module dans le
    répertoire courant déjà indexé.
    """
    arguments = arguments or []
    commands = {"endpoints", "flow", "properties", "openapi"}
    if arguments and arguments[0] in commands:
        if len(arguments) != 2:
            typer.echo(f"`modules {arguments[0]}` requiert un nom de module.", err=True)
            raise typer.Exit(code=2)
        repo_root = Path.cwd().resolve()
        selected = _selected_indexed_module(arguments[1], repo_root)
        with Store(repo_root, readonly=True) as store:
            if arguments[0] == "endpoints":
                endpoints = [endpoint for endpoint in store.all_endpoints() if endpoint.module == selected.name]
                typer.echo(json.dumps(render_endpoints_json(endpoints)) if json_output else render_endpoints_text(endpoints))
            elif arguments[0] == "flow":
                endpoints_by_module = group_endpoints_by_module(store.all_endpoints())
                edges = [
                    edge for edge in build_graph(endpoints_by_module)
                    if edge.from_service == selected.name or edge.to_service == selected.name
                ]
                involved = sorted({selected.name} | {edge.from_service for edge in edges} | {edge.to_service for edge in edges})
                result = render_graph_json(involved, edges, [], cross_module_data_available=True)
                typer.echo(json.dumps(result) if json_output else render_graph_text(result))
            elif arguments[0] == "properties":
                result = {"name": selected.name, "properties_example": selected.configuration_example}
                typer.echo(json.dumps(result) if json_output else selected.configuration_example.rstrip())
            else:
                _render_openapi_contracts(selected.name, selected.path, json_output)
        return
    if len(arguments) > 1:
        typer.echo("Usage : `cccr modules [module]` ou `cccr modules <endpoints|flow|properties|openapi> <module>`.", err=True)
        raise typer.Exit(code=2)
    module = arguments[0] if arguments else None
    repo_root = Path.cwd().resolve()
    if not db_path(repo_root).is_file():
        typer.echo("Index absent : lancez d'abord `cccr index` dans ce répertoire.", err=True)
        raise typer.Exit(code=2)
    try:
        with Store(repo_root, readonly=True) as store:
            modules = store.all_modules()
    except StoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if module is None:
        result = render_modules_list_json(modules)
        typer.echo(json.dumps(result) if json_output else render_modules_list_text(result))
        return
    matches = [item for item in modules if item.name == module]
    if not matches:
        typer.echo(f"Module introuvable : {module}", err=True)
        raise typer.Exit(code=2)
    if len(matches) > 1:
        paths = ", ".join(str(item.path) for item in matches)
        typer.echo(f"Module ambigu : {module} ({paths})", err=True)
        raise typer.Exit(code=2)
    selected = matches[0]
    result = render_module_detail_json(selected)
    typer.echo(json.dumps(result) if json_output else render_module_detail_text(result))


def _selected_indexed_module(name: str, repo_root: Path):
    if not db_path(repo_root).is_file():
        typer.echo("Index absent : lancez d'abord `cccr index` dans ce répertoire.", err=True)
        raise typer.Exit(code=2)
    try:
        with Store(repo_root, readonly=True) as store:
            matches = [item for item in store.all_modules() if item.name == name]
    except StoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if not matches:
        typer.echo(f"Module introuvable : {name}", err=True)
        raise typer.Exit(code=2)
    if len(matches) > 1:
        paths = ", ".join(str(item.path) for item in matches)
        typer.echo(f"Module ambigu : {name} ({paths})", err=True)
        raise typer.Exit(code=2)
    return matches[0]
@app.command(name="flow")
def flow_cmd(
    query: str,
    workspace: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--workspace",
        help="Répertoire parent Maven/Gradle à fédérer (BACKLOG-11 A2) pour tracer "
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
    Maven ou service Gradle si l'index couvre un répertoire multi-modules
    (BACKLOG-13/15) ;
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
            warnings = []
            repo_warning = _current_repo_endpoint_warning(store)
            if repo_warning is not None:
                warnings.append(repo_warning)
            try:
                result = trace_flow(query, endpoints_by_service, findings_by_service, warnings)
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
                result = trace_flow(
                    fallback_topic, endpoints_by_service, findings_by_service, warnings
                )

    rendered = render_flow_json(result)
    if json_output:
        typer.echo(json.dumps(rendered))
    else:
        typer.echo(render_flow_text(rendered))


@app.command(name="mcp")
def mcp_cmd() -> None:
    """Lance le serveur MCP (stdio) exposant les findings du repo courant.

    Enregistrement client (ex. Claude Code), à ajouter à la config MCP :

    {"mcpServers": {"cccr": {"command": "cccr", "args": ["mcp"]}}}
    """
    from ccc_radar.mcp_server import mcp as fastmcp_app

    fastmcp_app.run()


if __name__ == "__main__":
    app()
