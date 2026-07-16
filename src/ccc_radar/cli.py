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
from ccc_radar.architecture import (
    analyze as analyze_architecture,
    build_catalog,
    endpoint_implementation,
    list_objects as list_architecture_objects,
    neighbors as architecture_neighbors,
    render_text as render_architecture_text,
    show_object as show_architecture_object,
    trace_topic_flows,
)
from ccc_radar.code_search import search_code_with_findings
from ccc_radar.audit import assess_architecture, render_audit_json, render_audit_text
from ccc_radar.config import ConfigError, init_config, load_config
from ccc_radar.embedder import EmbeddingError, make_embedder, resolve_embedding_model
from ccc_radar.coco_indexer import index_repo_with_cocoindex
from ccc_radar.flow import (
    resolve_topic,
    resolve_topic_by_similarity,
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
from ccc_radar.modules import discover_modules
from ccc_radar.render import (
    render_code_search_text,
    render_endpoints_json,
    render_endpoints_text,
    render_fallback_findings_text,
    render_graph_d2,
    render_graph_drawio,
    render_graph_html,
    render_graph_json,
    render_graph_text,
    render_module_detail_json,
    render_module_detail_text,
    render_module_graph_drawio,
    render_module_graph_html,
    render_module_graph_json,
    render_module_graph_text,
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
    help="Explorer l'architecture et les constats d'un projet indexé."
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


def _manifest_rel_paths(repo_root: Path, paths: list[Path]) -> list[str]:
    manifests: list[str] = []
    seen: set[str] = set()
    for raw_path in paths:
        path = raw_path.expanduser()
        if not path.is_absolute():
            path = repo_root / path
        try:
            rel_path = path.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError as exc:
            raise typer.BadParameter(
                f"Le manifeste doit être dans le dépôt indexé : {raw_path}"
            ) from exc
        if not path.is_file():
            raise typer.BadParameter(f"Manifeste introuvable : {raw_path}")
        if path.suffix.lower() != ".md":
            raise typer.BadParameter(f"Le manifeste doit être un fichier Markdown .md : {raw_path}")
        if rel_path not in seen:
            seen.add(rel_path)
            manifests.append(rel_path)
    return manifests


@app.callback()
def main() -> None:
    """ccc-radar: indexe findings, code associé et signaux d'architecture."""


def _emit_architecture(result: object, json_output: bool) -> None:
    typer.echo(json.dumps(result) if json_output else render_architecture_text(result))


@app.command(name="topics")
def topics_cmd(
    arguments: list[str] = typer.Argument(
        None, help="Commande : list, show, neighbors, consumers, producers, search ou trace."
    ),
    root: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--root", help="Répertoire parent indexé. Défaut : répertoire courant."
    ),
    json_output: bool = typer.Option(False, "--json"),
    max_depth: int = typer.Option(6, "--max-depth", min=1, max=12, help="Nombre maximal de services suivis par trace."),
    limit: int = typer.Option(50, "--limit", min=1, max=200, help="Nombre maximal de chemins retournés par trace."),
) -> None:
    """Parcourir les topics Kafka et les services qui les publient ou consomment."""
    arguments = arguments or []
    workspace_root = (root or Path.cwd()).resolve()
    catalog = _microservice_catalog(workspace_root)
    if not arguments or arguments[0] == "list":
        if len(arguments) > 1:
            typer.echo("Usage : `cccr topics [list] --root <workspace>`.", err=True)
            raise typer.Exit(code=2)
        _emit_architecture(list_architecture_objects(catalog, "topic"), json_output)
        return
    command = arguments[0]
    if command in {"show", "neighbors", "consumers", "producers", "search", "trace"}:
        if len(arguments) != 2:
            typer.echo(f"`cccr topics {command}` requiert un topic.", err=True)
            raise typer.Exit(code=2)
        topic = arguments[1]
        if command == "show":
            result = show_architecture_object(catalog, "topic", topic)
        elif command == "neighbors":
            result = architecture_neighbors(catalog, "topic", topic)
        elif command == "search":
            result = _search_architecture_object(workspace_root, catalog, "topic", "kafka", topic)
        elif command == "trace":
            result = trace_topic_flows(catalog, topic, max_depth=max_depth, limit=limit)
        else:
            result = analyze_architecture(catalog, command, topic)
        if result is None:
            typer.echo(f"Topic introuvable : {topic}", err=True)
            raise typer.Exit(code=2)
        _emit_architecture(result, json_output)
        return
    typer.echo("Usage : `cccr topics [list|show|neighbors|consumers|producers|search|trace] [topic]`.", err=True)
    raise typer.Exit(code=2)


@app.command(name="apis")
def apis_cmd(
    arguments: list[str] = typer.Argument(
        None, help="Commande : list, show, neighbors, providers, consumers ou search."
    ),
    root: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--root", help="Répertoire parent indexé. Défaut : répertoire courant."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Parcourir les APIs HTTP et les services qui les exposent ou appellent."""
    arguments = arguments or []
    workspace_root = (root or Path.cwd()).resolve()
    catalog = _microservice_catalog(workspace_root)
    if not arguments or arguments[0] == "list":
        if len(arguments) > 1:
            typer.echo("Usage : `cccr apis [list] --root <workspace>`.", err=True)
            raise typer.Exit(code=2)
        _emit_architecture(list_architecture_objects(catalog, "api"), json_output)
        return
    command = arguments[0]
    if command in {"show", "neighbors", "providers", "consumers", "search"}:
        if len(arguments) != 2:
            typer.echo(f"`cccr apis {command}` requiert une API HTTP.", err=True)
            raise typer.Exit(code=2)
        api = arguments[1]
        if command == "show":
            result = show_architecture_object(catalog, "api", api)
        elif command == "neighbors":
            result = architecture_neighbors(catalog, "api", api)
        elif command == "search":
            result = _search_architecture_object(workspace_root, catalog, "api", "rest", api)
        else:
            summary = show_architecture_object(catalog, "api", api)
            result = (
                {"query": command, "api": api, "microservices": summary[command]}
                if summary is not None
                else None
            )
        if result is None:
            typer.echo(f"API HTTP introuvable : {api}", err=True)
            raise typer.Exit(code=2)
        _emit_architecture(result, json_output)
        return
    typer.echo("Usage : `cccr apis [list|show|neighbors|providers|consumers|search] [api]`.", err=True)
    raise typer.Exit(code=2)


@app.command(name="resources", hidden=True)
def resources_alias(
    arguments: list[str] = typer.Argument(None),
    root: Optional[Path] = typer.Option(None, "--root"),  # noqa: UP007
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Alias de compatibilité de `cccr apis`."""
    apis_cmd(arguments, root, json_output)


@app.command(name="mongodb")
def mongodb_cmd(
    arguments: list[str] = typer.Argument(
        None, help="Commande : list, show, neighbors, services ou search."
    ),
    root: Optional[Path] = typer.Option(  # noqa: UP007
        None, "--root", help="Répertoire parent indexé. Défaut : répertoire courant."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Parcourir les collections MongoDB et les microservices qui les utilisent."""
    arguments = arguments or []
    catalog = _microservice_catalog((root or Path.cwd()).resolve())
    if not arguments or arguments[0] == "list":
        if len(arguments) > 1:
            typer.echo("Usage : `cccr mongodb [list] --root <workspace>`.", err=True)
            raise typer.Exit(code=2)
        _emit_architecture(list_architecture_objects(catalog, "collection"), json_output)
        return
    command = arguments[0]
    if command not in {"show", "neighbors", "services", "search"} or len(arguments) != 2:
        typer.echo("Usage : `cccr mongodb [list|show|neighbors|services|search] [collection]`.", err=True)
        raise typer.Exit(code=2)
    collection = arguments[1]
    if command == "show":
        result = show_architecture_object(catalog, "collection", collection)
    elif command == "neighbors":
        result = architecture_neighbors(catalog, "collection", collection)
    elif command == "services":
        result = _mongodb_services(catalog, collection)
    else:
        result = _search_mongodb_collection(catalog, collection)
    if result is None:
        typer.echo(f"Collection MongoDB introuvable : {collection}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(result, json_output)


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
    manifest_args: Optional[list[Path]] = typer.Argument(  # noqa: UP007
        None, help="Manifeste(s) Markdown de topics Kafka à indexer explicitement."
    ),
    full: bool = typer.Option(False, "--full", help="Force un scan complet."),
    manifests: Optional[list[Path]] = typer.Option(  # noqa: UP007
        None, "--manifest", help="Manifeste Markdown de topics Kafka (répétable)."
    ),
    engine: Literal["manual", "cocoindex"] = typer.Option(
        "manual",
        "--engine",
        help="Moteur d'indexation : manual (défaut) ou cocoindex (expérimental).",
    ),
    disable: list[str] = typer.Option(
        None,
        "--disable",
        help=(
            "Type à désactiver : semgrep, properties, module-architecture "
            "ou module-tree-sitter. Répétable."
        ),
    ),
) -> None:
    """Indexe le code et les findings du projet (incrémental par défaut)."""
    repo_root = Path.cwd()
    _trace_index("cli.index.begin", root=repo_root, full=full, engine=engine)
    explicit_manifests = _manifest_rel_paths(repo_root, list(manifest_args or []) + list(manifests or []))
    disabled = frozenset(disable or [])
    known_disabled = {"semgrep", "properties", "module-architecture", "module-tree-sitter"}
    unknown = disabled - known_disabled
    if unknown:
        typer.echo(
            "Type d'indexation inconnu : "
            f"{', '.join(sorted(unknown))}. Valeurs : {', '.join(sorted(known_disabled))}.",
            err=True,
        )
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
                if explicit_manifests:
                    typer.echo(
                        "--manifest n'est pas supporté avec --engine cocoindex ; utilisez --engine manual.",
                        err=True,
                    )
                    raise typer.Exit(code=2)
                report = index_repo_with_cocoindex(
                    repo_root, config, store, embedder, full=full,
                    progress=_echo_index_progress, disabled=disabled,
                )
            else:
                report = index_repo(
                    repo_root, config, store, embedder, full=full, progress=_echo_index_progress,
                    disabled=disabled, extra_files=explicit_manifests,
                )
                store.set_meta("index_engine", "manual")
            _trace_index("store.close.begin")
    except (SemgrepError, EmbeddingError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(
        f"scanned={report.scanned} skipped={report.skipped} "
        f"+findings={report.findings_added} -findings={report.findings_removed} "
        f"+integrations={report.endpoints_added} -integrations={report.endpoints_removed}"
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


@app.command(name="integrations")
def integrations_cmd(
    system: Optional[str] = typer.Option(None, "--system"),  # noqa: UP007
    role: Optional[str] = typer.Option(None, "--role"),  # noqa: UP007
    topic: Optional[str] = typer.Option(None, "--topic"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    module: Optional[str] = typer.Option(  # noqa: UP007
        None, "--module", help="Nom du module Maven (artifactId, BACKLOG-13)."
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Lister les intégrations HTTP et Kafka détectées dans le projet indexé."""
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


@app.command(name="endpoints", hidden=True)
def endpoints_alias(
    system: Optional[str] = typer.Option(None, "--system"),  # noqa: UP007
    role: Optional[str] = typer.Option(None, "--role"),  # noqa: UP007
    topic: Optional[str] = typer.Option(None, "--topic"),  # noqa: UP007
    path: Optional[str] = typer.Option(None, "--path"),  # noqa: UP007
    module: Optional[str] = typer.Option(None, "--module"),  # noqa: UP007
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Alias de compatibilité de `cccr integrations`."""
    integrations_cmd(system, role, topic, path, module, json_output)


@app.command(name="graph")
def graph_cmd(
    workspace: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--workspace",
        help="Répertoire contenant plusieurs services indexés séparément.",
    ),
    json_output: bool = typer.Option(False, "--json"),
    drawio: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--drawio",
        help="Exporter le graphe au format Draw.io.",
    ),
    html: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--html",
        help="Exporter un graphe HTML interactif.",
    ),
    d2: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--d2",
        help="Exporter le graphe en D2 ou dans un format rendu par D2.",
    ),
    d2_layout: Literal["dagre", "elk"] = typer.Option(
        "elk",
        "--d2-layout",
        help="Moteur de placement D2 pour les formats rendus.",
    ),
    include_mongodb: bool = typer.Option(
        False,
        "--include-mongodb",
        help="Ajoute les collections MongoDB indexées aux exports Draw.io, HTML et D2.",
    ),
) -> None:
    """Afficher ou exporter les interactions HTTP et Kafka entre microservices.

    Ajoutez `--include-mongodb` pour afficher aussi les collections MongoDB.
    Utilisez `--workspace` lorsque les services sont indexés séparément.
    """
    repo_root = Path.cwd()
    _require_index(repo_root)
    if sum(output is not None for output in (drawio, html, d2)) > 1:
        typer.echo("Choisissez un seul rendu parmi --drawio, --html ou --d2.", err=True)
        raise typer.Exit(code=2)

    with Store(repo_root) as store:
        endpoints = store.all_endpoints()
        repo_warning = _current_repo_endpoint_warning(store)
        indexed_modules = store.all_modules() if include_mongodb else []

    outbound_calls = find_outbound_calls_in_consumers(endpoints)

    services_by_name: dict[str, list[MessageEndpoint]] = {}
    edges: list[GraphEdge] = []
    warnings: list[str] = [repo_warning] if repo_warning else []
    collections_by_service: dict[str, list[str]] = {}
    cross_module_data_available = False
    if workspace is not None:
        discovered = discover_maven_services(workspace)
        federation = load_federation(discovered)
        warnings.extend(federation.warnings)
        services_by_name = federation.endpoints_by_service
        edges = build_graph(services_by_name)
        if include_mongodb:
            collections_by_service = {
                service: list(module.mongo_collections)
                for service, module in federation.modules_by_service.items()
                if service in services_by_name and module.mongo_collections
            }
        cross_module_data_available = True
    else:
        grouped_endpoints = group_endpoints_by_module(endpoints)
        if grouped_endpoints:
            services_by_name = grouped_endpoints
            edges = build_graph(grouped_endpoints)
            if include_mongodb:
                collections_by_service = {
                    module.name: list(module.mongo_collections)
                    for module in indexed_modules
                    if module.name in services_by_name and module.mongo_collections
                }
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
            render_graph_drawio(services_by_name, edges, collections_by_service), encoding="utf-8"
        )
        typer.echo(f"Graphe écrit dans {drawio} ({len(services_by_name)} services, {len(edges)} arêtes).")
        if result["note"]:
            typer.echo(result["note"])
        return

    if html is not None:
        html.write_text(
            render_graph_html(services_by_name, edges, collections_by_service), encoding="utf-8"
        )
        typer.echo(f"Graphe écrit dans {html} ({len(services_by_name)} services, {len(edges)} arêtes).")
        if result["note"]:
            typer.echo(result["note"])
        return

    if d2 is not None:
        try:
            write_graph_d2(
                d2,
                render_graph_d2(services_by_name, edges, collections_by_service),
                layout=d2_layout,
            )
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
    """Signaler les risques et responsabilités d'architecture détectés."""
    repo_root = Path.cwd()
    _require_index(repo_root)
    if workspace is not None:
        federation = load_federation(discover_maven_services(workspace))
        endpoints_by_service = dict(federation.endpoints_by_service)
        endpoints_by_module = dict(federation.endpoints_by_module)
        modules = list(federation.modules_by_service.values())
    else:
        with Store(repo_root, readonly=True) as store:
            endpoints_by_module = group_endpoints_by_module(store.all_endpoints())
            modules = store.all_modules()
        endpoints_by_service = endpoints_by_module
    risks = assess_architecture(
        endpoints_by_service,
        build_graph(endpoints_by_service),
        modules=modules,
        endpoints_by_module=endpoints_by_module,
    )
    typer.echo(json.dumps(render_audit_json(risks)) if json_output else render_audit_text(risks))


@app.command(name="microservices")
def microservices_cmd(
    arguments: list[str] = typer.Argument(
        None,
        help="Nom d'un service, ou commande : show, topics, apis, mongodb, neighbors ou analyze.",
    ),
    root: Optional[Path] = typer.Option(  # noqa: UP007
        None,
        "--root", help="Répertoire parent à explorer. Défaut : répertoire courant.",
    ),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Lister les microservices ou résumer un microservice.

    Exemples : `cccr microservices`, `cccr microservices orders`,
    `cccr microservices topics orders`, `cccr microservices apis orders`,
    `cccr microservices mongodb orders`.
    """
    arguments = arguments or []
    commands = {
        "topics", "apis", "resources", "mongodb", "properties", "openapi", "show", "neighbors", "analyze", "implementation"
    }
    if arguments and arguments[0] in commands:
        workspace_root = (root or Path.cwd()).resolve()
        command = arguments[0]
        if command in {"topics", "apis", "resources", "mongodb", "properties", "openapi", "show"}:
            if len(arguments) != 2:
                typer.echo(f"`microservices {command}` requiert un nom de microservice.", err=True)
                raise typer.Exit(code=2)
            service = arguments[1]
        elif command == "neighbors":
            if len(arguments) != 2:
                typer.echo("`microservices neighbors` requiert un nom de microservice.", err=True)
                raise typer.Exit(code=2)
        elif command == "implementation":
            if len(arguments) != 3:
                typer.echo(f"`microservices {command}` requiert un type et un nom.", err=True)
                raise typer.Exit(code=2)
        elif len(arguments) not in {2, 3}:
            typer.echo("`microservices analyze` requiert une question et accepte une cible optionnelle.", err=True)
            raise typer.Exit(code=2)
        if command == "topics":
            _render_microservice_topics(service, workspace_root, json_output)
        elif command in {"apis", "resources"}:
            _render_microservice_apis(service, workspace_root, json_output)
        elif command == "mongodb":
            _render_microservice_mongodb(service, workspace_root, json_output)
        elif command == "properties":
            _render_microservice_properties(service, workspace_root, json_output)
        elif command == "openapi":
            _render_microservice_openapi(service, workspace_root, json_output)
        elif command == "show":
            _render_microservice_summary(service, workspace_root, json_output)
        elif command == "neighbors":
            _render_microservice_neighbors(arguments[1], workspace_root, json_output)
        elif command == "analyze":
            _render_microservice_analysis(
                arguments[1], arguments[2] if len(arguments) == 3 else None, workspace_root, json_output
            )
        else:
            _render_microservice_implementation(arguments[1], arguments[2], workspace_root, json_output)
        return
    if len(arguments) == 1:
        argument = arguments[0]
        explicit_workspace = (
            Path(argument).is_absolute() or argument in {".", ".."} or argument.startswith(f".{os.sep}")
        )
        if not explicit_workspace:
            _render_microservice_summary(argument, (root or Path.cwd()).resolve(), json_output)
            return
    if len(arguments) > 1:
        typer.echo("Usage : `cccr microservices [--root <root>]` ou `cccr microservices <service> --root <root>`.", err=True)
        raise typer.Exit(code=2)
    workspace_root = Path(arguments[0]) if arguments else (root or Path.cwd())
    services = [
        service
        for service in discover_maven_services(workspace_root)
        if service.kind == "microservice"
    ]
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


def _microservice_catalog(root: Path):
    if db_path(root).is_file():
        with Store(root, readonly=True) as store:
            modules = store.all_modules()
            if modules:
                return build_catalog(modules, store.all_endpoints())
    services = discover_maven_services(root)
    federation = load_federation(services)
    modules = [module for module in discover_modules(root) if module.starts_application]
    endpoints = [
        endpoint
        for service_endpoints in federation.endpoints_by_service.values()
        for endpoint in service_endpoints
    ]
    return build_catalog(modules, endpoints)


def _search_architecture_object(
    root: Path, catalog, kind: str, system: str, query: str
) -> dict[str, object] | None:
    endpoints = [endpoint for endpoint in catalog.endpoints if endpoint.system == system]
    resolved = resolve_topic(query, {endpoint.topic for endpoint in endpoints})
    if resolved is None and db_path(root).is_file():
        try:
            with Store(root, readonly=True) as store:
                config = load_config(root)
                resolved = resolve_topic_by_similarity(
                    store, make_embedder(config.embedding_model), query, endpoints
                )
        except (ConfigError, EmbeddingError, StoreError):
            resolved = None
    if resolved is None:
        return None
    summary = show_architecture_object(catalog, kind, resolved)
    return {"query": query, "resolved": resolved, "object": summary} if summary else None


def _search_mongodb_collection(catalog, query: str) -> dict[str, object] | None:
    collections = {
        collection
        for module in catalog.modules
        for collection in module.mongo_collections
    }
    resolved = resolve_topic(query, collections)
    if resolved is None:
        return None
    summary = show_architecture_object(catalog, "collection", resolved)
    return {"query": query, "resolved": resolved, "object": summary} if summary else None


def _mongodb_services(catalog, collection: str) -> dict[str, object] | None:
    summary = show_architecture_object(catalog, "collection", collection)
    if summary is None:
        return None
    microservices = [
        module.name
        for module in catalog.modules
        if module.starts_application and collection in module.mongo_collections
    ]
    return {"query": "services", "collection": collection, "microservices": microservices}


def _render_microservice_summary(service: str, root: Path, json_output: bool) -> None:
    result = show_architecture_object(_microservice_catalog(root), "microservice", service)
    if result is None:
        typer.echo(f"Microservice introuvable : {service}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(result, json_output)


def _render_microservice_neighbors(name: str, root: Path, json_output: bool) -> None:
    result = architecture_neighbors(_microservice_catalog(root), "microservice", name)
    if result is None:
        typer.echo(f"Microservice introuvable : {name}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(result, json_output)


def _render_microservice_analysis(
    query: str, target: str | None, root: Path, json_output: bool
) -> None:
    if query.casefold() in {"consumers", "consumer", "producers", "producer"}:
        typer.echo("Utilisez `cccr topics consumers <topic>` ou `cccr topics producers <topic>`.", err=True)
        raise typer.Exit(code=2)
    result = analyze_architecture(_microservice_catalog(root), query, target)
    if result is None:
        typer.echo(
            "Analyse impossible : vérifiez la question et sa cible (consumers/producers/calls/"
            "external-apis/orphan-integrations/impact).",
            err=True,
        )
        raise typer.Exit(code=2)
    _emit_architecture(result, json_output)


def _render_microservice_implementation(
    kind: str, identifier: str, root: Path, json_output: bool
) -> None:
    if kind.casefold() not in {"integration", "endpoint"}:
        typer.echo("Seule l'implémentation d'une intégration est disponible.", err=True)
        raise typer.Exit(code=2)
    result = endpoint_implementation(_microservice_catalog(root), identifier)
    if result is None:
        typer.echo(f"Intégration introuvable : {identifier}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(result, json_output)


def _render_microservice_topics(service: str, root: Path, json_output: bool) -> None:
    """Liste les topics Kafka publiés et consommés par un microservice."""
    summary = show_architecture_object(_microservice_catalog(root), "microservice", service)
    if summary is None:
        typer.echo(f"Microservice introuvable : {service}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(
        {
            "microservice": service,
            "published": summary["kafka_topics_published"],
            "consumed": summary["kafka_topics_consumed"],
        },
        json_output,
    )


def _render_microservice_apis(service: str, root: Path, json_output: bool) -> None:
    """Liste les APIs HTTP exposées et appelées par un microservice."""
    summary = show_architecture_object(_microservice_catalog(root), "microservice", service)
    if summary is None:
        typer.echo(f"Microservice introuvable : {service}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(
        {
            "microservice": service,
            "exposed": summary["http_apis_exposed"],
            "consumed": summary["http_apis_consumed"],
        },
        json_output,
    )


def _render_microservice_mongodb(service: str, root: Path, json_output: bool) -> None:
    """Liste les collections MongoDB utilisées par un microservice."""
    summary = show_architecture_object(_microservice_catalog(root), "microservice", service)
    if summary is None:
        typer.echo(f"Microservice introuvable : {service}", err=True)
        raise typer.Exit(code=2)
    _emit_architecture(
        {
            "microservice": service,
            "collections": summary["databases"]["mongodb_collections"],
        },
        json_output,
    )


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
    drawio: Optional[Path] = typer.Option(
        None, "--drawio", help="Exporte le graphe de dépendances de modules en .drawio."
    ),
    html: Optional[Path] = typer.Option(
        None, "--html", help="Exporte le graphe de dépendances de modules en HTML Sigma.js."
    ),
) -> None:
    """Liste les modules indexés ou détaille l'un d'eux.

    `cccr modules` liste. `cccr modules <module>` détaille. Les sous-commandes
    `integrations`, `properties` et `openapi` prennent un module dans le
    répertoire courant déjà indexé. `graph` affiche les dépendances de build
    entre modules et accepte `--drawio` ou `--html`.
    """
    arguments = arguments or []
    commands = {"integrations", "endpoints", "properties", "openapi", "graph"}
    if arguments and arguments[0] in commands:
        if arguments[0] == "graph":
            if len(arguments) != 1:
                typer.echo("`modules graph` ne prend pas de nom de module.", err=True)
                raise typer.Exit(code=2)
            _render_module_graph(Path.cwd().resolve(), json_output, drawio, html)
            return
        if len(arguments) != 2:
            typer.echo(f"`modules {arguments[0]}` requiert un nom de module.", err=True)
            raise typer.Exit(code=2)
        repo_root = Path.cwd().resolve()
        selected = _selected_indexed_module(arguments[1], repo_root)
        with Store(repo_root, readonly=True) as store:
            if arguments[0] in {"integrations", "endpoints"}:
                endpoints = [endpoint for endpoint in store.all_endpoints() if endpoint.module == selected.name]
                typer.echo(json.dumps(render_endpoints_json(endpoints)) if json_output else render_endpoints_text(endpoints))
            elif arguments[0] == "properties":
                result = {"name": selected.name, "properties_example": selected.configuration_example}
                typer.echo(json.dumps(result) if json_output else selected.configuration_example.rstrip())
            else:
                _render_openapi_contracts(selected.name, selected.path, json_output)
        return
    if len(arguments) > 1:
        typer.echo("Usage : `cccr modules [module]` ou `cccr modules <integrations|properties|openapi> <module>` ou `cccr modules graph`.", err=True)
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


def _render_module_graph(
    repo_root: Path, json_output: bool, drawio: Path | None, html: Path | None
) -> None:
    if not db_path(repo_root).is_file():
        typer.echo("Index absent : lancez d'abord `cccr index` dans ce répertoire.", err=True)
        raise typer.Exit(code=2)
    try:
        with Store(repo_root, readonly=True) as store:
            modules = store.all_modules()
            dependencies = store.all_module_dependencies()
            endpoints = store.all_endpoints()
    except StoreError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if drawio is not None and html is not None:
        typer.echo("Choisissez un seul rendu parmi --drawio ou --html.", err=True)
        raise typer.Exit(code=2)
    if drawio is not None:
        drawio.write_text(render_module_graph_drawio(modules, dependencies), encoding="utf-8")
        typer.echo(f"Graphe écrit dans {drawio} ({len(modules)} modules, {len(dependencies)} dépendances).")
        return
    if html is not None:
        html.write_text(render_module_graph_html(modules, dependencies, endpoints), encoding="utf-8")
        typer.echo(f"Graphe écrit dans {html} ({len(modules)} modules, {len(dependencies)} dépendances).")
        return
    result = render_module_graph_json(modules, dependencies)
    typer.echo(json.dumps(result) if json_output else render_module_graph_text(result))


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
