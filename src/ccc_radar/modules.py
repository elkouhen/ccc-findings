"""Inventaire de tous les modules Maven et Gradle d'un workspace."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from tree_sitter import Language, Parser
import tree_sitter_java

from ccc_radar.gradle import discover_gradle_modules
from ccc_radar.maven import parse_pom, pom_version
from ccc_radar.configuration import service_configuration_example


@dataclass(frozen=True)
class DiscoveredModule:
    name: str
    path: Path
    build_system: str  # maven | gradle
    version: str | None
    kind: str  # library | aggregator
    starts_application: bool
    configuration_example: str
    application_entrypoint: "SourceEvidence | None" = None
    mongo_collections: tuple[str, ...] = ()
    mongo_methods: tuple["MongoMethod", ...] = ()
    openapi_files: tuple[str, ...] = ()
    kafka_methods: tuple["KafkaMethod", ...] = ()
    blocking_points: tuple["BlockingPoint", ...] = ()


@dataclass(frozen=True)
class MongoMethod:
    operation: str
    receiver: str
    path: str
    line: int
    collection: str | None = None
    evidence: "SourceEvidence | None" = None


@dataclass(frozen=True)
class KafkaMethod:
    role: str  # send | receive
    mechanism: str
    method: str
    path: str
    line: int
    topic: str | None = None
    evidence: "SourceEvidence | None" = None


@dataclass(frozen=True)
class BlockingPoint:
    mechanism: str
    method: str
    path: str
    line: int
    detail: str
    evidence: "SourceEvidence | None" = None


@dataclass(frozen=True)
class SourceEvidence:
    start_line: int
    end_line: int
    snippet: str
    source_hash: str


class JavaArchitectureExtension(Protocol):
    """Extension d'inventaire appliquée aux sources Java de production."""

    name: str

    def extract(self, files: list[tuple[str, bytes]]) -> tuple[KafkaMethod, ...]: ...


_DOCUMENT_COLLECTION_RE = re.compile(
    r"@(?:[\w.]+\.)?Document\s*\(\s*(?:collection\s*=\s*)?[\"']([^\"']+)[\"']"
)
_DOCUMENT_CLASS_RE = re.compile(
    r"@(?:[\w.]+\.)?Document\s*\(\s*(?:collection\s*=\s*)?[\"']([^\"']+)[\"'][^)]*\)"
    r"\s*(?:public\s+)?(?:final\s+)?(?:class|record)\s+(\w+)",
    re.DOTALL,
)
_MONGO_REPOSITORY_DECLARATION_RE = re.compile(
    r"\binterface\s+(\w+)\b.*?\b(?:MongoRepository|ReactiveMongoRepository)\s*<\s*([A-Za-z_]\w*)",
    re.DOTALL,
)
_REPOSITORY_FIELD_RE = re.compile(
    r"\b([A-Za-z_]\w*)(?:\s*<\s*([A-Za-z_]\w*)[^>]*>)?\s+([A-Za-z_]\w*)\s*(?:=|;|,)"
)
_JAVA_RECEIVER_CALL_RE = re.compile(
    r"\s*(?:this\s*\.\s*)?([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\("
)
_MONGO_TEMPLATE_OPERATIONS = frozenset({
    "aggregate", "bulkOps", "count", "exists", "find", "findAll", "findAndModify",
    "findAndReplace", "findById", "findOne", "getCollection", "insert", "remove",
    "save", "updateFirst", "updateMulti", "upsert", "watch",
})
_REPOSITORY_OPERATIONS = re.compile(
    r"^(?:save(?:All)?|insert(?:All)?|delete(?:All(?:ById)?|ById)?|find(?:All|ById|One)?|"
    r"existsById|count|aggregate)$"
)
_OPENAPI_FILENAMES = (
    "openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json",
)
_MAX_NESTED_MODULE_DEPTH = 5
_KAFKA_TOPIC_RE = re.compile(r"(?:topics?|value)\s*=\s*[\"']([^\"']+)[\"']")
_FIRST_STRING_RE = re.compile(r"\(\s*[\"']([^\"']+)[\"']")


def _java_parser() -> Parser:
    parser = Parser()
    parser.language = Language(tree_sitter_java.language())
    return parser


def _starts_application(module_dir: Path) -> SourceEvidence | None:
    """Return whether this build module owns a Spring Boot entry point.

    The decision belongs to module parsing, independently of Maven/Gradle. It
    uses Java method boundaries from Tree-sitter and only recognises a
    ``main`` method that invokes ``SpringApplication.run``.
    """
    source_roots = sorted(module_dir.glob("**/src/main/java"))
    if not source_roots:
        return None
    parser = _java_parser()
    for source_root in source_roots:
        for path in source_root.rglob("*.java"):
            try:
                source = path.read_bytes()
            except OSError:
                continue
            tree = parser.parse(source)
            if tree.root_node.has_error:
                continue
            for node in _walk(tree.root_node):
                if node.type != "method_declaration":
                    continue
                name = node.child_by_field_name("name")
                if name is None or _node_text(source, name) != "main":
                    continue
                for invocation in _walk(node):
                    if invocation.type == "method_invocation" and "SpringApplication.run" in _node_text(source, invocation):
                        return _source_evidence(source, invocation, _module_relative(module_dir, path))
    return None


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _node_text(source: bytes, node) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _source_evidence(source: bytes, node, rel_path: str) -> SourceEvidence:
    snippet = _node_text(source, node)
    digest = hashlib.sha256(f"{rel_path}|{node.type}|{snippet}".encode()).hexdigest()
    return SourceEvidence(
        start_line=node.start_point.row + 1,
        end_line=node.end_point.row + 1,
        snippet=snippet,
        source_hash=f"sha256:{digest}",
    )


def _module_relative(module_dir: Path, path: Path) -> str:
    return path.relative_to(module_dir).as_posix()


def _module_files(module_dir: Path, module_roots: set[Path], pattern: str):
    """Yield files owned by this module, never files of nested modules."""
    for path in sorted(module_dir.rglob(pattern)):
        if not path.is_file():
            continue
        if any(parent in module_roots and parent != module_dir for parent in path.parents):
            continue
        yield path


def _is_module_within_depth(root: Path, module_dir: Path) -> bool:
    return len(module_dir.relative_to(root).parts) <= _MAX_NESTED_MODULE_DEPTH


class KafkaArchitectureExtension:
    """Extrait les usages Kafka sans dépendre des extracteurs Mongo/JPA."""

    name = "kafka"

    def extract(self, files: list[tuple[str, bytes]]) -> tuple[KafkaMethod, ...]:
        parser = _java_parser()
        methods: set[KafkaMethod] = set()
        for rel, source in files:
            source_text = source.decode("utf-8", errors="replace")
            tree = parser.parse(source)
            if tree.root_node.has_error:
                continue
            has_kafka_consumer = "KafkaConsumer" in source_text
            has_kafka_producer = "KafkaProducer" in source_text
            for method_node in _walk(tree.root_node):
                if method_node.type != "method_declaration":
                    continue
                method_name_node = method_node.child_by_field_name("name")
                if method_name_node is None:
                    continue
                method_name = _node_text(source, method_name_node)
                for annotation_node in _walk(method_node):
                    if annotation_node.type != "annotation":
                        continue
                    annotation = _node_text(source, annotation_node)
                    if "KafkaListener" in annotation or "KafkaHandler" in annotation:
                        topic_match = _KAFKA_TOPIC_RE.search(annotation)
                        methods.add(KafkaMethod(
                            role="receive", mechanism="spring-kafka-listener", method=method_name,
                            path=rel, line=method_node.start_point.row + 1,
                            topic=topic_match.group(1) if topic_match else None,
                            evidence=_source_evidence(source, annotation_node, rel),
                        ))
                    if "@SendTo" in annotation:
                        topic_match = _FIRST_STRING_RE.search(annotation)
                        methods.add(KafkaMethod(
                            role="send", mechanism="spring-kafka-send-to", method=method_name,
                            path=rel, line=method_node.start_point.row + 1,
                            topic=topic_match.group(1) if topic_match else None,
                            evidence=_source_evidence(source, annotation_node, rel),
                        ))
                for invocation in _walk(method_node):
                    if invocation.type != "method_invocation":
                        continue
                    invocation_text = _node_text(source, invocation)
                    call_match = _JAVA_RECEIVER_CALL_RE.match(invocation_text)
                    if call_match is None:
                        continue
                    receiver, operation = call_match.groups()
                    topic_match = _FIRST_STRING_RE.search(invocation_text)
                    topic = topic_match.group(1) if topic_match else None
                    mechanism: str | None = None
                    role: str | None = None
                    if operation in {"send", "sendDefault"} and (
                        receiver.lower().endswith("kafkatemplate") or "KafkaTemplate" in source_text
                    ):
                        role, mechanism = "send", "spring-kafka-template"
                    elif operation == "send" and has_kafka_producer:
                        role, mechanism = "send", "kafka-clients-producer"
                    elif operation == "send" and receiver.lower().endswith("streambridge"):
                        role, mechanism = "send", "spring-cloud-stream"
                    elif operation == "to" and ("StreamsBuilder" in source_text or "KStream" in source_text):
                        role, mechanism = "send", "kafka-streams"
                    elif operation == "poll" and has_kafka_consumer:
                        role, mechanism = "receive", "kafka-clients-poll"
                    elif operation == "stream" and ("StreamsBuilder" in source_text or "KStream" in source_text):
                        role, mechanism = "receive", "kafka-streams"
                    if role is not None and mechanism is not None:
                        methods.add(KafkaMethod(
                            role=role, mechanism=mechanism, method=method_name,
                            path=rel, line=invocation.start_point.row + 1, topic=topic,
                            evidence=_source_evidence(source, invocation, rel),
                        ))
        return tuple(sorted(methods, key=lambda item: (item.path, item.line, item.role, item.mechanism)))


JAVA_ARCHITECTURE_EXTENSIONS: tuple[JavaArchitectureExtension, ...] = (KafkaArchitectureExtension(),)


def _extract_java_architecture(
    module_dir: Path, module_roots: set[Path]
) -> tuple[tuple[str, ...], tuple[MongoMethod, ...], tuple[KafkaMethod, ...], tuple[BlockingPoint, ...]]:
    """Extract Mongo facts from Java syntax trees.

    This deliberately uses AST node boundaries rather than line regexes: comments,
    strings and nested expressions cannot masquerade as annotations or calls. Symbol
    resolution remains out of scope, so each extracted method retains its receiver and
    an optional collection only when a literal is statically present.
    """
    parser = _java_parser()
    java_files = list(_module_files(module_dir, module_roots, "*.java"))
    production_files: list[tuple[Path, str, bytes]] = []
    collections: set[str] = set()
    entity_collections: dict[str, str] = {}
    repository_entities: dict[str, str] = {}
    for path in java_files:
        rel = _module_relative(module_dir, path)
        segments = rel.split("/")
        if any(
            segment == "src" and index + 1 < len(segments)
            and (segments[index + 1] == "test" or segments[index + 1].endswith("Test"))
            for index, segment in enumerate(segments)
        ):
            continue
        try:
            source = path.read_bytes()
        except OSError:
            continue
        source_text = source.decode("utf-8", errors="replace")
        production_files.append((path, rel, source))
        for collection, entity in _DOCUMENT_CLASS_RE.findall(source_text):
            collections.add(collection)
            entity_collections[entity] = collection
        for repository, entity in _MONGO_REPOSITORY_DECLARATION_RE.findall(source_text):
            repository_entities[repository] = entity

    methods: set[MongoMethod] = set()
    kafka_methods = next(
        extension.extract([(rel, source) for _, rel, source in production_files])
        for extension in JAVA_ARCHITECTURE_EXTENSIONS
        if extension.name == "kafka"
    )
    blocking_points: set[BlockingPoint] = set()
    for path, rel, source in production_files:
        source_text = source.decode("utf-8", errors="replace")
        tree = parser.parse(source)
        if tree.root_node.has_error:
            continue
        repository_receivers: dict[str, str | None] = {}
        for node in _walk(tree.root_node):
            if node.type == "field_declaration":
                text = _node_text(source, node)
                for type_name, generic_entity, receiver in _REPOSITORY_FIELD_RE.findall(text):
                    entity = repository_entities.get(type_name) or generic_entity
                    if entity and (
                        type_name in repository_entities
                        or type_name in {"MongoRepository", "ReactiveMongoRepository"}
                    ):
                        repository_receivers[receiver] = entity_collections.get(entity)
                if "CrudRepository" in text:
                    for receiver in re.findall(r"\b([A-Za-z_]\w*)\s*(?:=|;|,)", text):
                        repository_receivers.setdefault(receiver, None)
            elif node.type == "annotation":
                match = _DOCUMENT_COLLECTION_RE.search(_node_text(source, node))
                if match:
                    collections.add(match.group(1))
        for method_node in _walk(tree.root_node):
            if method_node.type != "method_declaration":
                continue
            method_name_node = method_node.child_by_field_name("name")
            if method_name_node is None:
                continue
            method_name = _node_text(source, method_name_node)
            method_text = _node_text(source, method_node)
            for invocation in _walk(method_node):
                if invocation.type != "method_invocation":
                    continue
                invocation_text = _node_text(source, invocation)
                call_match = _JAVA_RECEIVER_CALL_RE.match(invocation_text)
                if call_match is None:
                    continue
                receiver, operation = call_match.groups()
                blocking_mechanism: str | None = None
                detail: str | None = None
                if receiver == "Thread" and operation == "sleep":
                    blocking_mechanism, detail = "thread-sleep", "Thread.sleep"
                elif operation == "wait":
                    blocking_mechanism, detail = "object-wait", "Object.wait"
                elif operation == "get" and any(token in receiver.lower() for token in ("future", "result", "promise")):
                    blocking_mechanism, detail = "future-get", "Future.get sans analyse de timeout"
                elif operation == "join" and any(token in receiver.lower() for token in ("thread", "future", "task")):
                    blocking_mechanism, detail = "thread-or-future-join"
                elif operation in {"lock", "lockInterruptibly"}:
                    blocking_mechanism, detail = "jvm-lock", operation
                elif operation in {"findAndModify", "findOneAndUpdate"} and "lock" in method_text.casefold():
                    blocking_mechanism, detail = "mongo-pessimistic-lock", operation
                if blocking_mechanism is not None and detail is not None:
                    blocking_points.add(BlockingPoint(
                        mechanism=blocking_mechanism, method=method_name, path=rel,
                        line=invocation.start_point.row + 1, detail=detail,
                        evidence=_source_evidence(source, invocation, rel),
                    ))
            for statement in _walk(method_node):
                if statement.type == "synchronized_statement":
                    blocking_points.add(BlockingPoint(
                        mechanism="jvm-synchronized", method=method_name, path=rel,
                        line=statement.start_point.row + 1, detail="synchronized block",
                        evidence=_source_evidence(source, statement, rel),
                    ))
        for node in _walk(tree.root_node):
            if node.type != "method_invocation":
                continue
            text = _node_text(source, node)
            match = _JAVA_RECEIVER_CALL_RE.match(text)
            if match is None:
                continue
            receiver, operation = match.groups()
            is_template = receiver.lower().endswith(("template", "operations"))
            is_repository = receiver in repository_receivers
            if (is_template and operation in _MONGO_TEMPLATE_OPERATIONS) or (
                is_repository and _REPOSITORY_OPERATIONS.match(operation)
            ):
                literal = re.search(r"getCollection\s*\(\s*[\"']([^\"']+)[\"']", text)
                methods.add(MongoMethod(
                    operation=operation,
                    receiver=receiver,
                    path=rel,
                    line=node.start_point.row + 1,
                    collection=literal.group(1) if literal else repository_receivers.get(receiver),
                    evidence=_source_evidence(source, node, rel),
                ))
    return (
        tuple(sorted(collections)),
        tuple(sorted(methods, key=lambda item: (item.path, item.line, item.operation))),
        kafka_methods,
        tuple(sorted(blocking_points, key=lambda item: (item.path, item.line, item.mechanism))),
    )


def _discover_openapi_files(module_dir: Path, module_roots: set[Path]) -> tuple[str, ...]:
    return tuple(
        _module_relative(module_dir, path)
        for path in _module_files(module_dir, module_roots, "*")
        if path.name.casefold() in _OPENAPI_FILENAMES
    )


def _enrich_module(module: DiscoveredModule, module_roots: set[Path]) -> DiscoveredModule:
    collections, methods, kafka_methods, blocking_points = _extract_java_architecture(module.path, module_roots)
    return DiscoveredModule(
        **{**module.__dict__, "mongo_collections": collections, "mongo_methods": methods,
           "openapi_files": _discover_openapi_files(module.path, module_roots),
           "kafka_methods": kafka_methods, "blocking_points": blocking_points}
    )


def discover_modules(root: Path) -> list[DiscoveredModule]:
    """Discover build modules, including libraries and aggregators."""
    root = root.resolve()
    modules: list[DiscoveredModule] = []
    seen_paths: set[Path] = set()
    for pom_path in sorted(root.rglob("pom.xml")):
        module_dir = pom_path.parent.resolve()
        if not _is_module_within_depth(root, module_dir):
            continue
        artifact_id, _, packaging = parse_pom(pom_path)
        entrypoint = _starts_application(module_dir)
        kind = (
            "aggregator"
            if packaging == "pom"
            else "library"
        )
        modules.append(
            DiscoveredModule(
                name=artifact_id or module_dir.name,
                path=module_dir,
                build_system="maven",
                version=pom_version(pom_path),
                kind=kind,
                starts_application=packaging != "pom" and entrypoint is not None,
                configuration_example=service_configuration_example(module_dir),
                application_entrypoint=entrypoint,
            )
        )
        seen_paths.add(module_dir)
    for name, module_dir, version in discover_gradle_modules(root):
        module_dir = module_dir.resolve()
        if module_dir in seen_paths:
            continue
        has_build_file = any(
            (module_dir / filename).is_file() for filename in ("build.gradle", "build.gradle.kts")
        )
        entrypoint = _starts_application(module_dir)
        modules.append(
            DiscoveredModule(
                name=name,
                path=module_dir,
                build_system="gradle",
                version=version,
                kind=(
                    "library"
                    if has_build_file
                    else "aggregator"
                ),
                starts_application=entrypoint is not None,
                configuration_example=service_configuration_example(module_dir),
                application_entrypoint=entrypoint,
            )
        )
    module_roots = {module.path for module in modules}
    return sorted(
        (_enrich_module(module, module_roots) for module in modules),
        key=lambda module: str(module.path),
    )
