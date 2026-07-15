import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.cli import app
from ccc_radar.config import Config
from ccc_radar.indexer import index_repo
from ccc_radar.models import MessageEndpoint
from ccc_radar.modules import discover_modules
from ccc_radar.store import Store

runner = CliRunner()


def _write_pom(path: Path, artifact: str, version: str | None, packaging: str = "jar") -> None:
    version_xml = f"<version>{version}</version>" if version is not None else ""
    path.write_text(
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
        "<modelVersion>4.0.0</modelVersion>"
        f"<artifactId>{artifact}</artifactId>{version_xml}"
        f"<packaging>{packaging}</packaging></project>"
    )


def test_discover_modules_includes_maven_aggregators_libraries_and_gradle_projects(
    tmp_path: Path,
) -> None:
    _write_pom(tmp_path / "pom.xml", "platform", "1.2.3", packaging="pom")
    library = tmp_path / "shared"
    library.mkdir()
    _write_pom(library / "pom.xml", "shared-kernel", "1.2.3")
    gradle = tmp_path / "adapter"
    gradle.mkdir()
    (gradle / "build.gradle").write_text("archivesBaseName = 'adapter-api'\nversion = '2.0.0'\n")

    modules = discover_modules(tmp_path)

    assert [(module.name, module.build_system, module.version, module.kind) for module in modules] == [
        ("platform", "maven", "1.2.3", "aggregator"),
        ("adapter-api", "gradle", "2.0.0", "library"),
        ("shared-kernel", "maven", "1.2.3", "library"),
    ]


def test_discover_modules_limits_nested_build_discovery_to_five_levels(tmp_path: Path) -> None:
    at_limit = tmp_path / "one" / "two" / "three" / "four" / "five"
    beyond_limit = at_limit / "six"
    at_limit.mkdir(parents=True)
    beyond_limit.mkdir()
    _write_pom(at_limit / "pom.xml", "at-limit", "1.0.0")
    _write_pom(beyond_limit / "pom.xml", "too-deep", "1.0.0")

    modules = discover_modules(tmp_path)

    assert [module.name for module in modules] == ["at-limit"]


def test_module_start_attribute_is_detected_from_its_java_entrypoint(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "OrdersApplication.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text(
        """import org.springframework.boot.SpringApplication;
class OrdersApplication {
  public static void main(String[] args) { SpringApplication.run(OrdersApplication.class, args); }
}
"""
    )

    modules = discover_modules(tmp_path)

    assert modules[0].kind == "library"
    assert modules[0].starts_application is True
    assert modules[0].application_entrypoint is not None
    assert modules[0].application_entrypoint.snippet.startswith("SpringApplication.run")


def test_modules_cli_lists_then_returns_module_detail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "App.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text('@Value("${server.port}") class App {}\n')
    with Store(tmp_path) as store:
        store.replace_modules(discover_modules(tmp_path))
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["modules", "--json"])

    assert result.exit_code == 0
    modules = json.loads(result.output)
    assert modules == [
        {
            "name": "orders-api",
            "path": str(module.resolve()),
            "build_system": "maven",
            "version": "3.1.0",
            "kind": "library",
            "starts_application": False,
            "mongo_collections": [],
            "mongo_method_count": 0,
            "kafka_method_count": 0,
            "blocking_point_count": 0,
            "openapi_files": [],
        }
    ]

    detail = runner.invoke(app, ["modules", "orders-api", "--json"])
    assert detail.exit_code == 0
    assert json.loads(detail.output)["configuration_example"] == "server:\n  port: 0\n"


def test_modules_index_mongo_facts_and_openapi_files_from_java_ast(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "OrderStore.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text(
        """import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.repository.MongoRepository;
@Document(collection = \"orders\") class Order {}
class OrderStore {
  MongoTemplate mongoTemplate;
  OrderRepository orderRepository;
  void save(Order order) {
    mongoTemplate.save(order);
    mongoTemplate.getCollection(\"audit\");
    orderRepository.findById(\"id\");
  }
}
interface OrderRepository extends MongoRepository<Order, String> {}
"""
    )
    contract = module / "src" / "main" / "resources" / "openapi.yaml"
    contract.parent.mkdir(parents=True)
    contract.write_text("openapi: 3.1.0\ninfo: {title: Orders, version: v1}\n")

    with Store(tmp_path) as store:
        store.replace_modules(discover_modules(tmp_path))
        indexed = store.all_modules()[0]

    assert indexed.mongo_collections == ("orders",)
    assert [(item.operation, item.receiver, item.collection) for item in indexed.mongo_methods] == [
        ("save", "mongoTemplate", None),
        ("getCollection", "mongoTemplate", "audit"),
        ("findById", "orderRepository", "orders"),
    ]
    assert indexed.openapi_files == ("src/main/resources/openapi.yaml",)
    proof = indexed.mongo_methods[0].evidence
    assert proof is not None
    assert proof.start_line == 10
    assert proof.snippet == "mongoTemplate.save(order)"
    assert proof.source_hash.startswith("sha256:")


def test_modules_resolve_injected_repository_collection_and_this_receiver(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "OrderStore.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text(
        "import org.springframework.data.mongodb.core.mapping.Document;\n"
        "import org.springframework.data.mongodb.repository.MongoRepository;\n"
        "@Document(collection = \"orders\") class Order {}\n"
        "interface OrderRepository extends MongoRepository<Order, String> {}\n"
        "class OrderStore {\n"
        "  private final OrderRepository orderRepository;\n"
        "  OrderStore(OrderRepository orderRepository) { this.orderRepository = orderRepository; }\n"
        "  void load() { this.orderRepository.findById(\"id\"); }\n"
        "}\n"
    )

    methods = discover_modules(tmp_path)[0].mongo_methods

    assert [(item.operation, item.receiver, item.collection, item.line) for item in methods] == [
        ("findById", "orderRepository", "orders", 8),
    ]


def test_modules_index_kafka_send_and_receive_methods_from_java_ast(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "OrderMessaging.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text(
        """import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.apache.kafka.clients.consumer.KafkaConsumer;
class OrderMessaging {
  KafkaTemplate<String, String> kafkaTemplate;
  KafkaConsumer<String, String> consumer;
  @KafkaListener(topics = "orders.created")
  void consume(String payload) { kafkaTemplate.send("orders.validated", payload); }
  void pollBroker() { consumer.poll(java.time.Duration.ofSeconds(1)); }
}
"""
    )

    module_info = discover_modules(tmp_path)[0]

    assert [(item.role, item.mechanism, item.method, item.topic) for item in module_info.kafka_methods] == [
        ("receive", "spring-kafka-listener", "consume", "orders.created"),
        ("send", "spring-kafka-template", "consume", "orders.validated"),
        ("receive", "kafka-clients-poll", "pollBroker", None),
    ]


def test_modules_index_blocking_points_from_java_ast(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "OrderLock.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text(
        """import org.springframework.data.mongodb.core.MongoTemplate;
class OrderLock {
  MongoTemplate mongoTemplate;
  void pause() throws InterruptedException { Thread.sleep(10); }
  void acquireLock() { mongoTemplate.findAndModify(null, null, Object.class); }
  void guarded() { synchronized (this) { mongoTemplate.findOne(null, Object.class); } }
}
"""
    )

    points = discover_modules(tmp_path)[0].blocking_points

    assert [(point.mechanism, point.method, point.detail) for point in points] == [
        ("thread-sleep", "pause", "Thread.sleep"),
        ("mongo-pessimistic-lock", "acquireLock", "findAndModify"),
        ("jvm-synchronized", "guarded", "synchronized block"),
    ]


def test_modules_cli_requires_an_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["modules", "--json"])

    assert result.exit_code == 2
    assert "Index absent" in result.output


def test_modules_cli_rejects_removed_root_and_properties_options(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["modules", "--root", str(tmp_path)])

    assert result.exit_code == 2
    assert "No such option: --root" in result.output
    properties = runner.invoke(app, ["modules", "--properties"])
    assert properties.exit_code == 2
    assert "No such option: --properties" in properties.output


def test_modules_cli_subcommands_render_endpoints_flow_properties_and_openapi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    orders = tmp_path / "orders"
    payments = tmp_path / "payments"
    for module, artifact in ((orders, "orders-api"), (payments, "payments-api")):
        (module / "src" / "main" / "resources").mkdir(parents=True)
        _write_pom(module / "pom.xml", artifact, "3.1.0")
    (orders / "src" / "main" / "resources" / "openapi.yml").write_text("openapi: 3.0.0\npaths: {}\n")
    call = MessageEndpoint("call", "call", "rest", "GET /payments", False, "code", "resttemplate", "OrderClient.java", 1, 1, "", "orders-api")
    serve = MessageEndpoint("serve", "serve", "rest", "GET /payments", False, "code", "spring", "PaymentController.java", 1, 1, "", "payments-api")
    with Store(tmp_path) as store:
        store.replace_modules(discover_modules(tmp_path))
        store.replace_endpoints_for_files([call.path, serve.path], [call, serve])
    monkeypatch.chdir(tmp_path)

    endpoints = runner.invoke(app, ["modules", "endpoints", "orders-api", "--json"])
    assert endpoints.exit_code == 0
    assert json.loads(endpoints.output)[0]["topic"] == "GET /payments"
    flow = runner.invoke(app, ["modules", "flow", "orders-api", "--json"])
    assert flow.exit_code == 0
    assert json.loads(flow.output)["edges"][0]["to_node"] == "payments-api"
    properties = runner.invoke(app, ["modules", "properties", "orders-api", "--json"])
    assert properties.exit_code == 0
    assert properties.output
    openapi = runner.invoke(app, ["modules", "openapi", "orders-api", "--json"])
    assert openapi.exit_code == 0
    assert json.loads(openapi.output)["contracts"][0]["path"] == "src/main/resources/openapi.yml"


def test_modules_are_read_from_the_persisted_index_snapshot(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    module.mkdir()
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    with Store(tmp_path) as store:
        store.replace_modules(discover_modules(tmp_path))
    (module / "pom.xml").unlink()

    with Store(tmp_path, readonly=True) as store:
        persisted = store.all_modules()

    assert [(item.name, item.version) for item in persisted] == [("orders-api", "3.1.0")]


def test_index_repo_materializes_modules_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = tmp_path / "orders"
    module.mkdir()
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    monkeypatch.setattr(
        "ccc_radar.indexer.invoke_semgrep_raw", lambda *_args, **_kwargs: '{"results": []}'
    )

    with Store(tmp_path) as store:
        index_repo(tmp_path, Config(rules=[]), store, embedder=object())
        persisted = store.all_modules()

    assert [(item.name, item.version) for item in persisted] == [("orders-api", "3.1.0")]
