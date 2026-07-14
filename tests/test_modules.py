import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ccc_radar.cli import app
from ccc_radar.config import Config
from ccc_radar.indexer import index_repo
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


def test_modules_cli_lists_then_returns_module_detail_and_properties(tmp_path: Path) -> None:
    module = tmp_path / "orders"
    source = module / "src" / "main" / "java" / "App.java"
    source.parent.mkdir(parents=True)
    _write_pom(module / "pom.xml", "orders-api", "3.1.0")
    source.write_text('@Value("${server.port}") class App {}\n')
    with Store(tmp_path) as store:
        store.replace_modules(discover_modules(tmp_path))

    result = runner.invoke(app, ["modules", "--root", str(tmp_path), "--json"])

    assert result.exit_code == 0
    modules = json.loads(result.output)
    assert modules == [
        {
            "name": "orders-api",
            "path": str(module.resolve()),
            "build_system": "maven",
            "version": "3.1.0",
            "kind": "library",
        }
    ]

    detail = runner.invoke(app, ["modules", "orders-api", "--root", str(tmp_path), "--json"])
    assert detail.exit_code == 0
    assert json.loads(detail.output)["configuration_example"] == "server:\n  port: 0\n"

    properties = runner.invoke(
        app, ["modules", "orders-api", "--root", str(tmp_path), "--properties"]
    )
    assert properties.exit_code == 0
    assert properties.output == "server:\n  port: 0\n"


def test_modules_cli_requires_an_index(tmp_path: Path) -> None:
    result = runner.invoke(app, ["modules", "--root", str(tmp_path), "--json"])

    assert result.exit_code == 2
    assert "Index absent" in result.output


def test_modules_cli_rejects_properties_without_module(tmp_path: Path) -> None:
    result = runner.invoke(app, ["modules", "--root", str(tmp_path), "--properties"])

    assert result.exit_code == 2
    assert "requiert le nom" in result.output


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
