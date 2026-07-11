import hashlib
import os
from pathlib import Path
from typing import Optional

import numpy as np
import typer

from cccf import __version__
from cccf.config import ConfigError, init_config, load_config
from cccf.embedder import Embedder
from cccf.indexer import index_repo
from cccf.scanner import SemgrepError
from cccf.store import Store

app = typer.Typer(help="ccc-findings: index Semgrep interrogeable par LLM")

_SEMGREP_CONFIG_CANDIDATES = [".semgrep.yml", "semgrep.yml", ".semgrep"]


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
        if detected is None:
            typer.echo(
                "Aucune config Semgrep détectée. Relancez avec --rules <chemin-ou-pack>.",
                err=True,
            )
            raise typer.Exit(code=1)
        rules_paths = [detected]

    try:
        path = init_config(repo_root, rules_paths)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Configuration créée : {path}")


class _FakeEmbedder:
    """Embedder déterministe sans dépendance réseau (CCCF_FAKE_EMBEDDER=1)."""

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        vectors = []
        for text in texts:
            digest = hashlib.sha256(text.encode()).digest()
            vector = np.frombuffer(digest[:8], dtype=np.uint8).astype(np.float32)
            norm = np.linalg.norm(vector)
            vectors.append(vector / norm if norm > 0 else vector)
        return np.array(vectors, dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_texts([text])[0]


def _make_embedder(model_name: str) -> object:
    if os.environ.get("CCCF_FAKE_EMBEDDER") == "1":
        return _FakeEmbedder()
    return Embedder(model_name)


@app.command(name="index")
def index_cmd(
    full: bool = typer.Option(False, "--full", help="Force un scan complet."),
) -> None:
    """Indexe le code et les findings du projet (incrémental par défaut)."""
    repo_root = Path.cwd()

    try:
        config = load_config(repo_root)
    except ConfigError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    embedder = _make_embedder(config.embedding_model)

    try:
        with Store(repo_root) as store:
            report = index_repo(repo_root, config, store, embedder, full=full)
    except SemgrepError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(
        f"scanned={report.scanned} skipped={report.skipped} "
        f"+findings={report.findings_added} -findings={report.findings_removed}"
    )


if __name__ == "__main__":
    app()
