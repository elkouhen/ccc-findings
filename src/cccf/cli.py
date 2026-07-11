import typer

from cccf import __version__

app = typer.Typer(help="ccc-findings: index Semgrep interrogeable par LLM")


@app.callback()
def main() -> None:
    """ccc-findings: index Semgrep interrogeable par LLM."""


@app.command()
def version() -> None:
    """Affiche la version du package."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
