from pathlib import Path

import numpy as np
import pytest

from ccc_radar.config import DEFAULT_EMBEDDING_MODEL
import ccc_radar.embedder as embedder_module
from ccc_radar.embedder import Embedder, finding_to_text, make_embedder, resolve_embedding_model
from ccc_radar.models import Finding


def make_finding() -> Finding:
    return Finding(
        id="abc123",
        rule_id="custom.sql-fstring",
        severity="ERROR",
        message="Une requête SQL construite par f-string permet une injection SQL.",
        path="app/db.py",
        start_line=6,
        end_line=6,
        snippet='    cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")   ',
        fix=None,
        cwe=["CWE-89"],
        owasp=["A03:2021"],
    )


def test_finding_to_text_exact_format() -> None:
    finding = make_finding()

    text = finding_to_text(finding)

    assert text == (
        "custom.sql-fstring | ERROR | "
        "Une requête SQL construite par f-string permet une injection SQL. | "
        "CWE-89 A03:2021 | app/db.py | "
        "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")"
    )


def test_make_embedder_reuses_cached_instances(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CCCR_FAKE_EMBEDDER", "1")

    first = make_embedder("test-cache-model")
    second = make_embedder("test-cache-model")

    assert first is second
    assert getattr(first, "signature") == "fake:test-cache-model:8"


def test_resolve_embedding_model_falls_back_to_local_default_for_remote_identifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_model = tmp_path / "local-model"
    local_model.mkdir()
    monkeypatch.setattr(embedder_module, "DEFAULT_EMBEDDING_MODEL", str(local_model))

    resolved, warning = resolve_embedding_model("Snowflake/snowflake-arctic-embed-xs")

    assert resolved == str(local_model)
    assert warning is not None
    assert "Snowflake/snowflake-arctic-embed-xs" in warning


@pytest.mark.slow
def test_embed_texts_returns_normalized_vectors() -> None:
    if not Path(DEFAULT_EMBEDDING_MODEL).expanduser().exists():
        pytest.skip(f"Modèle local absent: {DEFAULT_EMBEDDING_MODEL}")

    embedder = Embedder(DEFAULT_EMBEDDING_MODEL)

    vectors = embedder.embed_texts(["injection SQL", "appel shell dangereux"])

    assert vectors.shape[0] == 2
    assert vectors.dtype == np.float32
    norms = np.linalg.norm(vectors, axis=1)
    assert np.allclose(norms, 1.0, atol=1e-3)
