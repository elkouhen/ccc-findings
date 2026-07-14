import hashlib
import os
from functools import lru_cache

import numpy as np

from ccc_radar.models import Finding, MessageEndpoint


class EmbeddingError(Exception):
    pass


def finding_to_text(f: Finding) -> str:
    return (
        f"{f.rule_id} | {f.severity} | {f.message} | "
        f"{' '.join(f.cwe + f.owasp)} | {f.path} | "
        f"{' '.join(f.snippet.split())[:500]}"
    )


def endpoint_to_text(e: MessageEndpoint) -> str:
    """BACKLOG-10 K3 : rôle + topic/route + framework + extrait normalisé —
    même esprit que `finding_to_text`, pour la recherche NL sur les
    endpoints (résolution `cccr flow` en dernier recours, quand aucune
    correspondance textuelle exacte/non ambiguë n'existe)."""
    return (
        f"{e.role} {e.system} | {e.topic} | {e.framework or ''} | "
        f"{' '.join(e.snippet.split())[:500]}"
    )


class Embedder:
    def __init__(self, model_name: str) -> None:
        self._model_name = model_name
        self._model = None
        self.signature = f"sentence-transformers:{model_name}"

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name)
        return self._model

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        model = self._load()
        embeddings = model.encode(
            texts, batch_size=32, normalize_embeddings=True, convert_to_numpy=True
        )
        return embeddings.astype(np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_texts([text])[0]


class FakeEmbedder:
    """Embedder déterministe sans dépendance réseau, réservé aux tests."""

    def __init__(self, model_name: str, dim: int = 8) -> None:
        self._model_name = model_name
        self._dim = dim
        self.signature = f"fake:{model_name}:{dim}"

    def embed_texts(self, texts: list[str]) -> np.ndarray:
        vectors = []
        for text in texts:
            digest = hashlib.sha256(text.encode()).digest()
            raw = np.frombuffer(digest[: self._dim], dtype=np.uint8).astype(np.float32)
            norm = np.linalg.norm(raw)
            vectors.append(raw / norm if norm > 0 else raw)
        return np.array(vectors, dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self.embed_texts([text])[0]


@lru_cache(maxsize=None)
def _make_embedder_cached(model_name: str, fake: bool) -> object:
    if fake:
        return FakeEmbedder(model_name)
    return Embedder(model_name)


def make_embedder(model_name: str) -> object:
    fake = os.environ.get("CCCR_FAKE_EMBEDDER") == "1"
    return _make_embedder_cached(model_name, fake)
