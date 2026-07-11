import numpy as np

from cccf.models import Finding


def finding_to_text(f: Finding) -> str:
    return (
        f"{f.rule_id} | {f.severity} | {f.message} | "
        f"{' '.join(f.cwe + f.owasp)} | {f.path} | "
        f"{' '.join(f.snippet.split())[:500]}"
    )


class Embedder:
    def __init__(self, model_name: str) -> None:
        self._model_name = model_name
        self._model = None

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
