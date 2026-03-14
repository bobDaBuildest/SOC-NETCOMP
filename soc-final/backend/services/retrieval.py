import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class RetrievalError(Exception):
    pass


class MitigationRetriever:
    """Simple FAISS-based retriever for mitigation playbook entries.

    This loader builds an in-memory FAISS index over the playbook entries in
    `backend/data/mitigation_kb.json` using the `all-MiniLM-L6-v2` sentence
    transformer. It normalizes embeddings to allow cosine-similarity search.

    Usage:
        retriever = MitigationRetriever.get_instance()
        matches = retriever.query("SYN flood detected", top_k=2)
    """

    _INSTANCE: Optional["MitigationRetriever"] = None

    def __init__(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer
            import faiss
            import numpy as np  # noqa: F401
        except ImportError as e:
            raise RetrievalError(
                "Missing dependencies for retrieval. Install `sentence-transformers` and `faiss-cpu`."
            ) from e

        self._faiss = faiss
        self._model = SentenceTransformer("all-MiniLM-L6-v2")

        self._kb_path = Path(__file__).resolve().parent.parent / "data" / "mitigation_kb.json"
        self._items = self._load_kb()

        # Prepare texts for embedding.
        self._texts = [self._format_document_text(doc) for doc in self._items]
        self._embeddings = self._model.encode(
            self._texts, convert_to_numpy=True, normalize_embeddings=True
        )

        self._index = self._faiss.IndexFlatIP(self._embeddings.shape[1])
        self._index.add(self._embeddings)

    @classmethod
    def get_instance(cls) -> "MitigationRetriever":
        if cls._INSTANCE is None:
            cls._INSTANCE = cls()
        return cls._INSTANCE

    def _load_kb(self) -> List[Dict[str, Any]]:
        if not self._kb_path.exists():
            raise RetrievalError(f"Mitigation KB not found at {self._kb_path}")

        with open(self._kb_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise RetrievalError("Mitigation KB must be a JSON array of entries.")

        return data

    @staticmethod
    def _format_document_text(doc: Dict[str, Any]) -> str:
        title = doc.get("title") or doc.get("pattern") or ""
        description = doc.get("description") or ""
        steps = doc.get("mitigation_steps") or []
        steps_text = "\n".join(f"- {s}" for s in steps)
        return f"{title}\n{description}\n{steps_text}".strip()

    def query(self, query_text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Return the top_k KB entries most relevant to the query."""
        if top_k <= 0:
            return []

        q_emb = self._model.encode([query_text], convert_to_numpy=True, normalize_embeddings=True)
        distances, indices = self._index.search(q_emb, top_k)

        results: List[Dict[str, Any]] = []
        for idx in indices[0]:
            if idx < 0 or idx >= len(self._items):
                continue
            results.append(self._items[idx])
        return results
