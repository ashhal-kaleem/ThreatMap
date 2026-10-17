from functools import lru_cache
from typing import Optional, TypedDict

import numpy as np
from sentence_transformers import SentenceTransformer

from app.services.behavior_service import BehaviorSentence
from attck.loader import load_techniques, technique_embedding_text

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_THRESHOLD = 0.45
BATCH_SIZE = 64


class MappingResult(TypedDict):
    sentence: str
    technique_id: Optional[str]
    similarity: float
    confidence_ok: bool


@lru_cache(maxsize=1)
def get_model() -> SentenceTransformer:
    return SentenceTransformer(MODEL_NAME)


def _encode(texts: list[str]) -> np.ndarray:
    return get_model().encode(
        texts,
        batch_size=BATCH_SIZE,
        normalize_embeddings=True,
        convert_to_numpy=True,
        show_progress_bar=False,
    )


@lru_cache(maxsize=1)
def _technique_index() -> tuple[list[str], np.ndarray]:
    techniques = load_techniques()
    ids = [technique["technique_id"] for technique in techniques]
    matrix = _encode([technique_embedding_text(technique) for technique in techniques])
    return ids, matrix


def warm_up() -> None:
    _technique_index()


def similarity_matrix(texts: list[str]) -> np.ndarray:
    _, matrix = _technique_index()
    return _encode(texts) @ matrix.T


def top_candidates(texts: list[str], k: int = 3) -> list[list[tuple[str, float]]]:
    ids, _ = _technique_index()
    scores = similarity_matrix(texts)
    ranked = []
    for row in scores:
        order = np.argsort(-row)[:k]
        ranked.append([(ids[index], float(row[index])) for index in order])
    return ranked


def map_sentences(
    sentences: list[BehaviorSentence], threshold: Optional[float] = None
) -> list[MappingResult]:
    if not sentences:
        return []

    cutoff = DEFAULT_THRESHOLD if threshold is None else threshold
    ids, _ = _technique_index()
    texts = [item["sentence"] for item in sentences]
    scores = similarity_matrix(texts)

    results: list[MappingResult] = []
    for text, row in zip(texts, scores):
        best_index = int(np.argmax(row))
        best_score = float(row[best_index])
        confident = best_score >= cutoff
        results.append(
            {
                "sentence": text,
                "technique_id": ids[best_index] if confident else None,
                "similarity": best_score,
                "confidence_ok": confident,
            }
        )
    return results