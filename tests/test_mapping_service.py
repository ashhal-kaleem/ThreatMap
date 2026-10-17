"""
Unit Tests for ATT&CK Semantic Mapping and Abstention Logic.
Module: Behavior Detection & ATT&CK Mapping
"""

import numpy as np

from backend.app.services import mapping_service
from backend.app.services.mapping_service import DEFAULT_THRESHOLD, map_sentences

TECHNIQUE_IDS = ["T0001", "T0002", "T0003"]


def _sentences(count):
    return [{"sentence": f"sentence {index}", "source_page": 1} for index in range(count)]


def _fake_scores(monkeypatch, rows):
    matrix = np.array(rows, dtype=float)
    monkeypatch.setattr(
        mapping_service, "_technique_index", lambda: (TECHNIQUE_IDS, np.zeros((3, 1)))
    )
    monkeypatch.setattr(mapping_service, "similarity_matrix", lambda texts: matrix[: len(texts)])


def test_confident_match_returns_best_technique(monkeypatch):
    _fake_scores(monkeypatch, [[0.10, 0.80, 0.30]])
    result = map_sentences(_sentences(1))[0]
    assert result["technique_id"] == "T0002"
    assert result["confidence_ok"] is True
    assert result["similarity"] == 0.8


def test_low_score_abstains_and_keeps_best_similarity(monkeypatch):
    _fake_scores(monkeypatch, [[0.10, 0.20, 0.30]])
    result = map_sentences(_sentences(1))[0]
    assert result["technique_id"] is None
    assert result["confidence_ok"] is False
    assert result["similarity"] == 0.3


def test_score_equal_to_threshold_is_accepted(monkeypatch):
    _fake_scores(monkeypatch, [[0.1, DEFAULT_THRESHOLD, 0.1]])
    result = map_sentences(_sentences(1))[0]
    assert result["technique_id"] == "T0002"
    assert result["confidence_ok"] is True


def test_custom_threshold_overrides_default(monkeypatch):
    _fake_scores(monkeypatch, [[0.1, 0.5, 0.2]])
    strict = map_sentences(_sentences(1), threshold=0.9)[0]
    relaxed = map_sentences(_sentences(1), threshold=0.2)[0]
    assert strict["technique_id"] is None
    assert relaxed["technique_id"] == "T0002"


def test_abstention_invariant_holds_for_every_result(monkeypatch):
    rows = [[0.9, 0.1, 0.1], [0.1, 0.1, 0.1], [0.2, 0.46, 0.1], [0.0, 0.0, 0.0]]
    _fake_scores(monkeypatch, rows)
    for result in map_sentences(_sentences(4)):
        assert (result["technique_id"] is None) == (not result["confidence_ok"])
        assert 0.0 <= result["similarity"] <= 1.0


def test_order_and_text_are_preserved(monkeypatch):
    _fake_scores(monkeypatch, [[0.9, 0.1, 0.1], [0.1, 0.1, 0.1]])
    results = map_sentences(_sentences(2))
    assert [result["sentence"] for result in results] == ["sentence 0", "sentence 1"]


def test_empty_input_returns_empty_list():
    assert map_sentences([]) == []


def test_real_model_maps_clear_behaviors_and_abstains_on_noise():
    sentences = [
        {
            "sentence": "The actor sent spearphishing emails with a malicious attachment to the victim.",
            "source_page": 1,
        },
        {
            "sentence": "Attackers dumped credentials from LSASS memory using a custom tool.",
            "source_page": 1,
        },
        {
            "sentence": "The report was published in March and covers activity from last year.",
            "source_page": 1,
        },
    ]
    results = map_sentences(sentences)
    assert results[0]["technique_id"] == "T1566.001"
    assert results[1]["technique_id"] == "T1003.001"
    assert results[2]["technique_id"] is None
    assert results[2]["confidence_ok"] is False