"""
Unit Tests for the Deterministic MITRE ATT&CK Recommendation Service.
Module: Behavior Detection & ATT&CK Mapping
"""

from backend.app.services.recommendation_service import get_recommendations
from backend.attck.loader import load_techniques

REQUIRED_KEYS = {"mitigation_id", "name", "description", "usage_description"}


def test_abstention_returns_no_recommendations():
    assert get_recommendations(None) == []


def test_unknown_technique_returns_empty_list():
    assert get_recommendations("T9999") == []


def test_known_technique_returns_official_mitigations():
    results = get_recommendations("T1566.001")
    assert results
    for item in results:
        assert set(item) == REQUIRED_KEYS
        assert item["mitigation_id"].startswith("M")
        assert item["name"].strip()


def test_results_are_deterministic_and_sorted():
    first = get_recommendations("T1566.001")
    second = get_recommendations("T1566.001")
    assert first == second
    ids = [item["mitigation_id"] for item in first]
    assert ids == sorted(ids)


def test_returned_list_is_a_copy():
    first = get_recommendations("T1566.001")
    first[0]["name"] = "changed"
    first.pop()
    assert get_recommendations("T1566.001")[0]["name"] != "changed"


def test_every_curated_technique_can_be_queried():
    for technique in load_techniques():
        assert isinstance(get_recommendations(technique["technique_id"]), list)