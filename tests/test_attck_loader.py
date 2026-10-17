"""
Unit Tests for the ATT&CK Knowledge Base Loader.
Module: Behavior Detection & ATT&CK Mapping
"""

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.database import Base
from backend.app.models.db_models import (
    AttackMitigation,
    AttackTechnique,
    TechniqueMitigation,
)
from backend.attck.loader import (
    load_mitigations,
    load_techniques,
    seed_attack_data,
    technique_embedding_text,
)


def _count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_curated_technique_count_and_unique_ids():
    techniques = load_techniques()
    ids = [technique["technique_id"] for technique in techniques]
    assert 30 <= len(techniques) <= 40
    assert len(ids) == len(set(ids))


def test_technique_records_are_complete_and_clean():
    for technique in load_techniques():
        assert technique["technique_id"].startswith("T")
        assert technique["technique_name"].strip()
        assert technique["tactic"].strip()
        assert technique["description"].strip()
        assert "(Citation:" not in technique["description"]


def test_revoked_technique_is_replaced():
    ids = {technique["technique_id"] for technique in load_techniques()}
    assert "T1562.001" not in ids
    assert "T1685" in ids


def test_mitigation_links_reference_known_records():
    mitigations, links = load_mitigations()
    technique_ids = {technique["technique_id"] for technique in load_techniques()}
    mitigation_ids = {mitigation["mitigation_id"] for mitigation in mitigations}
    assert links
    for link in links:
        assert link["technique_id"] in technique_ids
        assert link["mitigation_id"] in mitigation_ids


def test_embedding_text_contains_name_and_description():
    technique = load_techniques()[0]
    text = technique_embedding_text(technique)
    assert technique["technique_name"] in text
    assert technique["description"] in text


def test_seed_attack_data_is_idempotent():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    techniques = load_techniques()
    mitigations, links = load_mitigations()
    unique_links = {(link["technique_id"], link["mitigation_id"]) for link in links}

    with Session(engine) as session:
        first = seed_attack_data(session)
        second = seed_attack_data(session)

        assert first == second
        assert _count(session, AttackTechnique) == len(techniques)
        assert _count(session, AttackMitigation) == len(mitigations)
        assert _count(session, TechniqueMitigation) == len(unique_links)