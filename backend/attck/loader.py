import json
from pathlib import Path
from typing import TypedDict

ATTCK_DIR = Path(__file__).resolve().parent


class TechniqueRecord(TypedDict):
    technique_id: str
    technique_name: str
    tactic: str
    description: str


class MitigationRecord(TypedDict):
    mitigation_id: str
    name: str
    description: str


class TechniqueMitigationLink(TypedDict):
    technique_id: str
    mitigation_id: str
    usage_description: str


def _read_json(file_name: str):
    with open(ATTCK_DIR / file_name, encoding="utf-8") as f:
        return json.load(f)


def load_techniques() -> list[TechniqueRecord]:
    techniques = _read_json("techniques.json")
    ids = [technique["technique_id"] for technique in techniques]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate technique ids in techniques.json")
    return techniques


def load_mitigations() -> tuple[list[MitigationRecord], list[TechniqueMitigationLink]]:
    data = _read_json("mitigations.json")
    mitigations = data["mitigations"]
    links = data["technique_mitigations"]

    technique_ids = {technique["technique_id"] for technique in load_techniques()}
    mitigation_ids = {mitigation["mitigation_id"] for mitigation in mitigations}

    for link in links:
        if link["technique_id"] not in technique_ids:
            raise ValueError(f"Unknown technique in link: {link['technique_id']}")
        if link["mitigation_id"] not in mitigation_ids:
            raise ValueError(f"Unknown mitigation in link: {link['mitigation_id']}")

    return mitigations, links


def technique_embedding_text(technique: TechniqueRecord) -> str:
    return f"{technique['technique_name']}. {technique['description']}"

def seed_attack_data(session) -> dict[str, int]:
    from backend.app.models.db_models import (
        AttackMitigation,
        AttackTechnique,
        TechniqueMitigation,
    )

    techniques = load_techniques()
    mitigations, links = load_mitigations()

    for technique in techniques:
        session.merge(AttackTechnique(**technique))
    for mitigation in mitigations:
        session.merge(AttackMitigation(**mitigation))
    session.flush()
    for link in links:
        session.merge(TechniqueMitigation(**link))
    session.commit()

    unique_links = {(link["technique_id"], link["mitigation_id"]) for link in links}
    return {
        "techniques": len(techniques),
        "mitigations": len(mitigations),
        "links": len(unique_links),
    }