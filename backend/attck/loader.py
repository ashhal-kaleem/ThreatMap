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