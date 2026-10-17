from functools import lru_cache
from typing import Optional, TypedDict

from attck.loader import load_mitigations, load_techniques


class MitigationRecommendation(TypedDict):
    mitigation_id: str
    name: str
    description: str
    usage_description: str


@lru_cache(maxsize=1)
def _recommendation_index() -> dict[str, list[MitigationRecommendation]]:
    techniques = load_techniques()
    mitigations, links = load_mitigations()
    mitigation_by_id = {mitigation["mitigation_id"]: mitigation for mitigation in mitigations}

    index: dict[str, list[MitigationRecommendation]] = {
        technique["technique_id"]: [] for technique in techniques
    }
    for link in links:
        mitigation = mitigation_by_id[link["mitigation_id"]]
        index[link["technique_id"]].append(
            {
                "mitigation_id": mitigation["mitigation_id"],
                "name": mitigation["name"],
                "description": mitigation["description"],
                "usage_description": link["usage_description"],
            }
        )

    for items in index.values():
        items.sort(key=lambda item: item["mitigation_id"])
    return index


def get_recommendations(technique_id: Optional[str]) -> list[MitigationRecommendation]:
    if technique_id is None:
        return []
    return [dict(item) for item in _recommendation_index().get(technique_id, [])]