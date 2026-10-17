import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_PATH = ROOT / "data" / "enterprise-attack.json"
OUT_DIR = ROOT / "backend" / "attck"
URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

TECHNIQUE_IDS = [
    "T1566.001", "T1566.002", "T1059.001", "T1059.003", "T1059.005",
    "T1204.002", "T1053.005", "T1547.001", "T1543.003", "T1055",
    "T1027", "T1070.004", "T1685", "T1003.001", "T1110",
    "T1555", "T1056.001", "T1082", "T1083", "T1057",
    "T1018", "T1021.001", "T1021.002", "T1047", "T1071.001",
    "T1573", "T1105", "T1041", "T1486", "T1490",
    "T1190", "T1078", "T1133", "T1568", "T1218.011",
    "T1140", "T1005", "T1560", "T1036",
]

CITATION = re.compile(r"\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
CODE_TAG = re.compile(r"</?code>")


def clean(text):
    text = CITATION.sub("", text)
    text = MD_LINK.sub(r"\1", text)
    text = CODE_TAG.sub("", text)
    return re.sub(r"\s+", " ", text).strip()

def strip_trailing_colon(text):
    text = clean(text)
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if sentences and sentences[-1].endswith(":"):
        sentences = sentences[:-1]
    return " ".join(sentences)


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def main():
    RAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not RAW_PATH.exists():
        print("Downloading MITRE ATT&CK Enterprise dataset...")
        urllib.request.urlretrieve(URL, RAW_PATH)

    with open(RAW_PATH, encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    patterns = {}
    for obj in objects:
        if obj["type"] == "attack-pattern" and is_active(obj):
            tid = external_id(obj)
            if tid:
                patterns[tid] = obj

    techniques = []
    stix_to_tid = {}
    for tid in TECHNIQUE_IDS:
        obj = patterns.get(tid)
        if obj is None:
            print("Missing technique:", tid)
            continue
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        first_paragraph = obj.get("description", "").split("\n")[0]
        techniques.append({
            "technique_id": tid,
            "technique_name": obj["name"],
            "tactic": phases[0] if phases else "unknown",
            "description": clean(first_paragraph),
        })
        stix_to_tid[obj["id"]] = tid

    course_of_action = {}
    for obj in objects:
        if obj["type"] == "course-of-action" and is_active(obj):
            course_of_action[obj["id"]] = obj

    links = []
    used_mitigation_ids = set()
    for obj in objects:
        if obj["type"] != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        if not is_active(obj):
            continue
        tid = stix_to_tid.get(obj["target_ref"])
        coa = course_of_action.get(obj["source_ref"])
        if tid is None or coa is None:
            continue
        mid = external_id(coa)
        if mid is None:
            continue
        used_mitigation_ids.add(mid)
        links.append({
            "technique_id": tid,
            "mitigation_id": mid,
            "usage_description": clean(obj.get("description", "")),
        })

    mitigations = []
    seen = set()
    for coa in course_of_action.values():
        mid = external_id(coa)
        if mid in used_mitigation_ids and mid not in seen:
            seen.add(mid)
            mitigations.append({
                "mitigation_id": mid,
                "name": coa["name"],
                "description": strip_trailing_colon(coa.get("description", "").split("\n")[0]),
            })

    mitigations.sort(key=lambda m: m["mitigation_id"])
    links.sort(key=lambda l: (l["technique_id"], l["mitigation_id"]))

    with open(OUT_DIR / "techniques.json", "w", encoding="utf-8") as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)

    with open(OUT_DIR / "mitigations.json", "w", encoding="utf-8") as f:
        json.dump(
            {"mitigations": mitigations, "technique_mitigations": links},
            f,
            indent=2,
            ensure_ascii=False,
        )

    print("Techniques:", len(techniques))
    print("Mitigations:", len(mitigations))
    print("Technique-mitigation links:", len(links))


if __name__ == "__main__":
    main()