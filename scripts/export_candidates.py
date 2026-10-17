import csv
import random
import sys
from pathlib import Path

import pymupdf

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.services.behavior_service import iter_sentence_records

SAMPLE_PER_REPORT = 20
SEED = 42


def read_pages(pdf_path):
    pages = []
    with pymupdf.open(pdf_path) as doc:
        for index, page in enumerate(doc, start=1):
            text = page.get_text()
            pages.append({"page_number": index, "page_text": text, "text": text})
    return pages


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "dev"
    rng = random.Random(SEED)
    rows = []

    for pdf_path in sorted((ROOT / "data" / "reports" / folder).glob("*.pdf")):
        records = iter_sentence_records(read_pages(pdf_path))
        passed = [r for r in records if r["passes_filter"]]
        rejected = [r for r in records if not r["passes_filter"]]
        print(f"{pdf_path.name} | sentences={len(records)} | passed={len(passed)}")

        half = SAMPLE_PER_REPORT // 2
        chosen = rng.sample(passed, min(half, len(passed)))
        chosen += rng.sample(rejected, min(half, len(rejected)))
        rng.shuffle(chosen)
        for record in chosen:
            rows.append(
                [
                    pdf_path.name,
                    record["source_page"],
                    record["sentence"],
                    record["passes_filter"],
                    "",
                    "",
                ]
            )

    out_dir = ROOT / "data" / "labeling"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{folder}_candidates.csv"
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["report", "page", "sentence", "filter_pass", "is_behavior", "technique_id"]
        )
        writer.writerows(rows)

    print("Rows written:", len(rows))
    print("File:", out_path)


if __name__ == "__main__":
    main()