"""Print the error breakdown for the portal (Claude) runs."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RECORDS = REPO / "docs" / "research" / "jev-email-triage" / "records"


def main() -> int:
    for path in sorted(RECORDS.glob("portal-*.jsonl")):
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        errors = [r for r in rows if r.get("kind") == "observation" and r.get("error")]
        observations = [r for r in rows if r.get("kind") == "observation"]
        print(f"== {path.name}: {len(observations)} obs, {len(errors)} errors")
        kinds = Counter()
        for row in errors:
            err = row["error"]
            label = "parse:" + err.split(":")[0] if ":" in err else err
            if "HTTP" in err:
                label = "HTTP " + err.split("HTTP ")[1].split(" ")[0].rstrip(":,")
            kinds[label] += 1
        for label, count in kinds.most_common(10):
            print(f"   {count:3d} x {label}")
        for row in errors[:4]:
            print(f"   sample: {row['email_id']} :: {row['error'][:160]}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
