"""Acquire a Certificate Transparency snapshot for the CTI pipeline.

This is the acquisition half of the split the pipeline documentation describes and
did not previously implement: this tool talks to the network and writes a dated,
hash-pinned snapshot; `tools/cti/` reads snapshots and never talks to the network.
Keeping them apart is what makes a pipeline run reproducible, because the analysis
can be re-run against the exact bytes that produced a published result.

Source: crt.sh, which indexes public Certificate Transparency logs. CT is the
highest-value free source for lure infrastructure, because an attacker who wants a
browser to trust a lookalike site must publish the certificate, and that
publication is the earliest public moment of the campaign.

**On what the output is.** Every row is a certificate that exists. Nothing here
establishes that any domain is malicious, and most matches for a brand term are
the brand's own infrastructure, its customers, or unrelated software that happens
to share a word. The snapshot is collection, not assessment. Treat scored output
as candidates for verification by a human, and do not publish a third party's
domain as malicious on the strength of a name match.

Usage:
    python tools/acquire_ct_snapshot.py --out tests/fixtures/cti/snapshots
    python tools/acquire_ct_snapshot.py --terms anthropic openai --no-write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.cti.relevance import BRAND_TERMS  # noqa: E402

CRTSH = "https://crt.sh/"
USER_AGENT = "threat-detection-lab/acquire_ct_snapshot (defensive research)"
DEFAULT_OUT = ROOT / "corpus" / "ct"

#: Seconds between queries. crt.sh is a free community service; hammering it is
#: both rude and the fastest way to lose access to it.
QUERY_DELAY_SECONDS = 2.0


class AcquisitionError(RuntimeError):
    """The snapshot could not be retrieved."""


def query_crtsh(term: str, timeout: int = 90, retries: int = 2) -> List[Dict[str, Any]]:
    """Return raw crt.sh rows for a substring term."""
    encoded = urllib.parse.quote(f"%{term}%", safe="")
    url = f"{CRTSH}?q={encoded}&output=json"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read().decode("utf-8", errors="replace")
            return json.loads(payload) if payload.strip() else []
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(3 * (attempt + 1))
    raise AcquisitionError(f"crt.sh query for '{term}' failed: {last}")


def to_records(
    rows: Iterable[Dict[str, Any]], term: str, since: Optional[date]
) -> List[Dict[str, Any]]:
    """Normalize crt.sh rows into the shape the pipeline's CT collector reads."""
    records: List[Dict[str, Any]] = []
    for row in rows:
        names = [
            n.strip().lower()
            for n in str(row.get("name_value", "")).splitlines()
            if n.strip()
        ]
        if not names:
            continue
        not_before = str(row.get("not_before", ""))[:10]
        if since and not_before:
            try:
                if datetime.strptime(not_before, "%Y-%m-%d").date() < since:
                    continue
            except ValueError:
                pass
        records.append(
            {
                "dns_names": sorted(set(names)),
                # crt.sh exposes an entry id and a serial, not a certificate
                # fingerprint. The id is the stable public reference back to the
                # source row, which is what provenance actually needs.
                "fingerprint_sha256": "",
                "crtsh_id": row.get("id"),
                "serial_number": row.get("serial_number", ""),
                "issuer": str(row.get("issuer_name", ""))[:200],
                "not_before": not_before,
                "matched_term": term,
            }
        )
    return records


def dedupe(records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[Any, Dict[str, Any]] = {}
    for record in records:
        key = record.get("crtsh_id") or tuple(record["dns_names"])
        if key not in seen:
            seen[key] = record
    return sorted(seen.values(), key=lambda r: (r.get("not_before", ""), str(r.get("crtsh_id"))))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_snapshot(
    records: Sequence[Dict[str, Any]], out_dir: Path, terms: Sequence[str], window_days: int
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n"
    snapshot = out_dir / "certificate_transparency.jsonl"
    snapshot.write_text(body, encoding="utf-8", newline="\n")

    lock = {
        "source": "crt.sh (public Certificate Transparency logs)",
        "source_url": CRTSH,
        "retrieval_date": date.today().isoformat(),
        "query_terms": list(terms),
        "window_days": window_days,
        "record_count": len(records),
        "snapshot_file": snapshot.name,
        "snapshot_sha256": sha256_text(body),
        "content_note": (
            "Certificate metadata only. Every row is a certificate that exists. Nothing "
            "in this snapshot establishes that any domain is malicious; most matches for "
            "a brand term are the brand's own infrastructure or unrelated software. "
            "Scored output is a queue for human verification, not an accusation."
        ),
    }
    (out_dir / "acquisition-lock.json").write_text(
        json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return lock


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--terms",
        nargs="*",
        default=list(BRAND_TERMS),
        help="substring terms to query; defaults to the relevance vocabulary brands",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--window-days",
        type=int,
        default=90,
        help="discard certificates first seen before this many days ago",
    )
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)

    since = date.today() - timedelta(days=args.window_days) if args.window_days else None
    all_records: List[Dict[str, Any]] = []
    failures: List[str] = []

    for index, term in enumerate(args.terms):
        if index:
            time.sleep(QUERY_DELAY_SECONDS)
        try:
            rows = query_crtsh(term)
        except AcquisitionError as exc:
            failures.append(str(exc))
            print(f"  [-] {exc}", file=sys.stderr)
            continue
        records = to_records(rows, term, since)
        all_records.extend(records)
        print(f"  {term:<16} {len(rows):>6} rows -> {len(records):>5} within window")

    records = dedupe(all_records)
    print(f"\nunique certificates: {len(records)}")
    unique_names = {n for r in records for n in r["dns_names"]}
    print(f"unique dns names:    {len(unique_names)}")
    if failures:
        print(f"failed queries:      {len(failures)}", file=sys.stderr)

    if not records:
        print("[-] no records retrieved", file=sys.stderr)
        return 2

    if not args.no_write:
        lock = write_snapshot(records, args.out, args.terms, args.window_days)
        print(f"\nwrote {(args.out / lock['snapshot_file']).relative_to(ROOT)}")
        print(f"sha256 {lock['snapshot_sha256']}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
