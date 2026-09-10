"""Acquire a snapshot of confirmed-malicious package identities.

Source: the OpenSSF `malicious-packages` dataset, which publishes OSV-format
reports for packages confirmed malicious by the ecosystem maintainers, security
vendors, and automated analysis pipelines.

**This tool downloads identities and metadata only. It never downloads, writes,
or extracts a malicious payload.** The OSV reports are JSON documents describing
what a package did; they do not contain the package itself. That distinction is
the reason this corpus can live in a public repository and be re-acquired on an
ordinary workstation without an isolated environment.

Recall against real malicious *manifest content* is a different measurement and
is deliberately not attempted here. See `docs/detections/RECALL.md` for why, and
for what acquiring that corpus would require.

Usage:
    python tools/acquire_malicious_corpus.py --ecosystem npm --out corpus/malicious
    python tools/acquire_malicious_corpus.py --ecosystem npm --limit 500 --no-write
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "corpus" / "malicious"

REPO = "ossf/malicious-packages"
API = "https://api.github.com"
DATASET_URL = f"https://github.com/{REPO}"
DATASET_LICENSE = "Apache-2.0"
USER_AGENT = "threat-detection-lab/acquire_malicious_corpus (defensive research)"

#: Path prefix inside the dataset repository.
MALICIOUS_PREFIX = "osv/malicious/"


class AcquisitionError(RuntimeError):
    """The dataset could not be retrieved or did not look like itself."""


def _force_rmtree(path: Path) -> None:
    """Remove a git working tree on Windows.

    Git marks objects in `.git` read-only. `shutil.rmtree` fails on them, leaving
    a partial directory that makes the next clone fail with a confusing message
    about a non-empty destination rather than the real cause.
    """

    def _on_error(func, target, _exc_info):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_on_error)


def _run_git(args: List[str], cwd: Optional[Path] = None, timeout: int = 900) -> str:
    """Run git, raising AcquisitionError with the real message on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AcquisitionError("git is not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError(f"git timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise AcquisitionError(f"git {' '.join(args)} failed: {result.stderr.strip()[:400]}")
    return result.stdout


def _clone_index(destination: Path) -> str:
    """Clone the dataset's file index without downloading any file contents.

    `--filter=blob:none --no-checkout` fetches commits and trees only. The result
    is a complete list of every advisory path in the dataset with zero package
    contents on disk, which is the whole point: the corpus is identities, and
    nothing that could execute is ever written.

    The GitHub tree API cannot serve this. The npm subtree alone holds more than
    two hundred thousand entries and the API truncates it, which would silently
    yield a partial corpus and therefore a wrong denominator.
    """
    _force_rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _run_git(
        [
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--no-checkout",
            f"https://github.com/{REPO}",
            str(destination),
        ]
    )
    return _run_git(["ls-tree", "-r", "--name-only", "HEAD"], cwd=destination)


def list_packages(ecosystem: str, workdir: Optional[Path] = None) -> List[Dict[str, str]]:
    """Return confirmed-malicious package identities for one ecosystem."""
    workdir = workdir or (Path(tempfile.gettempdir()) / "tdl-malicious-packages")
    try:
        listing = _clone_index(workdir)
        packages: List[Dict[str, str]] = []
        seen_ecosystems = set()
        prefix = MALICIOUS_PREFIX
        for path in listing.splitlines():
            if not path.startswith(prefix) or not path.endswith(".json"):
                continue
            parts = path[len(prefix):].split("/")
            if len(parts) < 2:
                continue
            found_eco = parts[0]
            seen_ecosystems.add(found_eco)
            if found_eco.lower() != ecosystem.lower():
                continue
            advisory = parts[-1].removesuffix(".json")
            name = "/".join(parts[1:-1])
            if name:
                packages.append(
                    {"name": name, "ecosystem": found_eco, "advisory": advisory}
                )
        if not packages:
            raise AcquisitionError(
                f"ecosystem '{ecosystem}' produced no packages; dataset contains: "
                f"{', '.join(sorted(seen_ecosystems))}"
            )
        return packages
    finally:
        _force_rmtree(workdir)


def dedupe(packages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """One row per package, keeping the earliest advisory identifier."""
    by_name: Dict[str, Dict[str, str]] = {}
    for package in packages:
        existing = by_name.get(package["name"])
        if existing is None or package["advisory"] < existing["advisory"]:
            by_name[package["name"]] = package
    return [by_name[name] for name in sorted(by_name)]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_snapshot(
    packages: List[Dict[str, str]], ecosystem: str, out_dir: Path, retrieved: str
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = out_dir / f"{ecosystem}_malicious_packages.jsonl"
    body = "\n".join(json.dumps(p, sort_keys=True) for p in packages) + "\n"
    snapshot_path.write_text(body, encoding="utf-8", newline="\n")

    lock = {
        "dataset": REPO,
        "source_url": DATASET_URL,
        "license": DATASET_LICENSE,
        "ecosystem": ecosystem,
        "retrieval_date": retrieved,
        "package_count": len(packages),
        "snapshot_file": snapshot_path.name,
        "snapshot_sha256": sha256_text(body),
        "content_note": (
            "Package identities and advisory identifiers only. No package contents, "
            "archives, or payloads are retrieved or stored by this tool."
        ),
    }
    lock_path = out_dir / f"{ecosystem}_acquisition-lock.json"
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")
    return lock


def load_snapshot(path: Path) -> Iterator[Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def verify_snapshot(out_dir: Path, ecosystem: str) -> bool:
    """Confirm a stored snapshot still matches its recorded hash."""
    lock_path = out_dir / f"{ecosystem}_acquisition-lock.json"
    if not lock_path.is_file():
        raise AcquisitionError(f"no acquisition lock at {lock_path}")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    snapshot = out_dir / lock["snapshot_file"]
    if not snapshot.is_file():
        raise AcquisitionError(f"snapshot named by the lock is missing: {snapshot}")
    actual = sha256_text(snapshot.read_text(encoding="utf-8"))
    return actual == lock["snapshot_sha256"]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ecosystem", default="npm", help="npm, PyPI, crates.io, go, maven")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=None, help="truncate for a smoke test")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--verify", action="store_true", help="check a stored snapshot's hash")
    args = parser.parse_args(argv)

    if args.verify:
        try:
            ok = verify_snapshot(args.out, args.ecosystem)
        except AcquisitionError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        print("snapshot hash matches" if ok else "SNAPSHOT HASH MISMATCH")
        return 0 if ok else 1

    try:
        packages = dedupe(list_packages(args.ecosystem))
    except AcquisitionError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    if args.limit:
        packages = packages[: args.limit]

    print(f"ecosystem:        {args.ecosystem}")
    print(f"unique packages:  {len(packages)}")
    print(f"sample:           {', '.join(p['name'] for p in packages[:5])}")

    if args.no_write:
        return 0

    lock = write_snapshot(packages, args.ecosystem, args.out, date.today().isoformat())
    print(f"\nwrote {args.out / lock['snapshot_file']}")
    print(f"sha256 {lock['snapshot_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
