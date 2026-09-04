#!/usr/bin/env python3
"""
Telemetry Acquisition & Verification Tool
=========================================
Acquires, caches, and verifies real-world telemetry datasets (EVTX, JSONL, Mordor)
against cryptographic SHA-256 digests declared in `tools/telemetry_manifest.json`.

Standards:
- ICD 203 Provenance & Grounding
- Fails closed on cryptographic hash mismatches
- Offline-first: Verifies local test fixtures without network calls
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("acquire_telemetry")


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Load and parse the telemetry manifest."""
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_dataset(
    name: str,
    meta: Dict[str, Any],
    base_dir: Path,
) -> bool:
    """Verify an existing local dataset against its declared SHA-256."""
    fixture_path = base_dir / meta.get("fixture_path", "")
    if not fixture_path.exists():
        logger.warning(f"[-] {name}: File not found at {fixture_path}")
        return False

    actual_hash = compute_sha256(fixture_path)
    expected_hash = meta.get("sha256", "").lower()

    if actual_hash.lower() == expected_hash:
        size_kb = fixture_path.stat().st_size / 1024
        logger.info(f"[+] {name}: SHA-256 verified ({size_kb:.1f} KB) -> {fixture_path}")
        return True
    else:
        logger.error(
            f"[!] {name}: HASH MISMATCH!\n"
            f"    Expected: {expected_hash}\n"
            f"    Actual:   {actual_hash}"
        )
        return False


def download_dataset(
    name: str,
    meta: Dict[str, Any],
    base_dir: Path,
    force: bool = False,
) -> bool:
    """Download and verify dataset if remote URL is available."""
    target_path = base_dir / meta.get("fixture_path", "")
    if target_path.exists() and not force:
        logger.info(f"[*] {name}: Already present at {target_path}, verifying hash...")
        return verify_dataset(name, meta, base_dir)

    url = meta.get("upstream_url")
    if not url:
        logger.info(f"[*] {name}: No upstream URL defined; verifying existing local fixture.")
        return verify_dataset(name, meta, base_dir)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    logger.info(f"[*] {name}: Downloading from {url} ...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThreatDetectionLab-Telemetry/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        target_path.write_bytes(data)
        logger.info(f"[+] {name}: Downloaded {len(data)} bytes to {target_path}")
    except Exception as exc:
        logger.error(f"[!] {name}: Failed to download from {url}: {exc}")
        return False

    return verify_dataset(name, meta, base_dir)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Acquire and cryptographically verify telemetry corpora against telemetry_manifest.json"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tools/telemetry_manifest.json"),
        help="Path to telemetry_manifest.json",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Specific dataset name to acquire/verify (default: all)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify existing fixtures without downloading missing ones",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download even if target file already exists",
    )
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except Exception as exc:
        logger.error(f"Failed to load manifest: {exc}")
        return 1

    datasets = manifest.get("datasets", {})
    if args.dataset:
        if args.dataset not in datasets:
            logger.error(f"Unknown dataset '{args.dataset}'. Available: {list(datasets.keys())}")
            return 1
        datasets = {args.dataset: datasets[args.dataset]}

    base_dir = Path.cwd()
    success = True
    logger.info(f"Processing {len(datasets)} dataset(s) from {args.manifest}...")

    for name, meta in datasets.items():
        if args.verify_only:
            if not verify_dataset(name, meta, base_dir):
                success = False
        else:
            if not download_dataset(name, meta, base_dir, force=args.force):
                success = False

    if success:
        logger.info("[+] All specified telemetry datasets cryptographically verified.")
        return 0
    else:
        logger.error("[!] One or more telemetry datasets failed cryptographic verification.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
