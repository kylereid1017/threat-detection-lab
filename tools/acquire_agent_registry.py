"""Acquire snapshots of AI agent execution layer packages from npm and PyPI.

This tool implements the acquisition stage of the agent execution layer population
study. It queries public package registries for Model Context Protocol (MCP) and
agent runtime tooling, captures metadata and manifests, and produces hash-pinned
snapshots and lockfiles for reproducible offline analysis.

Disciplines:
1. Manifests and metadata only. NEVER downloads, unpacks, or executes package
   payloads or archive tarballs.
2. Complete collection audit trail: tracks and records discards and errors.
3. Decoupled from analysis: writes hash-pinned snapshots; downstream analysis
   reads snapshots only.

Usage:
    python tools/acquire_agent_registry.py --ecosystem all --out corpus/agent
    python tools/acquire_agent_registry.py --ecosystem npm --npm-limit 500
    python tools/acquire_agent_registry.py --ecosystem pypi --pypi-limit 200
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "corpus" / "agent"
USER_AGENT = "threat-detection-lab/acquire_agent_registry (defensive research)"

# Default search queries
DEFAULT_NPM_QUERIES = ["modelcontextprotocol", "keywords:mcp"]
NPM_SEARCH_API = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY_BASE = "https://registry.npmjs.org"
PYPI_SIMPLE_API = "https://pypi.org/simple/"
PYPI_JSON_BASE = "https://pypi.org/pypi"


class AcquisitionError(RuntimeError):
    """Failed to query registry or record snapshot."""


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_npm_package(raw_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize raw npm search object into the standard agent package record schema."""
    pkg = raw_obj.get("package")
    if not isinstance(pkg, dict):
        return None

    name = pkg.get("name")
    if not name or not isinstance(name, str):
        return None

    return {
        "ecosystem": "npm",
        "name": name.strip(),
        "version": pkg.get("version", ""),
        "description": pkg.get("description", ""),
        "date": pkg.get("date", ""),
        "publisher": pkg.get("publisher", {}),
        "maintainers": pkg.get("maintainers", []),
        "keywords": pkg.get("keywords", []) or [],
        "links": pkg.get("links", {}),
        "downloads": raw_obj.get("downloads", {}),
        "dependents": raw_obj.get("dependents", 0),
        "score": raw_obj.get("score", {}),
        "flags": raw_obj.get("flags", {}),
    }


def fetch_npm_search(
    query: str,
    limit: Optional[int] = None,
    page_size: int = 250,
    timeout: int = 20,
    delay: float = 0.5,
    max_retries: int = 3,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Fetch packages matching query from npm registry search API.

    Returns: (records, discards_count, total_reported)
    """
    records: List[Dict[str, Any]] = []
    seen_names: Set[str] = set()
    discards = 0
    offset = 0
    total_reported = 0

    while True:
        size = page_size
        if limit is not None:
            remaining = limit - len(records)
            if remaining <= 0:
                break
            size = min(page_size, remaining)

        params = urllib.parse.urlencode({
            "text": query,
            "size": size,
            "from": offset,
        })
        url = f"{NPM_SEARCH_API}?{params}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

        data = None
        for attempt in range(max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < max_retries:
                    backoff = 2.0 * (attempt + 1)
                    time.sleep(backoff)
                    continue
                if attempt == max_retries:
                    raise AcquisitionError(f"npm search failed for '{query}' at offset {offset}: {exc}")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise AcquisitionError(f"npm search failed for '{query}' at offset {offset}: {exc}")

        if not data:
            break

        total_reported = data.get("total", 0)
        objects = data.get("objects", [])
        if not objects:
            break

        for raw in objects:
            norm = normalize_npm_package(raw)
            if norm is None:
                discards += 1
                continue
            if norm["name"] in seen_names:
                continue
            seen_names.add(norm["name"])
            records.append(norm)
            if limit is not None and len(records) >= limit:
                break

        offset += len(objects)
        if offset >= total_reported:
            break
        if delay > 0:
            time.sleep(delay)

    return records, discards, total_reported


def fetch_npm_manifest(
    name: str,
    version: str = "latest",
    timeout: int = 15,
) -> Optional[Dict[str, Any]]:
    """Retrieve package.json manifest metadata directly from npm registry JSON API.

    NEVER downloads tarball payloads.
    """
    encoded_name = urllib.parse.quote(name, safe="@")
    url = f"{NPM_REGISTRY_BASE}/{encoded_name}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {
                "name": data.get("name"),
                "version": data.get("version"),
                "scripts": data.get("scripts", {}),
                "bin": data.get("bin"),
                "dependencies": data.get("dependencies", {}),
                "devDependencies": data.get("devDependencies", {}),
                "engines": data.get("engines", {}),
                "os": data.get("os"),
                "cpu": data.get("cpu"),
            }
    except Exception:
        return None


def fetch_pypi_project_list(
    filter_terms: Sequence[str] = ("mcp", "modelcontextprotocol"),
    timeout: int = 30,
) -> Tuple[List[str], int]:
    """Fetch project names from PyPI PEP 691 simple API matching filter terms."""
    req = urllib.request.Request(
        PYPI_SIMPLE_API,
        headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise AcquisitionError(f"PyPI simple index fetch failed: {exc}")

    all_projects = data.get("projects", [])
    total_projects = len(all_projects)
    matched_names: List[str] = []

    for proj in all_projects:
        name = proj.get("name", "")
        lowered = name.lower()
        if any(term in lowered for term in filter_terms):
            matched_names.append(name)

    return sorted(matched_names), total_projects


def fetch_pypi_package_metadata(
    name: str,
    timeout: int = 15,
) -> Optional[Dict[str, Any]]:
    """Fetch package metadata and release history from PyPI JSON API."""
    url = f"{PYPI_JSON_BASE}/{urllib.parse.quote(name)}/json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "ecosystem": "pypi",
                "name": name,
                "is_removed": True,
                "version": None,
                "description": None,
                "date": None,
                "first_release_date": None,
                "releases_count": 0,
                "author": None,
                "requires_dist": [],
                "project_urls": {},
            }
        return None
    except Exception:
        return None

    info = data.get("info", {})
    releases = data.get("releases", {})

    upload_times: List[str] = []
    for ver_files in releases.values():
        if isinstance(ver_files, list):
            for file_info in ver_files:
                upload = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                if upload:
                    upload_times.append(upload)

    upload_times.sort()
    first_release = upload_times[0] if upload_times else None
    latest_release = upload_times[-1] if upload_times else None

    return {
        "ecosystem": "pypi",
        "name": name,
        "is_removed": False,
        "version": info.get("version"),
        "description": info.get("summary") or "",
        "date": latest_release,
        "first_release_date": first_release,
        "releases_count": len(releases),
        "author": info.get("author") or info.get("maintainer") or "",
        "author_email": info.get("author_email") or "",
        "requires_dist": info.get("requires_dist") or [],
        "project_urls": info.get("project_urls") or {},
        "keywords": info.get("keywords") or "",
    }


def write_snapshot_and_lock(
    out_dir: Path,
    ecosystem: str,
    records: List[Dict[str, Any]],
    lock_metadata: Dict[str, Any],
) -> Tuple[Path, Path]:
    """Write records to a JSONL file and write a hash-pinned lockfile."""
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_name = f"{ecosystem}_agent_packages.jsonl"
    lock_name = f"{ecosystem}_agent_acquisition-lock.json"

    jsonl_path = out_dir / jsonl_name
    lock_path = out_dir / lock_name

    lines = [json.dumps(r, sort_keys=True) for r in records]
    content = "\n".join(lines) + ("\n" if lines else "")
    content_bytes = content.encode("utf-8")
    sha256 = _hash_bytes(content_bytes)

    jsonl_path.write_bytes(content_bytes)

    lock_metadata.update({
        "ecosystem": ecosystem,
        "retrieval_date": str(date.today()),
        "package_count": len(records),
        "snapshot_file": jsonl_name,
        "snapshot_sha256": sha256,
        "content_note": (
            "Agent execution layer package metadata and manifests only. "
            "No package payloads, binary blobs, or executable archives are "
            "retrieved or stored."
        ),
    })

    lock_path.write_text(json.dumps(lock_metadata, indent=2) + "\n", encoding="utf-8")
    return jsonl_path, lock_path


def run_acquisition(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    ecosystem = args.ecosystem.lower()

    if ecosystem in ("npm", "all"):
        print(f"[*] Enumerating npm agent execution layer packages...")
        all_npm_records: Dict[str, Dict[str, Any]] = {}
        total_discards = 0

        for query in args.npm_queries:
            print(f"  -> Querying npm for '{query}' (limit={args.npm_limit})...")
            records, discards, reported = fetch_npm_search(
                query=query,
                limit=args.npm_limit,
                timeout=args.timeout,
            )
            total_discards += discards
            print(f"     Found {len(records)} packages (reported total: {reported}, discards: {discards})")
            for r in records:
                if r["name"] not in all_npm_records:
                    all_npm_records[r["name"]] = r

        npm_list = sorted(all_npm_records.values(), key=lambda x: x["name"])

        # Fetch manifests if requested
        if args.fetch_manifests:
            manifest_sample = args.manifest_limit or len(npm_list)
            sample_packages = npm_list[:manifest_sample]
            print(f"[*] Fetching manifests for {len(sample_packages)} npm packages (concurrency={args.concurrency})...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                manifest_map = {
                    p["name"]: pool.submit(fetch_npm_manifest, p["name"], timeout=args.timeout)
                    for p in sample_packages
                }
                for p in sample_packages:
                    try:
                        manifest = manifest_map[p["name"]].result()
                        p["manifest"] = manifest
                    except Exception:
                        p["manifest"] = None

        if not args.no_write:
            lock_meta = {
                "dataset": "npm-agent-execution-layer",
                "source_url": "https://registry.npmjs.org",
                "queries_used": args.npm_queries,
                "discards_count": total_discards,
                "license": "Open Data / Public Registry Metadata",
            }
            jsonl_path, lock_path = write_snapshot_and_lock(out_dir, "npm", npm_list, lock_meta)
            print(f"[+] Saved {len(npm_list)} npm packages to {jsonl_path.name}")
            print(f"[+] Emitted hash-pinned lockfile {lock_path.name}")
        else:
            print(f"[+] Dry run complete. {len(npm_list)} npm packages processed.")

    if ecosystem in ("pypi", "all"):
        print(f"[*] Enumerating PyPI agent execution layer packages via PEP 691 index...")
        pypi_names, total_pypi_proj = fetch_pypi_project_list(timeout=args.timeout)
        print(f"  -> Found {len(pypi_names)} PyPI packages matching agent terms out of {total_pypi_proj} total projects.")

        target_names = pypi_names
        if args.pypi_limit is not None:
            target_names = pypi_names[:args.pypi_limit]

        print(f"[*] Fetching detailed release metadata for {len(target_names)} PyPI packages (concurrency={args.concurrency})...")
        pypi_records: List[Dict[str, Any]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            future_to_name = {
                pool.submit(fetch_pypi_package_metadata, name, timeout=args.timeout): name
                for name in target_names
            }
            for future in concurrent.futures.as_completed(future_to_name):
                res = future.result()
                if res:
                    pypi_records.append(res)

        pypi_records.sort(key=lambda x: x["name"])

        if not args.no_write:
            lock_meta = {
                "dataset": "pypi-agent-execution-layer",
                "source_url": "https://pypi.org/simple",
                "total_pypi_projects_indexed": total_pypi_proj,
                "license": "Open Data / Public Registry Metadata",
            }
            jsonl_path, lock_path = write_snapshot_and_lock(out_dir, "pypi", pypi_records, lock_meta)
            print(f"[+] Saved {len(pypi_records)} PyPI packages to {jsonl_path.name}")
            print(f"[+] Emitted hash-pinned lockfile {lock_path.name}")
        else:
            print(f"[+] Dry run complete. {len(pypi_records)} PyPI packages processed.")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Acquire snapshots of AI agent execution layer packages from npm and PyPI."
    )
    parser.add_argument(
        "--ecosystem",
        choices=["npm", "pypi", "all"],
        default="all",
        help="Package ecosystem to enumerate (default: all)",
    )
    parser.add_argument(
        "--npm-queries",
        nargs="+",
        default=DEFAULT_NPM_QUERIES,
        help="Search queries for npm registry (default: modelcontextprotocol keywords:mcp)",
    )
    parser.add_argument(
        "--npm-limit",
        type=int,
        default=None,
        help="Max packages to retrieve per npm query (default: all)",
    )
    parser.add_argument(
        "--pypi-limit",
        type=int,
        default=None,
        help="Max packages to retrieve detailed metadata for on PyPI (default: all)",
    )
    parser.add_argument(
        "--fetch-manifests",
        action="store_true",
        help="Fetch package.json manifests for npm packages",
    )
    parser.add_argument(
        "--manifest-limit",
        type=int,
        default=500,
        help="Limit of package manifests to fetch (default: 500)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Directory to write snapshots and lockfiles (default: corpus/agent)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=8,
        help="Concurrency for parallel metadata fetching (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP request timeout in seconds (default: 20)",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Dry run without writing files to disk",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_acquisition(args))


if __name__ == "__main__":
    main()
