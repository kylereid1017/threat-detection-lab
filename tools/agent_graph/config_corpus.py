"""Acquire real agent tool configurations and the manifests they reference.

The composition thesis needs observed installations, not hypothetical ones.
Agent clients store their tool configuration in JSON files carrying an
`mcpServers` object, and those files are published in public repositories in
large numbers.

## What is collected, and the sampling bias in it

Configurations published to public repositories are not a random sample of
configurations in use. They skew toward example configs in server repositories,
template projects, and developers who publish dotfiles. Example configs in
particular tend to list a single server, which biases the corpus *against* the
finding this study is looking for. That direction matters: it means a measured
composed-closure rate is conservative rather than flattering, and the write-up
says so rather than burying it.

Configurations are deduplicated by their resolved server set, so a template
copied into two hundred forks counts once. Without that, the corpus measures
fork popularity rather than configuration practice.

## Boundaries

Read-only search and raw file reads over public data. No package payloads are
downloaded, nothing is executed, and no repository is modified. Package
manifests come from the registry's own metadata endpoint, which returns the
manifest and never the tarball.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "corpus" / "agent_configs"
USER_AGENT = "threat-detection-lab/agent_graph (defensive research)"
NPM_LATEST = "https://registry.npmjs.org/{name}/latest"

#: Code search queries. Several variants because a single query is capped at
#: 1,000 returned results regardless of how many matches exist.
SEARCH_QUERIES: Tuple[str, ...] = (
    "mcpServers in:file language:json filename:mcp.json",
    "mcpServers in:file language:json filename:claude_desktop_config.json",
    "mcpServers in:file language:json filename:.mcp.json",
    "mcpServers in:file language:json filename:mcp_config.json",
    "mcpServers in:file language:json filename:cline_mcp_settings.json",
)

#: Runner commands whose first non-flag argument is the package being executed.
#: These are how a configuration actually names a package: the config points at
#: a runner, and the package is an argument to it.
RUNNERS = {
    "npx": {"-y", "--yes", "-p", "--package", "--quiet", "-q"},
    "bunx": {"-y", "--yes"},
    "pnpm": {"dlx", "-y"},
    "yarn": {"dlx"},
    "uvx": {"--from", "-q", "--quiet"},
    "uv": {"tool", "run", "--from"},
    "pipx": {"run", "--spec"},
}


class CorpusError(RuntimeError):
    """Acquisition failed in a way that would silently shrink the corpus."""


def _gh_api(path: str, retries: int = 3) -> Dict[str, Any]:
    """Call the GitHub API through the authenticated CLI.

    The CLI is used rather than a raw request so the operator's existing
    credential handling applies and no token is read, stored, or logged here.
    """
    last = ""
    for attempt in range(retries):
        # Bytes, not text. On Windows `text=True` decodes with the ANSI code
        # page and dies on the UTF-8 the API actually returns.
        proc = subprocess.run(
            ["gh", "api", path],
            capture_output=True,
            timeout=120,
        )
        stderr = proc.stderr.decode("utf-8", errors="replace")
        if proc.returncode == 0:
            try:
                return json.loads(proc.stdout.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                last = f"unparseable response: {exc}"
        else:
            last = stderr.strip()[:300]
            if "rate limit" in last.lower():
                time.sleep(20 * (attempt + 1))
                continue
        time.sleep(3 * (attempt + 1))
    raise CorpusError(f"gh api {path} failed: {last}")


def search_config_files(
    queries: Sequence[str] = SEARCH_QUERIES,
    per_query: int = 300,
    page_size: int = 100,
) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Return candidate config file locations, plus per-query counts."""
    found: Dict[str, Dict[str, str]] = {}
    counts: Dict[str, int] = {}
    for query in queries:
        retrieved = 0
        page = 1
        while retrieved < per_query:
            size = min(page_size, per_query - retrieved)
            path = (
                "search/code?q="
                + urllib.parse.quote(query)
                + f"&per_page={size}&page={page}"
            )
            try:
                payload = _gh_api(path)
            except CorpusError:
                break
            items = payload.get("items", [])
            if not items:
                break
            for item in items:
                repo = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                sha = item.get("sha", "")
                if not repo or not file_path:
                    continue
                key = f"{repo}:{file_path}"
                found.setdefault(
                    key,
                    {"repo": repo, "path": file_path, "sha": sha, "query": query},
                )
            retrieved += len(items)
            counts[query] = counts.get(query, 0) + len(items)
            if len(items) < size:
                break
            page += 1
            # Authenticated code search allows ten requests a minute. Pacing
            # here rather than absorbing 403s keeps the corpus complete.
            time.sleep(6.5)
    return list(found.values()), counts


def fetch_raw(repo: str, path: str, timeout: int = 20) -> Optional[str]:
    """Read one file's raw content. Returns None rather than raising.

    Repository paths routinely contain spaces and other characters that are
    illegal in a URL, so every segment is percent-encoded. Skipping that turns
    one unusual filename into a failed run.
    """
    safe_path = "/".join(urllib.parse.quote(segment) for segment in path.split("/"))
    safe_repo = "/".join(urllib.parse.quote(segment) for segment in repo.split("/"))
    url = f"https://raw.githubusercontent.com/{safe_repo}/HEAD/{safe_path}"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception:
        # Any failure here is one missing file, and it is counted by the caller.
        # Letting it propagate would discard every other file in the batch.
        return None


def extract_package(command: str, args: Sequence[str]) -> Optional[str]:
    """Resolve the package a server entry actually runs.

    A configuration names a runner and passes the package as an argument, so
    reading the `command` field alone yields `npx` several thousand times and
    tells you nothing.
    """
    # Configurations in the wild are not schema-validated. `command` arrives as
    # a list, a number, or null often enough that assuming a string ends the run
    # on whichever file happens to be malformed.
    if isinstance(command, (list, tuple)):
        command = command[0] if command else ""
    command = str(command or "").strip().lower()
    if isinstance(args, (str, bytes)):
        args = [args]
    elif not isinstance(args, (list, tuple)):
        args = []
    base = command.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    base = base.removesuffix(".exe").removesuffix(".cmd")
    if base not in RUNNERS:
        return None
    skip = RUNNERS[base]
    for arg in args or []:
        token = str(arg).strip()
        if not token or token.startswith("-") or token in skip:
            continue
        if token in {"dlx", "run", "tool"}:
            continue
        # Strip python version specifiers (e.g. ==1.2.3, >=1.0, ~=2.0)
        token = re.split(r"[=><~]", token)[0]
        # Strip a version pin, keeping the scope on scoped names.
        if token.startswith("@"):
            parts = token.split("@")
            if len(parts) >= 3:
                token = "@" + parts[1]
        elif "@" in token:
            token = token.split("@", 1)[0]
        if "/" in token or token.replace("-", "").replace("_", "").replace(".", "").isalnum():
            return token
    return None


def parse_config(text: str) -> List[Dict[str, Any]]:
    """Extract server entries from a configuration document."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    servers = data.get("mcpServers") or data.get("mcp_servers")
    if not isinstance(servers, dict):
        return []
    entries: List[Dict[str, Any]] = []
    for label, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        package = extract_package(spec.get("command", ""), spec.get("args") or [])
        entries.append(
            {
                "label": str(label),
                "command": str(spec.get("command", "")),
                "package": package,
                "has_env": bool(spec.get("env")),
                "env_keys": sorted(str(k) for k in (spec.get("env") or {})),
                "transport": "remote" if spec.get("url") else "stdio",
            }
        )
    return entries


@dataclass
class ConfigRecord:
    repo: str
    path: str
    servers: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def packages(self) -> List[str]:
        return sorted({s["package"] for s in self.servers if s.get("package")})

    @property
    def fingerprint(self) -> str:
        """Identity of the configuration by its resolved server set."""
        return hashlib.sha256("|".join(self.packages).encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": self.repo,
            "path": self.path,
            "servers": self.servers,
            "packages": self.packages,
            "fingerprint": self.fingerprint,
        }


def collect_configs(
    locations: Sequence[Dict[str, str]], workers: int = 8
) -> Tuple[List[ConfigRecord], Dict[str, int]]:
    """Fetch and parse configuration files, reporting what was discarded."""
    stats = {"fetched": 0, "unreadable": 0, "unparseable": 0, "no_servers": 0}

    def one(location: Dict[str, str]) -> Optional[ConfigRecord]:
        try:
            text = fetch_raw(location["repo"], location["path"])
        except Exception:
            stats["unreadable"] += 1
            return None
        if text is None:
            stats["unreadable"] += 1
            return None
        stats["fetched"] += 1
        try:
            servers = parse_config(text)
        except Exception:
            # One malformed configuration must not end the acquisition. These
            # files are hand-written and unvalidated, so malformed is normal.
            stats["unparseable"] += 1
            return None
        if not servers:
            stats["no_servers"] += 1
            return None
        return ConfigRecord(location["repo"], location["path"], servers)

    records: List[ConfigRecord] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for record in pool.map(one, locations):
            if record is not None:
                records.append(record)
    return records, stats


def deduplicate(records: Sequence[ConfigRecord]) -> Tuple[List[ConfigRecord], int]:
    """One record per distinct resolved server set."""
    by_fingerprint: Dict[str, ConfigRecord] = {}
    duplicates = 0
    for record in records:
        if not record.packages:
            continue
        if record.fingerprint in by_fingerprint:
            duplicates += 1
            continue
        by_fingerprint[record.fingerprint] = record
    return sorted(by_fingerprint.values(), key=lambda r: r.repo), duplicates


def fetch_npm_manifest(name: str, timeout: int = 20) -> Optional[Dict[str, Any]]:
    """Registry metadata for a package. Returns the manifest, never a tarball."""
    url = NPM_LATEST.format(name=urllib.parse.quote(name, safe="@/"))
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None
    return {
        "name": data.get("name", name),
        "ecosystem": "npm",
        "description": data.get("description", ""),
        "keywords": data.get("keywords") or [],
        "manifest": {
            "dependencies": data.get("dependencies") or {},
            "bin": data.get("bin") or {},
            "scripts": data.get("scripts") or {},
        },
    }


def fetch_manifests(
    names: Iterable[str], workers: int = 10
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Fetch manifests concurrently, returning what resolved and what did not."""
    names = sorted(set(names))
    resolved: Dict[str, Dict[str, Any]] = {}
    missing: List[str] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, record in zip(names, pool.map(fetch_npm_manifest, names)):
            if record:
                resolved[name] = record
            else:
                missing.append(name)
    return resolved, missing


def write_snapshot(
    records: Sequence[ConfigRecord],
    manifests: Dict[str, Dict[str, Any]],
    out_dir: Path,
    stats: Dict[str, Any],
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    config_body = "\n".join(json.dumps(r.to_dict(), sort_keys=True) for r in records) + "\n"
    (out_dir / "agent_configs.jsonl").write_text(config_body, encoding="utf-8", newline="\n")
    manifest_body = (
        "\n".join(json.dumps(m, sort_keys=True) for _, m in sorted(manifests.items())) + "\n"
    )
    (out_dir / "referenced_packages.jsonl").write_text(
        manifest_body, encoding="utf-8", newline="\n"
    )

    lock = {
        "source": "GitHub code search over public repositories",
        "retrieval_date": date.today().isoformat(),
        "queries": list(SEARCH_QUERIES),
        "configs_retained": len(records),
        "packages_resolved": len(manifests),
        "acquisition_stats": stats,
        "configs_sha256": hashlib.sha256(config_body.encode("utf-8")).hexdigest(),
        "packages_sha256": hashlib.sha256(manifest_body.encode("utf-8")).hexdigest(),
        "sampling_note": (
            "Configurations published to public repositories are not a random sample "
            "of configurations in use. They skew toward example configs in server "
            "repositories and template projects, which typically list a single server. "
            "That biases the corpus against finding composed closures, so a measured "
            "composed rate is conservative."
        ),
        "content_note": (
            "Configuration files and registry manifest metadata only. No package "
            "payloads were downloaded and nothing was executed."
        ),
    }
    (out_dir / "acquisition-lock.json").write_text(
        json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return lock


def load_snapshot(out_dir: Path = DEFAULT_OUT) -> Tuple[List[ConfigRecord], Dict[str, Dict[str, Any]]]:
    configs_path = out_dir / "agent_configs.jsonl"
    packages_path = out_dir / "referenced_packages.jsonl"
    if not configs_path.is_file():
        raise CorpusError(f"no configuration snapshot at {configs_path}")
    records: List[ConfigRecord] = []
    for line in configs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        records.append(
            ConfigRecord(data["repo"], data["path"], data.get("servers", []))
        )
    manifests: Dict[str, Dict[str, Any]] = {}
    if packages_path.is_file():
        for line in packages_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                manifests[record["name"]] = record
    return records, manifests
