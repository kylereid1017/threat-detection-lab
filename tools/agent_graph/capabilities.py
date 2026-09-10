"""Static capability taxonomy for agent tool packages.

The question this answers is not "is this package malicious." It is "what can
this package do," which is a different and more useful question, because the
risk being modeled here is compositional: individually benign capabilities that
become an exfiltration chain when installed together.

The framing is Simon Willison's "lethal trifecta": an agent becomes dangerous
when three properties are present at once, and only when all three are present.
Access to private data. Exposure to content an attacker can plant. The ability
to send data outward. Any one alone is ordinary. All three in one agent context
is a working exfiltration path that requires no exploit and no malicious code.
The framing is his; the measurement in this repository is not his and he is not
responsible for it.

## Why evidence tiers exist

A capability claim is only as good as what it rests on. A package that depends
on `puppeteer` demonstrably drives a browser. A package whose description says
"browse the web" might do anything. Treating those as equal evidence produces a
taxonomy that looks precise and is not.

Every assignment therefore records the evidence that produced it and the tier
that evidence sits in:

- `DECLARED_DEPENDENCY`: the package depends on a library whose function is the
  capability, or the operator wired a credential into it that only grants that
  capability. Both are explicit declarations by someone who knows: the package
  author in one case, the person who installed it in the other. Configuration
  wiring matters more than it first appears, because modern servers reach the
  network with the runtime's built-in client and touch files with the standard
  library, leaving no dependency to observe. For those packages the credential
  in the configuration is the only static evidence that exists.
- `MANIFEST_STRUCTURE`: an entrypoint, lifecycle hook, or engine constraint.
  Structural fact about the package, not an inference about intent.
- `DECLARED_TEXT`: keywords, description, or name. Author-written marketing
  prose. Weakest tier, deliberately insufficient on its own.

`derive_capabilities` takes a minimum tier so that every published number can
state which evidence it rests on, and so the same corpus can be measured at
several strictness levels rather than one unexplained default.

## What this cannot see

Static analysis of manifests and dependency sets misses a package that
implements a capability with the standard library, that shells out, that loads
code at runtime, or that hides the behavior entirely. Absence of a capability
here means absence of evidence, never absence of the capability. Every rate
computed from this taxonomy is therefore a lower bound, and is labeled as one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class Tier(IntEnum):
    """Evidence classes. The number selects how much evidence to admit.

    `capabilities(min_tier)` returns every capability supported by evidence at
    or above the given tier, so tier 1 admits everything and tier 3 admits only
    dependency and wiring evidence.

    The original design assumed dependency evidence was strongest and set the
    default there. Measured against `labels.json` (n=23), that was wrong:

        dependencies and wiring only   precision 0.625   recall 0.323
        all evidence admitted          precision 0.733   recall 0.532

    Admitting the package's own description improved **both** precision and
    recall, which is not the usual shape of that tradeoff and is worth
    explaining. Agent tool servers are thin protocol wrappers. Their dependency
    sets are the protocol SDK and perhaps one HTTP client, because they reach
    services through the runtime's built-in fetch and touch files through the
    standard library. What the server is *for* never appears in its
    dependencies, while its description states it plainly, because a wrapper's
    entire reason to exist is the service it wraps.

    There is also a question of what each class measures. A dependency describes
    what the code *could* do. The composition model cares what the model can be
    made to do through exposed tools. Those differ: `node-fetch` in a source
    control server means the code can reach any URL, not that the agent has a
    tool to make it.

    The default is therefore `DECLARED_TEXT`, meaning all evidence. Dependency
    evidence is kept because it remains the upper bound on latent code
    capability, which matters if a package is compromised even though it is not
    the question this taxonomy asks.
    """

    DECLARED_TEXT = 1
    MANIFEST_STRUCTURE = 2
    DECLARED_DEPENDENCY = 3


class Leg(str):
    """The three properties whose combination is the hazard."""

    PRIVATE_DATA = "private_data"
    UNTRUSTED_INGRESS = "untrusted_ingress"
    EXFILTRATION = "exfiltration"


#: Capabilities, each mapped to the trifecta leg it satisfies.
#:
#: A capability belongs to exactly one leg. Where a real behavior spans two, it
#: is split into two capabilities rather than blurred, because the composition
#: model needs to know which leg a package actually closes.
CAPABILITY_LEGS: Dict[str, str] = {
    # Private data
    "fs_read": Leg.PRIVATE_DATA,
    "credential_read": Leg.PRIVATE_DATA,
    "database_read": Leg.PRIVATE_DATA,
    "repo_read": Leg.PRIVATE_DATA,
    "comms_read": Leg.PRIVATE_DATA,
    "cloud_read": Leg.PRIVATE_DATA,
    # Untrusted content ingress
    "web_fetch": Leg.UNTRUSTED_INGRESS,
    "search_results": Leg.UNTRUSTED_INGRESS,
    "browser_automation": Leg.UNTRUSTED_INGRESS,
    "issue_tracker": Leg.UNTRUSTED_INGRESS,
    "inbound_messages": Leg.UNTRUSTED_INGRESS,
    "document_parse": Leg.UNTRUSTED_INGRESS,
    # Exfiltration
    "net_egress": Leg.EXFILTRATION,
    "remote_write": Leg.EXFILTRATION,
    "message_send": Leg.EXFILTRATION,
    "repo_write": Leg.EXFILTRATION,
    "fs_write": Leg.EXFILTRATION,
}

#: Dependency name to capability. Matching is exact on the package name or on a
#: scope prefix, never a substring, because substring matching on dependency
#: names produced most of the false positives in the earlier package work.
#:
#: A dependency implies the capability it provides, not the capability the
#: depending package necessarily uses. A package that pulls in `axios` for its
#: own update check does have outbound network capability; that is the point.
DEPENDENCY_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    # Outbound HTTP clients: egress, and the ability to pull remote content.
    "axios": ("net_egress", "web_fetch"),
    "node-fetch": ("net_egress", "web_fetch"),
    "undici": ("net_egress", "web_fetch"),
    "got": ("net_egress", "web_fetch"),
    "superagent": ("net_egress", "web_fetch"),
    "request": ("net_egress", "web_fetch"),
    "cross-fetch": ("net_egress", "web_fetch"),
    "ky": ("net_egress", "web_fetch"),
    "requests": ("net_egress", "web_fetch"),
    "httpx": ("net_egress", "web_fetch"),
    "aiohttp": ("net_egress", "web_fetch"),
    "urllib3": ("net_egress", "web_fetch"),
    # Browser automation: strongest untrusted-content ingress there is.
    "puppeteer": ("browser_automation", "web_fetch", "net_egress"),
    "puppeteer-core": ("browser_automation", "web_fetch", "net_egress"),
    "playwright": ("browser_automation", "web_fetch", "net_egress"),
    "playwright-core": ("browser_automation", "web_fetch", "net_egress"),
    "selenium": ("browser_automation", "web_fetch", "net_egress"),
    "cheerio": ("document_parse",),
    "jsdom": ("document_parse",),
    "beautifulsoup4": ("document_parse",),
    "readability": ("document_parse",),
    "turndown": ("document_parse",),
    "pdf-parse": ("document_parse",),
    "pypdf": ("document_parse",),
    "mammoth": ("document_parse",),
    # Filesystem
    "fs-extra": ("fs_read", "fs_write"),
    "glob": ("fs_read",),
    "fast-glob": ("fs_read",),
    "globby": ("fs_read",),
    "chokidar": ("fs_read",),
    "graceful-fs": ("fs_read", "fs_write"),
    "watchdog": ("fs_read",),
    # Databases
    "pg": ("database_read",),
    "mysql": ("database_read",),
    "mysql2": ("database_read",),
    "sqlite3": ("database_read",),
    "better-sqlite3": ("database_read",),
    "mongodb": ("database_read",),
    "redis": ("database_read",),
    "ioredis": ("database_read",),
    "psycopg2": ("database_read",),
    "psycopg2-binary": ("database_read",),
    "pymongo": ("database_read",),
    "sqlalchemy": ("database_read",),
    "prisma": ("database_read",),
    "@prisma/client": ("database_read",),
    # Source control
    "simple-git": ("repo_read", "repo_write"),
    "isomorphic-git": ("repo_read", "repo_write"),
    "nodegit": ("repo_read", "repo_write"),
    "gitpython": ("repo_read", "repo_write"),
    "@octokit/rest": ("repo_read", "repo_write", "issue_tracker"),
    "@octokit/core": ("repo_read", "repo_write", "issue_tracker"),
    "@octokit/graphql": ("repo_read", "issue_tracker"),
    "octokit": ("repo_read", "repo_write", "issue_tracker"),
    "pygithub": ("repo_read", "repo_write", "issue_tracker"),
    "@gitbeaker/rest": ("repo_read", "repo_write", "issue_tracker"),
    # Messaging and mail
    "nodemailer": ("message_send",),
    "@slack/web-api": ("comms_read", "message_send", "inbound_messages"),
    "@slack/bolt": ("comms_read", "message_send", "inbound_messages"),
    "slack-sdk": ("comms_read", "message_send", "inbound_messages"),
    "discord.js": ("comms_read", "message_send", "inbound_messages"),
    "imapflow": ("comms_read", "inbound_messages"),
    "mailparser": ("comms_read", "inbound_messages", "document_parse"),
    "googleapis": ("comms_read", "cloud_read", "remote_write"),
    "twilio": ("message_send",),
    # Cloud and object storage
    "@aws-sdk/client-s3": ("cloud_read", "remote_write"),
    "@aws-sdk/client-sts": ("credential_read", "cloud_read"),
    "@aws-sdk/client-secrets-manager": ("credential_read",),
    "aws-sdk": ("cloud_read", "remote_write", "credential_read"),
    "boto3": ("cloud_read", "remote_write", "credential_read"),
    "@azure/storage-blob": ("cloud_read", "remote_write"),
    "@azure/identity": ("credential_read",),
    "@google-cloud/storage": ("cloud_read", "remote_write"),
    # Credentials and secrets
    "dotenv": ("credential_read",),
    "keytar": ("credential_read",),
    "python-dotenv": ("credential_read",),
    "keyring": ("credential_read",),
    # Search
    "@brave/search": ("search_results", "web_fetch"),
    "serpapi": ("search_results", "web_fetch"),
    "duckduckgo-search": ("search_results", "web_fetch"),
    "tavily-python": ("search_results", "web_fetch"),
}

#: Scope prefixes whose members share a capability set. Applied only when no
#: exact match is found, and matched on the scope boundary rather than as a
#: substring.
SCOPE_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "@aws-sdk/": ("cloud_read", "remote_write"),
    "@azure/": ("cloud_read", "remote_write"),
    "@google-cloud/": ("cloud_read", "remote_write"),
    "@octokit/": ("repo_read", "issue_tracker"),
    "@slack/": ("comms_read", "message_send", "inbound_messages"),
}

#: Keyword and description terms. Tier 1 evidence: never sufficient alone, and
#: excluded entirely from any measurement published at a higher minimum tier.
TEXT_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "filesystem": ("fs_read",),
    "file system": ("fs_read",),
    "browse": ("web_fetch",),
    "scrape": ("web_fetch", "document_parse"),
    "crawler": ("web_fetch",),
    "search": ("search_results",),
    "email": ("comms_read", "message_send"),
    "calendar": ("comms_read",),
    "database": ("database_read",),
    "postgres": ("database_read",),
    "sqlite": ("database_read",),
    "github": ("repo_read", "issue_tracker"),
    "gitlab": ("repo_read", "issue_tracker"),
    "jira": ("issue_tracker",),
    "slack": ("comms_read", "message_send"),
    "s3": ("cloud_read", "remote_write"),
    "secrets": ("credential_read",),
    "credentials": ("credential_read",),
}

#: Credential environment variables to the capability that possessing them
#: grants. Derived from the configuration rather than the package, because a
#: server wired to a source control token can reach source control whether or
#: not its manifest says so.
#:
#: Matching is on a normalized suffix so that `GITHUB_TOKEN`,
#: `GITHUB_PERSONAL_ACCESS_TOKEN`, and `MY_GITHUB_TOKEN` all resolve, without
#: the substring collisions that a naive contains-check would produce.
WIRING_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    "github": ("repo_read", "repo_write", "issue_tracker", "net_egress"),
    "gitlab": ("repo_read", "repo_write", "issue_tracker", "net_egress"),
    "slack": ("comms_read", "message_send", "inbound_messages", "net_egress"),
    "discord": ("comms_read", "message_send", "inbound_messages", "net_egress"),
    "brave": ("search_results", "web_fetch", "net_egress"),
    "tavily": ("search_results", "web_fetch", "net_egress"),
    "serp": ("search_results", "web_fetch", "net_egress"),
    "perplexity": ("search_results", "web_fetch", "net_egress"),
    "exa": ("search_results", "web_fetch", "net_egress"),
    "notion": ("document_parse", "remote_write", "net_egress"),
    "linear": ("issue_tracker", "remote_write", "net_egress"),
    "jira": ("issue_tracker", "remote_write", "net_egress"),
    "atlassian": ("issue_tracker", "remote_write", "net_egress"),
    "sentry": ("issue_tracker", "net_egress"),
    "aws_access_key": ("cloud_read", "remote_write", "credential_read"),
    "aws_secret": ("cloud_read", "remote_write", "credential_read"),
    "aws_session": ("cloud_read", "remote_write", "credential_read"),
    "gcp": ("cloud_read", "remote_write"),
    "google_application_credentials": ("cloud_read", "remote_write", "credential_read"),
    "azure": ("cloud_read", "remote_write"),
    "database_url": ("database_read", "net_egress"),
    "postgres": ("database_read",),
    "mysql": ("database_read",),
    "mongodb": ("database_read",),
    "redis": ("database_read",),
    "supabase": ("database_read", "remote_write", "net_egress"),
    "sendgrid": ("message_send", "net_egress"),
    "twilio": ("message_send", "net_egress"),
    "resend": ("message_send", "net_egress"),
    "stripe": ("remote_write", "net_egress"),
    "figma": ("remote_write", "net_egress"),
}


def capabilities_from_wiring(env_keys: Sequence[str]) -> List[Tuple[str, str]]:
    """Capabilities implied by the credentials an operator wired into a server.

    Returns (capability, matched_term) pairs so the evidence names the variable
    that produced it rather than asserting the capability bare.
    """
    found: List[Tuple[str, str]] = []
    for raw in env_keys or []:
        key = re.sub(r"[^a-z0-9]+", "_", str(raw).strip().lower())
        for term, capabilities in WIRING_CAPABILITIES.items():
            if term in key.split("_") or term in key:
                for capability in capabilities:
                    found.append((capability, str(raw)))
    return found


#: Lifecycle hooks that execute code at install time.
INSTALL_HOOKS = ("preinstall", "install", "postinstall")

#: Hooks that run in development and packaging flows rather than on consumer
#: install. Counted separately because conflating them overstates exposure.
BUILD_HOOKS = ("prepare", "prepack", "postpack", "prepublish", "prepublishOnly")


@dataclass(frozen=True)
class Evidence:
    """Why a capability was assigned."""

    capability: str
    tier: Tier
    source: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "tier": int(self.tier),
            "tier_name": self.tier.name,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass
class PackageCapabilities:
    """Derived capability surface for one package, with its evidence."""

    name: str
    ecosystem: str = "npm"
    evidence: List[Evidence] = field(default_factory=list)
    has_executable_entrypoint: bool = False
    install_hooks: List[str] = field(default_factory=list)
    build_hooks: List[str] = field(default_factory=list)
    manifest_available: bool = False

    def capabilities(self, min_tier: Tier = Tier.DECLARED_TEXT) -> Set[str]:
        return {e.capability for e in self.evidence if e.tier >= min_tier}

    def legs(self, min_tier: Tier = Tier.DECLARED_TEXT) -> Set[str]:
        return {CAPABILITY_LEGS[c] for c in self.capabilities(min_tier) if c in CAPABILITY_LEGS}

    def closes_trifecta_alone(self, min_tier: Tier = Tier.DECLARED_TEXT) -> bool:
        """True when one package supplies all three legs by itself."""
        return len(self.legs(min_tier)) == 3

    def evidence_for(self, capability: str) -> List[Evidence]:
        return [e for e in self.evidence if e.capability == capability]

    def to_dict(self, min_tier: Tier = Tier.DECLARED_TEXT) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "capabilities": sorted(self.capabilities(min_tier)),
            "legs": sorted(self.legs(min_tier)),
            "closes_trifecta_alone": self.closes_trifecta_alone(min_tier),
            "has_executable_entrypoint": self.has_executable_entrypoint,
            "install_hooks": self.install_hooks,
            "build_hooks": self.build_hooks,
            "manifest_available": self.manifest_available,
            "evidence": [e.to_dict() for e in self.evidence],
        }


def _normalize_dependency(name: str) -> str:
    return name.strip().lower()


def _text_blob(record: Dict[str, Any]) -> str:
    # The package name is declared text too, and in this ecosystem it is the most
    # informative text there is: `server-filesystem` and `brave-search` state
    # their function in the identifier. It also keeps packages that resolve to no
    # registry manifest from scoring as capability-free, which would silently
    # understate every composition rate.
    parts = [str(record.get("name") or ""), str(record.get("description") or "")]
    keywords = record.get("keywords") or []
    if isinstance(keywords, list):
        parts.extend(str(k) for k in keywords)
    return " ".join(parts).lower()


def derive_capabilities(
    record: Dict[str, Any], env_keys: Optional[Sequence[str]] = None
) -> PackageCapabilities:
    """Derive a package's capability surface from registry metadata.

    `record` is one row of an agent registry snapshot: name, ecosystem,
    description, keywords, and optionally a reduced `manifest` carrying
    dependencies, bin, and scripts.

    `env_keys` are the credential variable names the operator wired into this
    server in their configuration. Supplying them raises recall substantially on
    packages that reach services through the runtime's built-in client, which
    leaves nothing in the dependency set to observe.
    """
    result = PackageCapabilities(
        name=str(record.get("name", "")),
        ecosystem=str(record.get("ecosystem", "npm")),
    )
    seen: Set[Tuple[str, Tier, str]] = set()

    def add(capability: str, tier: Tier, source: str, detail: str) -> None:
        if capability not in CAPABILITY_LEGS:
            return
        key = (capability, tier, detail)
        if key in seen:
            return
        seen.add(key)
        result.evidence.append(Evidence(capability, tier, source, detail))

    manifest = record.get("manifest") or {}
    result.manifest_available = bool(manifest)

    # Tier 3: declared dependencies.
    dependencies: Dict[str, Any] = {}
    for block in ("dependencies", "devDependencies"):
        value = manifest.get(block)
        if isinstance(value, dict):
            # Development dependencies do not ship to consumers, so they are not
            # part of the runtime capability surface and are deliberately skipped.
            if block == "dependencies":
                dependencies.update(value)
    for dependency in dependencies:
        normalized = _normalize_dependency(dependency)
        capabilities = DEPENDENCY_CAPABILITIES.get(normalized)
        if capabilities:
            for capability in capabilities:
                add(capability, Tier.DECLARED_DEPENDENCY, "dependency", normalized)
            continue
        for scope, scoped_capabilities in SCOPE_CAPABILITIES.items():
            if normalized.startswith(scope):
                for capability in scoped_capabilities:
                    add(capability, Tier.DECLARED_DEPENDENCY, "dependency_scope", normalized)
                break

    # Tier 2: manifest structure.
    binaries = manifest.get("bin")
    if binaries:
        result.has_executable_entrypoint = True
    scripts = manifest.get("scripts")
    if isinstance(scripts, dict):
        result.install_hooks = sorted(h for h in INSTALL_HOOKS if h in scripts)
        result.build_hooks = sorted(h for h in BUILD_HOOKS if h in scripts)
        if result.install_hooks:
            # An install hook executes on the consumer's machine with the
            # consumer's privileges. It is not a trifecta leg, but it is the
            # mechanism by which a package acquires any capability at all.
            add(
                "fs_write",
                Tier.MANIFEST_STRUCTURE,
                "install_hook",
                ",".join(result.install_hooks),
            )

    # Configuration wiring, treated as declaration-strength evidence.
    for capability, matched in capabilities_from_wiring(env_keys or []):
        add(capability, Tier.DECLARED_DEPENDENCY, "config_env", matched)

    # Tier 1: author-written text.
    blob = _text_blob(record)
    for term, capabilities in TEXT_CAPABILITIES.items():
        if term in blob:
            for capability in capabilities:
                add(capability, Tier.DECLARED_TEXT, "text", term)

    return result


def derive_many(
    records: Iterable[Dict[str, Any]]
) -> List[PackageCapabilities]:
    return [derive_capabilities(r) for r in records]


def taxonomy_summary() -> Dict[str, Any]:
    """Machine-readable description of the taxonomy itself."""
    by_leg: Dict[str, List[str]] = {}
    for capability, leg in sorted(CAPABILITY_LEGS.items()):
        by_leg.setdefault(leg, []).append(capability)
    return {
        "legs": by_leg,
        "capability_count": len(CAPABILITY_LEGS),
        "dependency_rules": len(DEPENDENCY_CAPABILITIES),
        "scope_rules": len(SCOPE_CAPABILITIES),
        "text_rules": len(TEXT_CAPABILITIES),
        "tiers": {t.name: int(t) for t in Tier},
        "framing_credit": (
            "The three-property hazard framing follows Simon Willison's 'lethal "
            "trifecta'. The taxonomy, the measurement, and any errors in them are "
            "this repository's own."
        ),
        "lower_bound_note": (
            "Static derivation from manifests and dependency sets cannot see a "
            "capability implemented with the standard library, reached by shelling "
            "out, or loaded at runtime. Absence of a capability is absence of "
            "evidence, so every rate derived from this taxonomy is a lower bound."
        ),
    }
