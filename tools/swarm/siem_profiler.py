"""EPIC 3 — Multi-SIEM query complexity and performance profiler.

Enterprise SIEM clusters degrade under unoptimised detection logic. A rule that
is analytically correct can still be operationally unaffordable: leading
wildcards defeat term indexes and force full scans, unanchored regexes evaluate
per event, and wide OR expansions multiply clause evaluation.

This module compiles each Sigma rule to CrowdStrike LogScale (CQL), Splunk SPL,
and Elastic Lucene, then statically analyses the emitted query for the patterns
that drive search cost, producing a complexity score and an estimated
indexing/compute impact rating.

The scoring is a static heuristic, not a benchmark. It ranks rules against each
other and flags specific costly constructs; it does not predict wall-clock
search time on any particular cluster.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sigma.backends.crowdstrike import LogScaleBackend
from sigma.backends.elasticsearch import LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[2]

#: Impact rating thresholds applied to the complexity score.
IMPACT_THRESHOLDS: Tuple[Tuple[int, str], ...] = (
    (40, "Low"),
    (90, "Moderate"),
    (160, "High"),
)
COSTLY = "Costly"

#: Relative cost weights. Wildcard and regex penalties dominate because they
#: defeat index seeks; token count is a mild linear term.
WEIGHTS: Dict[str, float] = {
    "tokens": 0.5,
    "nesting_depth": 4.0,
    "boolean_clauses": 2.0,
    "leading_wildcards": 6.0,
    "unanchored_regexes": 5.0,
    "case_insensitive_ops": 1.0,
    "or_expansion_terms": 1.5,
}

# A quoted or bare term beginning with '*' cannot use a term index.
_LEADING_WC_RE = re.compile(r'(?:[:=]\s*|["(,]\s*)\*')
# LogScale/CQL style regex literals: /body/flags
_REGEX_LITERAL_RE = re.compile(r"/((?:[^/\\]|\\.)+)/([a-z]*)")
_TOKEN_RE = re.compile(r"[^\s()\[\],]+")


@dataclass
class QueryProfile:
    """Static cost profile of one compiled query for one SIEM backend."""

    rule_name: str
    backend: str
    query: str
    query_length: int = 0
    tokens: int = 0
    nesting_depth: int = 0
    boolean_clauses: int = 0
    leading_wildcards: int = 0
    unanchored_regexes: int = 0
    case_insensitive_ops: int = 0
    or_expansion_terms: int = 0
    complexity_score: float = 0.0
    impact: str = "Low"
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_name": self.rule_name,
            "backend": self.backend,
            "query_length": self.query_length,
            "tokens": self.tokens,
            "nesting_depth": self.nesting_depth,
            "boolean_clauses": self.boolean_clauses,
            "leading_wildcards": self.leading_wildcards,
            "unanchored_regexes": self.unanchored_regexes,
            "case_insensitive_ops": self.case_insensitive_ops,
            "or_expansion_terms": self.or_expansion_terms,
            "complexity_score": round(self.complexity_score, 2),
            "impact": self.impact,
            "findings": self.findings,
        }


@dataclass
class ProfilerReport:
    """Aggregate multi-backend profiling result across the rule corpus."""

    profiles: List[QueryProfile] = field(default_factory=list)

    def by_backend(self) -> Dict[str, List[QueryProfile]]:
        grouped: Dict[str, List[QueryProfile]] = {}
        for profile in self.profiles:
            grouped.setdefault(profile.backend, []).append(profile)
        return grouped

    def worst(self, limit: int = 5) -> List[QueryProfile]:
        return sorted(self.profiles, key=lambda p: -p.complexity_score)[:limit]

    def to_dict(self) -> Dict[str, object]:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "backends": sorted(self.by_backend()),
            "worst": [p.to_dict() for p in self.worst()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Renders an ICD 203 formatted query performance assessment."""
        lines = [
            "# Multi-SIEM Query Complexity Assessment",
            "",
            "**Scope.** Static cost analysis of every committed Sigma analytic as compiled "
            "to CrowdStrike LogScale, Splunk SPL, and Elastic Lucene.",
            "",
            "| Analytic | Backend | Tokens | Depth | Bools | Lead `*` | Unanch. regex | Score | Impact |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for profile in sorted(self.profiles, key=lambda p: (p.rule_name, p.backend)):
            lines.append(
                f"| {profile.rule_name} | {profile.backend} | {profile.tokens} | "
                f"{profile.nesting_depth} | {profile.boolean_clauses} | "
                f"{profile.leading_wildcards} | {profile.unanchored_regexes} | "
                f"{profile.complexity_score:.1f} | {profile.impact} |"
            )

        lines += ["", "## Highest-cost queries", ""]
        for profile in self.worst():
            lines.append(
                f"- **{profile.impact}** ({profile.complexity_score:.1f}) "
                f"`{profile.backend}` / {profile.rule_name}"
            )
            for finding in profile.findings:
                lines.append(f"  - {finding}")
        lines.append("")

        lines += [
            "## Assessment",
            "",
            self._judgement(),
            "",
            "> **Confidence.** We assess with moderate confidence that this ranking reflects "
            "relative search cost. The score is a static heuristic over emitted query syntax; "
            "it does not model cluster topology, index configuration, shard count, or data "
            "volume, all of which materially affect realised performance. Validate against "
            "the target platform's own query profiler before acting on these figures.",
        ]
        return "\n".join(lines)

    def _judgement(self) -> str:
        if not self.profiles:
            return "No analytics were profiled."
        costly = [p for p in self.profiles if p.impact in ("High", COSTLY)]
        wildcard_heavy = [p for p in self.profiles if p.leading_wildcards > 0]
        if not costly:
            return (
                "We judge every compiled analytic to sit within a **routine cost envelope**. "
                "No query exhibits the nesting depth or clause breadth that would degrade a "
                "production search cluster."
            )
        return (
            f"We judge {len(costly)} of {len(self.profiles)} compiled queries to carry "
            f"**elevated search cost**. The dominant driver is leading-wildcard matching, "
            f"present in {len(wildcard_heavy)} compiled queries, which arises from Sigma's "
            f"`endswith` and `contains` modifiers and prevents term-index seeks. It is "
            f"likely that constraining these analytics with an indexed field predicate, such "
            f"as a bounded event-code or channel filter evaluated first, would reduce scanned "
            f"volume more than any rewrite of the string matching itself."
        )


class SiemQueryProfiler:
    """Compiles Sigma rules across SIEM backends and statically profiles query cost."""

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or ROOT
        self.backends = {
            "LogScale": LogScaleBackend(),
            "Splunk": SplunkBackend(),
            "Lucene": LuceneBackend(),
        }

    def rule_paths(self) -> List[Path]:
        """Returns every Sigma rule, including multi-event correlation components."""
        paths = sorted((self.repo_root / "rules" / "sigma").glob("*.yml"))
        corr = self.repo_root / "rules" / "sigma" / "correlation"
        if corr.exists():
            paths.extend(sorted(corr.glob("*.yml")))
        return paths

    # -- static analysis --------------------------------------------------

    @staticmethod
    def _nesting_depth(query: str) -> int:
        depth = max_depth = 0
        for char in query:
            if char in "([":
                depth += 1
                max_depth = max(max_depth, depth)
            elif char in ")]":
                depth = max(depth - 1, 0)
        return max_depth

    @staticmethod
    def _count_regex_literals(query: str) -> Tuple[int, int]:
        """Returns (unanchored_regex_count, case_insensitive_flag_count)."""
        unanchored = 0
        case_insensitive = 0
        for body, flags in _REGEX_LITERAL_RE.findall(query):
            if "i" in flags:
                case_insensitive += 1
            # A regex anchored at neither end must be evaluated across the field.
            if not body.startswith("^") and not body.endswith("$"):
                unanchored += 1
        return unanchored, case_insensitive

    def analyze(self, rule_name: str, backend: str, query: str) -> QueryProfile:
        """Statically profiles one compiled query."""
        profile = QueryProfile(rule_name=rule_name, backend=backend, query=query)
        profile.query_length = len(query)
        profile.tokens = len(_TOKEN_RE.findall(query))
        profile.nesting_depth = self._nesting_depth(query)
        profile.boolean_clauses = len(re.findall(r"\b(?:AND|OR|NOT|and|or|not)\b", query))
        profile.leading_wildcards = len(_LEADING_WC_RE.findall(query))
        unanchored, case_insensitive = self._count_regex_literals(query)
        profile.unanchored_regexes = unanchored
        profile.case_insensitive_ops = case_insensitive
        # OR-expansion breadth: comma-separated IN members plus OR branches.
        profile.or_expansion_terms = query.count(",") + len(re.findall(r"\bOR\b|\bor\b", query))

        profile.complexity_score = (
            profile.tokens * WEIGHTS["tokens"]
            + profile.nesting_depth * WEIGHTS["nesting_depth"]
            + profile.boolean_clauses * WEIGHTS["boolean_clauses"]
            + profile.leading_wildcards * WEIGHTS["leading_wildcards"]
            + profile.unanchored_regexes * WEIGHTS["unanchored_regexes"]
            + profile.case_insensitive_ops * WEIGHTS["case_insensitive_ops"]
            + profile.or_expansion_terms * WEIGHTS["or_expansion_terms"]
        )
        profile.impact = self.rate_impact(profile.complexity_score)
        profile.findings = self._findings(profile)
        return profile

    @staticmethod
    def rate_impact(score: float) -> str:
        """Maps a complexity score onto an estimated indexing/compute impact band."""
        for threshold, label in IMPACT_THRESHOLDS:
            if score < threshold:
                return label
        return COSTLY

    @staticmethod
    def _findings(profile: QueryProfile) -> List[str]:
        findings: List[str] = []
        if profile.leading_wildcards:
            findings.append(
                f"{profile.leading_wildcards} leading-wildcard term(s) prevent term-index "
                f"seeks and force a scan of the candidate set."
            )
        if profile.unanchored_regexes:
            findings.append(
                f"{profile.unanchored_regexes} unanchored regex literal(s) evaluate against "
                f"the full field value for every candidate event."
            )
        if profile.case_insensitive_ops:
            findings.append(
                f"{profile.case_insensitive_ops} case-insensitive operation(s) defeat "
                f"case-sensitive index structures."
            )
        if profile.nesting_depth >= 3:
            findings.append(
                f"Boolean nesting depth of {profile.nesting_depth} increases clause "
                f"evaluation cost per event."
            )
        if profile.or_expansion_terms >= 20:
            findings.append(
                f"Wide OR expansion across {profile.or_expansion_terms} terms multiplies "
                f"per-event clause evaluation."
            )
        if not findings:
            findings.append("No costly search constructs detected.")
        return findings

    # -- driver -----------------------------------------------------------

    def profile_all(self) -> ProfilerReport:
        """Compiles and profiles every rule against every configured backend."""
        report = ProfilerReport()
        for rule_path in self.rule_paths():
            collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
            rule_name = collection.rules[0].title
            for backend_name, backend in self.backends.items():
                try:
                    queries = backend.convert(collection)
                except Exception as exc:  # backend cannot express this rule
                    report.profiles.append(
                        QueryProfile(
                            rule_name=rule_name,
                            backend=backend_name,
                            query="",
                            impact="Low",
                            findings=[f"Backend could not compile this rule: {exc}"],
                        )
                    )
                    continue
                for query in queries:
                    report.profiles.append(self.analyze(rule_name, backend_name, query))
        return report
