"""Static durability analysis for Sigma detection rules.

A detection rule can be correct today and worthless next quarter. The usual way
that happens is not a logic error: it is a dependency the rule never declared.
The rule enumerates the command-line spellings an adversary used last time. It
assumes the interpreter is a direct child of the shell. It reads a field the
audit policy may not populate. None of that shows up in a test suite built from
fixtures the rule author also wrote, because those fixtures encode the same
assumptions.

This module scores those dependencies from the rule text alone. It runs against
any Sigma corpus, including corpora written by other people, which is the point:
it is a measuring instrument rather than another detection.

Every dimension answers one question, and each is normalized to [0, 1] where
higher means more fragile:

`literal_enumeration`
    How many literal alternatives the rule enumerates. A rule listing twenty
    command-line substrings is betting the adversary picks one of those twenty
    spellings. Enumeration is a treadmill: each evasion adds a string, and the
    rule never becomes durable, only longer.

`substring_reliance`
    What share of matches are substring operations over free text rather than
    equality on a structured field. Substring matching over attacker-controlled
    text is where evasion lives, because the attacker chooses the text.

`commandline_dependence`
    Whether the rule can fire at all without command-line capture. This is both
    an audit-policy dependency and a telemetry-layer one: an adversary working
    in-process, through a cloud SDK or a language runtime, produces no command
    line for the rule to read.

`lineage_dependence`
    Whether the rule requires a specific parent process. Single-hop lineage
    assumptions break the moment any intermediate process is inserted, which is
    the cheapest evasion available.

`environment_coupling`
    Whether the rule contains literals that must be replaced per deployment,
    such as address ranges, role names, or allowlists. Coupling is not a defect;
    shipping it undocumented is, because the rule is then wrong by default in a
    way that looks like it is working.

`documentation_gap`
    Whether the rule declares its telemetry prerequisites and its false
    positives. A rule that states how it degrades can be operated. One that does
    not will be trusted past the point where it stopped seeing anything.

The composite weights are policy, not measurement, and are stated in `WEIGHTS`
so they can be argued with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

#: Fields whose contents an adversary chooses directly.
ATTACKER_CONTROLLED_FIELDS = (
    "commandline",
    "originalfilename",
    "imphash",
    "quer=",
    "querynam",
    "url",
    "targetfilename",
    "description",
    "product",
    "company",
)

#: Field names that carry a command line under some taxonomy or other.
COMMANDLINE_FIELDS = ("commandline", "parentcommandline", "processcommandline")

#: Field names expressing a parent-child relationship.
LINEAGE_FIELDS = ("parentimage", "parentcommandline", "parentprocessname", "parentuser")

#: Value-level modifiers that perform substring rather than equality matching.
SUBSTRING_MODIFIERS = ("contains", "startswith", "endswith", "re", "cidr")

#: Patterns whose presence means a literal must be replaced before deployment.
ENVIRONMENT_PATTERNS = (
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b"),  # CIDR
    re.compile(r"\b(?:assumed-role|arn:aws|serviceaccount:)\S*", re.IGNORECASE),
    re.compile(r"\b(?:allowlist|whitelist|approved|corp|internal)\b", re.IGNORECASE),
)

#: Composite weights. Policy, not measurement. They encode a judgment that a rule
#: which cannot fire at all under a plausible telemetry gap is worse off than one
#: that merely enumerates a lot of strings.
WEIGHTS: Dict[str, float] = {
    "commandline_dependence": 0.25,
    "literal_enumeration": 0.20,
    "lineage_dependence": 0.20,
    "substring_reliance": 0.15,
    "environment_coupling": 0.10,
    "documentation_gap": 0.10,
}

#: Enumeration count at which a rule is treated as fully enumeration-bound. Chosen
#: so that a handful of alternatives scores low and a list of dozens saturates.
ENUMERATION_SATURATION = 40


@dataclass
class RuleBrittleness:
    """Per-rule scores and the observations that produced them."""

    rule_id: str
    title: str
    path: str
    logsource: str
    dimensions: Dict[str, float] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    literal_count: int = 0
    match_count: int = 0
    substring_matches: int = 0
    parse_error: Optional[str] = None

    @property
    def composite(self) -> float:
        if not self.dimensions:
            return 0.0
        total = sum(WEIGHTS[k] * self.dimensions.get(k, 0.0) for k in WEIGHTS)
        return round(min(1.0, total), 4)

    @property
    def band(self) -> str:
        score = self.composite
        if score >= 0.60:
            return "fragile"
        if score >= 0.35:
            return "conditional"
        return "durable"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "path": self.path,
            "logsource": self.logsource,
            "composite": self.composite,
            "band": self.band,
            "dimensions": {k: round(v, 4) for k, v in self.dimensions.items()},
            "literal_count": self.literal_count,
            "match_count": self.match_count,
            "substring_matches": self.substring_matches,
            "observations": self.observations,
            "parse_error": self.parse_error,
        }


def _iter_leaf_values(node: Any) -> Iterable[Any]:
    if isinstance(node, dict):
        for value in node.values():
            yield from _iter_leaf_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_leaf_values(value)
    else:
        yield node


def _iter_field_specs(detection: Dict[str, Any]) -> Iterable[Tuple[str, Any]]:
    """Yield (field_spec, value) pairs from every selection in a detection block."""
    for key, block in detection.items():
        if key == "condition":
            continue
        for entry in block if isinstance(block, list) else [block]:
            if isinstance(entry, dict):
                for field_spec, value in entry.items():
                    yield str(field_spec), value


def _count_literals(value: Any) -> int:
    if isinstance(value, list):
        return sum(_count_literals(v) for v in value)
    if isinstance(value, dict):
        return sum(_count_literals(v) for v in value.values())
    return 1 if value is not None else 0


def _base_field(field_spec: str) -> str:
    return field_spec.split("|")[0].strip().lower()


def _modifiers(field_spec: str) -> List[str]:
    return [m.strip().lower() for m in field_spec.split("|")[1:]]


def analyze_rule(path: Path) -> RuleBrittleness:
    """Score one Sigma rule file on disk."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return RuleBrittleness(
            rule_id="", title=path.stem, path=path.name, logsource="",
            parse_error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
    return analyze_text(raw, path.name)


def analyze_text(raw: str, name: str) -> RuleBrittleness:
    """Score one Sigma rule from its text.

    Separated from file reading so a corpus can be analyzed straight out of git
    object storage without ever writing rule text to disk. That matters when the
    corpus is thousands of public detection rules full of live command-line
    strings and the host runs aggressive endpoint protection.
    """
    try:
        documents = [d for d in yaml.safe_load_all(raw) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        return RuleBrittleness(
            rule_id="", title=name, path=name, logsource="",
            parse_error=f"{type(exc).__name__}: {str(exc)[:200]}",
        )
    if not documents:
        return RuleBrittleness(
            rule_id="", title=name, path=name, logsource="",
            parse_error="no YAML documents",
        )
    path = Path(name)

    doc = documents[0]
    detection = doc.get("detection")
    logsource = doc.get("logsource") or {}
    logsource_label = "/".join(
        str(logsource.get(k, "")) for k in ("product", "category", "service")
    ).strip("/")

    result = RuleBrittleness(
        rule_id=str(doc.get("id", "")),
        title=str(doc.get("title", path.stem)),
        path=path.name,
        logsource=logsource_label,
    )

    if not isinstance(detection, dict):
        # Correlation rules have no detection block of their own; they inherit
        # the fragility of the rules they reference and are scored separately.
        result.parse_error = "no detection block (correlation or malformed rule)"
        return result

    literal_total = 0
    match_total = 0
    substring_total = 0
    uses_commandline = False
    uses_lineage = False
    non_lineage_selection = False

    for field_spec, value in _iter_field_specs(detection):
        base = _base_field(field_spec)
        mods = _modifiers(field_spec)
        count = _count_literals(value)
        literal_total += count
        match_total += 1
        if any(m in SUBSTRING_MODIFIERS for m in mods):
            substring_total += 1
        if base in COMMANDLINE_FIELDS:
            uses_commandline = True
        if base in LINEAGE_FIELDS:
            uses_lineage = True
        else:
            non_lineage_selection = True

    result.literal_count = literal_total
    result.match_count = match_total
    result.substring_matches = substring_total

    enumeration = min(1.0, literal_total / ENUMERATION_SATURATION)
    substring_reliance = (substring_total / match_total) if match_total else 0.0

    condition = str(detection.get("condition", "")).lower()
    can_fire_without_cmd = False
    can_fire_without_lineage = False

    try:
        from sigma.collection import SigmaCollection
        from sigma.conditions import ConditionOR, ConditionAND, ConditionNOT, ConditionFieldEqualsValueExpression

        def _evaluates_without_fields(node, forbidden_fields):
            if isinstance(node, ConditionFieldEqualsValueExpression):
                f = (node.field or "").lower()
                return f not in forbidden_fields
            if isinstance(node, ConditionOR):
                return any(_evaluates_without_fields(arg, forbidden_fields) for arg in node.args)
            if isinstance(node, ConditionAND):
                return all(_evaluates_without_fields(arg, forbidden_fields) for arg in node.args)
            if isinstance(node, ConditionNOT):
                return True
            return False

        col = SigmaCollection.from_yaml(raw)
        if col.rules:
            cond_ast = col.rules[0].detection.parsed_condition[0].parse()
            can_fire_without_cmd = _evaluates_without_fields(cond_ast, COMMANDLINE_FIELDS)
            can_fire_without_lineage = _evaluates_without_fields(cond_ast, LINEAGE_FIELDS)
    except Exception:
        can_fire_without_cmd = (" or " in condition) or ("1 of " in condition) or ("any of " in condition)
        can_fire_without_lineage = not ((" and " in condition) or not non_lineage_selection)

    commandline_dependence = 0.0
    if uses_commandline:
        commandline_dependence = 0.5 if can_fire_without_cmd else 1.0

    lineage_dependence = 0.0
    if uses_lineage:
        lineage_dependence = 0.5 if can_fire_without_lineage else 1.0

    text = yaml.safe_dump(doc, default_flow_style=False)
    environment_hits = [p.pattern for p in ENVIRONMENT_PATTERNS if p.search(text)]
    environment_coupling = min(1.0, len(environment_hits) / 2)

    has_prereqs = bool(doc.get("telemetry_prerequisites"))
    has_fps = bool(doc.get("falsepositives"))
    documentation_gap = 1.0 - (0.6 if has_prereqs else 0.0) - (0.4 if has_fps else 0.0)

    result.dimensions = {
        "literal_enumeration": enumeration,
        "substring_reliance": substring_reliance,
        "commandline_dependence": commandline_dependence,
        "lineage_dependence": lineage_dependence,
        "environment_coupling": environment_coupling,
        "documentation_gap": max(0.0, documentation_gap),
    }

    if literal_total >= ENUMERATION_SATURATION:
        result.observations.append(
            f"enumerates {literal_total} literal alternatives; each evasion adds a string "
            "and the rule never becomes durable, only longer"
        )
    if commandline_dependence == 1.0:
        result.observations.append(
            "cannot fire without command-line capture; an in-process or SDK-driven "
            "adversary produces nothing for this rule to read"
        )
    if lineage_dependence == 1.0:
        result.observations.append(
            "requires a specific parent process; one intermediate process defeats it"
        )
    if substring_reliance >= 0.8 and match_total >= 3:
        result.observations.append(
            f"{substring_total} of {match_total} matches are substring operations over "
            "text the adversary chooses"
        )
    if environment_hits and not has_prereqs:
        result.observations.append(
            "contains deployment-specific literals with no declared prerequisites; "
            "wrong by default in a way that looks like it is working"
        )
    if not has_prereqs:
        result.observations.append("declares no telemetry prerequisites")
    if not has_fps:
        result.observations.append("declares no false positives")

    return result


def analyze_corpus(rules_dir: Path, recursive: bool = True) -> List[RuleBrittleness]:
    pattern = "**/*.yml" if recursive else "*.yml"
    return [analyze_rule(p) for p in sorted(Path(rules_dir).glob(pattern))]


def summarize(results: List[RuleBrittleness], corpus_label: str) -> Dict[str, Any]:
    scored = [r for r in results if not r.parse_error]
    skipped = [r for r in results if r.parse_error]
    if not scored:
        return {
            "corpus": corpus_label,
            "rules_scored": 0,
            "rules_skipped": len(skipped),
            "note": "no scoreable rules found",
        }

    def mean(key: str) -> float:
        return round(sum(r.dimensions.get(key, 0.0) for r in scored) / len(scored), 4)

    bands: Dict[str, int] = {"durable": 0, "conditional": 0, "fragile": 0}
    for result in scored:
        bands[result.band] += 1

    ranked = sorted(scored, key=lambda r: -r.composite)
    return {
        "corpus": corpus_label,
        "rules_scored": len(scored),
        "rules_skipped": len(skipped),
        "skipped_reasons": {r.path: r.parse_error for r in skipped},
        "composite_mean": round(sum(r.composite for r in scored) / len(scored), 4),
        "band_counts": bands,
        "dimension_means": {key: mean(key) for key in WEIGHTS},
        "weights": dict(WEIGHTS),
        "weights_note": (
            "Composite weights are policy, not measurement. They encode a judgment that a "
            "rule which cannot fire at all under a plausible telemetry gap is worse off "
            "than one which merely enumerates many strings."
        ),
        "share_commandline_dependent": round(
            sum(1 for r in scored if r.dimensions.get("commandline_dependence", 0) == 1.0)
            / len(scored),
            4,
        ),
        "share_lineage_dependent": round(
            sum(1 for r in scored if r.dimensions.get("lineage_dependence", 0) == 1.0)
            / len(scored),
            4,
        ),
        "most_fragile": [r.to_dict() for r in ranked[:10]],
        "most_durable": [r.to_dict() for r in ranked[-5:]],
    }
