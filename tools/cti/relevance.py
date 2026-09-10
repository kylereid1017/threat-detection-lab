"""Relevance scoring for a frontier AI lab threat model.

The problem this solves: a general feed is mostly irrelevant to any specific
organization. Commodity phishing, unrelated botnet infrastructure, and generic
malware hashes drown the handful of indicators that matter. Prioritizing by the
source's own severity does not help, because the source does not know what is
being defended.

This scorer is deliberately explicit rather than learned. Every point is
attributable to a named rule, so an analyst can see why something was
prioritized and can argue with it. A learned model over a corpus this size would
be unjustifiable, and an unexplainable priority queue is one analysts stop
trusting after the first bad week.

Scores are bounded to [0, 1]. The thresholds are policy, not measurement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

#: Organizations and technologies whose names attackers imitate when targeting
#: AI research staff and infrastructure.
BRAND_TERMS: Tuple[str, ...] = (
    "anthropic",
    "openai",
    "huggingface",
    "deepmind",
    "pytorch",
    "nvidia",
    "databricks",
    "weightsandbiases",
    "wandb",
)

#: Lure vocabulary from recruitment-themed social engineering.
LURE_TERMS: Tuple[str, ...] = (
    "careers",
    "recruit",
    "recruiting",
    "recruiter",
    "hiring",
    "interview",
    "assessment",
    "candidate",
    "onboarding",
    "talent",
)

#: Terms tied to the assets a frontier lab actually loses in a breach.
ASSET_TERMS: Tuple[str, ...] = (
    "safetensors",
    "checkpoint",
    "modelweights",
    "weights",
    "gpucluster",
    "trainingrun",
)

#: Developer supply chain surfaces.
SUPPLY_CHAIN_TERMS: Tuple[str, ...] = (
    "npm",
    "pypi",
    "registry",
    "sdk",
    "cli",
    "package",
)

#: Weights are the tuning surface of this scorer. They are ordered by how much
#: each signal narrows the population, not by how alarming the words sound.
WEIGHTS: Dict[str, float] = {
    "brand_typosquat": 0.55,
    "brand_substring": 0.35,
    "lure_term": 0.20,
    "asset_term": 0.25,
    "supply_chain_term": 0.10,
    "suspicious_tld": 0.10,
    "hyphenated_brand_compound": 0.15,
    "recently_registered": 0.15,
    "recently_issued_cert": 0.15,
    "protected_inventory_typosquat": 0.50,
    "protected_inventory_compound": 0.40,
}

#: Top-level domains disproportionately represented in disposable infrastructure.
#: This is a prior, not evidence. It contributes little on its own by design.
SUSPICIOUS_TLDS: Tuple[str, ...] = (
    ".top",
    ".xyz",
    ".icu",
    ".cfd",
    ".sbs",
    ".click",
    ".work",
    ".rest",
)

#: Characters substituted to build visually similar names.
HOMOGLYPHS: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "rn": "m",
    "vv": "w",
}

TRIAGE_THRESHOLD = 0.35
PRIORITY_THRESHOLD = 0.60


@dataclass
class RelevanceVerdict:
    score: float
    reasons: List[str]

    @property
    def is_triage_worthy(self) -> bool:
        return self.score >= TRIAGE_THRESHOLD

    @property
    def is_priority(self) -> bool:
        return self.score >= PRIORITY_THRESHOLD


def normalize(value: str) -> str:
    """Collapse homoglyph substitutions and separators to a comparable form."""
    text = value.lower().strip()
    text = re.sub(r"^https?://", "", text)
    text = text.split("/")[0]
    for source, target in HOMOGLYPHS.items():
        text = text.replace(source, target)
    return re.sub(r"[^a-z0-9]", "", text)


def damerau_levenshtein(left: str, right: str) -> int:
    """Edit distance including transposition.

    Transposition matters here: swapping two adjacent characters of a brand name
    is one of the cheapest ways to build a lookalike, and plain Levenshtein
    charges two edits for it, which pushes real typosquats past a distance-1
    threshold.
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous_previous: List[int] = []
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        for j, rchar in enumerate(right, start=1):
            cost = 0 if lchar == rchar else 1
            current[j] = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + cost,
            )
            if (
                i > 1
                and j > 1
                and lchar == right[j - 2]
                and left[i - 2] == rchar
            ):
                current[j] = min(current[j], previous_previous[j - 2] + cost)
        previous_previous = previous
        previous = current
    return previous[len(right)]


def _candidate_labels(value: str) -> List[str]:
    """Split an observable into the parts a lookalike would occupy.

    Domain labels are the obvious case. Package names are not: `huggingfaec-hub`
    carries the imitation in one hyphenated segment, and comparing the whole
    string against a brand puts every such name far outside any sane edit budget.
    Ecosystem prefixes, hyphens, and underscores are all treated as separators
    for that reason.
    """
    host = re.sub(r"^https?://", "", value.lower()).split("/")[0]
    return [label for label in re.split(r"[.\-_:]+", host) if label]


def typosquat_of(value: str, brands: Sequence[str] = BRAND_TERMS) -> Tuple[str, int] | None:
    """Nearest brand within edit distance 1 or 2, excluding exact containment.

    A label that simply contains the brand is scored separately as a substring
    match. This function is for names that are close to a brand without being it,
    which is the case a substring test cannot see at all.
    """
    best: Tuple[str, int] | None = None
    for label in _candidate_labels(value):
        normalized = normalize(label)
        if not normalized or len(normalized) < 4:
            continue
        for brand in brands:
            if brand in normalized:
                continue
            distance = damerau_levenshtein(normalized, brand)
            # Allow a wider edit budget for longer brands, where a single
            # character change is a smaller proportion of the name.
            budget = 1 if len(brand) <= 7 else 2
            if distance <= budget and (best is None or distance < best[1]):
                best = (brand, distance)
    return best


def _contains_any(haystack: str, terms: Iterable[str]) -> List[str]:
    return [term for term in terms if term in haystack]


def score_indicator(
    value: str,
    indicator_type: str = "domain",
    context: Dict[str, object] | None = None,
    protected=None,
    brands: Sequence[str] = BRAND_TERMS,
) -> RelevanceVerdict:
    """Score one observable against the frontier AI lab threat model.

    `protected` is an optional registry of names the deploying organization
    depends on, exposing `nearest(name)`. It is the branch that generalizes:
    the vocabulary branches below measured 0% held-out recall against real
    malicious packages, because substring matching cannot catch imitation of a
    name it does not hold. See `tools/cti/protected_names.py`.

    `brands` is injectable so that a holdout evaluation can withhold part of the
    vocabulary and measure the mechanism rather than the list.
    """
    context = context or {}
    reasons: List[str] = []
    score = 0.0

    # Package indicators arrive as "<ecosystem>:<name>", which is the pipeline's
    # own formatting. Scoring that whole string let every package earn the supply
    # chain point for containing the word "npm" or "pypi" that this code added a
    # moment earlier, inflating the relevance of the entire population equally.
    scored_value = value
    if indicator_type == "package" and ":" in value:
        scored_value = value.split(":", 1)[1]

    normalized = normalize(scored_value)
    raw = scored_value.lower()

    squat = typosquat_of(scored_value, brands)
    if squat:
        brand, distance = squat
        score += WEIGHTS["brand_typosquat"]
        reasons.append(f"typosquat of '{brand}' at edit distance {distance}")
    else:
        matched_brands = _contains_any(normalized, brands)
        if matched_brands:
            score += WEIGHTS["brand_substring"]
            reasons.append(f"contains brand term: {', '.join(matched_brands)}")
            if any(f"-{brand}" in raw or f"{brand}-" in raw for brand in matched_brands):
                score += WEIGHTS["hyphenated_brand_compound"]
                reasons.append("brand used as a compound label, a common lure form")

    lures = _contains_any(normalized, LURE_TERMS)
    if lures:
        score += WEIGHTS["lure_term"]
        reasons.append(f"recruitment lure vocabulary: {', '.join(lures)}")

    assets = _contains_any(normalized, ASSET_TERMS)
    if assets:
        score += WEIGHTS["asset_term"]
        reasons.append(f"references protected assets: {', '.join(assets)}")

    supply = _contains_any(normalized, SUPPLY_CHAIN_TERMS)
    if supply and indicator_type in {"package", "domain", "url"}:
        score += WEIGHTS["supply_chain_term"]
        reasons.append(f"developer supply chain surface: {', '.join(supply)}")

    if any(raw.endswith(tld) or f"{tld}/" in raw for tld in SUSPICIOUS_TLDS):
        score += WEIGHTS["suspicious_tld"]
        reasons.append("top-level domain common in disposable infrastructure")

    if context.get("recently_registered"):
        score += WEIGHTS["recently_registered"]
        reasons.append("registered or first observed within the collection window")
    elif context.get("recently_issued_cert"):
        score += WEIGHTS["recently_issued_cert"]
        reasons.append("certificate recently issued within the observation window")

    if protected is not None:
        near = protected.nearest(scored_value)
        if near:
            # A compound is a weaker signal than a misspelling, because ecosystem
            # naming conventions legitimately embed a tool's name in dependent
            # packages (`eslint-plugin-x`, `babel-plugin-x`). It is still scored
            # above the triage threshold: measured on 232,729 real malicious
            # packages, surfacing compounds bought roughly 60 points of recall on
            # npm for roughly 1.5 points of false-positive rate. On a queue a human
            # reads, that trade is worth taking; for a blocking control it is not,
            # and dropping this weight to 0.25 removes compounds from the queue.
            kind = getattr(near, "kind", "misspelling")
            weight_key = (
                "protected_inventory_compound"
                if kind == "compound"
                else "protected_inventory_typosquat"
            )
            score += WEIGHTS[weight_key]
            reasons.append(
                f"{kind} of '{near.name}' from the protected dependency inventory "
                f"at edit distance {near.distance}"
            )

    return RelevanceVerdict(score=min(1.0, round(score, 4)), reasons=reasons)
