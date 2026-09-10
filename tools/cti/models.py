"""Core data model for the CTI collection and enrichment pipeline.

Design constraints that shaped this model:

Provenance is not optional. Every indicator carries the source that produced it
and the raw record it came from. An indicator whose origin cannot be stated is
not actionable, because an analyst cannot judge it and a detection engineer
cannot decide whether it is worth a rule.

Confidence and relevance are separate axes. Confidence is how sure we are the
indicator is what the source says it is. Relevance is how much it matters to
the environment being defended. A high-confidence commodity phishing domain and
a low-confidence lookalike of an AI research organization are not comparable on
one number, and collapsing them is how feeds become noise.

Every indicator expires. An indicator with no expiry becomes a permanent false
positive generator once the infrastructure is recycled, which is the normal
lifecycle of attacker infrastructure rather than an edge case.
"""

from __future__ import annotations

import hashlib
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional


class IndicatorType(str, Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"
    URL = "url"
    CERT_SHA256 = "cert_sha256"
    FILE_SHA256 = "file_sha256"
    PACKAGE = "package"
    ASN = "asn"
    EMAIL = "email"


class Confidence(str, Enum):
    """Analytic confidence, following the vocabulary used in the cables."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


#: Default time-to-live per indicator type, in days.
#:
#: These are policy defaults, not measurements. They encode how quickly each
#: class of infrastructure is typically recycled: hosting addresses turn over
#: fastest, registered domains persist longer, and file hashes do not change at
#: all once observed. A deployment should replace them with values derived from
#: its own observed indicator decay rather than inheriting these.
DEFAULT_TTL_DAYS: Dict[IndicatorType, int] = {
    IndicatorType.IPV4: 14,
    IndicatorType.URL: 30,
    IndicatorType.DOMAIN: 90,
    IndicatorType.CERT_SHA256: 180,
    IndicatorType.PACKAGE: 365,
    IndicatorType.ASN: 365,
    IndicatorType.EMAIL: 180,
    IndicatorType.FILE_SHA256: 3650,
}

#: Confidence multipliers applied to the base TTL.
CONFIDENCE_TTL_FACTOR: Dict[Confidence, float] = {
    Confidence.LOW: 0.5,
    Confidence.MODERATE: 1.0,
    Confidence.HIGH: 1.5,
}


@dataclass(frozen=True)
class Provenance:
    """Where an indicator came from and what the source actually said."""

    source: str
    collected: str
    raw_reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Indicator:
    """A single observable with provenance, scoring, and an expiry."""

    value: str
    type: IndicatorType
    provenance: Provenance
    confidence: Confidence = Confidence.MODERATE
    relevance: float = 0.0
    relevance_reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.value = self.value.strip()
        if not self.value:
            raise ValueError("indicator value cannot be empty")
        if self.type == IndicatorType.URL:
            parsed = urllib.parse.urlsplit(self.value)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            self.value = urllib.parse.urlunsplit((scheme, netloc, parsed.path, parsed.query, parsed.fragment))
        else:
            self.value = self.value.lower()
        if not self.first_seen:
            self.first_seen = self.provenance.collected

    @property
    def key(self) -> str:
        """Stable identity for deduplication across sources."""
        return f"{self.type.value}:{self.value}"

    @property
    def stix_id(self) -> str:
        digest = hashlib.sha256(self.key.encode("utf-8")).hexdigest()[:32]
        return f"indicator--{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"

    def ttl_days(self) -> int:
        base = DEFAULT_TTL_DAYS[self.type]
        return max(1, int(base * CONFIDENCE_TTL_FACTOR[self.confidence]))

    def expires_on(self) -> str:
        try:
            start = datetime.strptime(self.first_seen[:10], "%Y-%m-%d").date()
        except ValueError:
            start = date.today()
        return (start + timedelta(days=self.ttl_days())).isoformat()

    def merge(self, other: "Indicator") -> None:
        """Fold a duplicate observation of the same indicator into this one.

        Sources disagree. The merge keeps the highest confidence and relevance
        seen, unions the reasons and tags, and records the additional source, so
        a later reader can see that two feeds agreed rather than seeing one
        arbitrary winner.
        """
        if other.key != self.key:
            raise ValueError(f"cannot merge {other.key} into {self.key}")
        order = [Confidence.LOW, Confidence.MODERATE, Confidence.HIGH]
        if order.index(other.confidence) > order.index(self.confidence):
            self.confidence = other.confidence
        if other.relevance > self.relevance:
            self.relevance = other.relevance
        for reason in other.relevance_reasons:
            if reason not in self.relevance_reasons:
                self.relevance_reasons.append(reason)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        corroboration = self.context.setdefault("corroborating_sources", [])
        if other.provenance.source not in corroboration:
            corroboration.append(other.provenance.source)
        if other.first_seen and other.first_seen < self.first_seen:
            self.first_seen = other.first_seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type.value,
            "confidence": self.confidence.value,
            "relevance": round(self.relevance, 4),
            "relevance_reasons": list(self.relevance_reasons),
            "tags": list(self.tags),
            "first_seen": self.first_seen,
            "expires_on": self.expires_on(),
            "ttl_days": self.ttl_days(),
            "provenance": self.provenance.to_dict(),
            "context": self.context,
        }


@dataclass
class PivotEdge:
    """A relationship between two indicators, with the reason it was drawn."""

    source_key: str
    target_key: str
    relationship: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Cluster:
    """A set of indicators connected by shared infrastructure attributes."""

    cluster_id: str
    members: List[str]
    shared_attribute: str
    shared_value: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CollectionResult:
    """What one source returned, including what it failed to parse.

    Failures are counted rather than swallowed. A collector that silently drops
    malformed records reports a healthy run while losing indicators, which is
    the failure mode that makes a pipeline untrustworthy.
    """

    source: str
    indicators: List[Indicator] = field(default_factory=list)
    records_seen: int = 0
    records_skipped: int = 0
    skip_reasons: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None

    def skip(self, reason: str) -> None:
        self.records_skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "records_seen": self.records_seen,
            "indicators_produced": len(self.indicators),
            "records_skipped": self.records_skipped,
            "skip_reasons": self.skip_reasons,
            "error": self.error,
        }
