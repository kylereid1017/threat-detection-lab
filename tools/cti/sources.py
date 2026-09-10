"""Collectors for the CTI pipeline.

Every collector reads newline-delimited JSON records and emits indicators with
provenance. Collectors do not fetch over the network in this repository. They
read a local snapshot, and the snapshot is what tests and evaluations run
against.

That is a deliberate constraint rather than a limitation to apologize for. A
pipeline whose behavior depends on what a live feed happened to return today
cannot be regression tested, and its results cannot be reproduced by a reader.
Acquisition is a separate concern: fetch a snapshot, pin its hash, then run the
pipeline over it. `tools/acquire_telemetry.py` already establishes that pattern
for telemetry, and the same shape applies here.

Each collector normalizes a different record shape into the same Indicator
model, which is where most of the real work in a collection layer lives.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterator, List

from tools.cti.models import (
    CollectionResult,
    Confidence,
    Indicator,
    IndicatorType,
    Provenance,
)


#: Multi-label suffixes under which anyone can register a name. Without these,
#: taking the last two labels treats every site on a platform as one entity, and
#: the pivot graph reports a hosting provider as a campaign.
#:
#: This is a short hand-maintained list, not the Public Suffix List. A suffix that
#: is missing produces over-clustering, which the graph's fanout guard then
#: discards, so the failure mode is a lost pivot rather than a false campaign.
MULTI_LABEL_SUFFIXES = (
    "workers.dev",
    "hosted.app",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "github.io",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudfront.net",
    "amazonaws.com",
    "run.app",
    "code.run",
    "onrender.com",
    "fly.dev",
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.nz",
    "org.nz",
    "co.jp",
    "ne.jp",
    "com.br",
    "co.kr",
    "com.sg",
    "co.za",
    "com.tr",
    "com.mx",
    "com.ar",
    "co.in",
    "com.tw",
)


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain for a hostname.

    Approximate by design: a full Public Suffix List lookup would be more correct
    and is a dependency this repository does not carry. The approximation is
    documented where it is used rather than hidden.
    """
    labels = [p for p in host.strip().lower().lstrip("*.").split(".") if p]
    if len(labels) < 2:
        return host.strip().lower()
    for suffix in MULTI_LABEL_SUFFIXES:
        parts = suffix.split(".")
        if labels[-len(parts):] == parts:
            take = len(parts) + 1
            return ".".join(labels[-take:]) if len(labels) >= take else ".".join(labels)
    return ".".join(labels[-2:])


def read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    """Yield records from a newline-delimited JSON file, skipping blanks."""
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


class Collector:
    """Base collector. Subclasses implement `parse`."""

    #: Source identifier recorded in provenance.
    source = "unknown"

    def __init__(self, collected: str = "") -> None:
        self.collected = collected or date.today().isoformat()

    def parse(self, record: Dict[str, Any], result: CollectionResult) -> List[Indicator]:
        raise NotImplementedError

    def _provenance(self, reference: str = "") -> Provenance:
        return Provenance(
            source=self.source, collected=self.collected, raw_reference=reference
        )

    def collect(self, path: Path) -> CollectionResult:
        result = CollectionResult(source=self.source)
        if not path.is_file():
            result.error = f"snapshot not found: {path.name}"
            return result
        try:
            for record in read_jsonl(path):
                result.records_seen += 1
                try:
                    result.indicators.extend(self.parse(record, result))
                except (KeyError, TypeError, ValueError) as exc:
                    result.skip(type(exc).__name__)
        except json.JSONDecodeError as exc:
            result.error = f"malformed snapshot at record {result.records_seen + 1}: {exc.msg}"
        return result


class CertificateTransparencyCollector(Collector):
    """Domains observed in Certificate Transparency log monitors.

    Certificates identify newly issued domains before they serve content. A
    domain in CT is not necessarily active or malicious; it is an early sighting
    of infrastructure someone took the trouble to configure TLS for.
    """

    source = "certificate_transparency"

    def parse(self, record: Dict[str, Any], result: CollectionResult) -> List[Indicator]:
        fingerprint = str(record.get("cert_sha256") or record.get("fingerprint_sha256") or "").strip().lower()
        names = record.get("dns_names", [])
        if not names:
            result.skip("no_dns_names")
            return []
        seen = str(record.get("not_before", self.collected))[:10]
        recently_issued = bool(record.get("not_before"))
        indicators: List[Indicator] = []
        for name in names:
            name = str(name).lstrip("*.").strip().lower()
            if not name or "." not in name:
                result.skip("invalid_dns_name")
                continue
            indicators.append(
                Indicator(
                    value=name,
                    type=IndicatorType.DOMAIN,
                    provenance=self._provenance(fingerprint),
                    confidence=Confidence.LOW,
                    first_seen=seen,
                    tags=["ct-log"],
                    context={
                        "issuer": record.get("issuer", ""),
                        "cert_sha256": fingerprint,
                        "registrable_domain": registrable_domain(name),
                        "recently_issued_cert": recently_issued,
                    },
                )
            )
        if fingerprint:
            indicators.append(
                Indicator(
                    value=fingerprint,
                    type=IndicatorType.CERT_SHA256,
                    provenance=self._provenance(fingerprint),
                    confidence=Confidence.LOW,
                    first_seen=seen,
                    tags=["ct-log"],
                    context={"dns_names": names},
                )
            )
        return indicators


class PackageRegistryCollector(Collector):
    """Newly published packages from a language registry.

    Relevance here is not about the package being malicious. It is about the
    package occupying a name close to something a developer at the defended
    organization would plausibly install by mistake.
    """

    source = "package_registry"

    def parse(self, record: Dict[str, Any], result: CollectionResult) -> List[Indicator]:
        name = str(record.get("name", "")).strip().lower()
        if not name:
            result.skip("no_package_name")
            return []
        ecosystem = record.get("ecosystem", "npm")
        version = record.get("version", "")
        indicators = [
            Indicator(
                value=f"{ecosystem}:{name}",
                type=IndicatorType.PACKAGE,
                provenance=self._provenance(f"{name}@{version}"),
                confidence=Confidence.LOW,
                first_seen=str(record.get("published", self.collected))[:10],
                tags=["package-registry", str(ecosystem)],
                context={
                    "version": version,
                    "maintainer": record.get("maintainer", ""),
                    "has_install_hook": bool(record.get("has_install_hook")),
                    "recently_registered": True,
                },
            )
        ]
        homepage = str(record.get("homepage", "")).strip().lower()
        if homepage.startswith("http"):
            host = homepage.split("//", 1)[1].split("/")[0]
            if host:
                indicators.append(
                    Indicator(
                        value=host,
                        type=IndicatorType.DOMAIN,
                        provenance=self._provenance(f"{name}@{version} homepage"),
                        confidence=Confidence.LOW,
                        first_seen=str(record.get("published", self.collected))[:10],
                        tags=["package-registry", "homepage"],
                        context={"package": f"{ecosystem}:{name}"},
                    )
                )
        return indicators


class MaliciousUrlFeedCollector(Collector):
    """A curated malicious URL feed.

    Confidence starts higher than the discovery sources because a curated feed
    asserts maliciousness rather than merely observing existence. Relevance is
    usually low, which is the whole point of scoring the two separately.
    """

    source = "malicious_url_feed"

    def parse(self, record: Dict[str, Any], result: CollectionResult) -> List[Indicator]:
        url = str(record.get("url", "")).strip().lower()
        if not url.startswith("http"):
            result.skip("not_a_url")
            return []
        host = url.split("//", 1)[1].split("/")[0]
        seen = str(record.get("date_added", self.collected))[:10]
        threat = record.get("threat", "")
        indicators = [
            Indicator(
                value=url,
                type=IndicatorType.URL,
                provenance=self._provenance(str(record.get("id", ""))),
                confidence=Confidence.MODERATE,
                first_seen=seen,
                tags=["url-feed", str(threat)] if threat else ["url-feed"],
                context={"reporter": record.get("reporter", "")},
            )
        ]
        if host:
            indicators.append(
                Indicator(
                    value=host,
                    type=IndicatorType.DOMAIN,
                    provenance=self._provenance(str(record.get("id", ""))),
                    confidence=Confidence.MODERATE,
                    first_seen=seen,
                    tags=["url-feed"],
                    context={"observed_url": url},
                )
            )
        host_ip = str(record.get("resolved_ip", "")).strip()
        if host_ip:
            indicators.append(
                Indicator(
                    value=host_ip,
                    type=IndicatorType.IPV4,
                    provenance=self._provenance(str(record.get("id", ""))),
                    confidence=Confidence.LOW,
                    first_seen=seen,
                    tags=["url-feed", "resolution"],
                    context={
                        "resolved_from": host,
                        "asn": record.get("asn", ""),
                    },
                )
            )
        return indicators


#: Collector registry, keyed by the snapshot filename stem the CLI expects.
COLLECTORS = {
    "certificate_transparency": CertificateTransparencyCollector,
    "package_registry": PackageRegistryCollector,
    "malicious_url_feed": MaliciousUrlFeedCollector,
}
