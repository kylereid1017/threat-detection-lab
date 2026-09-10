"""Operational outputs from enriched indicators.

Three outputs, because three consumers need different things:

STIX 2.1 bundles are for exchange with peers and platforms. Every indicator
carries a `valid_until`, so a consumer that honors it expires the indicator
without needing a separate retirement process.

SIEM lookup tables are for detection engineering. A flat, typed table joined
against telemetry is how an indicator actually becomes a detection in most
stacks, and it is far cheaper than a rule per indicator.

Candidate Sigma drafts are for the human in the loop. They are explicitly drafts:
generated logic that has not been evaluated against a noise floor is a
suggestion, and this module marks them `status: unsupported` so no draft can be
mistaken for a graduated rule.
"""

from __future__ import annotations

import csv
import io
import json
import urllib.parse
import uuid
from datetime import date
from typing import Dict, Iterable, List

from tools.cti.models import Indicator, IndicatorType

STIX_TYPE_PATTERN = {
    IndicatorType.DOMAIN: "[domain-name:value = '{value}']",
    IndicatorType.IPV4: "[ipv4-addr:value = '{value}']",
    IndicatorType.URL: "[url:value = '{value}']",
    IndicatorType.FILE_SHA256: "[file:hashes.'SHA-256' = '{value}']",
    IndicatorType.CERT_SHA256: "[x509-certificate:hashes.'SHA-256' = '{value}']",
    IndicatorType.EMAIL: "[email-addr:value = '{value}']",
    IndicatorType.PACKAGE: "[software:name = '{value}']",
    IndicatorType.ASN: "[autonomous-system:number = '{value}']",
}


def to_stix_bundle(indicators: Iterable[Indicator], produced: str = "") -> Dict[str, object]:
    """Build a STIX 2.1 bundle. Every indicator carries an expiry."""
    produced = produced or date.today().isoformat()
    objects: List[Dict[str, object]] = []
    for indicator in indicators:
        pattern = STIX_TYPE_PATTERN.get(indicator.type)
        if not pattern:
            continue
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator.stix_id,
                "created": f"{produced}T00:00:00.000Z",
                "modified": f"{produced}T00:00:00.000Z",
                "valid_from": f"{indicator.first_seen}T00:00:00.000Z",
                "valid_until": f"{indicator.expires_on()}T00:00:00.000Z",
                "pattern": pattern.format(value=indicator.value),
                "pattern_type": "stix",
                "confidence": {"low": 15, "moderate": 50, "high": 85}[
                    indicator.confidence.value
                ],
                "labels": indicator.tags or ["unlabeled"],
                "description": "; ".join(indicator.relevance_reasons)
                or "no relevance signal recorded",
                "external_references": [
                    {
                        "source_name": indicator.provenance.source,
                        "external_id": indicator.provenance.raw_reference or indicator.value,
                    }
                ],
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_DNS, f'cti-{produced}')}",
        "objects": objects,
    }


def to_siem_lookup(indicators: Iterable[Indicator]) -> str:
    """CSV lookup table for joining against telemetry."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "indicator",
            "type",
            "confidence",
            "relevance",
            "first_seen",
            "expires_on",
            "tags",
            "reasons",
            "source",
        ]
    )
    for indicator in indicators:
        writer.writerow(
            [
                indicator.value,
                indicator.type.value,
                indicator.confidence.value,
                f"{indicator.relevance:.2f}",
                indicator.first_seen,
                indicator.expires_on(),
                ";".join(indicator.tags),
                ";".join(indicator.relevance_reasons),
                indicator.provenance.source,
            ]
        )
    return buffer.getvalue()


def to_candidate_sigma(
    indicators: Iterable[Indicator], cluster_id: str = "", produced: str = ""
) -> str:
    """Emit a candidate Sigma rule matching network contact with indicators.

    The draft is marked unsupported and carries an explicit review block. A
    generated rule that has not been measured against a noise floor is a
    hypothesis, and shipping it as anything else is how a pipeline starts
    degrading the detections it was built to feed.
    """
    produced = produced or date.today().isoformat()
    raw_hosts = set()
    for i in indicators:
        if i.type == IndicatorType.DOMAIN:
            raw_hosts.add(i.value)
        elif i.type == IndicatorType.URL:
            host = urllib.parse.urlsplit(i.value).hostname or urllib.parse.urlsplit(i.value).netloc.split(":")[0]
            if host:
                raw_hosts.add(host)
    domains = sorted(raw_hosts)
    if not domains:
        return ""
    reasons = sorted({r for i in indicators for r in i.relevance_reasons})
    earliest = min((i.first_seen for i in indicators if i.first_seen), default=produced)
    expiry = min((i.expires_on() for i in indicators), default=produced)

    lines = [
        f"title: Candidate - Network Contact With Clustered Lure Infrastructure ({cluster_id or 'unclustered'})",
        "status: unsupported",
        "description: |",
        "    AUTOMATICALLY DRAFTED. Not a production rule.",
        "    Generated from clustered collection output. It has not been evaluated against",
        "    a noise floor, has no fixture coverage, and its false-positive behavior is",
        "    unknown. Review, measure, and rewrite before deployment.",
        f"    Relevance signals: {'; '.join(reasons) if reasons else 'none recorded'}",
        f"author: tools/cti pipeline",
        f"date: {produced}",
        "tags:",
        "    - attack.command_and_control",
        "    - attack.t1071.001",
        "logsource:",
        "    category: dns_query",
        "detection:",
        "    selection:",
        "        QueryName:",
    ]
    lines.extend(f"            - '{domain}'" for domain in domains)
    lines.extend(
        [
            "    condition: selection",
            "fields:",
            "    - QueryName",
            "    - Image",
            "    - User",
            "falsepositives:",
            "    - Unmeasured. This draft has no false-positive evaluation.",
            "level: medium",
            "indicator_lifecycle:",
            f"    first_seen: {earliest}",
            f"    review_by: {expiry}",
            "    review_action: >-",
            "        Retire or re-validate on this date. An indicator rule left in place after its",
            "        infrastructure is recycled becomes a false positive source.",
        ]
    )
    return "\n".join(lines) + "\n"


def to_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"
