"""Agent 4 — The Detector: Local sandbox evaluation harness for YARA and Sigma rules."""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

import yara
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend

from .models import DetectionResult, Variant

ROOT = Path(__file__).resolve().parents[2]


class BaseDetector(ABC):
    """Abstract interface for local sandbox detection runners."""

    @abstractmethod
    def evaluate(self, variant: Variant) -> DetectionResult:
        """Evaluates a variant against the targeted detection logic."""
        pass


class YaraDetector(BaseDetector):
    """Local YARA detection runner."""

    def __init__(self, rule_path: Path | None = None) -> None:
        self.rule_path = rule_path or (ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar")
        self.rules = yara.compile(filepath=str(self.rule_path))
        self.target_rule_name = "Suspicious_Active_Content_SVG_Attachment"

    def evaluate(self, variant: Variant) -> DetectionResult:
        payload_bytes = variant.payload.encode("utf-8") if isinstance(variant.payload, str) else b""
        matches = self.rules.match(data=payload_bytes)

        matched = any(m.rule == self.target_rule_name for m in matches)
        matched_strings: List[str] = []
        if matched:
            for m in matches:
                if m.rule == self.target_rule_name:
                    # Collect matched string identifiers
                    for s in getattr(m, "strings", []):
                        matched_strings.append(str(s.identifier) if hasattr(s, "identifier") else str(s))

        return DetectionResult(
            variant_id=variant.id,
            rule_name=self.target_rule_name,
            detected=matched,
            matched_elements=matched_strings,
            details=f"YARA returned {len(matches)} matching rule(s)" if matched else "No YARA match"
        )


class SigmaDetector(BaseDetector):
    """Local Sigma detection runner executing over in-memory SQLite telemetry."""

    def __init__(self, rule_path: Path | None = None) -> None:
        self.rule_path = rule_path or (
            ROOT / "rules" / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        )
        self.collection = SigmaCollection.from_yaml(self.rule_path.read_text(encoding="utf-8"))
        self.target_rule_name = self.collection.rules[0].title
        self.backend = sqliteBackend()
        self.queries = self.backend.convert(self.collection)

    def evaluate(self, variant: Variant) -> DetectionResult:
        event_dict = variant.payload if isinstance(variant.payload, dict) else {}
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()

        cols = list(event_dict.keys())
        placeholders = ", ".join("?" * len(cols))
        col_defs = ", ".join(f'"{c}" TEXT' for c in cols)
        cursor.execute(f"CREATE TABLE events ({col_defs})")
        cursor.execute(
            f"INSERT INTO events VALUES ({placeholders})",
            [str(v) if v is not None else "" for v in event_dict.values()]
        )

        detected = False
        matched_queries: List[str] = []
        for q in self.queries:
            sql = q.replace("<TABLE_NAME>", "events")
            rows = cursor.execute(sql).fetchall()
            if rows:
                detected = True
                matched_queries.append(sql)

        return DetectionResult(
            variant_id=variant.id,
            rule_name=self.target_rule_name,
            detected=detected,
            matched_elements=matched_queries,
            details=f"Sigma condition satisfied by {len(matched_queries)} query clause(s)"
            if detected else "Sigma selection condition not met"
        )
