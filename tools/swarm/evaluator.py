"""EPIC 3 — Correlated multi-event telemetry evaluator.

Extends single-event detection to correlated, multi-log event streams. A
:class:`MultiEventEvaluator` runs a Sigma rule against every event in a sequence
(each event evaluated in its own in-memory SQLite row, mirroring the production
:class:`~tools.swarm.detectors.SigmaDetector`) and a :class:`CorrelationRule`
requires several component detections to fire, in order, inside a bounded time
window — the shape of a real detection-engineering correlation analytic.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from .models import (
    CorrelationResult,
    CorrelationRule,
    CorrelationStage,
    EventSequence,
    MultiEventResult,
    TelemetryEvent,
)

ROOT = Path(__file__).resolve().parents[2]


class MultiEventEvaluator:
    """Evaluates Sigma rules and temporal correlation rules over event sequences."""

    def __init__(self) -> None:
        self._backend = sqliteBackend()
        self._query_cache: Dict[str, List[str]] = {}

    # -- rule compilation -------------------------------------------------

    def _compile(self, *, rule_yaml: Optional[str] = None, rule_path: Optional[str] = None) -> List[str]:
        """Compiles a Sigma rule to SQLite queries, caching by source key."""
        if rule_yaml is None and rule_path is None:
            raise ValueError("Provide either rule_yaml or rule_path to compile a rule.")
        cache_key = rule_yaml if rule_yaml is not None else f"path::{rule_path}"
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        if rule_yaml is not None:
            yaml_text = rule_yaml
        else:
            path = Path(rule_path)
            if not path.is_absolute():
                path = ROOT / path
            yaml_text = path.read_text(encoding="utf-8")

        collection = SigmaCollection.from_yaml(yaml_text)
        queries = self._backend.convert(collection)
        self._query_cache[cache_key] = queries
        return queries

    @staticmethod
    def _event_matches(queries: List[str], event: TelemetryEvent) -> bool:
        """Runs each compiled query against a single-row table built from *event*."""
        record = event.to_record()
        conn = sqlite3.connect(":memory:")
        try:
            cursor = conn.cursor()
            cols = list(record.keys())
            placeholders = ", ".join("?" * len(cols))
            col_defs = ", ".join(f'"{c}" TEXT' for c in cols)
            cursor.execute(f"CREATE TABLE events ({col_defs})")
            cursor.execute(
                f"INSERT INTO events VALUES ({placeholders})",
                [str(v) if v is not None else "" for v in record.values()],
            )
            for query in queries:
                sql = query.replace("<TABLE_NAME>", "events")
                try:
                    if cursor.execute(sql).fetchall():
                        return True
                except sqlite3.OperationalError:
                    # Rule references a column absent from this event family: no match.
                    continue
            return False
        finally:
            conn.close()

    # -- single-rule, multi-event ----------------------------------------

    def evaluate_rule(
        self,
        sequence: EventSequence,
        *,
        rule_yaml: Optional[str] = None,
        rule_path: Optional[str] = None,
        rule_name: str = "",
        event_id: Optional[int] = None,
    ) -> MultiEventResult:
        """Evaluates a single Sigma rule against every event in *sequence*.

        Args:
            event_id: Optional Event ID filter; only events of that family are tested.

        Returns:
            A :class:`MultiEventResult` listing the indices of matching events.
        """
        queries = self._compile(rule_yaml=rule_yaml, rule_path=rule_path)
        matched_indices: List[int] = []
        for idx, event in enumerate(sequence.events):
            if event_id is not None and event.event_id != event_id:
                continue
            if self._event_matches(queries, event):
                matched_indices.append(idx)

        return MultiEventResult(
            rule_name=rule_name or (rule_path or "inline-rule"),
            matched=bool(matched_indices),
            matched_event_indices=matched_indices,
            details=(
                f"Matched {len(matched_indices)} of {len(sequence.events)} events"
                if matched_indices
                else "No event satisfied the rule selection"
            ),
        )

    # -- temporal correlation --------------------------------------------

    def evaluate_correlation(self, rule: CorrelationRule, sequence: EventSequence) -> CorrelationResult:
        """Evaluates a temporal :class:`CorrelationRule` over *sequence*.

        The rule matches when at least one event satisfies each stage and a single
        assignment of events (one per stage) can be selected such that, when
        ``rule.ordered`` is true, the events are non-decreasing in time and the
        full chain spans no more than ``rule.timespan_seconds``.
        """
        stage_matches: Dict[str, List[int]] = {}
        per_stage_indices: List[List[int]] = []

        for stage in rule.stages:
            result = self.evaluate_rule(
                sequence,
                rule_yaml=stage.rule_yaml,
                rule_path=stage.rule_path,
                rule_name=stage.name,
                event_id=stage.event_id,
            )
            stage_matches[stage.name] = result.matched_event_indices
            per_stage_indices.append(result.matched_event_indices)

        # Every stage must have at least one candidate event.
        if any(len(indices) == 0 for indices in per_stage_indices):
            return CorrelationResult(
                rule_name=rule.name,
                matched=False,
                within_window=False,
                stage_matches=stage_matches,
                selected_indices=[],
                span_seconds=None,
                details="One or more correlation stages produced no candidate events.",
            )

        selection = self._select_chain(rule, sequence, per_stage_indices)
        if selection is None:
            return CorrelationResult(
                rule_name=rule.name,
                matched=False,
                within_window=False,
                stage_matches=stage_matches,
                selected_indices=[],
                span_seconds=None,
                details=(
                    f"Candidate events exist for every stage but none satisfy the "
                    f"{rule.timespan_seconds}s ordered correlation window."
                ),
            )

        selected_indices, span = selection
        return CorrelationResult(
            rule_name=rule.name,
            matched=True,
            within_window=True,
            stage_matches=stage_matches,
            selected_indices=selected_indices,
            span_seconds=round(span, 3),
            details=(
                f"Correlated {len(rule.stages)} stages within {span:.1f}s "
                f"(window {rule.timespan_seconds}s)."
            ),
        )

    @staticmethod
    def _select_chain(
        rule: CorrelationRule,
        sequence: EventSequence,
        per_stage_indices: List[List[int]],
    ) -> Optional[tuple]:
        """Selects one *distinct* event per stage inside the correlation window.

        Each stage consumes a different event (an N-stage correlation requires N
        events). For ordered rules the selected events must be non-decreasing in
        time; for either mode the full chain must span no more than the window.

        Returns ``(selected_indices, span_seconds)`` or ``None`` if no valid chain exists.
        """
        times = [event.epoch() for event in sequence.events]

        if not rule.ordered:
            # Unordered: assign each stage its earliest still-unused candidate.
            used: set[int] = set()
            chosen: List[int] = []
            for indices in per_stage_indices:
                available = sorted((i for i in indices if i not in used), key=lambda i: times[i])
                if not available:
                    return None
                pick = available[0]
                used.add(pick)
                chosen.append(pick)
            span = max(times[i] for i in chosen) - min(times[i] for i in chosen)
            return (chosen, span) if span <= rule.timespan_seconds else None

        # Ordered: anchor on each candidate of the first stage (time-sorted), then
        # pick for each later stage the earliest distinct candidate at or after the
        # previously selected event's timestamp; verify the total span fits.
        for anchor in sorted(per_stage_indices[0], key=lambda i: times[i]):
            used = {anchor}
            selected = [anchor]
            prev_time = times[anchor]
            ok = True
            for indices in per_stage_indices[1:]:
                forward = sorted(
                    (i for i in indices if i not in used and times[i] >= prev_time),
                    key=lambda i: times[i],
                )
                if not forward:
                    ok = False
                    break
                pick = forward[0]
                used.add(pick)
                selected.append(pick)
                prev_time = times[pick]
            if not ok:
                continue
            span = times[selected[-1]] - times[selected[0]]
            if span <= rule.timespan_seconds:
                return selected, span
        return None


def build_correlation_rule(
    name: str,
    stages: List[CorrelationStage],
    timespan_seconds: int = 300,
    ordered: bool = True,
    technique_id: str = "",
    description: str = "",
) -> CorrelationRule:
    """Convenience factory constructing a validated :class:`CorrelationRule`."""
    if not stages:
        raise ValueError("A correlation rule requires at least one stage.")
    return CorrelationRule(
        name=name,
        stages=stages,
        timespan_seconds=timespan_seconds,
        ordered=ordered,
        technique_id=technique_id,
        description=description,
    )
