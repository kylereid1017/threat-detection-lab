"""Per-observation record layer for the endurance harness.

Every probe the swarm evaluates produces one append-only JSONL observation
record on disk.  Strategic aggregates (resilience, Cluster distribution,
campaign containment, Critic approval) are derived from these records rather
than from running counters, so any published figure can be traced back to the
raw observations that produced it.

Record fields (one JSON object per line):

    run_id        identifier shared by all records of a single endurance run
    seq           monotonically increasing sequence number within the run
    timestamp     ISO-8601 UTC observation time
    suite         pattern suite that produced the observation
    kind          observation kind (see KIND_* constants)
    probe_id      identifier of the evaluated variant, when applicable
    target        detection target ("sigma"/"yara"), when applicable
    axis          mutation axis (e.g. "lolbin_proxy", "parser_differential")
    cluster       evasion taxonomy cluster assigned to the observation
    rule_hash     sha256 of the detection rule the probe was evaluated against
    fixture_hash  sha256 of the generated payload / corpus that was evaluated
    outcome       detected | evaded | unclassified | error | contained |
                  uncontained  (aggregate observations carry "counts" instead)
    counts        event counts for aggregate observations (sweeps, benchmarks)
    detail        free-form supporting detail

Records with outcome ``unclassified`` (Critic safety-gate rejections) and
``error`` (evaluation failures) are preserved on disk but excluded from rate
denominators.  A rate over an empty denominator is ``None`` -- never 0 or 1 by
default.

Resilience basis (repository measurement policy): the denominator is
*attack variants that passed the gate and were evaluated*
(``detected + evaded``); benign observations are counted separately and are
never part of the denominator.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

logger = logging.getLogger("swarm.records")

# Observation kinds -----------------------------------------------------------------

KIND_ATTACK_VARIANT = "attack_variant"
KIND_CAMPAIGN_STAGE = "campaign_stage"
KIND_CAMPAIGN_SUMMARY = "campaign_summary"
KIND_DAG_VISIT = "dag_visit"
KIND_WALK_SUMMARY = "walk_summary"
KIND_TELEMETRY_SWEEP = "telemetry_sweep"
KIND_NOISE_BENCHMARK = "noise_benchmark"

ATTACK_KINDS = (KIND_ATTACK_VARIANT, KIND_CAMPAIGN_STAGE, KIND_DAG_VISIT)

# Outcomes --------------------------------------------------------------------------

OUTCOME_DETECTED = "detected"
OUTCOME_EVADED = "evaded"
OUTCOME_UNCLASSIFIED = "unclassified"
OUTCOME_ERROR = "error"
OUTCOME_CONTAINED = "contained"
OUTCOME_UNCONTAINED = "uncontained"

# File cache for corpus/rule hashing so repeated sweeps stay cheap.
_HASH_CACHE: Dict[str, Optional[str]] = {}


def sha256_text(text: str) -> str:
    """Returns the hex sha256 of *text* (utf-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> Optional[str]:
    """Returns the hex sha256 of a file's bytes, or None if unreadable."""
    key = str(path)
    if key in _HASH_CACHE:
        return _HASH_CACHE[key]
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = None
    _HASH_CACHE[key] = digest
    return digest


def canonical_payload_hash(payload: Any) -> str:
    """Returns a deterministic sha256 over a variant payload (dict or string)."""
    if isinstance(payload, str):
        canonical = payload
    else:
        try:
            canonical = json.dumps(payload, sort_keys=True, default=str)
        except (TypeError, ValueError):
            canonical = repr(payload)
    return sha256_text(canonical)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@dataclass
class Observation:
    """One raw observation.  ``seq`` and ``timestamp`` are auto-filled by the writer."""

    run_id: str
    suite: str
    kind: str
    probe_id: Optional[str] = None
    target: Optional[str] = None
    axis: Optional[str] = None
    cluster: Optional[str] = None
    rule_hash: Optional[str] = None
    fixture_hash: Optional[str] = None
    outcome: Optional[str] = None
    counts: Optional[Dict[str, Any]] = None
    detail: Optional[Dict[str, Any]] = None
    seq: int = 0
    timestamp: str = ""

    def as_row(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "seq": self.seq,
            "timestamp": self.timestamp or _utc_now_iso(),
            "suite": self.suite,
            "kind": self.kind,
            "probe_id": self.probe_id,
            "target": self.target,
            "axis": self.axis,
            "cluster": self.cluster,
            "rule_hash": self.rule_hash,
            "fixture_hash": self.fixture_hash,
            "outcome": self.outcome,
            "counts": self.counts,
            "detail": self.detail,
        }


def records_dir_for(results_dir: Path) -> Path:
    return Path(results_dir) / "records"


def records_path_for(results_dir: Path, run_id: str) -> Path:
    return records_dir_for(results_dir) / f"run-{run_id}.jsonl"


class RecordWriter:
    """Append-only JSONL writer for one endurance run."""

    def __init__(self, results_dir: Path, run_id: str, start_seq: int = 0) -> None:
        self.run_id = run_id
        self.path = records_path_for(Path(results_dir), run_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = start_seq
        self._count = start_seq

    @property
    def count(self) -> int:
        """Number of records written/known for this run (including prior appends)."""
        return self._count

    @property
    def seq(self) -> int:
        return self._seq

    def append(self, observation: Observation) -> Dict[str, Any]:
        """Appends one observation; returns the written row."""
        self._seq += 1
        self._count += 1
        observation.run_id = self.run_id
        observation.seq = self._seq
        if not observation.timestamp:
            observation.timestamp = _utc_now_iso()
        row = observation.as_row()
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
        return row


def existing_record_count(results_dir: Path, run_id: str) -> int:
    """Counts already-persisted records for *run_id* (0 if the file is absent)."""
    path = records_path_for(Path(results_dir), run_id)
    if not path.exists():
        return 0
    count = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    count += 1
    except OSError as exc:
        logger.warning("Could not read existing records %s: %s", path, exc)
        return 0
    return count


def latest_run_id(results_dir: Path) -> Optional[str]:
    """Returns the run id of the most recently modified records file, if any."""
    directory = records_dir_for(Path(results_dir))
    if not directory.exists():
        return None
    candidates = sorted(directory.glob("run-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return None
    name = candidates[0].name
    return name[len("run-"):-len(".jsonl")]


def load_records(results_dir: Path, run_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads records for *run_id*, or every run under *results_dir* when None.

    Unreadable lines are skipped with a warning (the aggregate they belong to
    then understates its evidence base, which callers can detect via the
    ``malformed`` counter that is prepended as a synthetic record).
    """
    directory = records_dir_for(Path(results_dir))
    if not directory.exists():
        return []
    if run_id is not None:
        files = [records_path_for(Path(results_dir), run_id)]
    else:
        files = sorted(directory.glob("run-*.jsonl"))
    rows: List[Dict[str, Any]] = []
    malformed = 0
    for path in files:
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        malformed += 1
        except OSError as exc:
            logger.warning("Could not read records file %s: %s", path, exc)
    if malformed:
        logger.warning("Skipped %d malformed record line(s) while aggregating", malformed)
        rows.append({"_malformed": malformed})
    return rows


@dataclass
class Aggregates:
    """Aggregates derived exclusively from raw observation records.

    All rate fields are ``None`` when their denominator is empty.  Benign
    observations are reported separately and are never part of the resilience
    denominator.
    """

    n_records: int = 0
    malformed: int = 0
    event_counts: int = 0                     # every evaluated event/probe/visit/stage
    stage_records: int = 0
    visit_records: int = 0
    attack_detected: int = 0
    attack_evaded: int = 0
    unclassified: int = 0
    errors: int = 0
    benign_events: int = 0
    benign_false_positives: int = 0
    attacks_by_target: Dict[str, Dict[str, int]] = field(default_factory=dict)
    clusters: Dict[str, int] = field(default_factory=dict)
    campaigns: Dict[str, Any] = field(default_factory=dict)
    walks: Dict[str, Any] = field(default_factory=dict)
    replays: Dict[str, Any] = field(default_factory=dict)
    noise: Dict[str, Any] = field(default_factory=dict)
    gated_considered: int = 0
    gated_blocked: int = 0
    run_ids: List[str] = field(default_factory=list)

    @property
    def attack_evaluated(self) -> int:
        """Attack variants that passed the gate and were evaluated (denominator)."""
        return self.attack_detected + self.attack_evaded

    @property
    def gated_approved(self) -> int:
        """Proposals that passed the Critic gate."""
        return self.gated_considered - self.gated_blocked

    @property
    def resilience(self) -> Optional[float]:
        """Attack-variant resilience, or None when no attack variants were evaluated."""
        if self.attack_evaluated == 0:
            return None
        return self.attack_detected / self.attack_evaluated

    @property
    def critic_approval_rate(self) -> Optional[float]:
        """Critic approval over gated variant proposals, or None when none were gated."""
        if self.gated_considered == 0:
            return None
        return (self.gated_considered - self.gated_blocked) / self.gated_considered

    @property
    def containment_rate(self) -> Optional[float]:
        """Campaign/walk containment, or None when none were evaluated."""
        runs = int(self.campaigns.get("evaluated", 0)) + int(self.walks.get("evaluated", 0))
        if runs == 0:
            return None
        contained = int(self.campaigns.get("contained", 0)) + int(self.walks.get("contained", 0))
        return contained / runs


def aggregate(records: Sequence[Dict[str, Any]]) -> Aggregates:
    """Folds raw observation records into :class:`Aggregates`."""
    agg = Aggregates()
    for row in records:
        if "_malformed" in row:
            agg.malformed += int(row["_malformed"])
            continue
        agg.n_records += 1
        run_id = row.get("run_id")
        if run_id and run_id not in agg.run_ids:
            agg.run_ids.append(run_id)
        kind = row.get("kind")
        outcome = row.get("outcome")
        counts = row.get("counts") or {}
        detail = row.get("detail") or {}

        if (
            kind == KIND_ATTACK_VARIANT
            and str(row.get("suite", "")).startswith("endurance")
            and outcome != OUTCOME_ERROR
        ):
            # Gated proposals (only the endurance sigma/yara sparring suites go
            # through the Critic).  Errored probes were never gated, so they do
            # not enter the approval-rate denominator.
            agg.gated_considered += 1
            if outcome == OUTCOME_UNCLASSIFIED:
                agg.gated_blocked += 1

        if kind in ATTACK_KINDS:
            agg.event_counts += 1
            if kind == KIND_CAMPAIGN_STAGE:
                agg.stage_records += 1
            elif kind == KIND_DAG_VISIT:
                agg.visit_records += 1
            target = row.get("target") or "untyped"
            bucket = agg.attacks_by_target.setdefault(
                str(target), {"probes": 0, "approved": 0, "detected": 0, "evaded": 0, "unclassified": 0}
            )
            bucket["probes"] += 1
            if outcome == OUTCOME_DETECTED:
                bucket["approved"] += 1
                bucket["detected"] += 1
                agg.attack_detected += 1
            elif outcome == OUTCOME_EVADED:
                bucket["approved"] += 1
                bucket["evaded"] += 1
                agg.attack_evaded += 1
                cluster = row.get("cluster")
                if cluster:
                    agg.clusters[str(cluster)] = agg.clusters.get(str(cluster), 0) + 1
            elif outcome == OUTCOME_UNCLASSIFIED:
                bucket["unclassified"] += 1
                agg.unclassified += 1
            elif outcome == OUTCOME_ERROR:
                agg.errors += 1
        elif kind == KIND_CAMPAIGN_SUMMARY:
            camp = agg.campaigns
            camp["evaluated"] = int(camp.get("evaluated", 0)) + 1
            if outcome == OUTCOME_CONTAINED:
                camp["contained"] = int(camp.get("contained", 0)) + 1
            camp["dod_sum"] = float(camp.get("dod_sum", 0.0)) + float(detail.get("depth_of_defense", 0.0))
            stage = detail.get("interception_stage")
            if stage is not None:
                intercepts = camp.setdefault("intercepts", {})
                intercepts[str(stage)] = int(intercepts.get(str(stage), 0)) + 1
        elif kind == KIND_WALK_SUMMARY:
            walks = agg.walks
            walks["evaluated"] = int(walks.get("evaluated", 0)) + 1
            if outcome == OUTCOME_CONTAINED:
                walks["contained"] = int(walks.get("contained", 0)) + 1
            walks["dod_sum"] = float(walks.get("dod_sum", 0.0)) + float(detail.get("depth_of_defense", 0.0))
            mttd = detail.get("mttd_seconds")
            if mttd is not None:
                walks["mttd_sum"] = float(walks.get("mttd_sum", 0.0)) + float(mttd)
                walks["detected_count"] = int(walks.get("detected_count", 0)) + 1
        elif kind == KIND_TELEMETRY_SWEEP:
            replays = agg.replays
            replays["sweeps"] = int(replays.get("sweeps", 0)) + 1
            events = int(counts.get("events", 0))
            detections = int(counts.get("detections", 0))
            agg.event_counts += events
            if counts.get("benign"):
                agg.benign_events += events
                agg.benign_false_positives += detections
                replays["benign_events"] = int(replays.get("benign_events", 0)) + events
                replays["benign_detected"] = int(replays.get("benign_detected", 0)) + detections
            else:
                agg.attack_detected += detections
                agg.attack_evaded += max(0, events - detections)
                replays["attack_events"] = int(replays.get("attack_events", 0)) + events
                replays["attack_detected"] = int(replays.get("attack_detected", 0)) + detections
        elif kind == KIND_NOISE_BENCHMARK:
            noise = agg.noise
            noise["benchmarks"] = int(noise.get("benchmarks", 0)) + 1
            benign_events = int(counts.get("benign_events", 0))
            attack_events = int(counts.get("attack_events", 0))
            attack_tp = int(counts.get("attack_true_positives", 0))
            attack_missed = int(counts.get("attack_missed", 0))
            benign_fp = int(counts.get("benign_false_positives", 0))
            generated = int(
                counts.get(
                    "generated_events",
                    benign_events + int(counts.get("generated_attack_variants", 0)),
                )
            )
            agg.event_counts += generated
            noise["generated_events"] = int(noise.get("generated_events", 0)) + generated
            agg.benign_events += benign_events
            agg.benign_false_positives += benign_fp
            agg.attack_detected += attack_tp
            agg.attack_evaded += attack_missed
            noise["attack_events"] = int(noise.get("attack_events", 0)) + attack_events
            noise["attack_detected"] = int(noise.get("attack_detected", 0)) + attack_tp
            noise["attack_missed"] = int(noise.get("attack_missed", 0)) + attack_missed
            noise["benign_events"] = int(noise.get("benign_events", 0)) + benign_events
            noise["benign_false_positives"] = int(noise.get("benign_false_positives", 0)) + benign_fp

    return agg


def to_runner_counters(agg: Aggregates) -> Dict[str, Any]:
    """Maps aggregates back onto EnduranceRunner counter names (exact restore)."""
    targets = {t: dict(v) for t, v in agg.attacks_by_target.items()}
    for t in ("sigma", "yara"):
        targets.setdefault(t, {"probes": 0, "approved": 0, "detected": 0, "evaded": 0, "unclassified": 0})
    return {
        "total_probes": agg.event_counts,
        # Legacy counter semantics: every event that passed its gate — sparring
        # probe approvals + campaign stages + DAG visits + every replayed event
        # + every generated noise-floor event.  Blocked (unclassified) and
        # errored probes never passed, so they are excluded.
        "critic_approved": (
            agg.gated_approved
            + agg.stage_records
            + agg.visit_records
            + int(agg.replays.get("attack_events", 0))
            + int(agg.replays.get("benign_events", 0))
            + int(agg.noise.get("generated_events", 0))
        ),
        "true_positives": agg.attack_detected,
        "evasion_gaps": agg.attack_evaded,
        "target_probes": targets,
        "cluster_counts": dict(agg.clusters),
        "campaigns_count": int(agg.campaigns.get("evaluated", 0)),
        "campaigns_contained": int(agg.campaigns.get("contained", 0)),
        "campaign_dod_sum": float(agg.campaigns.get("dod_sum", 0.0)),
        "graph_walks_count": int(agg.walks.get("evaluated", 0)),
        "graph_walks_contained": int(agg.walks.get("contained", 0)),
        "graph_dod_sum": float(agg.walks.get("dod_sum", 0.0)),
        "graph_mttd_sum": float(agg.walks.get("mttd_sum", 0.0)),
        "graph_detected_count": int(agg.walks.get("detected_count", 0)),
        "replay_evals_count": int(agg.replays.get("sweeps", 0)),
        "noise_benchmarks_count": int(agg.noise.get("benchmarks", 0)),
        "benign_events": agg.benign_events,
        "benign_false_positives": agg.benign_false_positives,
        "gated_approved": agg.gated_considered - agg.gated_blocked,
        "gated_blocked": agg.gated_blocked,
        "error_records": agg.errors,
    }
