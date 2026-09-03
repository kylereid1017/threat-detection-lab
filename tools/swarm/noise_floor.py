"""EPIC 1 — Enterprise telemetry noise floor and precision/recall engine.

A detection that catches every attack variation is operationally useless if it
also fires on routine administrative activity. Fifteen static negative fixtures
establish a correctness gate; they do not characterise signal-to-noise ratio at
enterprise volume.

This module generates a high-volume corpus of realistic benign Windows
background telemetry, mixes it with labelled malicious telemetry, and computes
confusion matrices and derived statistics for each analytic.

Two measurement decisions matter for the figures to mean anything:

*   **Per-analytic recall is scored only against the events that analytic owns.**
    Charging the LSASS rule for failing to catch a scheduled-task fixture would
    manufacture a recall figure that describes nothing.
*   **Corpus-level metrics are computed per event, not by pooling per-rule
    matrices.** A benign event that four analytics all ignore is one true
    negative, not four.

The benign corpus deliberately includes a small proportion of *ambiguous*
events: legitimate administrative activity that genuinely resembles attacker
tradecraft. These produce real-world false positives, and excluding them would
manufacture a precision score of 1.0 that means nothing.

All generated telemetry is inert and constrained to RFC 2606 / RFC 5737
reserved endpoints by :mod:`tools.swarm.telemetry_generator`.
"""

from __future__ import annotations

import json
import random
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from .models import TelemetryEvent
from .telemetry_generator import TelemetryGenerator

ROOT = Path(__file__).resolve().parents[2]

_SELECT_RE = re.compile(r"^\s*SELECT\s+\*\s+FROM\s+<TABLE_NAME>", re.IGNORECASE)

#: Ground truth: which analytic each committed positive fixture is meant to trigger.
RULE_EXPECTED_FIXTURES: Dict[str, Tuple[str, ...]] = {
    "proc_creation_win_defense_evasion_tampering.yml": (
        "clickfix_wevtutil_log_clear",
        "clickfix_defender_disable",
    ),
    "proc_creation_win_rundll32_lsass_dump.yml": (
        "clickfix_rundll32_comsvcs_dump",
        "clickfix_rundll32_comsvcs_ordinal",
    ),
    "proc_creation_win_schtasks_persistence.yml": (
        "clickfix_schtasks_logon_powershell",
        "clickfix_schtasks_minute_cmd",
    ),
    "proc_creation_win_explorer_clickfix_execution.yml": (
        "clickfix_cmd_powershell_staging",
        "clickfix_curl_temp_exec",
        "clickfix_mshta_remote",
        "clickfix_powershell_encoded",
        "clickfix_powershell_irm_iex",
        "clickfix_powershell_webclient_hidden",
    ),
}


@dataclass
class LabelledEvent:
    """A telemetry event carrying ground truth for metric computation."""

    event: TelemetryEvent
    label: int  # 1 = malicious, 0 = benign
    profile: str = ""
    ambiguous: bool = False
    target_rule: str = ""  # rule filename this event is expected to trigger

    def record(self) -> Dict[str, object]:
        return self.event.to_record()


@dataclass
class RuleMetrics:
    """Confusion matrix and derived statistics for a single analytic."""

    rule_name: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    false_positive_profiles: Dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_discovery_rate(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.false_positives / denom if denom else 0.0

    @property
    def alerts(self) -> int:
        return self.true_positives + self.false_positives

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_name": self.rule_name,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_discovery_rate": round(self.false_discovery_rate, 4),
            "false_positive_profiles": self.false_positive_profiles,
        }


@dataclass
class NoiseFloorReport:
    """Aggregate signal-to-noise assessment across all evaluated analytics."""

    total_events: int
    benign_events: int
    malicious_events: int
    ambiguous_events: int
    corpus_metrics: RuleMetrics = field(default_factory=lambda: RuleMetrics(rule_name="CORPUS"))
    per_rule: List[RuleMetrics] = field(default_factory=list)

    def false_positive_rate(self) -> float:
        """Benign events raising at least one alert, as a proportion of all benign events."""
        if self.benign_events == 0:
            return 0.0
        return self.corpus_metrics.false_positives / self.benign_events

    def alerts_per_thousand_benign(self) -> float:
        """Analyst-facing noise rate: benign alerts raised per 1,000 benign events."""
        return self.false_positive_rate() * 1000

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_events": self.total_events,
            "benign_events": self.benign_events,
            "malicious_events": self.malicious_events,
            "ambiguous_events": self.ambiguous_events,
            "false_positive_rate": round(self.false_positive_rate(), 5),
            "alerts_per_1000_benign": round(self.alerts_per_thousand_benign(), 3),
            "corpus": self.corpus_metrics.to_dict(),
            "per_rule": [m.to_dict() for m in self.per_rule],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Renders an ICD 203 formatted precision/recall assessment."""
        corpus = self.corpus_metrics
        lines = [
            "# Enterprise Telemetry Noise Floor Assessment",
            "",
            "**Scope.** Signal-to-noise characterisation of the committed detection corpus "
            "against high-volume synthetic enterprise background telemetry.",
            "",
            "## Corpus composition",
            "",
            "| Population | Count |",
            "|---|---|",
            f"| Total events | {self.total_events} |",
            f"| Benign background | {self.benign_events} |",
            f"| Malicious (labelled) | {self.malicious_events} |",
            f"| Ambiguous-by-design benign | {self.ambiguous_events} |",
            "",
            "## Headline: analyst workload",
            "",
            "False-positive rate is the base-rate-independent figure and the one that "
            "governs whether an analytic can run unattended.",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Benign false-positive rate | {self.false_positive_rate():.3%} |",
            f"| Benign alerts per 1,000 events | {self.alerts_per_thousand_benign():.2f} |",
            f"| Corpus recall | {corpus.recall:.3f} |",
            f"| Corpus precision (base-rate conditional) | {corpus.precision:.3f} |",
            "",
            "## Per-analytic performance",
            "",
            "Recall is scored only against the malicious events each analytic owns. "
            "False positives are scored against the entire benign population.",
            "",
            "| Analytic | TP | FP | TN | FN | Precision | Recall | F1 | FDR |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for metric in self.per_rule:
            lines.append(
                f"| {metric.rule_name} | {metric.true_positives} | {metric.false_positives} | "
                f"{metric.true_negatives} | {metric.false_negatives} | "
                f"{metric.precision:.3f} | {metric.recall:.3f} | "
                f"{metric.f1_score:.3f} | {metric.false_discovery_rate:.3f} |"
            )
        lines += [
            f"| **CORPUS (per event)** | {corpus.true_positives} | {corpus.false_positives} | "
            f"{corpus.true_negatives} | {corpus.false_negatives} | {corpus.precision:.3f} | "
            f"{corpus.recall:.3f} | {corpus.f1_score:.3f} | {corpus.false_discovery_rate:.3f} |",
            "",
        ]
        if corpus.false_positive_profiles:
            lines += [
                "### False positives by benign activity profile",
                "",
                "| Benign profile | Alerts raised |",
                "|---|---|",
            ]
            for profile, count in sorted(
                corpus.false_positive_profiles.items(), key=lambda kv: -kv[1]
            ):
                lines.append(f"| `{profile}` | {count} |")
            lines.append("")

        lines += [
            "## Assessment",
            "",
            self._judgement(),
            "",
            "> **Confidence.** We assess with high confidence that these figures characterise "
            "analytic behaviour against the modelled benign population. Confidence in "
            "extrapolation to a live production estate is moderate: the synthetic corpus "
            "models common administrative patterns but does not reproduce the full tail of "
            "site-specific tooling.",
            "",
            "> **Base-rate caveat.** Precision is conditional on the malicious-to-benign "
            "ratio of this corpus, which is far higher than any production estate. A "
            "production deployment would show materially lower precision at the same "
            "false-positive rate. Compare analytics on false-positive rate and recall; "
            "treat precision as descriptive of this corpus only.",
        ]
        return "\n".join(lines)

    def _judgement(self) -> str:
        """Produces an estimative-language judgement from the corpus matrix."""
        fpr = self.false_positive_rate()
        recall = self.corpus_metrics.recall
        if self.corpus_metrics.false_positives == 0:
            return (
                f"We judge the analytic corpus to be **highly precise** against the modelled "
                f"benign population: no background event raised an alert. Corpus recall of "
                f"{recall:.1%} is the binding constraint, not precision."
            )
        if fpr <= 0.01:
            return (
                f"We judge the false-positive rate of {fpr:.2%} to be **operationally "
                f"acceptable** for unattended alerting. Residual false positives concentrate "
                f"in administrative activity that is genuinely indistinguishable from "
                f"attacker tradecraft on process-creation telemetry alone. It is likely that "
                f"resolving them requires correlating additional event families rather than "
                f"tightening command-line string matching."
            )
        return (
            f"We judge the false-positive rate of {fpr:.2%} to be **above the threshold for "
            f"unattended alerting**. It is likely that deploying this corpus without further "
            f"tuning, or without correlation against a second event family, would impose an "
            f"unsustainable triage burden at enterprise event volume."
        )


class EnterpriseNoiseGenerator:
    """Generates realistic, inert benign Windows background telemetry at volume.

    Args:
        seed: Deterministic seed. The same seed always yields the same corpus.
        ambiguous_rate: Proportion of benign events drawn from the ambiguous
            profiles, which model legitimate administrative activity that
            resembles attacker tradecraft.
    """

    #: Benign profiles that must never resemble attacker tradecraft.
    ROUTINE_PROFILES: Tuple[str, ...] = (
        "defender_signature_update",
        "defender_scheduled_scan",
        "intune_management_extension",
        "sccm_client_operations",
        "disk_maintenance",
        "service_control_query",
        "admin_activedirectory_query",
        "admin_exchange_management",
        "admin_module_import",
        "group_policy_refresh",
        "windows_update_servicing",
    )

    #: Benign profiles that legitimately resemble attacker tradecraft. These are
    #: the population that produces genuine production false positives.
    AMBIGUOUS_PROFILES: Tuple[str, ...] = (
        "admin_hidden_window_script",
        "deployment_scheduled_task",
    )

    def __init__(self, seed: int = 20260903, ambiguous_rate: float = 0.03) -> None:
        if not 0.0 <= ambiguous_rate <= 1.0:
            raise ValueError("ambiguous_rate must be between 0.0 and 1.0")
        self.rng = random.Random(seed)
        self.ambiguous_rate = ambiguous_rate
        self.telemetry = TelemetryGenerator(
            seed=seed, base_time="2026-09-03 08:00:00", dwell_seconds=1
        )

    def _builders(self) -> Dict[str, Callable[[], Tuple[str, str, str, str]]]:
        """Maps profile name to a builder returning (image, parent, cmdline, user)."""
        r = self.rng
        host = f"WKS-{r.randint(1000, 9999)}"
        return {
            "defender_signature_update": lambda: (
                "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11\\MpCmdRun.exe",
                "C:\\Windows\\System32\\services.exe",
                "MpCmdRun.exe -SignatureUpdate -ScheduleJob",
                "NT AUTHORITY\\SYSTEM",
            ),
            "defender_scheduled_scan": lambda: (
                "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11\\MpCmdRun.exe",
                "C:\\Windows\\System32\\svchost.exe",
                f"MpCmdRun.exe -Scan -ScanType {r.choice([1, 2])} -ScheduleJob",
                "NT AUTHORITY\\SYSTEM",
            ),
            "intune_management_extension": lambda: (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe",
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
                f"\"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\{r.randint(10000, 99999)}_inventory.ps1\"",
                "NT AUTHORITY\\SYSTEM",
            ),
            "sccm_client_operations": lambda: (
                "C:\\Windows\\CCM\\CcmExec.exe",
                "C:\\Windows\\System32\\services.exe",
                f"CcmExec.exe -ProcessID {r.randint(1000, 9000)}",
                "NT AUTHORITY\\SYSTEM",
            ),
            "disk_maintenance": lambda: (
                "C:\\Windows\\System32\\defrag.exe",
                "C:\\Windows\\System32\\svchost.exe",
                f"defrag.exe {r.choice(['C:', 'D:'])} -k -h -o",
                "NT AUTHORITY\\SYSTEM",
            ),
            "service_control_query": lambda: (
                "C:\\Windows\\System32\\sc.exe",
                "C:\\Windows\\System32\\cmd.exe",
                f"sc.exe query {r.choice(['wuauserv', 'WinDefend', 'BITS', 'Spooler', 'CcmExec'])}",
                f"{host}\\svc_monitor",
            ),
            "admin_activedirectory_query": lambda: (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\explorer.exe",
                "powershell.exe -Command \"Get-ADUser -Filter * -Properties LastLogonDate "
                f"-SearchBase 'OU=Staff,DC=corp,DC={r.choice(['example', 'invalid'])}'\"",
                f"{host}\\admin.kreid",
            ),
            "admin_exchange_management": lambda: (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\explorer.exe",
                "powershell.exe -Command \"Get-Mailbox -ResultSize 200 | "
                "Select-Object DisplayName,PrimarySmtpAddress\"",
                f"{host}\\admin.kreid",
            ),
            "admin_module_import": lambda: (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\System32\\cmd.exe",
                f"powershell.exe -Command \"Import-Module {r.choice(['ActiveDirectory', 'GroupPolicy', 'ServerManager'])}; Get-Command -Module *\"",
                f"{host}\\admin.kreid",
            ),
            "group_policy_refresh": lambda: (
                "C:\\Windows\\System32\\gpupdate.exe",
                "C:\\Windows\\System32\\taskeng.exe",
                "gpupdate.exe /target:computer /force",
                "NT AUTHORITY\\SYSTEM",
            ),
            "windows_update_servicing": lambda: (
                "C:\\Windows\\System32\\dism.exe",
                "C:\\Windows\\System32\\svchost.exe",
                "dism.exe /Online /Cleanup-Image /RestoreHealth",
                "NT AUTHORITY\\SYSTEM",
            ),
            # -- ambiguous by design ---------------------------------------
            "admin_hidden_window_script": lambda: (
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "C:\\Windows\\explorer.exe",
                "powershell.exe -w hidden -Command \"Get-Service -Name "
                f"{r.choice(['Spooler', 'BITS', 'WinDefend'])} | Restart-Service\"",
                f"{host}\\admin.kreid",
            ),
            "deployment_scheduled_task": lambda: (
                "C:\\Windows\\System32\\schtasks.exe",
                "C:\\Windows\\System32\\cmd.exe",
                f"schtasks.exe /create /tn \"CorpInventory{r.randint(1, 99)}\" /tr "
                "\"powershell.exe -File C:\\ProgramData\\Corp\\inventory.ps1\" /sc onlogon /ru SYSTEM",
                "NT AUTHORITY\\SYSTEM",
            ),
        }

    def generate(self, count: int = 2500) -> List[LabelledEvent]:
        """Generates *count* benign, validated background telemetry events."""
        if count < 0:
            raise ValueError("count must be non-negative")
        builders = self._builders()
        events: List[LabelledEvent] = []

        for _ in range(count):
            is_ambiguous = self.rng.random() < self.ambiguous_rate
            pool = self.AMBIGUOUS_PROFILES if is_ambiguous else self.ROUTINE_PROFILES
            profile = self.rng.choice(pool)
            image, parent, cmdline, user = builders[profile]()
            event = self.telemetry.process_creation(
                image_path=image,
                command_line=cmdline,
                parent_image=parent,
                user=user,
            )
            event.fields["NoiseProfile"] = profile
            events.append(
                LabelledEvent(event=event, label=0, profile=profile, ambiguous=is_ambiguous)
            )
        return events


class DetectionMetricsCalculator:
    """Evaluates analytics over a labelled corpus and computes confusion matrices.

    Evaluation uses a single bulk SQL query per analytic across the whole corpus
    rather than one connection per event, so a 5,000-event corpus stays tractable.
    """

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = repo_root or ROOT
        self._backend = sqliteBackend()

    # -- corpus assembly --------------------------------------------------

    def load_malicious_fixtures(self) -> List[LabelledEvent]:
        """Loads committed positive Sigma fixtures, tagged with the analytic they own."""
        pos_dir = self.repo_root / "tests" / "fixtures" / "sigma" / "positive"
        owner: Dict[str, str] = {}
        for rule_file, fixtures in RULE_EXPECTED_FIXTURES.items():
            for stem in fixtures:
                owner[stem] = rule_file

        events: List[LabelledEvent] = []
        for fixture in sorted(pos_dir.glob("*.json")):
            record = json.loads(fixture.read_text(encoding="utf-8"))
            event = TelemetryEvent(
                event_id=int(record.get("EventID", 1)),
                channel="Microsoft-Windows-Sysmon/Operational",
                utc_time=str(record.get("UtcTime", "2026-09-03 12:00:00.000")),
                fields={k: v for k, v in record.items() if k not in ("EventID", "UtcTime")},
                description=fixture.name,
            )
            events.append(
                LabelledEvent(
                    event=event,
                    label=1,
                    profile=fixture.stem,
                    target_rule=owner.get(fixture.stem, ""),
                )
            )
        return events

    def generate_attack_variants(self, count: int = 0) -> List[LabelledEvent]:
        """Generates novel attack permutations owned by the ClickFix execution analytic.

        These are deliberately harder than the committed fixtures: many are known
        evasions, so they measure recall against variation rather than against the
        exact patterns the rule was written for.
        """
        if count <= 0:
            return []
        from .prompt_engine import PromptEngine

        engine = PromptEngine()
        events: List[LabelledEvent] = []
        for idx in range(count):
            _prompt, variant = engine.generate_novel_hypothesis(target_type="sigma", index=idx)
            payload = variant.payload if isinstance(variant.payload, dict) else {}
            event = TelemetryEvent(
                event_id=int(payload.get("EventID", 1)),
                channel="Microsoft-Windows-Sysmon/Operational",
                utc_time="2026-09-03 12:00:00.000",
                fields={k: v for k, v in payload.items() if k != "EventID"},
                description=variant.mutation_name,
            )
            events.append(
                LabelledEvent(
                    event=event,
                    label=1,
                    profile=f"variant_{variant.mutation_name}",
                    target_rule="proc_creation_win_explorer_clickfix_execution.yml",
                )
            )
        return events

    def build_corpus(
        self,
        benign_count: int = 2500,
        seed: int = 20260903,
        ambiguous_rate: float = 0.03,
        attack_variants: int = 0,
    ) -> List[LabelledEvent]:
        """Assembles a mixed corpus of benign background and labelled malicious events."""
        generator = EnterpriseNoiseGenerator(seed=seed, ambiguous_rate=ambiguous_rate)
        corpus = generator.generate(benign_count)
        corpus.extend(self.load_malicious_fixtures())
        corpus.extend(self.generate_attack_variants(attack_variants))
        return corpus

    # -- evaluation -------------------------------------------------------

    def _sigma_rule_paths(self) -> List[Path]:
        return sorted((self.repo_root / "rules" / "sigma").glob("*.yml"))

    @staticmethod
    def _bulk_match(queries: Sequence[str], records: Sequence[Dict[str, object]]) -> Set[int]:
        """Returns the row indices of *records* matched by any of *queries*."""
        if not records:
            return set()
        columns: List[str] = []
        seen: Set[str] = set()
        for record in records:
            for key in record:
                if key not in seen:
                    seen.add(key)
                    columns.append(str(key))

        conn = sqlite3.connect(":memory:")
        try:
            cursor = conn.cursor()
            col_defs = ", ".join(f'"{c}" TEXT' for c in columns)
            cursor.execute(f"CREATE TABLE events (__row_id INTEGER, {col_defs})")
            placeholders = ", ".join("?" * (len(columns) + 1))
            rows = [
                [idx] + [str(record[c]) if record.get(c) is not None else "" for c in columns]
                for idx, record in enumerate(records)
            ]
            cursor.executemany(f"INSERT INTO events VALUES ({placeholders})", rows)

            matched: Set[int] = set()
            for query in queries:
                sql = _SELECT_RE.sub("SELECT __row_id FROM events", query)
                if "<TABLE_NAME>" in sql:  # unexpected shape; fall back to whole table
                    sql = sql.replace("<TABLE_NAME>", "events")
                try:
                    for (row_id,) in cursor.execute(sql).fetchall():
                        matched.add(int(row_id))
                except sqlite3.OperationalError:
                    # Analytic references a column absent from this corpus: no match.
                    continue
            return matched
        finally:
            conn.close()

    def evaluate(self, corpus: Sequence[LabelledEvent]) -> NoiseFloorReport:
        """Computes per-analytic and per-event corpus confusion matrices."""
        records = [item.record() for item in corpus]
        per_rule: List[RuleMetrics] = []
        alerted_any: Set[int] = set()

        for rule_path in self._sigma_rule_paths():
            collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
            rule_title = collection.rules[0].title
            queries = self._backend.convert(collection)
            matched = self._bulk_match(queries, records)
            alerted_any |= matched

            metrics = RuleMetrics(rule_name=rule_title)
            for idx, item in enumerate(corpus):
                fired = idx in matched
                if item.label == 1:
                    # Recall is scored only over the events this analytic owns.
                    if item.target_rule != rule_path.name:
                        continue
                    if fired:
                        metrics.true_positives += 1
                    else:
                        metrics.false_negatives += 1
                else:
                    if fired:
                        metrics.false_positives += 1
                        metrics.false_positive_profiles[item.profile] = (
                            metrics.false_positive_profiles.get(item.profile, 0) + 1
                        )
                    else:
                        metrics.true_negatives += 1
            per_rule.append(metrics)

        # Corpus-level matrix, computed once per event across the union of analytics.
        corpus_metrics = RuleMetrics(rule_name="CORPUS")
        for idx, item in enumerate(corpus):
            fired = idx in alerted_any
            if item.label == 1:
                if fired:
                    corpus_metrics.true_positives += 1
                else:
                    corpus_metrics.false_negatives += 1
            else:
                if fired:
                    corpus_metrics.false_positives += 1
                    corpus_metrics.false_positive_profiles[item.profile] = (
                        corpus_metrics.false_positive_profiles.get(item.profile, 0) + 1
                    )
                else:
                    corpus_metrics.true_negatives += 1

        return NoiseFloorReport(
            total_events=len(corpus),
            benign_events=sum(1 for i in corpus if i.label == 0),
            malicious_events=sum(1 for i in corpus if i.label == 1),
            ambiguous_events=sum(1 for i in corpus if i.ambiguous),
            corpus_metrics=corpus_metrics,
            per_rule=per_rule,
        )


def run_benchmark(
    benign_count: int = 2500,
    seed: int = 20260903,
    ambiguous_rate: float = 0.03,
    attack_variants: int = 0,
    repo_root: Optional[Path] = None,
) -> NoiseFloorReport:
    """Convenience entry point: build the mixed corpus and evaluate it."""
    calculator = DetectionMetricsCalculator(repo_root=repo_root)
    corpus = calculator.build_corpus(
        benign_count=benign_count,
        seed=seed,
        ambiguous_rate=ambiguous_rate,
        attack_variants=attack_variants,
    )
    return calculator.evaluate(corpus)
