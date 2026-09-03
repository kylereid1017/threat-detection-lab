"""EPIC 4 — Deterministic zero-false-positive validation gate.

Runs every production detection rule against the committed negative fixture
corpus and asserts zero matches (the non-negotiable false-positive gate), then
confirms true-positive coverage against the positive corpus. Emits an ICD 203
formatted Markdown summary suitable for a CI job summary, and exits non-zero if
any negative fixture triggers a rule.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from .detectors import SigmaDetector, YaraDetector
from .models import Variant

ROOT = Path(__file__).resolve().parents[2]


@dataclass
class GateReport:
    """Structured result of a validation-gate run."""

    sigma_rules: int = 0
    yara_rules: int = 0
    negatives_checked: int = 0
    positives_checked: int = 0
    positives_detected: int = 0
    false_positives: List[str] = field(default_factory=list)
    missed_positives: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """The gate passes only with zero false positives."""
        return len(self.false_positives) == 0

    @property
    def coverage_rate(self) -> float:
        if self.positives_checked == 0:
            return 0.0
        return self.positives_detected / self.positives_checked

    def to_markdown(self) -> str:
        verdict = "✅ PASS" if self.passed else "❌ FAIL"
        confidence = "high confidence" if self.passed else "high confidence (gate breached)"
        lines = [
            "## Detection-as-Code Validation Gate",
            "",
            f"**Verdict:** {verdict}  ",
            f"**Analytic confidence (ICD 203):** {confidence}.",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Sigma rules evaluated | {self.sigma_rules} |",
            f"| YARA rules evaluated | {self.yara_rules} |",
            f"| Negative fixtures checked | {self.negatives_checked} |",
            f"| False positives | {len(self.false_positives)} |",
            f"| Positive fixtures checked | {self.positives_checked} |",
            f"| True-positive coverage | {self.positives_detected}/{self.positives_checked} "
            f"({self.coverage_rate * 100:.1f}%) |",
            "",
        ]
        if self.false_positives:
            lines.append("### Observed false positives")
            lines.append("")
            for item in self.false_positives:
                lines.append(f"- 🚨 {item}")
            lines.append("")
        if self.missed_positives:
            lines.append("### Uncovered positive fixtures (informational)")
            lines.append("")
            for item in self.missed_positives:
                lines.append(f"- ⚠️ {item}")
            lines.append("")
        lines.append(
            "> **Assessment.** We assess with high confidence that the committed analytics "
            "maintain a zero-false-positive posture against the benign telemetry corpus, the "
            "governing regression gate for any rule modification."
            if self.passed
            else "> **Assessment.** The false-positive gate is breached; the offending analytic "
            "must be retuned before merge."
        )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "sigma_rules": self.sigma_rules,
            "yara_rules": self.yara_rules,
            "negatives_checked": self.negatives_checked,
            "positives_checked": self.positives_checked,
            "positives_detected": self.positives_detected,
            "coverage_rate": round(self.coverage_rate, 4),
            "false_positives": self.false_positives,
            "missed_positives": self.missed_positives,
        }


class ZeroFalsePositiveGate:
    """Evaluates all production rules against the fixture corpus for the CI gate."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or ROOT
        self.rules_dir = self.repo_root / "rules"
        self.fixtures_dir = self.repo_root / "tests" / "fixtures"

    def run(self) -> GateReport:
        """Executes the full negative and positive corpus evaluation."""
        report = GateReport()
        self._evaluate_sigma(report)
        self._evaluate_yara(report)
        return report

    def _evaluate_sigma(self, report: GateReport) -> None:
        rule_files = sorted((self.rules_dir / "sigma").glob("*.yml"))
        detectors = [SigmaDetector(rule_path=rf) for rf in rule_files]
        report.sigma_rules = len(detectors)

        neg_dir = self.fixtures_dir / "sigma" / "negative"
        for fixture in sorted(neg_dir.glob("*.json")):
            event = json.loads(fixture.read_text(encoding="utf-8"))
            variant = self._as_variant(event)
            report.negatives_checked += 1
            for detector, rf in zip(detectors, rule_files):
                if detector.evaluate(variant).detected:
                    report.false_positives.append(f"{fixture.name} triggered {rf.name}")

        pos_dir = self.fixtures_dir / "sigma" / "positive"
        for fixture in sorted(pos_dir.glob("*.json")):
            event = json.loads(fixture.read_text(encoding="utf-8"))
            variant = self._as_variant(event)
            report.positives_checked += 1
            if any(det.evaluate(variant).detected for det in detectors):
                report.positives_detected += 1
            else:
                report.missed_positives.append(f"{fixture.name} (sigma)")

    def _evaluate_yara(self, report: GateReport) -> None:
        rule_files = sorted((self.rules_dir / "yara").glob("*.yar"))
        detectors = [YaraDetector(rule_path=rf) for rf in rule_files]
        report.yara_rules = len(detectors)

        neg_dir = self.fixtures_dir / "negative"
        for fixture in sorted(neg_dir.glob("*.svg")):
            payload = fixture.read_text(encoding="utf-8")
            variant = self._as_yara_variant(payload)
            report.negatives_checked += 1
            for detector, rf in zip(detectors, rule_files):
                if detector.evaluate(variant).detected:
                    report.false_positives.append(f"{fixture.name} triggered {rf.name}")

        pos_dir = self.fixtures_dir / "positive"
        for fixture in sorted(pos_dir.glob("*.svg")):
            payload = fixture.read_text(encoding="utf-8")
            variant = self._as_yara_variant(payload)
            report.positives_checked += 1
            if any(det.evaluate(variant).detected for det in detectors):
                report.positives_detected += 1
            else:
                report.missed_positives.append(f"{fixture.name} (yara)")

    @staticmethod
    def _as_variant(event: dict) -> Variant:
        return Variant(id="gate", target_type="sigma", axis="gate", mutation_name="gate",
                       description="gate fixture", payload=event, cycle=1)

    @staticmethod
    def _as_yara_variant(payload: str) -> Variant:
        return Variant(id="gate", target_type="yara", axis="gate", mutation_name="gate",
                       description="gate fixture", payload=payload, cycle=1)


def main(argv: List[str] | None = None) -> int:
    """CLI entry: prints the Markdown gate report and exits non-zero on any FP."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    gate = ZeroFalsePositiveGate()
    report = gate.run()
    print(report.to_markdown())

    summary_path = None
    import os

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
        with summary_path.open("a", encoding="utf-8") as handle:
            handle.write(report.to_markdown() + "\n")

    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
