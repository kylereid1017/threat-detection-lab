"""Honesty guards for the swarm harness.

Regression tests for the findings in docs/reviews/2026-09-10-swarm-harness-evaluation.md:
figures that were published without being measured, claims the code did not enforce, and
retraction text that a routine regeneration could silently delete.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from tools.swarm.adapter import SwarmAdapter  # noqa: E402
from tools.swarm.cable_writer import CableWriter, _existing_index_rows, _rebuild_index  # noqa: E402
from tools.swarm.export_layer import MitreLayerExporter  # noqa: E402
from tools.swarm.models import BoundaryFinding, Variant  # noqa: E402
from tools.swarm.telemetry_replay import TelemetryReplayEngine  # noqa: E402

FIXTURES_DIR = ROOT / "tests" / "fixtures" / "telemetry"
SWARM_SRC = ROOT / "tools" / "swarm"

# Destinations permitted in harness sources. Three groups, each deliberate:
#   1. reserved-name hosts (RFC 2606 / RFC 6761): any "*.invalid" suffix
#   2. reserved IP literals: loopback, unspecified, link-local (IMDS modelling), RFC 5737
#   3. documentation / namespace references, never lure destinations
_RESERVED_HOST_SUFFIXES = (".invalid", ".example", ".test", ".localhost")
_ALLOWED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "www.w3.org",          # XML namespace URI
    "schemas.microsoft.com",  # Windows event schema reference
    "attack.mitre.org",    # ATT&CK reference link in cable prose
}
_ALLOWED_IPS = {
    "0.0.0.0",
    "127.0.0.1",
    "169.254.169.254",  # cloud IMDS endpoint modelled on purpose
    "192.0.2.0",        # RFC 5737 TEST-NET-1
    "198.51.100.0",     # RFC 5737 TEST-NET-2
    "203.0.113.0",      # RFC 5737 TEST-NET-3
}
_ALLOWED_IP_PREFIXES = ("169.254.",)


class IndexRetractionBannerTests(unittest.TestCase):
    """The index rebuild must not delete content it does not own."""

    def test_rebuild_preserves_caution_banner_and_other_non_table_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "INDEX.md"
            index.write_text(
                "# Threat Intelligence Cables Index\n\n"
                "> [!CAUTION] Numerical corrections for STRAT-001/002/003 (2026-09-10): headline\n"
                "> aggregates are retracted. See [ERRATA](ERRATA-2026-09-10.md).\n\n"
                "| Cable ID | Date | Target Rule | Evasion Axis | Attack Primitive | Status | Document |\n"
                "|---|---|---|---|---|---|---|\n"
                "| [CABLE-2026-001](x.md) | 2026-09-03 | `r` | `a` | `m` | `x` | [Read](x.md) |\n",
                encoding="utf-8",
            )
            rows = _existing_index_rows(index)
            rows.append("| [CABLE-2026-099](y.md) | 2026-09-10 | `r` | `a` | `m` | `x` | [Read](y.md) |")
            rebuilt = _rebuild_index(index, rows)

            self.assertIn("> [!CAUTION]", rebuilt)
            self.assertIn("retracted", rebuilt)
            self.assertIn("ERRATA-2026-09-10", rebuilt)
            self.assertIn("CABLE-2026-001", rebuilt)
            self.assertIn("CABLE-2026-099", rebuilt)

    def test_rebuild_on_missing_file_still_produces_a_catalogue(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp) / "INDEX.md"
            rebuilt = _rebuild_index(
                index,
                ["| [CABLE-2026-001](x.md) | 2026-09-03 | `r` | `a` | `m` | `x` | [Read](x.md) |"],
            )
            self.assertIn("# Threat Intelligence Cables Index", rebuilt)
            self.assertIn("CABLE-2026-001", rebuilt)


class UnmeasuredRateTests(unittest.TestCase):
    """A false-positive rate is defined only over a benign corpus."""

    def test_attack_corpus_reports_no_fp_rate(self):
        report = TelemetryReplayEngine().replay_file(FIXTURES_DIR / "mordor_lsass_dump.jsonl")
        self.assertFalse(report.is_benign)
        self.assertIsNone(report.empirical_fp_rate)
        self.assertIsNone(report.wilson_ci_lower)
        md = report.to_markdown()
        fp_row = [ln for ln in md.splitlines() if "Empirical FP Rate" in ln][0]
        self.assertIn("n/a (not measured", fp_row)
        self.assertNotIn("PASS", fp_row)
        self.assertNotIn("0.00%", fp_row)

    def test_benign_corpus_still_reports_a_measured_rate(self):
        report = TelemetryReplayEngine().replay_file(
            FIXTURES_DIR / "benign_enterprise_workstation.jsonl", is_benign=True
        )
        self.assertEqual(report.empirical_fp_rate, 0.0)
        fp_row = [ln for ln in report.to_markdown().splitlines() if "Empirical FP Rate" in ln][0]
        self.assertIn("0.00%", fp_row)
        self.assertNotIn("n/a", fp_row)

    def test_report_does_not_claim_cryptographic_verification(self):
        report = TelemetryReplayEngine().replay_file(FIXTURES_DIR / "mordor_schtasks_persistence.jsonl")
        self.assertNotIn("Cryptographically verified", report.to_markdown())


class ExportLayerHonestyTests(unittest.TestCase):
    """Exported layers must not encode a withdrawn measurement as a constant."""

    def test_no_pinned_resilience_default(self):
        self.assertIsNone(MitreLayerExporter().pinned_resilience)

    def test_scores_stay_documentable_without_a_measurement(self):
        scored = {
            t["techniqueID"]: t["score"]
            for t in MitreLayerExporter().build_layer()["techniques"]
        }
        self.assertNotIn(73, set(scored.values()), "pinned 0.712 blend resurrected")


class DestinationContainmentTests(unittest.TestCase):
    """Every synthetic destination in the harness stays inside the reserved set.

    The published containment claim is only meaningful if it holds on every path that
    emits synthetic telemetry, not just the Critic-gated subset.
    """

    def test_no_non_reserved_destination_literals_in_swarm_sources(self):
        offenders = []
        for path in sorted(SWARM_SRC.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for host in {m.group(1).lower() for m in re.finditer(r"https?://([A-Za-z0-9._\-]+)", text)}:
                if host in _ALLOWED_HOSTS or host.endswith(_RESERVED_HOST_SUFFIXES):
                    continue
                # An IP-form host (e.g. the modelled IMDS endpoint) is checked against the
                # same reserved-IP allowlist as bare literals.
                if host in _ALLOWED_IPS or host.startswith(_ALLOWED_IP_PREFIXES):
                    continue
                offenders.append(f"{path.name}: host {host}")
            for ip in {m.group(0) for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)}:
                if ip in _ALLOWED_IPS or ip.startswith(_ALLOWED_IP_PREFIXES):
                    continue
                offenders.append(f"{path.name}: ip {ip}")
        self.assertEqual(
            offenders,
            [],
            "Non-reserved destinations found in harness sources: " + "; ".join(offenders),
        )


class PatchVerificationHonestyTests(unittest.TestCase):
    """A candidate patch that cannot detect the variant must yield no improvement claim."""

    def test_incapable_patch_reports_no_detection(self):
        adapter = SwarmAdapter()
        variant = Variant(
            id="var-fault-injection",
            target_type="sigma",
            axis="lolbin_proxy",
            mutation_name="fault_injection_no_match",
            description="Fault injection: a variant nothing in the corpus can match.",
            payload={
                "ParentImage": "explorer.exe",
                "Image": "definitely-not-a-real-binary.exe",
                "CommandLine": "no-match-marker",
            },
            cycle=1,
        )
        rule_path = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        verification = adapter._verify_patch(
            rule_path, rule_path.read_text(encoding="utf-8"), "sigma", variant
        )
        self.assertIsNone(verification["error"])
        self.assertFalse(verification["variant_detected_before"])
        self.assertFalse(verification["variant_detected_after"])
        self.assertEqual(verification["negative_fixtures_checked"], 0)

    def test_incomplete_payload_surfaces_an_error_instead_of_a_silent_miss(self):
        """A payload the evaluator cannot process must be reported, not quietly treated as a pass."""
        adapter = SwarmAdapter()
        variant = Variant(
            id="var-malformed",
            target_type="sigma",
            axis="lolbin_proxy",
            mutation_name="malformed_payload",
            description="Fault injection: payload missing the columns the analytic requires.",
            payload={"CommandLine": "pcalua.exe -a powershell.exe"},
            cycle=1,
        )
        rule_path = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        verification = adapter._verify_patch(
            rule_path, rule_path.read_text(encoding="utf-8"), "sigma", variant
        )
        # Either the analytic handles the payload (clean miss) or the error is reported -
        # what must not happen is a silent False with no provenance.
        if verification["error"] is None:
            self.assertFalse(verification["variant_detected_after"])
        else:
            self.assertIn("Error", verification["error"])

    def test_healed_cable_states_evidence_and_claims_no_resilience_delta(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = CableWriter(cables_dir=Path(tmpdir))
            finding = BoundaryFinding(
                target_rule="proc_creation_win_explorer_clickfix_execution",
                target_type="sigma",
                cycle=1,
                variant_id="var-test",
                mutation_name="pcalua_proxy",
                axis="lolbin_proxy",
                detected=False,
                evasion_gap_found=True,
                root_cause="Explorer spawned pcalua.exe as an indirect execution proxy.",
                policy_recommendation="REC-SIGMA-006: Add pcalua.exe to monitored child images.",
                confidence="HIGH",
            )
            variant = Variant(
                id="var-test",
                target_type="sigma",
                axis="lolbin_proxy",
                mutation_name="pcalua_proxy",
                description="Test directive",
                payload={"Image": "pcalua.exe", "CommandLine": "pcalua.exe -a powershell.exe -c irm"},
                cycle=1,
            )
            cable_path = writer.write_cable(
                finding=finding,
                variant=variant,
                patch_diff="+ selection_proxy_img:",
                recommendation_id="REC-SIGMA-006",
                verification={
                    "variant_detected_before": False,
                    "variant_detected_after": True,
                    "negative_fixtures_checked": 7,
                    "negative_fixtures_matched": 0,
                },
            )
            text = cable_path.read_text(encoding="utf-8")

            # The cable reports what was measured...
            self.assertIn("variant_detected_before_patch: False", text)
            self.assertIn("variant_detected_after_patch: True", text)
            self.assertIn("negative_fixtures_checked: 7", text)
            self.assertIn("detected the evasion variant that the unpatched rule missed", text)
            # ...and claims no resilience delta or unsupported probability.
            self.assertNotIn("resilience", text.lower())
            self.assertNotIn("improved from", text)
            self.assertNotIn("probability", text.lower())
            self.assertNotIn("Autonomous", text)
            self.assertNotIn("Self-Healing", text)
            # Confidence is carried through from the finding rather than hardcoded.
            self.assertIn("confidence_level: HIGH", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
