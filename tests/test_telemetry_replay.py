"""Unit tests for Real-World Telemetry Replay & Kernel-Level Grounding."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.acquire_telemetry import compute_sha256, load_manifest, main as acquire_main
from tools.swarm.models import TelemetryEvent
from tools.swarm.telemetry_replay import (
    EvtxParser,
    JsonlParser,
    SlidingWindowEventStore,
    TelemetryNormalizer,
    TelemetryReplayEngine,
    wilson_score_interval,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "telemetry"
MANIFEST_PATH = ROOT / "tools" / "telemetry_manifest.json"


class WilsonScoreTests(unittest.TestCase):
    """Verifies Wilson score binomial confidence interval calculation."""

    def test_zero_total_returns_zeros(self):
        low, high = wilson_score_interval(0, 0)
        self.assertEqual(low, 0.0)
        self.assertEqual(high, 0.0)

    def test_zero_events_measured(self):
        low, high = wilson_score_interval(0, 100, confidence=0.95)
        self.assertEqual(low, 0.0)
        self.assertAlmostEqual(high, 0.0370, places=3)

    def test_symmetric_interval(self):
        low, high = wilson_score_interval(50, 100, confidence=0.95)
        self.assertAlmostEqual(low, 0.4038, places=3)
        self.assertAlmostEqual(high, 0.5961, places=3)

    def test_bounded_between_zero_and_one(self):
        low, high = wilson_score_interval(100, 100, confidence=0.95)
        self.assertAlmostEqual(low, 0.9630, places=3)
        self.assertEqual(high, 1.0)


class EvtxParserTests(unittest.TestCase):
    """Verifies binary Windows .evtx parsing using sample_sysmon_process_create.evtx."""

    def setUp(self):
        self.evtx_path = FIXTURES_DIR / "sample_sysmon_process_create.evtx"

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(EvtxParser.parse("nonexistent_path.evtx"))

    def test_parses_real_sysmon_evtx(self):
        records = list(EvtxParser.parse(self.evtx_path))
        self.assertEqual(len(records), 6)
        eids = [r.get("EventID") for r in records]
        self.assertEqual(eids, [1, 7, 7, 1, 11, 10])

        # Verify Record #4 comsvcs minidump command line
        rec4 = records[3]
        self.assertEqual(rec4.get("EventID"), 1)
        self.assertEqual(rec4.get("Channel"), "Microsoft-Windows-Sysmon/Operational")
        self.assertIn("comsvcs.dll", rec4.get("CommandLine", ""))
        self.assertIn("rundll32.exe", rec4.get("Image", ""))


class JsonlParserTests(unittest.TestCase):
    """Verifies JSONL and NDJSON streaming parser."""

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(JsonlParser.parse("missing.jsonl"))

    def test_parses_mordor_jsonl(self):
        records = list(JsonlParser.parse(FIXTURES_DIR / "mordor_lsass_dump.jsonl"))
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["EventID"], 10)
        self.assertEqual(records[1]["EventID"], 11)
        self.assertEqual(records[2]["EventID"], 1)

    def test_parses_json_array(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump([{"EventID": 1, "test": "a"}, {"EventID": 2, "test": "b"}], f)
            temp_path = Path(f.name)
        try:
            records = list(JsonlParser.parse(temp_path))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["test"], "a")
        finally:
            temp_path.unlink()

    def test_handles_empty_and_malformed_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write("\n\n{\"EventID\": 1}\nNOT_VALID_JSON\n{\"EventID\": 2}\n")
            temp_path = Path(f.name)
        try:
            records = list(JsonlParser.parse(temp_path))
            self.assertEqual(len(records), 2)
            self.assertEqual(records[1]["EventID"], 2)
        finally:
            temp_path.unlink()


class TelemetryNormalizerTests(unittest.TestCase):
    """Verifies field alias mapping, casing standardization, and timestamp extraction."""

    def test_normalizes_security_4688(self):
        raw = {
            "EventID": "4688",
            "Channel": "Security",
            "TimeCreated": "2026-09-04T12:00:00.000Z",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "ProcessCommandLine": "cmd.exe /c whoami",
            "SubjectUserName": "jsmith",
            "SubjectDomainName": "CORP",
            "Computer": "WKSTN-01",
        }
        evt = TelemetryNormalizer.normalize(raw)
        self.assertEqual(evt.event_id, 4688)
        self.assertEqual(evt.channel, "Security")
        self.assertEqual(evt.fields["Image"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(evt.fields["ParentImage"], "C:\\Windows\\explorer.exe")
        self.assertEqual(evt.fields["CommandLine"], "cmd.exe /c whoami")
        self.assertEqual(evt.fields["User"], "CORP\\jsmith")
        self.assertEqual(evt.fields["Computer"], "WKSTN-01")

    def test_normalizes_sysmon_guid_casing(self):
        raw = {
            "EventID": 10,
            "SourceProcessGUID": "{1111-2222}",
            "TargetProcessGUID": "{3333-4444}",
        }
        evt = TelemetryNormalizer.normalize(raw)
        self.assertIn("SourceProcessGuid", evt.fields)
        self.assertNotIn("SourceProcessGUID", evt.fields)
        self.assertEqual(evt.fields["SourceProcessGuid"], "{1111-2222}")

    def test_epoch_parsing_various_formats(self):
        raw1 = {"EventID": 1, "@timestamp": "2026-09-04T12:00:00.000Z"}
        evt1 = TelemetryNormalizer.normalize(raw1)
        self.assertGreater(evt1.epoch(), 1700000000)

        raw2 = {"EventID": 1, "UtcTime": "2026-09-04 12:00:00"}
        evt2 = TelemetryNormalizer.normalize(raw2)
        self.assertGreater(evt2.epoch(), 1700000000)


class SlidingWindowEventStoreTests(unittest.TestCase):
    """Verifies chronological ordering and host partitioning."""

    def test_ingest_and_sort(self):
        store = SlidingWindowEventStore()
        e1 = TelemetryEvent(1, "Sysmon", "2026-09-04 12:05:00", {"Computer": "HOST-A"})
        e2 = TelemetryEvent(1, "Sysmon", "2026-09-04 12:01:00", {"Computer": "HOST-B"})
        store.ingest(e1)
        store.ingest(e2)
        store.sort_by_time()
        self.assertEqual(store.events[0], e2)
        self.assertEqual(store.events[1], e1)

    def test_group_by_computer(self):
        store = SlidingWindowEventStore()
        store.ingest(TelemetryEvent(1, "Sysmon", "2026-09-04 12:00:00", {"Computer": "HOST-A"}))
        store.ingest(TelemetryEvent(1, "Sysmon", "2026-09-04 12:01:00", {"Computer": "HOST-B"}))
        store.ingest(TelemetryEvent(1, "Sysmon", "2026-09-04 12:02:00", {"Computer": "HOST-A"}))
        groups = store.get_groups(group_by="Computer")
        self.assertEqual(len(groups), 2)
        self.assertEqual(len(groups["HOST-A"].events), 2)
        self.assertEqual(len(groups["HOST-B"].events), 1)


class TelemetryReplayEngineTests(unittest.TestCase):
    """Verifies end-to-end replay across authentic Mordor, EVTX, and Benign datasets."""

    def setUp(self):
        self.engine = TelemetryReplayEngine()

    def test_replay_mordor_lsass_dump(self):
        report = self.engine.replay_file(FIXTURES_DIR / "mordor_lsass_dump.jsonl")
        self.assertEqual(report.total_events, 3)
        self.assertEqual(report.corpus_format, "jsonl")
        self.assertGreaterEqual(report.total_detections, 2)
        self.assertIn("LSASS Process Memory Dump via Rundll32 Comsvcs.dll", report.rule_hit_counts)
        self.assertIn("Correlated LSASS Memory Access and Dump File Creation", report.rule_hit_counts)
        self.assertEqual(len(report.correlation_detections), 1)
        corr = report.correlation_detections[0]
        self.assertAlmostEqual(corr["span_seconds"], 4.2, places=1)
        self.assertEqual(corr["selected_indices"], [0, 1])

    def test_replay_mordor_schtasks_persistence(self):
        report = self.engine.replay_file(FIXTURES_DIR / "mordor_schtasks_persistence.jsonl")
        self.assertEqual(report.total_events, 2)
        self.assertIn("Suspicious Scheduled Task Creation Spawning Shell or Script Engine", report.rule_hit_counts)
        self.assertEqual(report.rule_hit_counts["Suspicious Scheduled Task Creation Spawning Shell or Script Engine"], 1)

    def test_replay_sample_sysmon_process_create_evtx(self):
        report = self.engine.replay_file(FIXTURES_DIR / "sample_sysmon_process_create.evtx")
        self.assertEqual(report.total_events, 6)
        self.assertEqual(report.corpus_format, "evtx")
        self.assertIn("LSASS Process Memory Dump via Rundll32 Comsvcs.dll", report.rule_hit_counts)
        self.assertEqual(report.rule_hit_counts["LSASS Process Memory Dump via Rundll32 Comsvcs.dll"], 1)

    def test_replay_benign_workstation_zero_false_positives(self):
        report = self.engine.replay_file(FIXTURES_DIR / "benign_enterprise_workstation.jsonl", is_benign=True)
        self.assertEqual(report.total_events, 50)
        self.assertEqual(report.total_detections, 0)
        self.assertEqual(report.empirical_fp_rate, 0.0)
        self.assertEqual(report.wilson_ci_lower, 0.0)
        self.assertLess(report.wilson_ci_upper, 0.08)

    def test_corpus_path_is_repo_relative(self):
        """Committed replay reports must not embed the operator's absolute paths."""
        report = self.engine.replay_file(FIXTURES_DIR / "mordor_lsass_dump.jsonl")
        self.assertEqual(
            report.corpus_path, "tests/fixtures/telemetry/mordor_lsass_dump.jsonl"
        )
        self.assertNotIn(":", report.corpus_path)  # no Windows drive letter
        self.assertFalse(report.corpus_path.startswith("/"))

    def test_corpus_path_outside_repo_degrades_to_filename(self):
        """A corpus outside the repository must still not leak an absolute path."""
        with tempfile.TemporaryDirectory() as tmp:
            external = Path(tmp) / "external_corpus.jsonl"
            external.write_bytes(
                (FIXTURES_DIR / "mordor_lsass_dump.jsonl").read_bytes()
            )
            report = self.engine.replay_file(external)
            self.assertEqual(report.corpus_path, "external_corpus.jsonl")

    def test_report_serialization_and_markdown(self):
        report = self.engine.replay_file(FIXTURES_DIR / "mordor_lsass_dump.jsonl")
        d = report.to_dict()
        self.assertIn("total_events", d)
        self.assertIn("wilson_ci_lower", d)

        j = report.to_json()
        self.assertIn('"total_events": 3', j)

        md = report.to_markdown()
        self.assertIn("# TELEMETRY REPLAY & GROUNDING REPORT (ICD 203)", md)
        self.assertIn("LSASS Process Memory Dump via Rundll32 Comsvcs.dll", md)
        self.assertIn("Correlated LSASS Memory Access and Dump File Creation", md)
        self.assertIn("95% Wilson Binomial Confidence Interval", md)


class AcquireTelemetryCliTests(unittest.TestCase):
    """Verifies the acquire_telemetry CLI and manifest verification."""

    def setUp(self):
        self.manifest = load_manifest(MANIFEST_PATH)
        self.datasets = self.manifest["datasets"]

    def test_compute_sha256_matches_hashlib(self):
        """compute_sha256 must agree with hashlib over the exact bytes on disk."""
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "probe.bin"
            payload = b"threat-detection-lab telemetry digest probe\n"
            probe.write_bytes(payload)
            self.assertEqual(compute_sha256(probe), hashlib.sha256(payload).hexdigest())

    def test_compute_sha256_spans_multiple_read_chunks(self):
        """Digest must be correct for files larger than the 64 KiB read buffer."""
        with tempfile.TemporaryDirectory() as tmp:
            probe = Path(tmp) / "large.bin"
            payload = bytes(range(256)) * 1024  # 256 KiB, four read chunks
            probe.write_bytes(payload)
            self.assertEqual(compute_sha256(probe), hashlib.sha256(payload).hexdigest())

    def test_manifest_digests_match_fixtures_on_disk(self):
        """The manifest is the sole source of truth for fixture integrity."""
        for name, meta in self.datasets.items():
            with self.subTest(dataset=name):
                fixture = ROOT / meta["fixture_path"]
                self.assertTrue(fixture.exists(), f"{name}: fixture missing at {fixture}")
                self.assertEqual(compute_sha256(fixture), meta["sha256"])

    def test_text_fixtures_are_lf_normalised(self):
        """Guards the manifest against CRLF drift between Windows and Linux CI.

        Digests are computed over working-tree bytes. A CRLF checkout would
        change every digest, so text corpora must contain no carriage returns.
        `.gitattributes` enforces this; this test proves the enforcement holds.
        """
        for name, meta in self.datasets.items():
            path = ROOT / meta["fixture_path"]
            if path.suffix.lower() == ".evtx":
                continue  # native binary container; CR bytes are payload data
            with self.subTest(dataset=name):
                self.assertNotIn(
                    b"\r\n",
                    path.read_bytes(),
                    f"{name} contains CRLF; digests will diverge on Linux CI",
                )

    def test_acquire_main_verify_only(self):
        ret = acquire_main(["--verify-only", "--manifest", str(ROOT / "tools" / "telemetry_manifest.json")])
        self.assertEqual(ret, 0)

    def test_acquire_main_single_dataset(self):
        ret = acquire_main([
            "--verify-only",
            "--manifest", str(ROOT / "tools" / "telemetry_manifest.json"),
            "--dataset", "mordor_lsass_dump",
        ])
        self.assertEqual(ret, 0)

    def test_acquire_main_missing_manifest(self):
        ret = acquire_main(["--manifest", "nonexistent_manifest.json"])
        self.assertEqual(ret, 1)

    def test_acquire_main_unknown_dataset(self):
        ret = acquire_main([
            "--manifest", str(ROOT / "tools" / "telemetry_manifest.json"),
            "--dataset", "nonexistent_dataset_name",
        ])
        self.assertEqual(ret, 1)

    def test_verify_dataset_missing_file(self):
        from tools.acquire_telemetry import verify_dataset
        res = verify_dataset("test", {"fixture_path": "missing_file.jsonl", "sha256": "abc"}, ROOT)
        self.assertFalse(res)

    def test_verify_dataset_hash_mismatch(self):
        from tools.acquire_telemetry import verify_dataset
        res = verify_dataset(
            "mordor_lsass_dump",
            {"fixture_path": "tests/fixtures/telemetry/mordor_lsass_dump.jsonl", "sha256": "bad_hash"},
            ROOT,
        )
        self.assertFalse(res)

    def test_download_dataset_already_present(self):
        """A present, verified fixture short-circuits before any network call."""
        from tools.acquire_telemetry import download_dataset

        meta = self.datasets["mordor_lsass_dump"]
        self.assertTrue(download_dataset("mordor_lsass_dump", meta, ROOT, force=False))


if __name__ == "__main__":
    unittest.main()
