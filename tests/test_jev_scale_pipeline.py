"""Behavioral tests for the scale-battery pipeline.

Covers tools/jev_triage/{fetch_scale, build_corpus_scale, run_jev_scale, score_scale}
with tiny local fixtures and monkeypatched network calls. No API keys, no downloads;
everything writes under temp dirs.

Run with either:
  ./.venv/Scripts/python.exe -m unittest tests.test_jev_scale_pipeline
  ./.venv/Scripts/python.exe -m pytest tests/test_jev_scale_pipeline.py
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))

import build_corpus_scale  # noqa: E402
import fetch_scale  # noqa: E402
import run_jev_scale  # noqa: E402
import run_llm_scale  # noqa: E402
import score  # noqa: E402
import score_scale  # noqa: E402


def _patch_attrs(testcase, obj, **attrs):
    for name, value in attrs.items():
        testcase.addCleanup(setattr, obj, name, getattr(obj, name))
        setattr(obj, name, value)


def _raw_message(subject: str, body: str, sender: str = "author@example.test") -> bytes:
    return (f"From: {sender}\r\nSubject: {subject}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").encode("utf-8")


def _tar_bz2(members: list[tuple[bytes, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:bz2") as archive:
        for index, (raw, name) in enumerate(members):
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def _csv_text(rows: list[dict], columns=("sender", "subject", "body", "label")) -> bytes:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns))
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8")


def _fake_download(files: dict):
    """Return a fake fetch download() serving {target_name: bytes}."""
    def download(url, target: Path):
        data = files[target.name]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"sha256": fetch_scale.fpc.sha256_bytes(data), "bytes": len(data), "cached": False}
    return download


LONG_BODY = "This is a sufficiently long body for the exclusion rules to keep. " * 2


class TestCheckCommon(unittest.TestCase):
    def _record(self, **overrides):
        record = {"from": "a@b.example", "subject": "Hello there", "body": LONG_BODY}
        record.update(overrides)
        return record

    def test_valid_record_passes(self):
        self.assertIsNone(fetch_scale.check_common(self._record()))

    def test_artifact_subject_and_sender(self):
        self.assertEqual(fetch_scale.check_common(self._record(subject="DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA")),
                         "corpus-artifact")
        artifact_sender = self._record()
        artifact_sender["from"] = "Mail System <MAILER-DAEMON@monkey.org>"
        self.assertEqual(fetch_scale.check_common(artifact_sender), "corpus-artifact")

    def test_other_exclusions(self):
        self.assertEqual(fetch_scale.check_common(self._record(subject="   ")), "no-subject")
        self.assertEqual(fetch_scale.check_common(self._record(body="short")), "body-too-short")
        self.assertEqual(fetch_scale.check_common(self._record(body="d" * (101 * 1024))), "body-over-100KB")
        self.assertEqual(fetch_scale.check_common(self._record(body="\u4e2d\u6587" * 60)), "non-ascii-dominant")


class TestNormalizeCsvRow(unittest.TestCase):
    SOURCE = {"name": "nazario", "label": "attack", "label_basis": "test basis"}

    def test_mapping_and_hash(self):
        row = {"sender": "  bad@actor.example ", "subject": "Urgent", "body": f"  {LONG_BODY}  ",
               "label": "1"}
        record, reason = fetch_scale.normalize_csv_row(row, self.SOURCE, "file.csv")
        self.assertEqual(reason, "")
        self.assertEqual(record["from"], "bad@actor.example")
        self.assertEqual(record["body"], LONG_BODY.strip())
        self.assertEqual(record["reply_to"], "")
        expected = fetch_scale.fpc.sha256_bytes(("Urgent\n" + LONG_BODY.strip()).encode("utf-8"))
        self.assertEqual(record["content_sha256"], expected)

    def test_exclusion_reason_returned(self):
        row = {"sender": "x@y.example", "subject": "", "body": LONG_BODY, "label": "1"}
        record, reason = fetch_scale.normalize_csv_row(row, self.SOURCE, "file.csv")
        self.assertIsNone(record)
        self.assertEqual(reason, "no-subject")


class TestProcessSources(unittest.TestCase):
    def test_process_sa_source_pool_and_exclusions(self):
        tar_bytes = _tar_bz2([
            (_raw_message("Alpha", LONG_BODY), "easy_ham/0001"),
            (_raw_message("Alpha", LONG_BODY), "easy_ham/0002"),
            (_raw_message("Beta", LONG_BODY), "easy_ham/0003"),
            (_raw_message("", LONG_BODY), "easy_ham/0004"),
        ])
        source = {"name": "sa_test", "file": "t.tar.bz2", "label": "safe", "label_basis": "test"}
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, fetch_scale, DOWNLOADS=Path(td))
            with mock.patch.object(fetch_scale.fpc, "download", _fake_download({"t.tar.bz2": tar_bytes})):
                entry = fetch_scale.process_sa_source(source)
        self.assertEqual(entry["rows_total"], 4)
        self.assertEqual(entry["exclusions"], {"duplicate": 1, "no-subject": 1})
        self.assertEqual(len(entry["pool"]), 2)
        self.assertEqual(entry["pool"][0]["label"], "safe")

    def test_process_csv_source_selection_and_exclusions(self):
        rows = [
            {"sender": "a@x.example", "subject": "One", "body": LONG_BODY, "label": "1"},
            {"sender": "b@x.example", "subject": "Two", "body": LONG_BODY, "label": "0"},
            {"sender": "c@x.example", "subject": "Three", "body": LONG_BODY, "label": ""},
            {"sender": "d@x.example", "subject": "FOLDER INTERNAL DATA", "body": LONG_BODY, "label": "1"},
            {"sender": "a@x.example", "subject": "One", "body": LONG_BODY, "label": "1"},
        ]
        source = {"name": "csv_test", "file": "t.csv", "label": "attack",
                  "select_label": "1", "label_basis": "test"}
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, fetch_scale, DOWNLOADS=Path(td))
            with mock.patch.object(fetch_scale.fpc, "download", _fake_download({"t.csv": _csv_text(rows)})):
                entry = fetch_scale.process_csv_source(source)
        self.assertEqual(entry["rows_total"], 5)
        self.assertEqual(entry["out_of_scope"], 1)
        self.assertEqual(entry["exclusions"],
                         {"label-unparseable": 1, "corpus-artifact": 1, "duplicate": 1})
        self.assertEqual(len(entry["pool"]), 1)
        self.assertEqual(entry["columns"], ["sender", "subject", "body", "label"])

    def test_process_csv_source_missing_columns_raises(self):
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, fetch_scale, DOWNLOADS=Path(td))
            bad = b"alpha,beta\n1,2\n"
            with mock.patch.object(fetch_scale.fpc, "download", _fake_download({"t.csv": bad})):
                with self.assertRaises(RuntimeError):
                    fetch_scale.process_csv_source(
                        {"name": "x", "file": "t.csv", "label": "spam", "label_basis": "t"})


class TestApplyCaps(unittest.TestCase):
    def _row(self, label, tag):
        return {"label": label, "content_sha256": f"hash-{tag}"}

    def test_caps_truncate_deterministically(self):
        union = [self._row("safe", "a"), self._row("safe", "b"), self._row("safe", "c"),
                 self._row("attack", "d")]
        included, taken, dropped = fetch_scale.apply_caps(union, {"safe": 2, "attack": 10})
        self.assertEqual([r["content_sha256"] for r in included], ["hash-a", "hash-b", "hash-d"])
        self.assertEqual(taken, {"safe": 2, "attack": 1})
        self.assertEqual(dropped, {"safe": 1})

    def test_default_caps_do_not_truncate_tiny_input(self):
        union = [self._row("spam", "a")]
        included, taken, dropped = fetch_scale.apply_caps(union)
        self.assertEqual(len(included), 1)
        self.assertEqual(dropped, {})


class TestFetchScaleMain(unittest.TestCase):
    def test_main_end_to_end_with_fake_sources(self):
        tar_bytes = _tar_bz2([
            (_raw_message("Alpha", LONG_BODY), "easy_ham/0001"),
            (_raw_message("Gamma", LONG_BODY), "easy_ham/0002"),
        ])
        csv_bytes = _csv_text([
            {"sender": "phish@x.example", "subject": "Verify", "body": LONG_BODY, "label": "1"},
            {"sender": "ham@x.example", "subject": "Notice", "body": LONG_BODY, "label": "0"},
        ])
        with tempfile.TemporaryDirectory() as td:
            scale_dir = Path(td) / "scale"
            _patch_attrs(self, fetch_scale,
                         SCALE_DIR=scale_dir,
                         DOWNLOADS=scale_dir / "_downloads_scale",
                         NORMALIZED=scale_dir / "scale-normalized.jsonl",
                         LOCK=scale_dir / "scale-lock.json",
                         SA_SOURCES=[{"name": "sa_test", "file": "t.tar.bz2", "label": "safe",
                                      "label_basis": "test"}],
                         CSV_SOURCES=[{"name": "csv_test", "file": "t.csv", "label": "attack",
                                       "select_label": "1", "label_basis": "test"}])
            with mock.patch.object(fetch_scale.fpc, "download",
                                   _fake_download({"t.tar.bz2": tar_bytes, "t.csv": csv_bytes})):
                rc = fetch_scale.main()
            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in
                    fetch_scale.NORMALIZED.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([r["email_id"] for r in rows], ["scale-00001", "scale-00002", "scale-00003"])
            self.assertEqual([r["label"] for r in rows], ["safe", "safe", "attack"])
            lock = json.loads(fetch_scale.LOCK.read_text(encoding="utf-8"))
            self.assertEqual(lock["included_total"], 3)
            self.assertEqual(lock["class_counts_included"], {"safe": 2, "attack": 1})
            self.assertEqual(len(lock["sources"]), 2)
            self.assertEqual(lock["sources"][1]["out_of_scope"], 1)
            # a second run refuses while the lock exists
            self.assertEqual(fetch_scale.main(), 1)

    def test_apply_caps_with_small_caps_in_main(self):
        tar_bytes = _tar_bz2([
            (_raw_message("Alpha", LONG_BODY), "easy_ham/0001"),
            (_raw_message("Beta", LONG_BODY), "easy_ham/0002"),
            (_raw_message("Gamma", LONG_BODY), "easy_ham/0003"),
        ])
        with tempfile.TemporaryDirectory() as td:
            scale_dir = Path(td) / "scale"
            _patch_attrs(self, fetch_scale,
                         SCALE_DIR=scale_dir,
                         DOWNLOADS=scale_dir / "_downloads_scale",
                         NORMALIZED=scale_dir / "scale-normalized.jsonl",
                         LOCK=scale_dir / "scale-lock.json",
                         SA_SOURCES=[{"name": "sa_test", "file": "t.tar.bz2", "label": "safe",
                                      "label_basis": "test"}],
                         CSV_SOURCES=[],
                         CAPS={"safe": 2})
            with mock.patch.object(fetch_scale.fpc, "download", _fake_download({"t.tar.bz2": tar_bytes})):
                rc = fetch_scale.main()
            self.assertEqual(rc, 0)
            lock = json.loads(fetch_scale.LOCK.read_text(encoding="utf-8"))
            self.assertEqual(lock["class_counts_included"], {"safe": 2})
            self.assertEqual(lock["cap_dropped"], {"safe": 1})


class TestBuildCorpusScale(unittest.TestCase):
    def _record(self, email_id, label, from_value, subject, body, source="sa_test"):
        return {"email_id": email_id, "label": label, "from": from_value, "subject": subject,
                "body": body, "source": source,
                "content_sha256": f"hash-{email_id}"}

    def test_main_happy_path(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            normalized = base / "scale-normalized.jsonl"
            records = [
                self._record("scale-00002", "attack", "p@x.example", "Two", LONG_BODY),
                self._record("scale-00001", "safe", "a@x.example", "One", LONG_BODY),
                self._record("scale-00003", "spam", "", "Three", LONG_BODY, source="ling"),
            ]
            normalized.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            _patch_attrs(self, build_corpus_scale, NORMALIZED=normalized,
                         MERGED=base / "scale-corpus.jsonl", MANIFEST=base / "scale-manifest.json")
            rc = build_corpus_scale.main()
            self.assertEqual(rc, 0)
            merged = [json.loads(line) for line in
                      build_corpus_scale.MERGED.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([r["email_id"] for r in merged],
                             ["scale-00001", "scale-00002", "scale-00003"])
            manifest = json.loads(build_corpus_scale.MANIFEST.read_text(encoding="utf-8"))
            self.assertEqual(manifest["total"], 3)
            self.assertEqual(manifest["by_label"], {"attack": 1, "safe": 1, "spam": 1})
            self.assertEqual(manifest["empty_from_rows"], 1)
            self.assertEqual(manifest["empty_from_by_source"], {"ling": 1})

    def test_main_validation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            normalized = base / "scale-normalized.jsonl"
            records = [
                self._record("scale-00001", "safe", "a@x.example", "One", LONG_BODY),
                self._record("scale-00002", "bogus", "b@x.example", "Two", LONG_BODY),
                self._record("scale-00003", "spam", "", "Three", LONG_BODY, source="ling"),
            ]
            normalized.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            _patch_attrs(self, build_corpus_scale, NORMALIZED=normalized,
                         MERGED=base / "scale-corpus.jsonl", MANIFEST=base / "scale-manifest.json")
            self.assertEqual(build_corpus_scale.main(), 1)
            self.assertFalse(build_corpus_scale.MERGED.exists())

    def test_main_missing_input(self):
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, build_corpus_scale, NORMALIZED=Path(td) / "nope.jsonl",
                         MERGED=Path(td) / "out.jsonl", MANIFEST=Path(td) / "m.json")
            self.assertEqual(build_corpus_scale.main(), 1)


def _good_response(choice="safe", confidence=0.9):
    return {"model": "jev-1.13.0-test",
            "answers": {"disposition": {"choice": choice, "confidence": confidence},
                        "deception_present": {"noul": 0.1},
                        "requests_credentials_or_payment": {"noul": 0.05}},
            "usage": {"input_tokens": 700, "output_tokens": 12}}


class TestRunJevScale(unittest.TestCase):
    def _corpus(self, td, n=3):
        corpus = Path(td) / "scale-corpus.jsonl"
        rows = [{"email_id": f"scale-{i:05d}", "label": "safe", "from": "a@x.example",
                 "subject": f"S{i}", "body": LONG_BODY, "source": "sa_test"}
                for i in range(1, n + 1)]
        corpus.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return corpus

    def test_new_run_writes_meta_and_observations(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = self._corpus(td, 3)
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_jev_scale, CORPUS=corpus, RECORDS_DIR=records_dir)
            with mock.patch.object(run_jev_scale.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": (_good_response(), 0.012)):
                with mock.patch.object(sys, "argv", ["run_jev_scale.py"]):
                    rc = run_jev_scale.main()
            self.assertEqual(rc, 0)
            run_files = list(records_dir.glob("jev-scale-*.jsonl"))
            self.assertEqual(len(run_files), 1)
            lines = [json.loads(l) for l in run_files[0].read_text(encoding="utf-8").splitlines()]
            self.assertEqual(lines[0]["kind"], "run_meta")
            self.assertEqual(lines[0]["corpus_size"], 3)
            obs = [l for l in lines[1:] if l["kind"] == "observation"]
            self.assertEqual(len(obs), 3)
            self.assertEqual(obs[0]["label_pred"], "safe")
            self.assertEqual(obs[0]["confidence"], 0.9)
            self.assertEqual(obs[0]["input_tokens"], 700)
            self.assertIsNone(obs[0]["error"])

    def test_limit_and_resume_with_error_retry(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = self._corpus(td, 3)
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_jev_scale, CORPUS=corpus, RECORDS_DIR=records_dir)
            calls = {"n": 0}

            def flaky(state, questions, model="jev-latest"):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise RuntimeError("HTTP 503 upstream")
                return _good_response(), 0.01

            with mock.patch.object(run_jev_scale.clients, "jev_system_one", flaky):
                with mock.patch.object(sys, "argv", ["run_jev_scale.py"]):
                    self.assertEqual(run_jev_scale.main(), 0)
            run_file = next(records_dir.glob("jev-scale-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").splitlines()]
            obs = [l for l in lines if l.get("kind") == "observation"]
            self.assertEqual(len(obs), 3)
            self.assertEqual(sum(1 for l in obs if l["error"]), 1)
            # resume retries only the errored id
            with mock.patch.object(run_jev_scale.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": (_good_response(), 0.01)):
                with mock.patch.object(sys, "argv", ["run_jev_scale.py", "--resume"]):
                    self.assertEqual(run_jev_scale.main(), 0)
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").splitlines()]
            obs = [l for l in lines if l.get("kind") == "observation"]
            self.assertEqual(len(obs), 4)
            done = {l["email_id"] for l in obs if not l["error"]}
            self.assertEqual(len(done), 3)

    def test_resume_without_run_and_missing_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, run_jev_scale, CORPUS=self._corpus(td, 1), RECORDS_DIR=Path(td) / "records")
            with mock.patch.object(sys, "argv", ["run_jev_scale.py", "--resume"]):
                self.assertEqual(run_jev_scale.main(), 1)
            _patch_attrs(self, run_jev_scale, CORPUS=Path(td) / "missing.jsonl")
            with mock.patch.object(sys, "argv", ["run_jev_scale.py"]):
                self.assertEqual(run_jev_scale.main(), 1)

    def test_limit(self):
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, run_jev_scale, CORPUS=self._corpus(td, 3), RECORDS_DIR=Path(td) / "records")
            with mock.patch.object(run_jev_scale.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": (_good_response(), 0.01)):
                with mock.patch.object(sys, "argv", ["run_jev_scale.py", "--limit", "1"]):
                    self.assertEqual(run_jev_scale.main(), 0)
            run_file = next((Path(td) / "records").glob("jev-scale-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(lines[0]["corpus_size"], 1)


def _obs(email_id, true, pred, confidence=None, latency=120, source="sa_test", error=None):
    return {"kind": "observation", "run_id": "t", "email_id": email_id, "label_true": true,
            "label_pred": pred, "confidence": confidence, "latency_ms": latency,
            "input_tokens": 700, "output_tokens": 12, "error": error, "source": source,
            "ts_utc": "2026-09-17T14:00:00+00:00"}


class TestCriteria(unittest.TestCase):
    def _run(self, rows):
        return {"meta": {"run_id": "jev-scale-test", "model_requested": "jev-latest",
                         "provider": "typesafe", "corpus_size": len(rows)},
                "path": Path("jev-scale-test.jsonl"), "observations": rows}

    def _evaluate(self, rows):
        run = self._run(rows)
        summary = score.summarize_run(run)
        sweep = score.sweep_thresholds(run, None)
        return {c["id"]: c for c in score_scale.criteria(run, summary, sweep)}

    def test_all_pass_boundary_case(self):
        rows = [_obs(f"scale-{i:05d}", "attack", "attack", confidence=0.9) for i in range(1, 10)]
        rows.append(_obs("scale-00010", "attack", "gray", confidence=0.2))
        rows.append(_obs("scale-00011", "safe", "safe", confidence=0.9))
        # recall exactly 9/10 = 0.90 -> C1 PASS at the boundary
        crit = self._evaluate(rows)
        self.assertEqual(crit["C1"]["result"], "PASS")
        self.assertEqual(crit["C2"]["result"], "PASS")
        self.assertEqual(crit["C6"]["result"], "PASS")   # every miss at 0.2 < 0.5
        self.assertEqual(crit["C4"]["result"], "PASS")
        self.assertEqual(crit["C5"]["result"], "PASS")

    def test_c2_and_c6_misses_are_surfaced(self):
        rows = [_obs("scale-00001", "attack", "safe", confidence=0.60),   # auto-delivered!
                _obs("scale-00002", "safe", "safe", confidence=0.90)]
        crit = self._evaluate(rows)
        self.assertEqual(crit["C2"]["result"], "MISS")
        self.assertEqual(crit["C2"]["actual"], 1)
        self.assertEqual(crit["C6"]["result"], "MISS")   # miss confidence 0.60 >= 0.50
        self.assertEqual(crit["C1"]["result"], "MISS")   # recall 0.0

    def test_c6_vacuous_when_no_misses(self):
        rows = [_obs("scale-00001", "attack", "attack", confidence=0.9),
                _obs("scale-00002", "safe", "safe", confidence=0.9)]
        crit = self._evaluate(rows)
        self.assertEqual(crit["C6"]["result"], "PASS")
        self.assertEqual(crit["C6"]["actual"]["miss_count"], 0)

    def test_c3_auto_coverage_gate(self):
        rows = [_obs("scale-00001", "safe", "safe", confidence=0.50),
                _obs("scale-00002", "attack", "attack", confidence=0.50),
                _obs("scale-00003", "gray", "gray", confidence=0.99),  # gray never auto-decides
                _obs("scale-00004", "spam", "spam", confidence=0.99)]
        crit = self._evaluate(rows)
        self.assertEqual(crit["C3"]["result"], "PASS")   # 2/4 = 50% auto, 0% error


class TestScoreScaleMain(unittest.TestCase):
    def _write_records(self, base: Path):
        records_dir = base / "records" / "scale"
        records_dir.mkdir(parents=True)
        rows = [
            _obs("scale-00001", "attack", "attack", confidence=0.9),
            _obs("scale-00002", "safe", "safe", confidence=0.9),
            _obs("scale-00003", "spam", "spam", confidence=0.4),
            _obs("scale-00004", "attack", "gray", confidence=0.2),
        ]
        meta = {"kind": "run_meta", "run_id": "jev-scale-20260917T000000Z",
                "model_requested": "jev-latest", "provider": "typesafe", "corpus_size": 4,
                "corpus": "corpus/email/scale/scale-corpus.jsonl", "corpus_sha256": "abc123",
                "ts_utc": "2026-09-17T00:00:00+00:00"}
        run_file = records_dir / "jev-scale-20260917T000000Z.jsonl"
        run_file.write_text("\n".join([json.dumps(meta)] + [json.dumps(r) for r in rows]) + "\n",
                            encoding="utf-8")
        return records_dir, run_file

    def test_main_renders_results_with_deviations(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            records_dir, _ = self._write_records(base)
            deviations = base / "scale-deviations.json"
            deviations.write_text(json.dumps(["test deviation item"]), encoding="utf-8")
            _patch_attrs(self, score_scale,
                         RECORDS_DIR=records_dir,
                         OUT_DIR=base / "out",
                         SCALE_MANIFEST=base / "missing-manifest.json",
                         DEVIATIONS=deviations)
            rc = score_scale.main()
            self.assertEqual(rc, 0)
            results = json.loads((score_scale.OUT_DIR / "results-scale.json").read_text(encoding="utf-8"))
            self.assertEqual(len(results["criteria"]), 6)
            self.assertEqual(results["reconciliation"][0]["ok"], True)
            self.assertEqual(results["attack_misses"][0]["email_id"], "scale-00004")
            self.assertEqual(results["deviations"], ["test deviation item"])
            report = (score_scale.OUT_DIR / "RESULTS-SCALE.md").read_text(encoding="utf-8")
            self.assertIn("## Registered criteria (A7)", report)
            self.assertIn("test deviation item", report)
            self.assertIn("## Provenance", report)

    def test_main_without_runs_or_jev_run(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _patch_attrs(self, score_scale, RECORDS_DIR=base / "empty", OUT_DIR=base / "out",
                         SCALE_MANIFEST=base / "m.json", DEVIATIONS=base / "d.json")
            self.assertEqual(score_scale.main(), 1)
            # records exist but none from typesafe -> "no Jev scale run"
            records_dir = base / "other"
            records_dir.mkdir(parents=True)
            rows = [{"kind": "run_meta", "run_id": "x", "model_requested": "deepseek-flash",
                     "provider": "deepseek", "corpus_size": 1},
                    _obs("scale-00001", "safe", "safe", confidence=0.9)]
            (records_dir / "jev-scale-other.jsonl").write_text(
                "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            _patch_attrs(self, score_scale, RECORDS_DIR=records_dir)
            self.assertEqual(score_scale.main(), 1)


class TestRunLlmScaleSubset(unittest.TestCase):
    def _row(self, label, tag):
        return {"email_id": f"scale-{tag:05d}", "label": label,
                "content_sha256": f"hash-{tag}", "from": "a@x.example",
                "subject": f"S{tag}", "body": LONG_BODY, "source": "sa_test"}

    def test_proportional_allocation_and_hash_order(self):
        records = ([self._row("attack", i) for i in range(1, 11)] +
                   [self._row("safe", i) for i in range(11, 16)])
        subset = run_llm_scale.select_subset(records, size=6)
        labels = [r["label"] for r in subset]
        self.assertEqual(labels.count("attack"), 4)   # round(6 x 10/15)
        self.assertEqual(labels.count("safe"), 2)     # round(6 x 5/15)
        attack_hashes = sorted(r["content_sha256"] for r in subset if r["label"] == "attack")
        expected = sorted(f"hash-{i}" for i in range(1, 11))[:4]
        self.assertEqual(attack_hashes, expected)
        ids = [r["email_id"] for r in subset]
        self.assertEqual(ids, sorted(ids))

    def test_rounding_drift_adjusts_deterministically(self):
        records = [self._row("attack", 1), self._row("safe", 2), self._row("spam", 3)]
        subset = run_llm_scale.select_subset(records, size=2)   # round() sums to 3 -> drift -1
        self.assertEqual(len(subset), 2)
        labels = sorted(r["label"] for r in subset)
        self.assertEqual(labels, ["attack", "safe"])   # largest-tie adjustment (lexicographic) trims spam

    def test_empty_input(self):
        self.assertEqual(run_llm_scale.select_subset([], size=10), [])

    def test_main_writes_subset_records(self):
        with tempfile.TemporaryDirectory() as td:
            corpus = Path(td) / "scale-corpus.jsonl"
            records = [self._row("attack", i) for i in range(1, 4)] + [self._row("safe", i) for i in range(4, 6)]
            corpus.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_llm_scale, CORPUS=corpus, RECORDS_DIR=records_dir)

            def fake_deepseek(model, messages, *, max_tokens=64, temperature=0.0, **kwargs):
                reply = '{"label": "attack", "confidence": 0.8}'
                return ({"choices": [{"message": {"content": reply}}],
                         "usage": {"prompt_tokens": 900, "completion_tokens": 20}}, 0.9)

            with mock.patch.object(run_llm_scale.clients, "deepseek_chat", fake_deepseek):
                with mock.patch.object(sys, "argv", ["run_llm_scale.py"]):
                    self.assertEqual(run_llm_scale.main(), 0)
            run_file = next(records_dir.glob("deepseek-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(lines[0]["kind"], "run_meta")
            self.assertEqual(lines[0]["subset_allocations"], {"attack": 3, "safe": 2})
            obs = [l for l in lines if l.get("kind") == "observation"]
            self.assertEqual(len(obs), 5)   # requested 2000 clamps to available rows
            self.assertEqual(obs[0]["label_pred"], "attack")
            # resume without a run dir refuses
            _patch_attrs(self, run_llm_scale, RECORDS_DIR=Path(td) / "empty")
            with mock.patch.object(sys, "argv", ["run_llm_scale.py", "--resume"]):
                self.assertEqual(run_llm_scale.main(), 1)


class TestLoadDeviations(unittest.TestCase):
    def test_missing_file_is_empty_and_list_roundtrips(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "none.json"
            _patch_attrs(self, score_scale, DEVIATIONS=missing)
            self.assertEqual(score_scale.load_deviations(), [])
            present = Path(td) / "dev.json"
            present.write_text(json.dumps(["one", "two"]), encoding="utf-8")
            _patch_attrs(self, score_scale, DEVIATIONS=present)
            self.assertEqual(score_scale.load_deviations(), ["one", "two"])


if __name__ == "__main__":
    unittest.main()
