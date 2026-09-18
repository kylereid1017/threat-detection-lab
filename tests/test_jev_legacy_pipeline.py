"""Behavioral tests for the original Jev pipeline modules (fetch/run) that the
scale-battery modules import and reuse: fetch_public_corpus, run_jev, run_llm.

Importing these modules via the scale tests measures them for coverage; these tests
exercise their own logic (normalization, mains, parsing) with local fixtures and
monkeypatched network calls. No API keys, no downloads.

Run:
  ./.venv/Scripts/python.exe -m unittest tests.test_jev_legacy_pipeline
"""

from __future__ import annotations

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

import fetch_public_corpus as fpc  # noqa: E402
import run_jev  # noqa: E402
import run_llm  # noqa: E402

LONG_BODY = "A long enough body to satisfy the minimum body length rule. " * 2


def _raw_message(subject: str, body: str) -> bytes:
    return (f"From: author@example.test\r\nSubject: {subject}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").encode("utf-8")


def _html_message(subject: str) -> bytes:
    return (f"From: author@example.test\r\nSubject: {subject}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            f"<html><body><p>{LONG_BODY}</p></body></html>\r\n").encode("utf-8")


def _binary_message(subject: str) -> bytes:
    return (f"From: author@example.test\r\nSubject: {subject}\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgc=\r\n").encode("utf-8")


def _tar_bz2(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:bz2") as archive:
        for name, raw in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def _patch_attrs(testcase, obj, **attrs):
    for name, value in attrs.items():
        testcase.addCleanup(setattr, obj, name, getattr(obj, name))
        setattr(obj, name, value)


def _fake_download(files):
    def download(url, target: Path):
        data = files[target.name]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"sha256": fpc.sha256_bytes(data), "bytes": len(data), "cached": False}
    return download


class TestFetchPublicCorpus(unittest.TestCase):
    SOURCE = {"name": "sa_test", "label": "safe", "label_basis": "test"}

    def test_normalize_plain_html_and_binary(self):
        record, reason = fpc.normalize(_raw_message("Hello", LONG_BODY), self.SOURCE, "0001")
        self.assertEqual(reason, "")
        self.assertEqual(record["body_source"], "text/plain")
        expected = fpc.sha256_bytes(("Hello\n" + LONG_BODY.strip()).encode("utf-8"))
        self.assertEqual(record["content_sha256"], expected)

        record, reason = fpc.normalize(_html_message("Promo"), self.SOURCE, "0002")
        self.assertEqual(reason, "")
        self.assertEqual(record["body_source"], "html-stripped")
        self.assertNotIn("<p>", record["body"])

        record, reason = fpc.normalize(_binary_message("Attach"), self.SOURCE, "0003")
        self.assertIsNone(record)
        self.assertEqual(reason, "no-text-body")

    def test_normalize_subject_requirement_and_decode_header(self):
        raw = b"From: a@b.test\r\nSubject:\r\nContent-Type: text/plain\r\n\r\n" + LONG_BODY.encode()
        record, reason = fpc.normalize(raw, self.SOURCE, "0004")
        self.assertIsNone(record)
        self.assertEqual(reason, "no-subject")
        self.assertEqual(fpc.decode_header_value(None), "")
        self.assertEqual(fpc.decode_header_value("=?utf-8?b?SGVsbG8=?="), "Hello")

    def test_main_with_fake_source(self):
        tar_bytes = _tar_bz2([("easy_ham/0001", _raw_message("One", LONG_BODY)),
                              ("easy_ham/0002", _raw_message("Two", LONG_BODY))])
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            _patch_attrs(self, fpc,
                         CORPUS_DIR=base,
                         DOWNLOADS=base / "_downloads",
                         NORMALIZED=base / "normalized_public.jsonl",
                         LOCK=base / "email-corpus-lock.json",
                         SOURCES=[{"name": "sa_test", "url": "https://x.test/t.tar.bz2",
                                   "label": "safe", "label_basis": "test"}],
                         SAMPLE_PER_SOURCE=5)
            with mock.patch.object(fpc, "download", _fake_download({"t.tar.bz2": tar_bytes})):
                self.assertEqual(fpc.main(), 0)
            rows = [json.loads(l) for l in
                    fpc.NORMALIZED.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["email_id"], "pub-001")
            lock = json.loads(fpc.LOCK.read_text(encoding="utf-8"))
            self.assertEqual(lock["included_total"], 2)
            self.assertEqual(lock["sources"][0]["pool_size"], 2)
            self.assertEqual(fpc.main(), 1)  # lock guard


class TestRunJev(unittest.TestCase):
    def _corpus(self, td):
        corpus = Path(td) / "corpus.jsonl"
        rows = [{"email_id": f"pub-{i:03d}", "label": "safe", "from": "a@x.example",
                 "reply_to": "", "subject": f"S{i}", "body": LONG_BODY}
                for i in range(1, 4)]
        corpus.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return corpus

    def _response(self):
        return ({"model": "jev-1.13.0-test",
                 "answers": {"disposition": {"choice": "safe", "confidence": 0.9}},
                 "usage": {"input_tokens": 700, "output_tokens": 8}}, 0.02)

    def test_main_and_resume(self):
        with tempfile.TemporaryDirectory() as td:
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_jev, CORPUS=self._corpus(td), RECORDS_DIR=records_dir)
            with mock.patch.object(run_jev.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": self._response()):
                with mock.patch.object(sys, "argv", ["run_jev.py"]):
                    self.assertEqual(run_jev.main(), 0)
            run_file = next(records_dir.glob("jev-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(lines[0]["kind"], "run_meta")
            self.assertEqual(len([l for l in lines if l.get("kind") == "observation"]), 3)
            with mock.patch.object(run_jev.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": self._response()):
                with mock.patch.object(sys, "argv", ["run_jev.py", "--resume"]):
                    self.assertEqual(run_jev.main(), 0)

    def test_error_row_and_resume_without_run(self):
        with tempfile.TemporaryDirectory() as td:
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_jev, CORPUS=self._corpus(td), RECORDS_DIR=records_dir)

            def boom(state, questions, model="jev-latest"):
                raise RuntimeError("HTTP 500")

            with mock.patch.object(run_jev.clients, "jev_system_one", boom):
                with mock.patch.object(sys, "argv", ["run_jev.py"]):
                    self.assertEqual(run_jev.main(), 0)
            run_file = next(records_dir.glob("jev-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(sum(1 for l in lines if l.get("error")), 3)
            _patch_attrs(self, run_jev, RECORDS_DIR=Path(td) / "none")
            with mock.patch.object(sys, "argv", ["run_jev.py", "--resume"]):
                self.assertEqual(run_jev.main(), 1)

    def test_limit(self):
        with tempfile.TemporaryDirectory() as td:
            _patch_attrs(self, run_jev, CORPUS=self._corpus(td), RECORDS_DIR=Path(td) / "records")
            with mock.patch.object(run_jev.clients, "jev_system_one",
                                   lambda state, questions, model="jev-latest": self._response()):
                with mock.patch.object(sys, "argv", ["run_jev.py", "--limit", "2"]):
                    self.assertEqual(run_jev.main(), 0)
            run_file = next((Path(td) / "records").glob("jev-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(lines[0]["corpus_size"], 2)


class TestRunLlm(unittest.TestCase):
    def test_parse_reply_variants(self):
        label, confidence, error = run_llm.parse_reply('{"label": "attack", "confidence": 0.9}')
        self.assertEqual((label, confidence, error), ("attack", 0.9, ""))
        label, confidence, error = run_llm.parse_reply('Sure: {"label": "spam", "confidence": 2} done')
        self.assertEqual(label, "spam")
        self.assertEqual(confidence, 1.0)  # clamped
        self.assertEqual(run_llm.parse_reply("no json here")[0], None)
        self.assertTrue(run_llm.parse_reply("no json here")[2].startswith("no-json"))
        self.assertTrue(run_llm.parse_reply("{not valid json}")[2].startswith("bad-json"))
        self.assertTrue(run_llm.parse_reply('{"label": "wat", "confidence": 1}')[2].startswith("bad-label"))

    def test_call_provider_and_extract_branches(self):
        with mock.patch.object(run_llm.clients, "anthropic_messages",
                               lambda *a, **k: ({"content": [{"type": "text", "text": "x"}],
                                                "usage": {"input_tokens": 5, "output_tokens": 1}}, 0.1)):
            response, _ = run_llm.call_provider("anthropic", "claude-haiku-4-5", "state", 16)
        self.assertEqual(run_llm.extract("anthropic", response)[0], "x")
        with mock.patch.object(run_llm.clients, "portal_chat",
                               lambda *a, **k: ({"choices": [{"message": {"content": '{"label": "safe"}'}}],
                                                "usage": {}}, 0.1)):
            response, _ = run_llm.call_provider("portal", "anthropic/claude-haiku-4.5", "state", 16)
        self.assertEqual(run_llm.extract("portal", response)[0], '{"label": "safe"}')
        with self.assertRaises(RuntimeError):
            run_llm.call_provider("nope", "m", "state", 16)
        with self.assertRaises(RuntimeError):
            run_llm.extract(
                "deepseek",
                {"choices": [{"message": {"content": "", "reasoning": "hmm"},
                              "finish_reason": "length"}], "usage": {}})

    def _corpus(self, td):
        corpus = Path(td) / "corpus.jsonl"
        rows = [{"email_id": f"pub-{i:03d}", "label": "attack" if i % 2 else "safe",
                 "from": "a@x.example", "subject": f"S{i}", "body": LONG_BODY}
                for i in range(1, 7)]
        corpus.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return corpus

    def _fake_deepseek(self, label="attack"):
        def fake(model, messages, *, max_tokens=64, temperature=0.0, **kwargs):
            reply = json.dumps({"label": label, "confidence": 0.8})
            return ({"choices": [{"message": {"content": reply}}],
                     "usage": {"prompt_tokens": 800, "completion_tokens": 15}}, 0.8)
        return fake

    def test_main_paths(self):
        with tempfile.TemporaryDirectory() as td:
            records_dir = Path(td) / "records"
            _patch_attrs(self, run_llm, CORPUS=self._corpus(td), RECORDS_DIR=records_dir)
            with mock.patch.object(run_llm.clients, "deepseek_chat", self._fake_deepseek()):
                with mock.patch.object(sys, "argv", ["run_llm.py", "--provider", "deepseek",
                                                     "--model", "deepseek-flash", "--limit", "2"]):
                    self.assertEqual(run_llm.main(), 0)
            run_file = next(records_dir.glob("deepseek-*.jsonl"))
            lines = [json.loads(l) for l in run_file.read_text(encoding="utf-8").split("\n") if l.strip()]
            self.assertEqual(lines[0]["corpus_size"], 2)
            self.assertEqual(lines[0]["provider"], "deepseek")
            self.assertEqual(lines[0]["sample"], None)
            with mock.patch.object(run_llm.clients, "deepseek_chat", self._fake_deepseek("safe")):
                with mock.patch.object(sys, "argv", ["run_llm.py", "--provider", "deepseek",
                                                     "--model", "deepseek-flash", "--sample", "4"]):
                    self.assertEqual(run_llm.main(), 0)
            # email-ids filter + resume
            new_records = Path(td) / "records2"
            _patch_attrs(self, run_llm, RECORDS_DIR=new_records)
            with mock.patch.object(run_llm.clients, "deepseek_chat", self._fake_deepseek()):
                with mock.patch.object(sys, "argv", ["run_llm.py", "--provider", "deepseek",
                                                     "--model", "deepseek-flash",
                                                     "--email-ids", "pub-001,pub-003"]):
                    self.assertEqual(run_llm.main(), 0)
            with mock.patch.object(sys, "argv", ["run_llm.py", "--provider", "deepseek",
                                                 "--model", "deepseek-flash", "--resume"]):
                pass
            _patch_attrs(self, run_llm, RECORDS_DIR=Path(td) / "none")
            with mock.patch.object(sys, "argv", ["run_llm.py", "--provider", "deepseek",
                                                 "--model", "deepseek-flash", "--resume"]):
                self.assertEqual(run_llm.main(), 1)


if __name__ == "__main__":
    unittest.main()
