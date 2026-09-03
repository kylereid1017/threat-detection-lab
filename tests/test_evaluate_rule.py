import hashlib
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import evaluate_rule as ev


class MetricTests(unittest.TestCase):
    def test_confusion_counts(self):
        counts = ev.confusion(
            positives=[("p1", True), ("p2", False)],
            negatives=[("n1", False), ("n2", True), ("n3", False)],
        )
        self.assertEqual(counts["true_positives"], 1)
        self.assertEqual(counts["false_negatives"], 1)
        self.assertEqual(counts["true_negatives"], 2)
        self.assertEqual(counts["false_positives"], 1)

    def test_empty_inputs(self):
        counts = ev.confusion(positives=[], negatives=[])
        for key in ("true_positives", "false_negatives", "true_negatives", "false_positives"):
            self.assertEqual(counts[key], 0)


class HashVerificationTests(unittest.TestCase):
    def test_sha256_of_known_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.bin"
            p.write_bytes(b"abc")
            self.assertEqual(
                ev.sha256_file(p),
                hashlib.sha256(b"abc").hexdigest(),
            )

    def test_hash_mismatch_raises(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.bin"
            p.write_bytes(b"unexpected contents")
            with self.assertRaises(ev.ProvenanceError):
                ev.verify_sha256(p, "0" * 64)


if __name__ == "__main__":
    unittest.main()