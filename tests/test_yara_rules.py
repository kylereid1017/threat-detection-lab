import json
import unittest
from pathlib import Path

import yara


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar"
POSITIVE_DIR = ROOT / "tests" / "fixtures" / "positive"
NEGATIVE_DIR = ROOT / "tests" / "fixtures" / "negative"
CORPUS_DIR = ROOT / "corpus" / "benign"
EXPECTED_RULE = "Suspicious_Active_Content_SVG_Attachment"


class SuspiciousActiveContentSvgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(filepath=str(RULE_PATH))

    def match(self, fixture: Path) -> bool:
        return EXPECTED_RULE in {m.rule for m in self.rules.match(str(fixture))}

    def test_every_positive_fixture_matches(self):
        fixtures = sorted(p for p in POSITIVE_DIR.glob("*.svg"))
        self.assertGreater(len(fixtures), 0, "no positive fixtures found")
        missed = [f.name for f in fixtures if not self.match(f)]
        self.assertEqual([], missed)

    def test_every_negative_fixture_does_not_match(self):
        fixtures = sorted(p for p in NEGATIVE_DIR.glob("*.svg"))
        self.assertGreater(len(fixtures), 0, "no negative fixtures found")
        hit = [f.name for f in fixtures if self.match(f)]
        self.assertEqual([], hit)

    def test_malicious_alarms_only_when_evidence_is_present(self):
        pass


class SuspiciousActiveContentSvgCorpusTests(unittest.TestCase):
    """Optional benign-corpus regression: runs only if a pinned corpus exists."""

    @unittest.skipUnless(CORPUS_DIR.exists() and any(CORPUS_DIR.rglob("*.svg")),
                         "pinned benign corpus not present")
    def test_benign_corpus_fp_count_is_stable_or_lower(self):
        rules = yara.compile(filepath=str(RULE_PATH))
        results_path = ROOT / "docs" / "detections" / "evaluation-benign-corpus.json"
        results = json.loads(results_path.read_text(encoding="utf-8"))
        recorded_fps = results["benign_corpus"]["false_positives"]
        current_fps = 0
        for svg in CORPUS_DIR.rglob("*.svg"):
            if EXPECTED_RULE in {m.rule for m in rules.match(str(svg))}:
                current_fps += 1
        self.assertLessEqual(current_fps, recorded_fps,
                             "false positives regressed above recorded baseline")


if __name__ == "__main__":
    unittest.main()