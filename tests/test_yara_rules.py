from pathlib import Path
import unittest

import yara


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "rules" / "yara" / "suspicious_active_content_svg.yar"
POSITIVE_DIR = ROOT / "tests" / "fixtures" / "positive"
NEGATIVE_DIR = ROOT / "tests" / "fixtures" / "negative"
EXPECTED_RULE = "Suspicious_Active_Content_SVG_Attachment"


class SuspiciousActiveContentSvgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(filepath=str(RULE_PATH))

    def assert_fixture_matches(self, fixture: Path):
        matches = {match.rule for match in self.rules.match(str(fixture))}
        self.assertIn(EXPECTED_RULE, matches, fixture.name)

    def assert_fixture_does_not_match(self, fixture: Path):
        matches = {match.rule for match in self.rules.match(str(fixture))}
        self.assertNotIn(EXPECTED_RULE, matches, fixture.name)

    def test_redirect_script_matches(self):
        self.assert_fixture_matches(POSITIVE_DIR / "synthetic_redirect.svg")

    def test_event_handler_redirect_matches(self):
        self.assert_fixture_matches(POSITIVE_DIR / "synthetic_onload_redirect.svg")

    def test_static_svg_does_not_match(self):
        self.assert_fixture_does_not_match(NEGATIVE_DIR / "benign_static.svg")

    def test_linked_svg_without_script_does_not_match(self):
        self.assert_fixture_does_not_match(NEGATIVE_DIR / "benign_link.svg")

    def test_script_without_external_navigation_does_not_match(self):
        self.assert_fixture_does_not_match(NEGATIVE_DIR / "benign_local_script.svg")


if __name__ == "__main__":
    unittest.main()
