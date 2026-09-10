"""Generated strategic cables must not overclaim.

An earlier revision of the synthesizer template asserted, as virtually certain,
a resilience ceiling of 70 to 80 percent, while the same cable's own frontmatter
reported 98.3 percent. The claim was hardcoded prose and the number was computed,
so they drifted apart and the document contradicted itself on its first page.

Worse than the arithmetic: the confidence language treated a large sample of
self-generated probes as external evidence. Sample size inside a closed loop does
not establish external validity, and no volume of self-play can.

These tests enforce the framing structurally rather than leaving it to whoever
edits the template next.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNTHESIZER = ROOT / "tools" / "swarm" / "synthesizer.py"
CABLES_DIR = ROOT / "docs" / "cables"

#: Estimative phrases that assert near-certainty. None of them may be applied to
#: a figure the harness produced about itself.
NEAR_CERTAINTY = (
    "virtually certain",
    "almost certain",
    "99–100% probability",
    "95–99% probability",
)

STRATEGIC_CABLES = sorted(CABLES_DIR.glob("CABLE-*-STRAT-*.md"))
ALL_CABLES = sorted(CABLES_DIR.glob("CABLE-*.md"))


class SynthesizerTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SYNTHESIZER.read_text(encoding="utf-8")

    def test_template_states_the_closed_loop_limitation(self):
        for phrase in (
            "closed loop",
            "regression signal",
            "not an estimate of evasion resistance",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.source)

    def test_template_does_not_assert_near_certainty(self):
        found = [p for p in NEAR_CERTAINTY if p in self.source]
        self.assertEqual(
            [],
            found,
            f"near-certainty language in a self-generated measurement: {found}",
        )

    def test_confidence_level_is_capped_below_high(self):
        self.assertNotIn("**Analytic Confidence Level:** **HIGH**", self.source)
        self.assertIn("**Analytic Confidence Level:** **MODERATE**", self.source)

    def test_hardcoded_resilience_ranges_are_gone(self):
        """A prose range drifts away from the computed figure it describes."""
        matches = re.findall(r"between \*\*\d+% and \d+%\*\*", self.source)
        self.assertEqual([], matches, f"hardcoded resilience range in template: {matches}")

    def test_containment_claims_are_scoped_to_the_model(self):
        self.assertIn("modeled kill chain", self.source)


class PublishedCableTests(unittest.TestCase):
    """Published cables carry the same discipline as the template."""

    def test_strategic_cables_exist(self):
        self.assertTrue(STRATEGIC_CABLES, "no strategic cables found")

    def test_all_cables_exist(self):
        self.assertTrue(ALL_CABLES, "no cables found")

    def test_no_published_cable_asserts_near_certainty(self):
        """No published cable (strategic, campaign, or operational) may assert near-certainty forecasts."""
        offenders = []
        for cable in ALL_CABLES:
            text = cable.read_text(encoding="utf-8").lower()
            for phrase in NEAR_CERTAINTY:
                if phrase in text:
                    offenders.append(f"{cable.name}: {phrase}")
        self.assertEqual([], offenders, f"overclaiming cables: {offenders}")


    def test_every_strategic_cable_carries_the_scope_caveat(self):
        missing = []
        for cable in STRATEGIC_CABLES:
            text = cable.read_text(encoding="utf-8").lower()
            if "closed loop" not in text and "self-generated" not in text:
                missing.append(cable.name)
        self.assertEqual(
            [],
            missing,
            f"strategic cables with no statement of what the evidence is: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
