"""Guard: committed HTML artifacts must be self-contained.

The interactive artifacts ship as static pages: they render offline with no
third-party runtime fetch. A CDN ``<script>`` or ``<link>`` tag re-introduces
exactly the trust-boundary problem the 2026-09-06 review flagged (R04), so this
test fails if one comes back. External hyperlinks (``<a href>``) are fine -
they are user-clicked, not loaded.

Every artifact is listed explicitly so that adding a new one forces a conscious
update of this guard; the directory scan below catches new files added to the
artifact folders.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ARTIFACTS = (
    "index.html",
    "swarm_workbench.html",
    "tools/agent_graph/artifact_template.html",
    "docs/cables/CABLE-2026-STRAT-001.html",
    "docs/cables/CABLE-2026-STRAT-002.html",
    "docs/cables/CABLE-2026-STRAT-003.html",
    "docs/research/agent-capability-composition.html",
    "docs/research/agent-execution-layer-dashboard.html",
)

ARTIFACT_DIRS = ("docs/cables/*.html", "docs/research/*.html", "tools/agent_graph/*.html")

EXTERNAL_REF = re.compile(
    r"""<(?:script[^>]+?src|link[^>]+?href)\s*=\s*["']https?://""",
    re.IGNORECASE,
)


class ArtifactSelfContainmentTests(unittest.TestCase):
    def test_no_artifact_loads_external_resources(self):
        offenders = {}
        for relative in ARTIFACTS:
            text = (ROOT / relative).read_text(encoding="utf-8", errors="replace")
            found = len(EXTERNAL_REF.findall(text))
            if found:
                offenders[relative] = found
        self.assertEqual(
            {},
            offenders,
            f"external script/link references in committed artifacts: {offenders}",
        )

    def test_artifact_directories_are_fully_covered(self):
        covered = {Path(name).name for name in ARTIFACTS}
        for pattern in ARTIFACT_DIRS:
            for path in ROOT.glob(pattern):
                self.assertIn(
                    path.name,
                    covered,
                    f"artifact not covered by this guard: {path.relative_to(ROOT)}",
                )
