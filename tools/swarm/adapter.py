"""Adapter: rule patch proposal and in-memory verification."""

from __future__ import annotations

import difflib
import logging
from pathlib import Path
from typing import List, Optional, Tuple

from .cable_writer import CableWriter
from .detectors import BaseDetector, SigmaDetector, YaraDetector
from .models import BoundaryFinding, Variant

logger = logging.getLogger(__name__)


class SwarmAdapter:
    """Adapter role: proposes candidate rule patches for confirmed gaps and verifies them in memory."""

    def __init__(self, repo_root: Optional[Path] = None, cable_writer: Optional[CableWriter] = None) -> None:
        self.repo_root = repo_root or Path(__file__).resolve().parents[2]
        self.rules_dir = self.repo_root / "rules"
        self.cable_writer = cable_writer or CableWriter()

    def resolve_rule_path(self, finding: BoundaryFinding) -> Optional[Path]:
        """Resolves the target rule file path from a BoundaryFinding."""
        # 1. YARA resolution
        if finding.target_type == "yara" or finding.target_rule.endswith(".yar"):
            yara_dir = self.rules_dir / "yara"
            if finding.target_rule:
                target = finding.target_rule.lower().strip()
                for p in yara_dir.glob("*.yar"):
                    if p.name.lower() == target or p.stem.lower() == target:
                        return p
                    try:
                        content = p.read_text(encoding="utf-8")
                        if f"rule {finding.target_rule.strip()}" in content:
                            return p
                    except OSError:
                        continue
            default_yara = yara_dir / "suspicious_active_content_svg.yar"
            return default_yara if default_yara.exists() else None

        # 2. Sigma resolution
        target = finding.target_rule.strip() if finding.target_rule else ""
        sigma_dir = self.rules_dir / "sigma"

        candidates: List[Path] = sorted(list(sigma_dir.glob("*.yml")) + list((sigma_dir / "correlation").glob("*.yml")))
        if not candidates:
            return None

        if not target:
            # Default fallback for backward compatibility
            default_sigma = sigma_dir / "proc_creation_win_explorer_clickfix_execution.yml"
            return default_sigma if default_sigma.exists() else candidates[0]

        target_lower = target.lower()

        # Check exact filename or stem match
        for p in candidates:
            if p.name.lower() == target_lower or p.stem.lower() == target_lower:
                return p

        # Check rule title inside candidate files
        for p in candidates:
            try:
                text = p.read_text(encoding="utf-8")
                for line in text.splitlines()[:5]:
                    if line.startswith("title:"):
                        rule_title = line.split("title:", 1)[1].strip().strip('"\'').lower()
                        if rule_title == target_lower or target_lower in rule_title or rule_title in target_lower:
                            return p
            except OSError:
                continue

        # Check canonical keyword alias mapping
        alias_map = {
            "clickfix": "proc_creation_win_explorer_clickfix_execution.yml",
            "explorer": "proc_creation_win_explorer_clickfix_execution.yml",
            "schtasks": "proc_creation_win_schtasks_persistence.yml",
            "task": "proc_creation_win_schtasks_persistence.yml",
            "persistence": "proc_creation_win_schtasks_persistence.yml",
            "lsass": "proc_creation_win_rundll32_lsass_dump.yml",
            "rundll32": "proc_creation_win_rundll32_lsass_dump.yml",
            "comsvcs": "proc_creation_win_rundll32_lsass_dump.yml",
            "tampering": "proc_creation_win_defense_evasion_tampering.yml",
            "defense_evasion": "proc_creation_win_defense_evasion_tampering.yml",
            "wevtutil": "proc_creation_win_defense_evasion_tampering.yml",
            "clearlog": "proc_creation_win_defense_evasion_tampering.yml",
            "script_block": "posh_script_block_download_cradle.yml",
            "download_cradle": "posh_script_block_download_cradle.yml",
            "process_access": "sysmon_process_access_lsass.yml",
        }
        for alias, filename in alias_map.items():
            if alias in target_lower:
                for p in candidates:
                    if p.name == filename:
                        return p

        return None

    def heal_gap(
        self,
        finding: BoundaryFinding,
        variant: Variant,
        detector: Optional[BaseDetector] = None,
        apply_patch: bool = True,
    ) -> Tuple[bool, Optional[Path], str]:
        """Diagnoses an evasion gap, synthesizes a candidate rule patch, verifies it, and authors an intelligence cable."""
        rule_path = self.resolve_rule_path(finding)
        if not rule_path or not rule_path.exists():
            target_desc = finding.target_rule or f"{finding.target_type} default"
            return False, None, f"Target rule could not be resolved from finding: '{target_desc}'"

        target_type = "yara" if (finding.target_type == "yara" or rule_path.suffix == ".yar") else "sigma"

        if target_type == "sigma":
            patched_content, rec_id, patch_diff = self._synthesize_sigma_patch(rule_path, finding, variant)
        else:
            patched_content, rec_id, patch_diff = self._synthesize_yara_patch(rule_path, finding, variant)

        if not patched_content or patched_content == rule_path.read_text(encoding="utf-8"):
            return False, None, f"No patch candidate could be synthesized for vector '{variant.mutation_name}' on rule '{rule_path.name}'."

        # Verification Gate: measure that the patch detects the variant without regressions.
        verification = self._verify_patch(rule_path, patched_content, target_type, variant)
        if verification["error"]:
            return False, None, f"Candidate patch could not be verified: {verification['error']}"
        if not verification["variant_detected_after"] or verification["negative_fixtures_matched"]:
            return False, None, "Verification gate failed: candidate patch introduced regressions or failed to catch variant."

        # Author the cable from measured evidence only. There is deliberately no resilience
        # delta here: the former 0.60 -> 1.00 pair was a constant, not a measurement.
        cable_path = self.cable_writer.write_cable(
            finding=finding,
            variant=variant,
            patch_diff=patch_diff,
            recommendation_id=rec_id,
            verification=verification,
        )

        # Apply Patch to Disk if requested
        if apply_patch:
            rule_path.write_text(patched_content, encoding="utf-8", newline="\n")

        return True, cable_path, patch_diff

    @staticmethod
    def _anchors_present(text: str, anchors: Tuple[str, ...]) -> bool:
        """True only when every anchor the upcoming edit needs is still in the rule."""
        return all(anchor in text for anchor in anchors)

    def _drift(self, rule_name: str, rec_id: str, what: str) -> Tuple[None, str, str]:
        """Reports a rule that no longer matches the template the synthesizer expects.

        Returning a silently unchanged rule as a "patch" is what this replaces: a drifted rule
        must produce no patch and a loud error, not a no-op that later fails verification with a
        reason that points at the variant instead of at the rule.
        """
        logger.error(
            "Rule drift: %s is missing the %s anchor that %s patches, so no patch was "
            "synthesized. The rule template changed and the synthesizer needs updating.",
            rule_name, what, rec_id,
        )
        return None, rec_id, ""

    def _synthesize_sigma_patch(
        self, rule_path: Path, finding: BoundaryFinding, variant: Variant
    ) -> Tuple[Optional[str], str, str]:
        """Synthesizes a rule patch for the specified Sigma rule."""
        original = rule_path.read_text(encoding="utf-8")
        patched = original
        rec_id = "REC-SIGMA-GENERIC"
        rule_name = rule_path.name
        mutation_name = variant.mutation_name.lower()
        axis = finding.axis.lower()

        # Rule 1: Explorer ClickFix Execution
        if "clickfix" in rule_name:
            if "pcalua" in mutation_name or "wt" in mutation_name or "hh" in mutation_name or "proxy" in axis:
                rec_id = "REC-SIGMA-006"
                if not self._anchors_present(
                    patched,
                    (
                        "    condition: selection_parent and (",
                        "(selection_wscript_img and selection_wscript_target))",
                    ),
                ):
                    return self._drift(rule_name, rec_id, "pcalua proxy")
                if "selection_proxy_img:" not in patched:
                    proxy_block = """    selection_proxy_img:
        Image|endswith:
            - '\\pcalua.exe'
            - '\\wt.exe'
            - '\\hh.exe'
    selection_proxy_target:
        CommandLine|contains:
            - 'powershell'
            - 'pwsh'
            - 'http://'
            - 'https://'
            - '.chm'
"""
                    patched = patched.replace(
                        "    condition: selection_parent and (",
                        f"{proxy_block}    condition: selection_parent and (",
                    )
                    patched = patched.replace(
                        "(selection_wscript_img and selection_wscript_target))",
                        "(selection_wscript_img and selection_wscript_target) or (selection_proxy_img and selection_proxy_target))",
                    )
            elif "stdin" in mutation_name or "pipe" in mutation_name or "argument" in axis:
                rec_id = "REC-SIGMA-007"
                if not self._anchors_present(
                    patched,
                    (
                        "    condition: selection_parent and (",
                        "(selection_wscript_img and selection_wscript_target))",
                    ),
                ):
                    return self._drift(rule_name, rec_id, "powershell stdin")
                if "selection_pwsh_stdin:" not in patched:
                    stdin_block = """    selection_pwsh_stdin:
        CommandLine|endswith:
            - ' -'
            - ' - '
"""
                    patched = patched.replace(
                        "    condition: selection_parent and (",
                        f"{stdin_block}    condition: selection_parent and (",
                    )
                    patched = patched.replace(
                        "(selection_wscript_img and selection_wscript_target))",
                        "(selection_wscript_img and selection_wscript_target) or (selection_pwsh_img and selection_pwsh_stdin))",
                    )

        # Rule 2: Scheduled Tasks Persistence
        elif "schtasks" in rule_name:
            if "daily" in mutation_name or "weekly" in mutation_name or "onidle" in mutation_name or "trigger" in axis:
                rec_id = "REC-SIGMA-SCHTASKS-001"
                if not self._anchors_present(patched, ("CommandLine|contains:\n            - '/sc onlogon'",)):
                    return self._drift(rule_name, rec_id, "scheduled-task trigger")
                for trig in ["/sc daily", "/sc weekly", "/sc onidle", "daily", "onidle"]:
                    if trig not in patched:
                        patched = patched.replace(
                            "        CommandLine|contains:\n            - '/sc onlogon'",
                            f"        CommandLine|contains:\n            - '{trig}'\n            - '/sc onlogon'",
                        )
            elif "regsvr32" in mutation_name or "pcalua" in mutation_name or "payload" in axis or "binary" in axis:
                rec_id = "REC-SIGMA-SCHTASKS-002"
                if not self._anchors_present(patched, ("CommandLine|contains:\n            - 'powershell'",)):
                    return self._drift(rule_name, rec_id, "scheduled-task binary")
                for bin_name in ["regsvr32", "pcalua", "certutil", "wmic"]:
                    if bin_name not in patched:
                        patched = patched.replace(
                            "        CommandLine|contains:\n            - 'powershell'",
                            f"        CommandLine|contains:\n            - '{bin_name}'\n            - 'powershell'",
                        )

        # Rule 3: Rundll32 LSASS Memory Dump
        elif "rundll32" in rule_name or "lsass" in rule_name:
            if "ordinal" in mutation_name or "minidump" in mutation_name or "syntax" in axis or "comma" in mutation_name:
                rec_id = "REC-SIGMA-LSASS-001"
                if not self._anchors_present(patched, ("CommandLine|contains:\n            - 'MiniDump'",)):
                    return self._drift(rule_name, rec_id, "LSASS ordinal")
                for variant_token in ["#0024", "#+24", "minidumpw", "MiniDumpW", "comsvcs.dll,#24", "comsvcs.dll, #24"]:
                    if variant_token not in patched:
                        patched = patched.replace(
                            "        CommandLine|contains:\n            - 'MiniDump'",
                            f"        CommandLine|contains:\n            - '{variant_token}'\n            - 'MiniDump'",
                        )

        # Rule 4: Defense Evasion & Software Tampering
        elif "tampering" in rule_name or "defense_evasion" in rule_name:
            if "defender" in mutation_name or "remove" in mutation_name or "disable" in mutation_name or "tamper" in axis:
                rec_id = "REC-SIGMA-TAMPER-001"
                if not self._anchors_present(patched, ("            - 'Set-MpPreference'\n",)):
                    return self._drift(rule_name, rec_id, "Defender tampering")
                for cmdlet in ["Remove-MpPreference", "DisableBehaviorMonitoring", "DisableScriptScanning"]:
                    if cmdlet not in patched:
                        patched = patched.replace(
                            "            - 'Set-MpPreference'\n",
                            f"            - '{cmdlet}'\n            - 'Set-MpPreference'\n",
                        )
            elif "wevtutil" in mutation_name or "clear" in mutation_name or "log" in axis:
                rec_id = "REC-SIGMA-TAMPER-002"
                if not self._anchors_present(patched, ("            - ' cl '\n",)):
                    return self._drift(rule_name, rec_id, "event-log clearing")
                for cmd_var in [" cl:", "/cl ", "clearlog", "/clear-log"]:
                    if cmd_var not in patched:
                        patched = patched.replace(
                            "            - ' cl '\n",
                            f"            - '{cmd_var}'\n            - ' cl '\n",
                        )

        if rec_id == "REC-SIGMA-GENERIC":
            logger.warning(
                "No synthesis path matched %s (axis=%s, mutation=%s); no patch produced.",
                rule_name, finding.axis, variant.mutation_name,
            )
            return None, rec_id, ""

        if patched == original:
            logger.info(
                "No patch produced for %s via %s: the rule already carries this hardening.",
                rule_name, rec_id,
            )
            return None, rec_id, ""

        logger.info("Synthesized %s for %s (mutation %s).", rec_id, rule_name, variant.mutation_name)

        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=str(rule_path.name),
                tofile=f"{rule_path.name} (Patched)",
            )
        )
        return patched, rec_id, diff

    def _synthesize_yara_patch(
        self, rule_path: Path, finding: BoundaryFinding, variant: Variant
    ) -> Tuple[Optional[str], str, str]:
        """Synthesizes a rule patch for the YARA active SVG rule."""
        original = rule_path.read_text(encoding="utf-8")
        rec_id = "REC-YARA-004"
        name = variant.mutation_name.lower()

        patched = original

        # Case 1: HTML ForeignObject / Meta Refresh
        if "foreignobject" in name or "meta" in name or "differential" in finding.axis:
            rec_id = "REC-YARA-004"
            if not self._anchors_present(patched, ("    strings:",)):
                return self._drift(rule_path.name, rec_id, "strings section")
            if "$foreign_meta_refresh" not in patched:
                # Add strings
                new_strings = r"""        $foreign_meta_refresh = /<meta[\x09\x0a\x0d\x20][^>]*?refresh/ nocase
"""
                patched = patched.replace("    strings:", f"    strings:\n{new_strings}")
                patched = patched.replace(
                    "1 of ($active_script, $active_handler, $javascript_uri) and",
                    "1 of ($active_script, $active_handler, $javascript_uri, $foreign_meta_refresh) and",
                )
                patched = patched.replace(
                    "1 of ($navigation, $navigation_method, $navigation_bracket, $window_open, $javascript_uri) and",
                    "1 of ($navigation, $navigation_method, $navigation_bracket, $window_open, $javascript_uri, $foreign_meta_refresh) and",
                )

        # Case 2: SMIL Animate Href
        elif "animate" in name or "smil" in name:
            rec_id = "REC-YARA-005"
            if not self._anchors_present(patched, ("    strings:",)):
                return self._drift(rule_path.name, rec_id, "strings section")
            if "$smil_animate" not in patched:
                new_strings = r"""        $smil_animate = /<animate[\x09\x0a\x0d\x20][^>]*?attributeName[\x09\x0a\x0d\x20]*=[\x09\x0a\x0d\x20]*['"]href['"]/ nocase
"""
                patched = patched.replace("    strings:", f"    strings:\n{new_strings}")
                patched = patched.replace(
                    "1 of ($active_script, $active_handler, $javascript_uri) and",
                    "1 of ($active_script, $active_handler, $javascript_uri, $smil_animate) and",
                )
                patched = patched.replace(
                    "1 of ($navigation, $navigation_method, $navigation_bracket, $window_open, $javascript_uri) and",
                    "1 of ($navigation, $navigation_method, $navigation_bracket, $window_open, $javascript_uri, $smil_animate) and",
                )

        if patched == original:
            logger.info(
                "No patch produced for %s via %s: the rule already carries this hardening.",
                rule_path.name, rec_id,
            )
            return None, rec_id, ""

        logger.info("Synthesized %s for %s (mutation %s).", rec_id, rule_path.name, variant.mutation_name)

        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=str(rule_path.name),
                tofile=f"{rule_path.name} (Patched)",
            )
        )
        return patched, rec_id, diff

    def _verify_patch(self, rule_path: Path, patched_content: str, target_type: str, variant: Variant) -> dict:
        """Measures whether a candidate patch detects the evasive variant without regressions.

        Returns the measured evidence rather than a bare boolean so that the authored cable
        states what was actually evaluated. An unexpected error is reported in ``error``
        instead of being silently collapsed into a pass/fail with no provenance.
        """
        import json

        evidence = {
            "variant_detected_before": None,
            "variant_detected_after": None,
            "negative_fixtures_checked": 0,
            "negative_fixtures_matched": 0,
            "error": None,
        }
        try:
            original_content = rule_path.read_text(encoding="utf-8")
            if target_type == "sigma":
                original_detector = SigmaDetector(custom_yaml=original_content)
                temp_detector = SigmaDetector(custom_yaml=patched_content)
                neg_dir = self.repo_root / "tests" / "fixtures" / "sigma" / "negative"
                pattern = "*.json"
            else:
                original_detector = YaraDetector(custom_source=original_content)
                temp_detector = YaraDetector(custom_source=patched_content)
                neg_dir = self.repo_root / "tests" / "fixtures" / "negative"
                pattern = "*.svg"

            evidence["variant_detected_before"] = bool(original_detector.evaluate(variant).detected)
            evidence["variant_detected_after"] = bool(temp_detector.evaluate(variant).detected)
            if not evidence["variant_detected_after"]:
                return evidence

            # Negative regression gate (zero false positives on the pinned fixtures).
            if neg_dir.exists():
                for f in sorted(neg_dir.glob(pattern)):
                    if target_type == "sigma":
                        data = json.loads(f.read_text(encoding="utf-8"))
                        dummy_v = Variant(id="neg", target_type="sigma", axis="test", mutation_name="neg", description="neg", payload=data, cycle=1)
                    else:
                        dummy_v = Variant(id="neg", target_type="yara", axis="test", mutation_name="neg", description="neg", payload=f.read_text(encoding="utf-8"), cycle=1)
                    evidence["negative_fixtures_checked"] += 1
                    if temp_detector.evaluate(dummy_v).detected:
                        evidence["negative_fixtures_matched"] += 1
            return evidence
        except Exception as exc:  # noqa: BLE001 - reported, never raised into the caller's loop
            # Broad on purpose: a detector that cannot evaluate one candidate must not abort a
            # whole run, but the failure has to be visible and attributed, not silent.
            logger.error("Patch verification could not evaluate the candidate: %s: %s", type(exc).__name__, exc)
            evidence["error"] = f"{type(exc).__name__}: {exc}"
            return evidence
