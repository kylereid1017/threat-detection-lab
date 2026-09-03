"""Agent 4 — The Analyst: Attribution, boundary discovery, and policy recommendations."""

from __future__ import annotations

from typing import Dict, List, Tuple

from .models import BoundaryFinding, BoundaryMap, CriticVerdict, DetectionResult, Variant


class SwarmAnalyst:
    """Analyzes detection outcomes, identifies precise boundaries, and formulates tuning recommendations."""

    def analyze_cycle(
        self,
        cycle_results: List[Tuple[Variant, CriticVerdict, DetectionResult]],
        target_rule: str,
        target_type: str,
    ) -> List[BoundaryFinding]:
        findings: List[BoundaryFinding] = []

        for variant, critic, detection in cycle_results:
            if not critic.passed:
                continue

            if not detection.detected:
                # Evasion discovered! Perform root-cause attribution
                root_cause, recommendation = self._attribute_evasion(variant)
                findings.append(
                    BoundaryFinding(
                        axis=variant.axis,
                        mutation_name=variant.mutation_name,
                        detected=False,
                        evasion_gap_found=True,
                        root_cause=root_cause,
                        policy_recommendation=recommendation,
                        confidence="HIGH",
                    )
                )
            else:
                # Detection held
                findings.append(
                    BoundaryFinding(
                        axis=variant.axis,
                        mutation_name=variant.mutation_name,
                        detected=True,
                        evasion_gap_found=False,
                        root_cause="Rule logic successfully triggered on variant features.",
                        policy_recommendation="Current rule signature is resilient against this variation.",
                        confidence="HIGH",
                    )
                )

        return findings

    def generate_boundary_map(
        self,
        target_rule: str,
        target_type: str,
        cycles_completed: int,
        all_results: List[Tuple[Variant, CriticVerdict, DetectionResult]],
        all_findings: List[BoundaryFinding],
    ) -> BoundaryMap:
        """Constructs an aggregate detection boundary map."""
        total_generated = len(all_results)
        approved = [r for r in all_results if r[1].passed]
        critic_approved = len(approved)
        detected_count = sum(1 for r in approved if r[2].detected)
        evaded_count = sum(1 for r in approved if not r[2].detected)
        resilience = (detected_count / critic_approved) if critic_approved > 0 else 0.0

        return BoundaryMap(
            target_rule=target_rule,
            target_type=target_type,
            cycles_completed=cycles_completed,
            total_generated=total_generated,
            critic_approved=critic_approved,
            detected_count=detected_count,
            evaded_count=evaded_count,
            resilience_score=round(resilience, 4),
            findings=all_findings,
        )

    def _attribute_evasion(self, variant: Variant) -> Tuple[str, str]:
        """Diagnoses why a variant evaded detection based on its structure and payload."""
        name = variant.mutation_name

        # YARA Evasion Attribution
        if "comment_padding" in name:
            return (
                "YARA rule enforces `$svg at 0 or $svg in (0..1024)`. Prepending comments >1 KB pushes "
                "the root element outside the scan window.",
                "REC-YARA-001: Expand root search window to 4,096 bytes or complement with structural XML parser.",
            )
        if "string_concat" in name:
            return (
                "Literal string matching for 'location' and 'href' was bypassed via JavaScript property "
                "bracket access and string concatenation (`window['loc'+'ation']`).",
                "REC-YARA-002: Pair static file matching with dynamic sandbox inspection or AST JavaScript tokenization.",
            )
        if "namespace_prefix" in name:
            return (
                "Namespace prefixing (`<svg:svg>`) alters the literal tag representation from `<svg`.",
                "REC-YARA-003: Update regex to accept optional namespace prefixes: `<([a-zA-Z0-9_-]+:)?svg`.",
            )

        # Sigma Evasion Attribution
        if "numeric" in name or "short_h" in name:
            return (
                "Sigma rule checks for literal `*-w hidden*` or `*-windowstyle hidden*`, missing valid "
                "PowerShell switch aliases (`-w 1`, `-w h`, `-windowstyle 1`).",
                "REC-SIGMA-001: Add `-w 1`, `-w h`, and `-windowstyle 1` to CommandLine selection.",
            )
        if "split_invoke" in name:
            return (
                "PowerShell invocation expression `&('Inv'+'oke-RestMethod')` evades literal `CommandLine|contains`.",
                "REC-SIGMA-002: Layer with PowerShell Script Block Logging (Event ID 4104) to catch deobfuscated tokens.",
            )
        if "minimized" in name:
            return (
                "CMD used `start /min` instead of `start /b`.",
                "REC-SIGMA-003: Expand CMD staging switches to include `/min` alongside `/b`.",
            )
        if "rundll32" in name:
            return (
                "The Sigma rule inspects powershell, mshta, curl, and cmd, but does not monitor `rundll32.exe` "
                "when executing `url.dll,FileProtocolHandler` or `mshtml`.",
                "REC-SIGMA-004: Add `rundll32.exe` with `url.dll` or `mshtml` to monitored child LOLBins.",
            )
        if "wscript" in name:
            return (
                "The Sigma rule does not monitor Windows Script Host (`wscript.exe`/`cscript.exe`) fetching network scripts.",
                "REC-SIGMA-005: Add `wscript.exe` and `cscript.exe` with HTTP(S) destinations to monitored child images.",
            )

        return (
            f"Variant bypassed selection filters on axis '{variant.axis}'.",
            f"Review rule logic for missing coverage on {variant.mutation_name}.",
        )
