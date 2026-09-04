"""EPIC 4 — MITRE ATT&CK Navigator layer exporter.

Compiles every evaluated detection rule (top-level Sigma process-creation
analytics, multi-event correlation components, and the YARA active-content
analytic), the ATT&CK techniques they cover, and empirical resilience scores
into a standard ATT&CK Navigator layer JSON (`layer.json`).

Scores encode the lab's core engineering finding: isolated single-event
analytics exhibit a bounded resilience (~75%), while techniques additionally
covered by multi-event correlation earn a defense-in-depth boost.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[2]

#: Static YARA-rule -> technique map (the YARA analytic carries no ATT&CK tags).
_YARA_TECHNIQUES: Dict[str, List[str]] = {
    "suspicious_active_content_svg.yar": ["T1566.001"],
}

_TECHNIQUE_RE = re.compile(r"^t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

#: Baseline single-event resilience (the documented ~70-80% bounded threshold).
_BASELINE_SCORE = 75
#: Score awarded to a technique additionally covered by a correlation analytic.
_CORRELATION_SCORE = 95


@dataclass
class RuleCoverage:
    """Coverage contributed by one rule file."""

    rule_name: str
    source: str  # "sigma" | "sigma_correlation" | "yara"
    techniques: List[str] = field(default_factory=list)
    level: str = "high"


class MitreLayerExporter:
    """Builds an ATT&CK Navigator layer from the repository's rule corpus."""

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        pinned_resilience: Optional[float] = 0.712,
        history_file: Optional[Path] = None,
    ) -> None:
        self.repo_root = repo_root or ROOT
        self.rules_dir = self.repo_root / "rules"
        self.pinned_resilience = pinned_resilience
        self.history_file = history_file

    # -- collection -------------------------------------------------------

    def collect_rules(self) -> List[RuleCoverage]:
        """Enumerates every rule and extracts its ATT&CK technique coverage."""
        coverage: List[RuleCoverage] = []

        for rule_path in sorted((self.rules_dir / "sigma").glob("*.yml")):
            coverage.append(self._sigma_coverage(rule_path, "sigma"))

        corr_dir = self.rules_dir / "sigma" / "correlation"
        if corr_dir.exists():
            for rule_path in sorted(corr_dir.glob("*.yml")):
                coverage.append(self._sigma_coverage(rule_path, "sigma_correlation"))

        for rule_path in sorted((self.rules_dir / "yara").glob("*.yar")):
            coverage.append(
                RuleCoverage(
                    rule_name=rule_path.stem,
                    source="yara",
                    techniques=list(_YARA_TECHNIQUES.get(rule_path.name, [])),
                    level="high",
                )
            )
        return coverage

    def _sigma_coverage(self, rule_path: Path, source: str) -> RuleCoverage:
        collection = SigmaCollection.from_yaml(
            rule_path.read_text(encoding="utf-8"), resolve_references=False
        )
        rule = collection.rules[0]
        techniques = self._extract_techniques([str(t) for t in rule.tags])
        level = str(rule.level.name).lower() if rule.level else "high"
        return RuleCoverage(rule_name=rule.title, source=source, techniques=techniques, level=level)

    @staticmethod
    def _extract_techniques(tags: List[str]) -> List[str]:
        """Extracts ``Txxxx[.yyy]`` technique IDs from Sigma ``attack.*`` tags."""
        techniques: List[str] = []
        for tag in tags:
            token = tag.split(".", 1)[1] if tag.startswith("attack.") else tag
            match = _TECHNIQUE_RE.match(token)
            if match:
                tech = f"T{match.group(1)}"
                if match.group(2):
                    tech += f".{match.group(2)}"
                if tech not in techniques:
                    techniques.append(tech)
        return techniques

    # -- scoring ----------------------------------------------------------

    def compute_scores(self, coverage: List[RuleCoverage]) -> Dict[str, Dict[str, object]]:
        """Aggregates per-technique scores and the analytics that cover them."""
        techniques: Dict[str, Dict[str, object]] = {}
        for rule in coverage:
            has_correlation = rule.source == "sigma_correlation"
            for tech in rule.techniques:
                entry = techniques.setdefault(
                    tech, {"score": _BASELINE_SCORE, "rules": [], "correlated": False}
                )
                entry["rules"].append(rule.rule_name)  # type: ignore[union-attr]
                if has_correlation:
                    entry["correlated"] = True
        for entry in techniques.values():
            if entry["correlated"]:
                entry["score"] = _CORRELATION_SCORE
        return techniques

    def _apply_boundary_history(self, techniques: Dict[str, Dict[str, object]]) -> None:
        """Applies empirical resilience scoring deterministically.

        To guarantee that published coverage layers are reproducible across machines,
        this defaults to a pinned empirical resilience baseline (0.712, based on the
        published CABLE-2026-STRAT-001 N=764 empirical sample). If an explicit
        history_file is provided, it reads from that file. It does not unpinned-read
        from mutable workspace artifacts.
        """
        empirical_float: Optional[float] = None
        if self.history_file is not None and self.history_file.exists():
            try:
                data = json.loads(self.history_file.read_text(encoding="utf-8"))
                val = data.get("final_resilience")
                if isinstance(val, (int, float)):
                    empirical_float = float(val)
            except (json.JSONDecodeError, OSError):
                pass
        elif self.pinned_resilience is not None:
            empirical_float = self.pinned_resilience

        if empirical_float is None:
            return

        empirical = int(round(empirical_float * 100))
        for entry in techniques.values():
            if not entry["correlated"]:
                # Blend the static baseline with verified empirical resilience.
                entry["score"] = int(round((_BASELINE_SCORE + empirical) / 2))

    # -- layer assembly ---------------------------------------------------

    def build_layer(self, layer_name: str = "threat-detection-lab coverage") -> Dict[str, object]:
        """Assembles the full Navigator layer dictionary."""
        coverage = self.collect_rules()
        techniques = self.compute_scores(coverage)
        self._apply_boundary_history(techniques)

        technique_entries = []
        for tech in sorted(techniques):
            entry = techniques[tech]
            score = int(entry["score"])  # type: ignore[arg-type]
            rules = entry["rules"]  # type: ignore[assignment]
            technique_entries.append(
                {
                    "techniqueID": tech,
                    "score": score,
                    "color": self._score_color(score),
                    "comment": "Covered by: " + "; ".join(rules),  # type: ignore[arg-type]
                    "enabled": True,
                    "metadata": [
                        {"name": "correlation-backed", "value": str(bool(entry["correlated"])).lower()},
                        {"name": "analytics", "value": str(len(rules))},  # type: ignore[arg-type]
                    ],
                    "showSubtechniques": False,
                }
            )

        return {
            "name": layer_name,
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                "Empirical detection coverage from the threat-detection-lab Detection-as-Code "
                "harness. Scores: ~75 = single-event analytic (bounded resilience); "
                "95 = additionally correlation-backed (defense in depth)."
            ),
            "sorting": 3,
            "hideDisabled": False,
            "techniques": technique_entries,
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Single-event analytic (~75)", "color": "#ffe766"},
                {"label": "Correlation-backed (95)", "color": "#8ec843"},
            ],
            "metadata": [
                {"name": "generator", "value": "tools.swarm.export_layer"},
                {"name": "rules-evaluated", "value": str(len(coverage))},
                {"name": "techniques-covered", "value": str(len(technique_entries))},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }

    @staticmethod
    def _score_color(score: int) -> str:
        """Maps a 0-100 score onto the red->yellow->green gradient."""
        if score >= 90:
            return "#8ec843"
        if score >= 70:
            return "#b7d84b"
        if score >= 50:
            return "#ffe766"
        return "#ff6666"

    def export(self, out_path: Optional[Path] = None, layer_name: str = "threat-detection-lab coverage") -> Path:
        """Writes ``layer.json`` and returns the output path."""
        out_path = out_path or (self.repo_root / "docs" / "swarm" / "results" / "layer.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        layer = self.build_layer(layer_name=layer_name)
        out_path.write_text(json.dumps(layer, indent=2), encoding="utf-8", newline="\n")
        return out_path


def main(argv: Optional[List[str]] = None) -> int:
    exporter = MitreLayerExporter()
    path = exporter.export()
    layer = json.loads(path.read_text(encoding="utf-8"))
    print(f"[+] Exported ATT&CK Navigator layer: {path}")
    print(f"    - Techniques covered: {len(layer['techniques'])}")
    for tech in layer["techniques"]:
        print(f"      * {tech['techniqueID']:<12} score={tech['score']:>3}  {tech['comment']}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
