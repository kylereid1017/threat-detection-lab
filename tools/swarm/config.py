"""Configuration and safety controls for the Adversarial Swarm."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass(frozen=True)
class SafetyConstraints:
    """Immutable safety controls enforcing sandbox containment."""
    # RFC 2606 reserved domains only
    allowed_tlds: List[str] = field(
        default_factory=lambda: [".invalid", ".example", ".test", ".localhost"]
    )
    forbid_live_ips: bool = True
    forbid_binary_payloads: bool = True
    forbid_real_c2_telemetry: bool = True
    max_absolute_cycles: int = 10
    max_absolute_variants_per_cycle: int = 50


@dataclass
class OperatorDirective:
    """Operator directive driving the swarm's testing scope and parameters."""
    target: str  # "yara" or "sigma"
    evasion_axes: List[str] = field(default_factory=list)
    max_cycles: int = 3
    variants_per_cycle: int = 6
    require_operator_approval: bool = False
    output_dir: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[2] / "docs" / "swarm" / "results"
    )
    safety: SafetyConstraints = field(default_factory=SafetyConstraints)

    def validate(self) -> None:
        """Enforces hard limits on operator directives."""
        if self.target not in ("yara", "sigma"):
            raise ValueError(f"Target '{self.target}' is not supported. Must be 'yara' or 'sigma'.")
        if self.max_cycles > self.safety.max_absolute_cycles:
            raise ValueError(
                f"Requested cycles ({self.max_cycles}) exceeds hard ceiling ({self.safety.max_absolute_cycles})."
            )
        if self.variants_per_cycle > self.safety.max_absolute_variants_per_cycle:
            raise ValueError(
                f"Requested variants ({self.variants_per_cycle}) exceeds hard ceiling "
                f"({self.safety.max_absolute_variants_per_cycle})."
            )
