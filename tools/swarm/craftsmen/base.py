"""Abstract base class for Swarm Craftsmen."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..models import Variant


class BaseCraftsman(ABC):
    """Specialized adversarial generator operating along specific evasion axes."""

    @abstractmethod
    def generate_variants(self, cycle: int, feedback: List[str] | None = None) -> List[Variant]:
        """Generates variants for the current cycle, optionally guided by adapter feedback."""
        pass
