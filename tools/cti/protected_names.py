"""Protected-name registry built from an organization's dependency inventory.

Why this exists, stated plainly: the vocabulary-based branches of the relevance
scorer measured **0% held-out recall** against 877 real malicious packages that
imitate the AI toolchain (`docs/detections/evaluation-relevance-recall.json`).
Substring matching against a hand-written brand list cannot, even in principle,
catch imitation of a name the list does not hold. Adding names to the list raises
the score on the next measurement and changes nothing about the mechanism.

The mechanism that generalizes is different in kind. Real typosquat detection
does not require knowing which brand is being imitated. It requires knowing which
names are **worth** imitating, and then flagging near misses of any of them.

The correct operational source for that list is the organization's own dependency
inventory. You protect what you actually install. A package one edit away from
something already in your lockfiles is a candidate confusion attack regardless of
whether anyone thought to add it to a brand list, and a package one edit away from
something nobody uses is not worth an analyst's time.

This module builds that registry from manifests or from an explicit list, and
answers one question: is this name a near miss of something we depend on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

import re

from tools.cti.relevance import HOMOGLYPHS as _HOMOGLYPHS
from tools.cti.relevance import damerau_levenshtein


class Imitation(NamedTuple):
    """A protected name the candidate appears to imitate, and how."""

    name: str
    distance: int
    #: "misspelling" for a near miss of the whole name, "substitution" for a
    #: homoglyph collision, "compound" for a protected name inside a longer one.
    kind: str


def normalize_package(value: str) -> str:
    """Normalize a package name.

    `relevance.normalize` is written for hosts and URLs, so it splits on "/" and
    keeps the first segment. Applied to a scoped package that is actively wrong:
    `@eslint/object-schema` reduces to `eslint`, which then matches every ESLint
    plugin in the ecosystem. That bug produced most of the measured false
    positives on the benign control before it was found.
    """
    text = value.strip().lower()
    for source, target in _HOMOGLYPHS.items():
        text = text.replace(source, target)
    return re.sub(r"[^a-z0-9]", "", text)


def _strip_only(value: str) -> str:
    """Lowercase and drop punctuation, without folding homoglyphs.

    `normalize` folds digit-for-letter substitutions, which is what makes
    `l0dash` comparable to `lodash`. It also erases the difference between
    `foo-bar`, `foo.bar`, and `foobar`, which are routinely three spellings of
    the same real package rather than an attack. Comparing on this stricter form
    separates the two cases.
    """
    return re.sub(r"[^a-z0-9]", "", value.strip().lower())

#: Names too short to typosquat meaningfully. Below this length, an edit budget
#: of one matches a large share of the registry by coincidence.
MIN_PROTECTED_LENGTH = 5

#: Package names common enough that near misses are ordinary rather than
#: suspicious. Without this, every short utility package generates noise.
GENERIC_NAMES: Set[str] = {
    "test",
    "tests",
    "utils",
    "util",
    "common",
    "core",
    "types",
    "config",
    "build",
    "index",
    "server",
    "client",
    "shared",
    "helpers",
}


def _edit_budget(name: str) -> int:
    """Edit distance allowed when judging a near miss.

    Longer names tolerate more, because one character is a smaller share of the
    name and a two-edit variant of a twelve-character package is still visually
    the same word to a hurried developer.
    """
    if len(name) <= 6:
        return 1
    if len(name) <= 12:
        return 2
    return 3


@dataclass
class ProtectedRegistry:
    """Names an organization depends on, and therefore names worth imitating."""

    names: Set[str] = field(default_factory=set)
    source: str = "unspecified"
    #: Normalized form to original, so findings can name the real package.
    _index: Dict[str, str] = field(default_factory=dict, repr=False)
    #: Normalized names bucketed by length for cheap candidate filtering.
    _by_length: Dict[int, List[str]] = field(default_factory=dict, repr=False)
    #: Literal inventory names, lowercased only. Used for the "this IS the real
    #: package" exclusion, which must not be done on the normalized form: homoglyph
    #: folding turns `l0dash` into `lodash`, so excluding on the normalized name
    #: suppresses exactly the substitution attack this registry exists to catch.
    _literal: Set[str] = field(default_factory=set, repr=False)
    #: Punctuation-stripped names, used to tell a character substitution apart
    #: from a mere separator variant of the same package.
    _stripped: Set[str] = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        self.reindex()

    def reindex(self) -> None:
        self._index.clear()
        self._by_length.clear()
        self._literal = {n.strip().lower() for n in self.names if n}
        self._stripped = {_strip_only(n) for n in self.names if n}
        for original in self.names:
            normalized = normalize_package(original)
            if len(normalized) < MIN_PROTECTED_LENGTH or normalized in GENERIC_NAMES:
                continue
            self._index.setdefault(normalized, original)
            self._by_length.setdefault(len(normalized), []).append(normalized)

    @property
    def indexed_count(self) -> int:
        return len(self._index)

    def add(self, names: Iterable[str]) -> None:
        self.names.update(n for n in names if n)
        self.reindex()

    def contains_exact(self, candidate: str) -> bool:
        """True when the candidate literally is an inventory name."""
        return candidate.strip().lower() in self._literal

    def _components(self, candidate: str) -> List[str]:
        """Name parts a compound lure would place a protected name into."""
        lowered = candidate.lower().replace("@", "").replace("/", "-")
        parts = []
        for raw in lowered.replace("_", "-").replace(".", "-").split("-"):
            cleaned = normalize_package(raw)
            if cleaned and cleaned not in parts:
                parts.append(cleaned)
        return parts

    def nearest(self, candidate: str) -> Optional[Imitation]:
        """Closest protected name, or None.

        Two imitation forms are checked, because real lures use both. A near miss
        of the whole name is the misspelling form (`langchian` for `langchain`).
        A protected name sitting inside a compound is the companion form
        (`langchain-toolkit`), which edit distance cannot see at all: the length
        gap alone puts it outside any sane budget.

        An exact match of the *whole* name is never a finding. That is the real
        package, and returning it would flag every dependency in the inventory.
        A component match is only meaningful once the whole name has been ruled
        out as genuine.
        """
        normalized = normalize_package(candidate)
        if not normalized or len(normalized) < MIN_PROTECTED_LENGTH:
            return None
        if self.contains_exact(candidate):
            return None

        best: Optional[Tuple[str, int]] = None
        # A normalized collision with a different literal name is a homoglyph or
        # separator substitution of a real dependency, which is the strongest
        # imitation signal available and reads as distance zero.
        collision = self._index.get(normalized)
        if collision is not None:
            # A collision only after homoglyph folding is a character
            # substitution attack. A collision that survives without folding is
            # a separator variant of a real package, which is ordinary and was
            # measured costing 2.7 points of precision for 0.4 of recall.
            if _strip_only(candidate) not in self._stripped:
                return (collision, 0)
        budget = _edit_budget(normalized)
        for length in range(len(normalized) - budget, len(normalized) + budget + 1):
            for protected in self._by_length.get(length, ()):
                allowed = min(budget, _edit_budget(protected))
                distance = damerau_levenshtein(normalized, protected)
                if distance <= allowed and (best is None or distance < best.distance):
                    best = Imitation(self._index[protected], distance, "misspelling")
                    if distance == 1:
                        return best
        if best:
            return best

        for component in self._components(candidate):
            if len(component) < MIN_PROTECTED_LENGTH:
                continue
            if component in self._index:
                return Imitation(self._index[component], 0, "compound")
        return None

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source,
            "names_supplied": len(self.names),
            "names_indexed": self.indexed_count,
            "min_length": MIN_PROTECTED_LENGTH,
            "excluded_generic": sorted(GENERIC_NAMES),
        }


def from_manifests(root: Path, limit: Optional[int] = None) -> ProtectedRegistry:
    """Build a registry from `package.json` files under a directory tree.

    This is the realistic deployment path: point it at the dependency trees the
    organization actually builds against, and the registry is the real attack
    surface rather than someone's guess at it.
    """
    names: Set[str] = set()
    for path in Path(root).rglob("package.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            continue
        name = data.get("name")
        if isinstance(name, str) and name:
            names.add(name)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            block = data.get(section)
            if isinstance(block, dict):
                names.update(k for k in block if isinstance(k, str) and k)
        if limit and len(names) >= limit:
            break
    return ProtectedRegistry(names=names, source=f"manifests under {Path(root).name}")


def from_names(names: Sequence[str], source: str = "explicit list") -> ProtectedRegistry:
    return ProtectedRegistry(names=set(names), source=source)


def from_json(path: Path) -> ProtectedRegistry:
    """Load a registry previously exported by `save`."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ProtectedRegistry(
        names=set(data.get("names", [])), source=data.get("source", str(path))
    )


def save(registry: ProtectedRegistry, path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(
        json.dumps(
            {"source": registry.source, "names": sorted(registry.names)}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
