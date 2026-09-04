"""Meta-tests that guard the regression suite against silently losing coverage.

A detection-as-code platform is only as trustworthy as the tests that gate it.
Python resolves duplicate class or method definitions by keeping the last one,
so a copy-pasted test class silently voids every test in the earlier
definition. `unittest` reports no error and the run still shows green. This
module makes that failure mode loud.
"""

from __future__ import annotations

import ast
import collections
import unittest
from pathlib import Path
from typing import List

TESTS_DIR = Path(__file__).resolve().parent


def _test_modules() -> List[Path]:
    return sorted(p for p in TESTS_DIR.glob("test_*.py"))


class SuiteIntegrityTests(unittest.TestCase):
    """Verifies no test is unreachable because a later definition shadows it."""

    def test_module_discovery_is_not_empty(self):
        """Guards against this meta-test passing vacuously."""
        self.assertGreaterEqual(len(_test_modules()), 2)

    def test_no_duplicate_test_class_names(self):
        """A repeated class name shadows the earlier class and voids its tests."""
        for module in _test_modules():
            tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
            classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
            counts = collections.Counter(c.name for c in classes)
            duplicates = {name: n for name, n in counts.items() if n > 1}
            with self.subTest(module=module.name):
                self.assertEqual(
                    duplicates,
                    {},
                    f"{module.name} defines these classes more than once, so the "
                    f"earlier definitions never run: {sorted(duplicates)}",
                )

    def test_no_duplicate_test_method_names_within_a_class(self):
        """A repeated method name shadows the earlier method and voids that test."""
        for module in _test_modules():
            tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                methods = [
                    m.name
                    for m in node.body
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                ]
                counts = collections.Counter(methods)
                duplicates = sorted(name for name, n in counts.items() if n > 1)
                with self.subTest(module=module.name, cls=node.name):
                    self.assertEqual(
                        duplicates,
                        [],
                        f"{module.name}:{node.name} redefines {duplicates}; "
                        f"only the last definition runs",
                    )


if __name__ == "__main__":
    unittest.main()
