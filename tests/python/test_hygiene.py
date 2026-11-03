"""Repository-wide checks on the Python code itself."""
import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PY_FILES = sorted(
    list((REPO / "oscal").glob("*.py"))
    + list((REPO / "tests").glob("*.py"))
    + list((REPO / "tests" / "python").glob("*.py"))
)


def _is_main_guard(node):
    """`if __name__ == "__main__":`"""
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__")


class HygieneTests(unittest.TestCase):
    def test_every_python_file_parses_as_python_3_8(self):
        # Ubuntu 20.04 ships Python 3.8.
        self.assertTrue(PY_FILES)
        for path in PY_FILES:
            with self.subTest(path.name):
                ast.parse(path.read_text(encoding="utf-8"), str(path), feature_version=(3, 8))

    def test_main_guard_is_the_last_statement(self):
        # Anything defined after `unittest.main()` is silently left out when
        # a test file is run directly.
        for path in PY_FILES:
            body = ast.parse(path.read_text(encoding="utf-8")).body
            guards = [i for i, node in enumerate(body) if _is_main_guard(node)]
            if guards or path.name.startswith("test_"):
                with self.subTest(path.name):
                    self.assertEqual(guards, [len(body) - 1])


if __name__ == "__main__":
    unittest.main()
