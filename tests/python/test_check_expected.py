"""Tests for tests/check_expected.py, the integration-test verdict script."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "check_expected.py"


def run(findings, expected):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "findings.jsonl")
        # json.dumps default separators include spaces, like the real script.
        f.write_text("".join(json.dumps(o) + "\n" for o in findings))
        e = Path(d, "expected.txt")
        e.write_text("# comment\n\n" + "\n".join(expected) + "\n")
        return subprocess.run([sys.executable, str(SCRIPT), str(f), str(e)],
                              capture_output=True, text=True)


class CheckExpectedTests(unittest.TestCase):
    def test_passes_when_every_expected_check_failed(self):
        r = run([{"check_id": "check_a", "status": "not-satisfied"},
                 {"check_id": "check_b", "status": "not-satisfied"}],
                ["check_a", "check_b"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS  check_a", r.stdout)

    def test_fails_when_expected_check_was_satisfied(self):
        r = run([{"check_id": "check_a", "status": "satisfied"}], ["check_a"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL  check_a", r.stdout)

    def test_fails_when_expected_check_is_missing(self):
        r = run([{"check_id": "check_a", "status": "not-satisfied"}],
                ["check_a", "check_missing"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISSING  check_missing", r.stdout)

    def test_fails_on_empty_findings(self):
        r = run([], ["check_a"])
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
