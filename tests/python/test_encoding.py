"""Findings that are not valid UTF-8.

record_finding (lib/common.sh) encodes JSON in pure bash and writes values
from the audited system, such as file names, byte for byte. A file name in
Latin-1 therefore puts bytes that are not UTF-8 into the findings file, and
every tool that reads that file must still produce its output.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OSCAL = REPO / "oscal"
MAPPING = REPO / "mappings" / "control-mapping.json"
REPLACEMENT = "�"

# Written by the real encoder. Some values end in an invalid byte right
# before the closing quote, so a decoder that swallowed the quote would
# break the JSON.
RECORD_FINDINGS = r"""
source "$1/ubuntu-sec-audit.sh"
FINDINGS_FILE="$2"
record_finding check_secrets "$(printf 'World-readable secret in caf\xe9')" not-satisfied \
    "$(printf '/home/caf\xe9/.env is world-readable\nsecond line \xff')" \
    "$(printf 'chmod 600 /home/caf\xe9/.env')" 12
record_finding check_umask "check_umask: all sub-checks passed" satisfied \
    "No issues detected during check_umask" "" 0
"""

# The tools must cope whatever the locale; C.UTF-8 makes the default codec
# UTF-8 (strict) and is what Ubuntu uses when nothing else is set.
ENV = dict(os.environ, LC_ALL="C.UTF-8")
ENV.pop("PYTHONUTF8", None)
ENV.pop("PYTHONIOENCODING", None)


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class NonUtf8FindingsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.findings = self.tmp / "findings.jsonl"
        subprocess.run(["bash", "-c", RECORD_FINDINGS, "bash", str(REPO), str(self.findings)],
                       check=True, env=ENV)
        raw = self.findings.read_bytes()
        # Guard: the file really holds bytes that are not UTF-8.
        with self.assertRaises(UnicodeDecodeError):
            raw.decode("utf-8")
        self.assertEqual(raw.count(b"\n"), 2, raw)

    def tearDown(self):
        self._tmp.cleanup()

    def run_tool(self, *args):
        r = subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True,
                           env=ENV, errors="replace")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_oscal_generator_writes_the_assessment_results(self):
        out = self.tmp / "out" / "oscal-ar.json"
        self.run_tool(OSCAL / "oscal_generate.py", "--findings", self.findings,
                      "--mapping", MAPPING, "--output", out)
        result = json.loads(out.read_text(encoding="utf-8"))["assessment-results"]["results"][0]
        self.assertEqual(len(result["observations"]), 2)
        secrets = next(o for o in result["observations"]
                       if any(p["value"] == "check_secrets" for p in o["props"]))
        self.assertIn("/home/caf" + REPLACEMENT + "/.env", secrets["description"])
        self.assertTrue(secrets["description"].endswith("second line " + REPLACEMENT))

    def test_html_report_is_written(self):
        out = self.tmp / "report.html"
        self.run_tool(OSCAL / "html_report.py", "--findings", self.findings, "--score", "88",
                      "--grade", "B", "--hostname", "h", "--output", out)
        html = out.read_text(encoding="utf-8")
        self.assertIn("/home/caf" + REPLACEMENT + "/.env", html)
        self.assertIn("check_umask", html)

    def test_ssp_is_updated(self):
        ssp = self.tmp / "ssp.json"
        ssp.write_text(json.dumps({"system-security-plan": {"control-implementation": {
            "implemented-requirements": [{"uuid": "1", "control-id": "ia-5"}]}}}))
        out = self.tmp / "ssp-out.json"
        self.run_tool(OSCAL / "update_ssp.py", "--ssp", ssp, "--findings", self.findings,
                      "--mapping", MAPPING, "--output", out)
        req = json.loads(out.read_text(encoding="utf-8"))[
            "system-security-plan"]["control-implementation"]["implemented-requirements"][0]
        self.assertIn("Assessment status: partial", req["remarks"])
        self.assertIn("/home/caf" + REPLACEMENT + "/.env", req["remarks"])

    def test_integration_verdict_reads_the_file(self):
        expected = self.tmp / "expected.txt"
        expected.write_text("check_secrets\n")
        r = self.run_tool(REPO / "tests" / "check_expected.py", self.findings, expected)
        self.assertIn("PASS  check_secrets", r.stdout)


if __name__ == "__main__":
    unittest.main()
