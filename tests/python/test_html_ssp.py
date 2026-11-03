"""Tests for oscal/html_report.py and oscal/update_ssp.py."""
import html as htmllib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HTML = REPO / "oscal" / "html_report.py"
SSP = REPO / "oscal" / "update_ssp.py"
MAPPING = REPO / "mappings" / "control-mapping.json"

FINDINGS = [
    {"check_id": "check_ssh", "title": "SSH weak", "status": "not-satisfied", "evidence": "e",
     "remediation": "r", "points": 10},
    {"check_id": "check_umask", "title": "ok", "status": "satisfied", "evidence": "", "points": 0},
    {"check_id": "check_auditd", "title": "check_auditd: check did not complete", "status": "error",
     "evidence": "1 unexpected error(s)", "points": 0},
]


def write_findings(d):
    f = Path(d, "f.jsonl")
    f.write_text("".join(json.dumps(o) + "\n" for o in FINDINGS))
    return f


class HtmlReportTests(unittest.TestCase):
    def render(self, score=50):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "r.html")
            subprocess.run([sys.executable, str(HTML), "--findings", str(write_findings(d)),
                            "--score", str(score), "--grade", "F", "--hostname", "h",
                            "--frameworks", "nist", "--output", str(out)], check=True)
            return out.read_text()

    def test_incomplete_checks_are_listed_separately_not_as_passed(self):
        html = self.render()
        passed = re.search(r'<details class="passed-section">.*?</details>', html, re.S).group(0)
        self.assertNotIn("check_auditd", passed)
        self.assertIn("Incomplete checks", html)
        self.assertIn("check_auditd", html)

    def test_gauge_arc_is_proportional_to_the_visible_half_circle(self):
        html = self.render(score=50)
        dash = re.findall(r'stroke-dasharray="([0-9.]+) ([0-9.]+)"', html)[-1]
        filled, total = map(float, dash)
        # 50/100 of a half circle of radius 60 is a quarter of the circumference.
        self.assertAlmostEqual(filled, 3.14159 * 60 / 2, delta=1.0)


# Breaks out of an attribute, an element and a <details> block.
PAYLOAD = "\"'><script>alert(1)</script></details><img src=x onerror=alert(1)>"


def render_html(findings, score=50, grade="F", hostname="h", frameworks="nist", duration="1s"):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d, "f.jsonl")
        f.write_text("".join(json.dumps(o) + "\n" for o in findings), encoding="utf-8")
        out = Path(d, "r.html")
        r = subprocess.run([sys.executable, str(HTML), "--findings", str(f), "--score", str(score),
                            "--grade", grade, "--hostname", hostname, "--frameworks", frameworks,
                            "--duration", duration, "--output", str(out)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(r.stdout + r.stderr)
        return out.read_text(encoding="utf-8")


class HtmlEscapingTests(unittest.TestCase):
    def assert_escaped(self, page, inputs):
        for raw in ("<script", "<img", PAYLOAD):
            self.assertFalse(raw in page.lower(), f"unescaped {raw!r} in the page")
        self.assertEqual(page.count("</details>"), page.count("<details"))
        for name, value in inputs.items():
            with self.subTest(name):
                # Rendered, and only in escaped form.
                self.assertIn(htmllib.escape(value), page)

    def test_every_input_is_escaped(self):
        v = {name: name + PAYLOAD for name in (
            "check_id", "title", "evidence", "remediation", "severity", "hostname",
            "framework", "duration", "grade", "error_check_id", "error_evidence",
            "passed_check_id")}
        findings = [
            {"check_id": v["check_id"], "title": v["title"], "status": "not-satisfied",
             "evidence": v["evidence"], "remediation": v["remediation"], "points": 10,
             "severity": v["severity"]},
            {"check_id": v["error_check_id"], "title": "t", "status": "error",
             "evidence": v["error_evidence"], "points": 0},
            {"check_id": v["passed_check_id"], "title": "t", "status": "satisfied",
             "evidence": "", "points": 0},
        ]
        page = render_html(findings, grade=v["grade"], hostname=v["hostname"],
                           frameworks="nist," + v["framework"], duration=v["duration"])
        self.assert_escaped(page, v)

    def test_points_that_are_not_a_number_are_not_inserted(self):
        page = render_html([{"check_id": "check_x", "title": "t", "status": "not-satisfied",
                             "evidence": "e", "remediation": "r", "points": "9" + PAYLOAD}])
        self.assert_escaped(page, {})


class UpdateSspTests(unittest.TestCase):
    def test_controls_with_an_incomplete_check_are_not_implemented(self):
        ssp = {"system-security-plan": {"control-implementation": {"implemented-requirements": [
            {"uuid": "1", "control-id": "au-2"}, {"uuid": "2", "control-id": "ac-17"}]}}}
        with tempfile.TemporaryDirectory() as d:
            s = Path(d, "ssp.json")
            s.write_text(json.dumps(ssp))
            out = Path(d, "out.json")
            r = subprocess.run([sys.executable, str(SSP), "--ssp", str(s), "--findings", str(write_findings(d)),
                                "--mapping", str(MAPPING), "--catalog", "nist", "--output", str(out)],
                               capture_output=True, text=True, check=True)
            reqs = json.loads(out.read_text())["system-security-plan"]["control-implementation"]["implemented-requirements"]
        au2 = next(q for q in reqs if q["control-id"] == "au-2")
        self.assertIn("Assessment status: partial", au2["remarks"])
        self.assertIn("did not complete", au2["remarks"])
        self.assertIn("PARTIAL: au-2", r.stdout)


if __name__ == "__main__":
    unittest.main()
