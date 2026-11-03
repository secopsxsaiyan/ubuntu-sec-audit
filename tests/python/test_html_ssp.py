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
    def render(self, score=50, extra=()):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "r.html")
            subprocess.run([sys.executable, str(HTML), "--findings", str(write_findings(d)),
                            "--score", str(score), "--grade", "F", "--hostname", "h",
                            "--frameworks", "nist", "--output", str(out), *extra], check=True)
            return out.read_text()

    def test_a_partial_run_is_labelled_without_touching_the_grade(self):
        html = self.render(extra=("--partial",))
        self.assertIn("Partial run", html)
        self.assertIn("Grade F<", html)
        self.assertNotIn("Partial run", self.render())

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


NOT_ASSESSED = [
    {"check_id": "check_aide", "title": "check_aide: not checked", "status": "skipped",
     "evidence": "aide is not installed", "remediation": "", "points": 0},
    {"check_id": "check_secure_boot", "title": "check_secure_boot: not applicable",
     "status": "not-applicable", "evidence": "not applicable in docker", "remediation": "", "points": 0},
]


class HtmlNotAssessedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = render_html(FINDINGS + NOT_ASSESSED)

    def section(self, pattern):
        m = re.search(pattern, self.page, re.S)
        self.assertIsNotNone(m, pattern)
        return m.group(0)

    def test_not_assessed_checks_have_their_own_labelled_list_with_the_reason(self):
        sec = self.section(r'<section[^>]*id="not-assessed".*?</section>')
        self.assertIn("Not assessed (2)", sec)
        self.assertRegex(sec, r"check_aide.*Skipped.*aide is not installed")
        self.assertRegex(sec, r"check_secure_boot.*Not applicable.*not applicable in docker")

    def test_they_are_not_failures(self):
        table = self.section(r"<tbody>.*?</tbody>")
        incomplete = self.section(r'class="passed-section incomplete-section".*?</div>')
        for check in ("check_aide", "check_secure_boot"):
            self.assertNotIn(check, table)
            self.assertNotIn(check, incomplete)

    def test_they_are_not_passes(self):
        passed = self.section(r'<details class="passed-section">.*?</details>')
        self.assertNotIn("check_aide", passed)
        self.assertNotIn("check_secure_boot", passed)
        self.assertIn('<div class="num passed">1</div>', self.page)  # check_umask only

    def test_an_issue_wins_over_a_not_applicable_record(self):
        page = render_html([FINDINGS[0], dict(NOT_ASSESSED[1], check_id="check_ssh")])
        self.assertNotIn('id="not-assessed"', page)


class HtmlEscapingTests(unittest.TestCase):
    def assert_escaped(self, page, inputs):
        for raw in ("<script", "<img", PAYLOAD):
            self.assertFalse(raw in page.lower(), f"unescaped {raw!r} in the page")
        self.assertEqual(page.count("</details>"), page.count("<details"))
        for name, value in inputs.items():
            with self.subTest(name):
                # Rendered, and only in escaped form.
                self.assertTrue(htmllib.escape(value) in page, f"{name} is not shown escaped")

    def test_every_input_is_escaped(self):
        v = {name: name + PAYLOAD for name in (
            "check_id", "title", "evidence", "remediation", "severity", "hostname",
            "framework", "duration", "grade", "error_check_id", "error_evidence",
            "passed_check_id", "skipped_check_id", "skipped_evidence", "na_check_id",
            "na_evidence")}
        findings = [
            {"check_id": v["check_id"], "title": v["title"], "status": "not-satisfied",
             "evidence": v["evidence"], "remediation": v["remediation"], "points": 10,
             "severity": v["severity"]},
            {"check_id": v["error_check_id"], "title": "t", "status": "error",
             "evidence": v["error_evidence"], "points": 0},
            {"check_id": v["passed_check_id"], "title": "t", "status": "satisfied",
             "evidence": "", "points": 0},
            {"check_id": v["skipped_check_id"], "title": "t", "status": "skipped",
             "evidence": v["skipped_evidence"], "points": 0},
            {"check_id": v["na_check_id"], "title": "t", "status": "not-applicable",
             "evidence": v["na_evidence"], "points": 0},
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


HISTORY_SEP = "\n--- Previous ---\n"
OLD_TIME = "2020-01-01T00:00:00Z"


def make_ssp(*reqs):
    return {"system-security-plan": {
        "uuid": "6c1b4c0e-4c4a-4f0e-9d1e-0a1b2c3d4e5f",
        "metadata": {"title": "SSP", "last-modified": OLD_TIME, "version": "1", "oscal-version": "1.1.2"},
        "control-implementation": {"implemented-requirements": list(reqs)}}}


def run_ssp(d, ssp, findings, output=None):
    """Run update_ssp.py; returns (process, {control-id: requirement}, written document)."""
    s = Path(d, "ssp.json")
    if ssp is not None:
        s.write_text(json.dumps(ssp))
    f = Path(d, "findings.jsonl")
    f.write_text("".join(json.dumps(o) + "\n" for o in findings))
    out = Path(output) if output else Path(d, "out.json")
    r = subprocess.run([sys.executable, str(SSP), "--ssp", str(s), "--findings", str(f),
                        "--mapping", str(MAPPING), "--catalog", "nist", "--output", str(out)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(r.stdout + r.stderr)
    doc = json.loads(out.read_text())
    reqs = doc["system-security-plan"]["control-implementation"]["implemented-requirements"]
    return r, {q["control-id"]: q for q in reqs}, doc


class UpdateSspStatusTests(unittest.TestCase):
    def test_checks_that_were_not_assessed_do_not_update_controls(self):
        findings = NOT_ASSESSED + [
            {"check_id": "check_disk_encryption", "title": "ok", "status": "satisfied",
             "evidence": "LUKS on /", "points": 0}]
        ssp = make_ssp({"uuid": "1", "control-id": "si-7", "remarks": "Owner: ops team"},
                       {"uuid": "2", "control-id": "au-9"},
                       {"uuid": "3", "control-id": "sc-28"})
        with tempfile.TemporaryDirectory() as d:
            r, reqs, _ = run_ssp(d, ssp, findings)
        # SI-7 and AU-9: only skipped / not-applicable checks.
        self.assertEqual(reqs["si-7"]["remarks"], "Owner: ops team")
        self.assertNotIn("remarks", reqs["au-9"])
        self.assertNotIn("si-7", r.stdout)
        # SC-28: decided by check_disk_encryption alone.
        self.assertIn("Assessment status: implemented", reqs["sc-28"]["remarks"])
        self.assertIn("LUKS on /", reqs["sc-28"]["remarks"])
        self.assertNotIn("not applicable in docker", reqs["sc-28"]["remarks"])

    def test_a_status_it_does_not_know_is_not_called_implemented(self):
        findings = [{"check_id": "check_umask", "title": "t", "status": "bogus", "evidence": "e", "points": 0}]
        with tempfile.TemporaryDirectory() as d:
            _, reqs, _ = run_ssp(d, make_ssp({"uuid": "1", "control-id": "cm-6"}), findings)
        self.assertIn("Assessment status: partial", reqs["cm-6"]["remarks"])


class UpdateSspWriteTests(unittest.TestCase):
    def test_last_modified_is_bumped_when_the_ssp_changes(self):
        with tempfile.TemporaryDirectory() as d:
            _, _, doc = run_ssp(d, make_ssp({"uuid": "1", "control-id": "ac-17"}), FINDINGS)
        modified = doc["system-security-plan"]["metadata"]["last-modified"]
        self.assertGreater(modified, OLD_TIME)
        self.assertRegex(modified, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_last_modified_is_kept_when_nothing_changes(self):
        with tempfile.TemporaryDirectory() as d:
            _, _, doc = run_ssp(d, make_ssp({"uuid": "1", "control-id": "pe-3"}), FINDINGS)
        self.assertEqual(doc["system-security-plan"]["metadata"]["last-modified"], OLD_TIME)

    def test_the_ssp_can_be_updated_in_place_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            s = Path(d, "ssp.json")
            s.write_text(json.dumps(make_ssp({"uuid": "1", "control-id": "ac-17"})))
            s.chmod(0o640)
            before = s.stat()
            _, reqs, _ = run_ssp(d, None, FINDINGS, output=s)
            after = s.stat()
            leftovers = sorted(p.name for p in Path(d).iterdir())
        self.assertIn("Assessment status: partial", reqs["ac-17"]["remarks"])
        # Replaced by a new file (a rename), never rewritten in place...
        self.assertNotEqual(before.st_ino, after.st_ino)
        # ...which keeps the permissions and leaves no temporary file behind.
        self.assertEqual(after.st_mode & 0o777, 0o640)
        self.assertEqual(leftovers, ["findings.jsonl", "ssp.json"])

    def test_the_remarks_history_is_capped_and_keeps_other_remarks(self):
        old_blocks = [f"[ubuntu-sec-audit 2020-01-{day:02d}T00:00:00Z] Assessment status: implemented.\n"
                      for day in range(15, 0, -1)]  # newest first, as the script writes them
        remarks = HISTORY_SEP.join(old_blocks + ["Owner: ops team"])
        ssp = make_ssp({"uuid": "1", "control-id": "ac-17", "remarks": remarks})
        with tempfile.TemporaryDirectory() as d:
            _, reqs, _ = run_ssp(d, ssp, FINDINGS)
        parts = reqs["ac-17"]["remarks"].split(HISTORY_SEP)
        blocks = [p for p in parts if p.startswith("[ubuntu-sec-audit ")]
        self.assertEqual(len(blocks), 10)
        self.assertNotIn("2020-01", blocks[0])                # the new one first
        self.assertEqual(blocks[1:], old_blocks[:9])          # then the newest old ones
        self.assertEqual(parts[-1], "Owner: ops team")        # remarks by people are kept


if __name__ == "__main__":
    unittest.main()
