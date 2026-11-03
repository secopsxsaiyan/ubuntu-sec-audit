"""Tests for oscal/oscal_generate.py: schema validity and control linkage."""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GEN = REPO / "oscal" / "oscal_generate.py"
MAPPING = REPO / "mappings" / "control-mapping.json"
AP = REPO / "oscal" / "assessment-plan.json"

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
# OSCAL "token": starts with a letter or underscore; letters, digits, . - _
TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]*$")

FINDINGS = [
    {"check_id": "check_ssh", "title": "SSH configuration weaknesses found", "status": "not-satisfied",
     "evidence": "PermitRootLogin yes", "remediation": "fix ssh", "points": 10, "timestamp": "2026-01-01T00:00:00Z"},
    {"check_id": "check_disk_encryption", "title": "No disk encryption detected", "status": "not-satisfied",
     "evidence": "no LUKS", "remediation": "", "points": 8, "timestamp": "2026-01-01T00:00:00Z"},
    {"check_id": "check_umask", "title": "check_umask: all sub-checks passed", "status": "satisfied",
     "evidence": "ok", "remediation": "", "points": 0, "timestamp": "2026-01-01T00:00:00Z"},
    {"check_id": "check_auditd", "title": "check_auditd: check did not complete", "status": "error",
     "evidence": "1 unexpected error(s)", "remediation": "", "points": 0, "timestamp": "2026-01-01T00:00:00Z"},
]


def run_generator(tmp, *extra, findings=FINDINGS, catalog="nist", env=None):
    f = Path(tmp, "findings.jsonl")
    f.write_text("".join(json.dumps(o) + "\n" for o in findings))
    out = Path(tmp, "out", "oscal-ar.json")
    r = subprocess.run([sys.executable, str(GEN), "--findings", str(f), "--mapping", str(MAPPING),
                        "--catalog", catalog, "--hostname", "h1", "--ubuntu-version", "24.04",
                        "--output", str(out), *extra], capture_output=True, text=True, env=env)
    return r, out


def generate(tmp, *extra, findings=FINDINGS, catalog="nist"):
    r, out = run_generator(tmp, *extra, findings=findings, catalog=catalog)
    if r.returncode != 0:
        raise AssertionError(r.stdout + r.stderr)
    return out, json.loads(out.read_text())


def have_trestle():
    try:
        import trestle  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


def walk(obj, key):
    """Yield every value stored under KEY anywhere in OBJ."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                yield v
            yield from walk(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v, key)


class SchemaTests(unittest.TestCase):
    def test_validates_against_trestle_models(self):
        try:
            from trestle.oscal.assessment_results import AssessmentResults  # type: ignore
        except ImportError:
            self.skipTest("compliance-trestle not installed")
        for catalog in ("nist", "cis"):
            with tempfile.TemporaryDirectory() as d:
                _, ar = generate(d, "--frameworks", "nist,cis,iso27001,soc2", catalog=catalog)
                AssessmentResults.model_validate(ar["assessment-results"])

    def test_parties_are_people_or_organisations(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        for party in ar["assessment-results"]["metadata"]["parties"]:
            self.assertIn(party["type"], ("person", "organization"))

    def test_tool_actors_reference_a_component(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        result = ar["assessment-results"]["results"][0]
        components = {c["uuid"] for c in result["local-definitions"]["components"]}
        actors = list(walk(result.get("risks", []), "actors"))
        self.assertTrue(actors)
        for actor_list in actors:
            for actor in actor_list:
                self.assertEqual(actor["type"], "tool")
                self.assertIn(actor["actor-uuid"], components)
                self.assertNotIn("title", actor)

    def test_every_uuid_is_rfc4122(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        for u in walk(ar, "uuid"):
            self.assertRegex(u, UUID_RE)


class ValidateFlagTests(unittest.TestCase):
    def test_validate_fails_when_trestle_is_missing(self):
        # A CI gate that asks for validation must not pass without it.
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d, "no-trestle", "trestle")
            fake.mkdir(parents=True)
            (fake / "__init__.py").write_text("raise ImportError('simulated: not installed')\n")
            env = dict(os.environ, PYTHONPATH=str(fake.parent))
            r, out = run_generator(d, "--validate", env=env)
            self.assertTrue(out.is_file())  # the AR itself is still written
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("compliance-trestle", r.stderr)
        self.assertNotIn("PASSED", r.stdout + r.stderr)
        self.assertNotIn("SKIPPED", r.stdout + r.stderr)

    @unittest.skipUnless(have_trestle(), "compliance-trestle not installed")
    def test_validate_passes_with_trestle(self):
        with tempfile.TemporaryDirectory() as d:
            r, _ = run_generator(d, "--validate")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASSED", r.stdout)


class ControlIdTests(unittest.TestCase):
    def test_nist_enhancements_use_oscal_ids(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        ids = [c["control-id"] for c in walk(ar, "include-controls") for c in c]
        self.assertIn("sc-28.1", ids)
        self.assertNotIn("sc-28(1)", ids)
        for cid in ids:
            self.assertRegex(cid, TOKEN_RE)

    def test_cis_ids_are_valid_tokens(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d, catalog="cis")
        ids = [c["control-id"] for c in walk(ar, "include-controls") for c in c]
        self.assertTrue(ids)
        for cid in ids:
            self.assertRegex(cid, TOKEN_RE)
        self.assertIn("cis_5.1.20", ids)  # PermitRootLogin, CIS Ubuntu 24.04

    def test_findings_link_to_their_controls(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        targets = {f["target"]["target-id"] for f in ar["assessment-results"]["results"][0]["findings"]}
        self.assertIn("ac-17_obj", targets)   # check_ssh
        self.assertIn("sc-28.1_obj", targets)  # check_disk_encryption

    def test_profile_filtering_understands_enhancement_ids(self):
        profile = {"profile": {"uuid": "3f9d1c2a-1b2c-4d5e-8f90-123456789abc", "metadata": {},
                               "imports": [{"href": "x", "include-controls": [{"with-ids": ["sc-28.1"]}]}]}}
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "profile.json")
            p.write_text(json.dumps(profile))
            _, ar = generate(d, "--profile", str(p))
        checks = {prop["value"] for f in ar["assessment-results"]["results"][0]["findings"]
                  for prop in f.get("props", []) if prop["name"] == "check-id"}
        self.assertIn("check_disk_encryption", checks)
        self.assertNotIn("check_ssh", checks)


class ContentTests(unittest.TestCase):
    def test_import_ap_points_to_an_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            out, ar = generate(d)
            href = ar["assessment-results"]["import-ap"]["href"]
            self.assertTrue((out.parent / href).resolve().is_file(), href)

    def test_an_outdated_assessment_plan_next_to_the_ar_is_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            plan = Path(d, "out", "assessment-plan.json")
            plan.parent.mkdir()
            plan.write_text('{"assessment-plan": "from an older version"}')
            generate(d)
            self.assertEqual(plan.read_bytes(), AP.read_bytes())

    def test_an_identical_assessment_plan_is_left_alone(self):
        with tempfile.TemporaryDirectory() as d:
            plan = Path(d, "out", "assessment-plan.json")
            plan.parent.mkdir()
            plan.write_bytes(AP.read_bytes())
            os.utime(plan, (1000000000, 1000000000))
            generate(d)
            self.assertEqual(plan.stat().st_mtime, 1000000000)

    def test_the_plan_may_already_be_the_one_next_to_the_ar(self):
        with tempfile.TemporaryDirectory() as d:
            plan = Path(d, "out", "assessment-plan.json")
            plan.parent.mkdir()
            plan.write_bytes(AP.read_bytes())
            generate(d, "--assessment-plan", str(plan))
            self.assertEqual(plan.read_bytes(), AP.read_bytes())

    def test_tool_version_comes_from_the_caller(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d, "--tool-version", "9.8.7")
        props = {p["name"]: p["value"] for p in ar["assessment-results"]["metadata"]["props"]}
        self.assertEqual(props["tool-version"], "9.8.7")

    def test_other_framework_ids_are_written_as_props(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d, "--frameworks", "nist,iso27001,soc2")
        obs = [o for o in ar["assessment-results"]["results"][0]["observations"]
               if any(p["value"] == "check_ssh" for p in o["props"])][0]
        values = {(p["name"], p["value"]) for p in obs["props"]}
        self.assertIn(("iso27001-control", "A.8.5"), values)
        self.assertIn(("soc2-control", "CC6.1"), values)
        for p in obs["props"]:
            if p["name"].endswith("-control"):
                self.assertIn("ns", p)

    def test_a_check_that_did_not_complete_is_not_satisfied(self):
        with tempfile.TemporaryDirectory() as d:
            _, ar = generate(d)
        for f in ar["assessment-results"]["results"][0]["findings"]:
            if any(p["value"] == "check_auditd" for p in f.get("props", [])):
                self.assertEqual(f["target"]["status"]["state"], "not-satisfied")
                self.assertIn("did not complete", f["description"])
                break
        else:
            self.fail("no finding for check_auditd")


class StaticDocumentTests(unittest.TestCase):
    def test_static_oscal_documents_use_real_uuids(self):
        for path in list((REPO / "oscal").glob("*.json")) + list((REPO / "oscal" / "profiles").glob("*.json")):
            doc = json.loads(path.read_text())
            for u in walk(doc, "uuid"):
                self.assertRegex(u, UUID_RE, f"{path.name}: {u}")


class MappingTests(unittest.TestCase):
    def test_cis_ids_exist_in_the_ubuntu_2404_benchmark(self):
        ref = REPO / "tests" / "data" / "cis-ubuntu-24.04-ids.txt"
        known = {l.strip() for l in ref.read_text().splitlines() if l.strip() and not l.startswith("#")}
        mapping = json.loads(MAPPING.read_text())
        unknown = sorted(f"{check}: {cid}" for check, entry in mapping.items() if isinstance(entry, dict)
                         for cid in entry.get("cis", []) if cid not in known)
        self.assertEqual(unknown, [], "CIS ids not in the 24.04 benchmark")


class StaticDocumentValidationTests(unittest.TestCase):
    def test_static_documents_validate_with_trestle(self):
        try:
            from trestle.oscal.assessment_plan import AssessmentPlan  # type: ignore
            from trestle.oscal.component import ComponentDefinition  # type: ignore
            from trestle.oscal.profile import Profile  # type: ignore
        except ImportError:
            self.skipTest("compliance-trestle not installed")
        docs = [("assessment-plan.json", AssessmentPlan, "assessment-plan"),
                ("component_definition.json", ComponentDefinition, "component-definition")]
        docs += [(f"profiles/{p.name}", Profile, "profile") for p in (REPO / "oscal" / "profiles").glob("*.json")]
        for rel, model, key in docs:
            with self.subTest(rel):
                model.model_validate(json.loads((REPO / "oscal" / rel).read_text())[key])


if __name__ == "__main__":
    unittest.main()
