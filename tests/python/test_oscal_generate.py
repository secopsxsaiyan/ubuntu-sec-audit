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
    # Not assessed. SI-7, AU-9 and SC-39 have no assessed check here;
    # SC-28 does (check_disk_encryption).
    {"check_id": "check_aide", "title": "check_aide: not checked", "status": "skipped",
     "evidence": "aide is not installed", "remediation": "", "points": 0, "timestamp": "2026-01-01T00:00:00Z"},
    {"check_id": "check_kernel_lockdown", "title": "check_kernel_lockdown: not applicable",
     "status": "not-applicable", "evidence": "not applicable in docker", "remediation": "", "points": 0,
     "timestamp": "2026-01-01T00:00:00Z"},
    {"check_id": "check_secure_boot", "title": "check_secure_boot: not applicable", "status": "not-applicable",
     "evidence": "not applicable in docker", "remediation": "", "points": 0, "timestamp": "2026-01-01T00:00:00Z"},
    # In no catalog of the mapping.
    {"check_id": "check_not_in_the_mapping", "title": "Something is wrong", "status": "not-satisfied",
     "evidence": "found it", "remediation": "fix it", "points": 5, "timestamp": "2026-01-01T00:00:00Z"},
]
NOT_ASSESSED = {"check_aide", "check_kernel_lockdown", "check_secure_boot"}


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
        cases = {
            "all statuses": FINDINGS,
            "nothing assessed": [f for f in FINDINGS if f["check_id"] in NOT_ASSESSED],
            "nothing mapped": [f for f in FINDINGS if f["check_id"] == "check_not_in_the_mapping"],
            "no findings": [],
        }
        for name, findings in cases.items():
            for catalog in ("nist", "cis"):
                with self.subTest(name, catalog=catalog), tempfile.TemporaryDirectory() as d:
                    _, ar = generate(d, "--frameworks", "nist,cis,iso27001,soc2",
                                     findings=findings, catalog=catalog)
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


def check_of(item):
    return next((p["value"] for p in item.get("props", []) if p["name"] == "check-id"), None)


def reviewed(result):
    sel = result["reviewed-controls"]["control-selections"]
    return ({c["control-id"] for s in sel for c in s.get("include-controls", [])},
            {c["control-id"] for s in sel for c in s.get("exclude-controls", [])})


class NotAssessedTests(unittest.TestCase):
    """Skipped and not-applicable checks are recorded, but decide nothing."""

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            cls.result = generate(d)[1]["assessment-results"]["results"][0]

    def test_no_finding_comes_from_a_check_that_was_not_assessed(self):
        checks = {check_of(f) for f in self.result["findings"]}
        self.assertEqual(checks & NOT_ASSESSED, set())
        self.assertIn("check_disk_encryption", checks)

    def test_the_observation_says_it_was_not_assessed_and_why(self):
        obs = {check_of(o): o for o in self.result["observations"]}
        for check, status, reason in (("check_aide", "skipped", "aide is not installed"),
                                      ("check_secure_boot", "not-applicable", "not applicable in docker")):
            with self.subTest(check):
                o = obs[check]
                self.assertIn(("status", status), {(p["name"], p["value"]) for p in o["props"]})
                text = (o["description"] + " " + " ".join(
                    e["description"] for e in o.get("relevant-evidence", []))).lower()
                self.assertIn("not assessed", text)
                self.assertIn(reason, text)

    def test_a_control_with_no_assessed_check_has_no_finding(self):
        targets = {f["target"]["target-id"]: f for f in self.result["findings"]}
        for control in ("si-7", "si-7.9", "au-9", "sc-39"):
            self.assertNotIn(control + "_obj", targets)
        # SC-28 comes only from check_disk_encryption, which was assessed.
        sc28 = [f for f in self.result["findings"] if f["target"]["target-id"] == "sc-28_obj"]
        self.assertEqual({check_of(f) for f in sc28}, {"check_disk_encryption"})
        self.assertEqual({f["target"]["status"]["state"] for f in sc28}, {"not-satisfied"})

    def test_reviewed_controls_are_the_assessed_ones(self):
        included, excluded = reviewed(self.result)
        self.assertIn("sc-28", included)
        self.assertEqual({"si-7", "si-7.9", "au-9", "sc-39"} & included, set())
        self.assertEqual({"si-7", "si-7.9", "au-9", "sc-39"}, excluded)

    def test_no_risk_comes_from_a_check_that_was_not_assessed(self):
        obs = {o["uuid"]: check_of(o) for o in self.result["observations"]}
        for risk in self.result.get("risks", []):
            for ref in risk["related-observations"]:
                self.assertNotIn(obs[ref["observation-uuid"]], NOT_ASSESSED)

    def test_counts(self):
        props = {p["name"]: p["value"] for p in self.result["props"]}
        self.assertEqual(props["skipped"], "1")
        self.assertEqual(props["not-applicable"], "2")
        self.assertEqual(props["satisfied"], "1")


class UnmappedCheckTests(unittest.TestCase):
    def test_findings_only_target_objectives_of_reviewed_controls(self):
        # No made-up objective ids such as "check_x-obj".
        for catalog in ("nist", "cis"):
            with self.subTest(catalog), tempfile.TemporaryDirectory() as d:
                result = generate(d, catalog=catalog)[1]["assessment-results"]["results"][0]
                included, _ = reviewed(result)
                for f in result["findings"]:
                    self.assertEqual(f["target"]["type"], "objective-id")
                    self.assertIn(f["target"]["target-id"], {c + "_obj" for c in included})

    def test_an_unmapped_check_is_an_observation_without_a_finding(self):
        with tempfile.TemporaryDirectory() as d:
            result = generate(d)[1]["assessment-results"]["results"][0]
        self.assertNotIn("check_not_in_the_mapping", {check_of(f) for f in result["findings"]})
        self.assertIn("check_not_in_the_mapping", {check_of(o) for o in result["observations"]})

    def test_a_check_without_ids_in_the_selected_catalog_has_no_finding(self):
        # check_disk_encryption maps to NIST only.
        with tempfile.TemporaryDirectory() as d:
            result = generate(d, catalog="cis")[1]["assessment-results"]["results"][0]
        self.assertNotIn("check_disk_encryption", {check_of(f) for f in result["findings"]})
        self.assertIn("check_ssh", {check_of(f) for f in result["findings"]})


NIST_CATALOG = ("https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
                "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json")


def static_documents():
    paths = list((REPO / "oscal").glob("*.json")) + list((REPO / "oscal" / "profiles").glob("*.json"))
    return {p.relative_to(REPO / "oscal").as_posix(): json.loads(p.read_text(encoding="utf-8"))
            for p in paths}


class StaticDocumentTests(unittest.TestCase):
    def test_static_oscal_documents_use_real_uuids(self):
        for name, doc in static_documents().items():
            for u in walk(doc, "uuid"):
                self.assertRegex(u, UUID_RE, f"{name}: {u}")

    def test_profiles_import_the_nist_oscal_catalog(self):
        for name, doc in static_documents().items():
            if name.startswith("profiles/"):
                for imp in doc["profile"]["imports"]:
                    self.assertEqual(imp["href"], NIST_CATALOG, name)

    def test_nist_control_implementations_name_the_oscal_catalog(self):
        cd = static_documents()["component_definition.json"]["component-definition"]
        sources = [ci["source"] for comp in cd["components"]
                   for ci in comp.get("control-implementations", [])]
        self.assertIn(NIST_CATALOG, sources)

    def test_no_reference_points_at_the_nist_html_page(self):
        for name, doc in static_documents().items():
            for key in ("href", "source"):
                for value in walk(doc, key):
                    self.assertNotIn("csrc.nist.gov", value, name)

    def test_fragment_references_resolve_to_a_back_matter_resource(self):
        # "#<uuid>" names a resource in the same document's back-matter.
        for name, doc in static_documents().items():
            resources = {r["uuid"] for lst in walk(doc, "resources") for r in lst}
            for href in walk(doc, "href"):
                if href.startswith("#"):
                    self.assertIn(href[1:], resources, f"{name}: {href}")

    def test_assessment_plan_imports_a_described_ssp(self):
        ap = static_documents()["assessment-plan.json"]["assessment-plan"]
        href = ap["import-ssp"]["href"]
        self.assertTrue(href.startswith("#"), href)
        resource = next(r for r in ap["back-matter"]["resources"] if r["uuid"] == href[1:])
        self.assertIn("System Security Plan", resource["title"])
        self.assertTrue(resource.get("description"))

    def test_assessment_plan_schedule_matches_the_timers(self):
        timing = {}
        for task in static_documents()["assessment-plan.json"]["assessment-plan"]["tasks"]:
            mode = "deep" if "Deep" in task["title"] else "standard"
            freq = task["timing"]["at-frequency"]
            timing[mode] = (freq["period"], freq["unit"])
        self.assertEqual(timing, {"standard": (1, "weeks"), "deep": (1, "months")})
        # The timers the plan describes.
        self.assertIn("Weekly", (REPO / "systemd" / "ubuntu-sec-audit.timer").read_text())
        self.assertIn("Monthly", (REPO / "systemd" / "ubuntu-sec-audit-deep.timer").read_text())

    def test_assessment_plan_names_the_files_the_tool_writes(self):
        text = AP.read_text(encoding="utf-8")
        for name in ("oscal-ar-YYYYMMDD-HHMMSS.json", "fix-audit-YYYYMMDD-HHMMSS.sh"):
            self.assertTrue(name in text, f"{name} is not in the assessment plan")
        self.assertNotRegex(text, r"YYYYMMDD-HHMM(?!SS)")
        self.assertNotIn("weekly deep", text.lower())
        # ... which are named after RUN_ID, a %Y%m%d-%H%M%S timestamp.
        lib = (REPO / "lib" / "report.sh").read_text() + (REPO / "lib" / "fixscript.sh").read_text()
        self.assertIn("RUN_ID=$(_new_run_id)", lib)
        self.assertIn("id=$(date +%Y%m%d-%H%M%S)", lib)
        self.assertIn('oscal-ar-${RUN_ID}.json', lib)
        self.assertIn('fix-audit-${RUN_ID', lib)


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
