#!/usr/bin/env python3
"""
oscal_generate.py — OSCAL Assessment Results generator for ubuntu-sec-audit.

Reads the JSONL findings file produced by ubuntu-sec-audit.sh and emits an
OSCAL 1.1.2 Assessment Results document.

Requirements: Python 3.6+ stdlib only.
Optional: pip install compliance-trestle  ->  enables --validate.

Usage:
  python3 oscal/oscal_generate.py \\
      --findings /var/log/audits/sec-audit-findings-20250115-103000.jsonl \\
      --mapping  mappings/control-mapping.json \\
      --catalog  nist \\
      --hostname myserver \\
      --ubuntu-version 24.04 \\
      --tool-version 2.3.0 \\
      --output   /var/log/audits/oscal-ar-20250115-103000.json

  # Also record ISO 27001 and SOC 2 control IDs as props:
  python3 oscal/oscal_generate.py ... --frameworks nist,iso27001,soc2

  # With OSCAL profile filtering:
  python3 oscal/oscal_generate.py ... --profile oscal/profiles/ssh-hardening.json

  # With compliance-trestle schema validation:
  python3 oscal/oscal_generate.py ... --validate

  # Delta comparison against a previous run:
  python3 oscal/oscal_generate.py ... --compare /var/log/audits/oscal-ar-20250101.json

Control IDs
  NIST ids follow the OSCAL SP 800-53 catalog: "SC-28(1)" becomes "sc-28.1".
  CIS recommendation numbers are not valid OSCAL tokens (they start with a
  digit), so they are written as "cis_<number>", e.g. "cis_5.1.20".

Check statuses
  Every check becomes one observation. Findings (one per mapped control
  objective, "<control>_obj") and risks are derived only from checks that
  were assessed:
    satisfied, not-satisfied  finding with that state
    error                     the check did not complete: not-satisfied,
                              because compliance is unknown
    skipped, not-applicable   not assessed (could not be performed / does
                              not apply to this host). OSCAL finding states
                              are only satisfied and not-satisfied, so these
                              checks get no finding and no risk; the
                              observation says they were not assessed and
                              why. Controls that only such checks map to
                              are listed under reviewed-controls
                              "exclude-controls".
  A check with no control in the selected catalog also gets an observation
  only; no control or objective id is made up for it.
"""

import argparse
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

OSCAL_VERSION = "1.1.2"
TOOL_NAME = "ubuntu-sec-audit"
# Namespace for props that OSCAL itself does not define.
NS = "https://github.com/secopsxsaiyan/ubuntu-sec-audit/ns/oscal"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_AP = SCRIPT_DIR / "assessment-plan.json"
AP_NAME = "assessment-plan.json"
FRAMEWORKS = ("nist", "cis", "iso27001", "soc2")
# Statuses of a check that was not assessed, with what they mean.
NOT_ASSESSED = {
    "skipped": "the check could not be performed",
    "not-applicable": "the check does not apply to this host",
}
STATUSES = ("satisfied", "not-satisfied", "error", "skipped", "not-applicable")


def is_assessed(item: Dict) -> bool:
    """False for a check that was skipped or does not apply."""
    return item.get("status") not in NOT_ASSESSED


def status_counts(findings: List[Dict]) -> Dict[str, int]:
    return {s: sum(1 for f in findings if f.get("status") == s) for s in STATUSES}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def make_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def prop(name: str, value: Any) -> Dict[str, str]:
    """A tool-specific property (namespaced, as OSCAL asks for custom names)."""
    return {"name": name, "value": str(value), "ns": NS}


def write_atomic(path: Path, data: bytes) -> None:
    """Write DATA to PATH through a temporary file in the same directory.

    Readers never see a half-written file, and PATH may also be the file
    the data was read from. A symlink is followed (as open() would), and
    an existing file keeps its permission bits.
    """
    path = Path(os.path.realpath(str(path)))
    try:
        mode = stat.S_IMODE(os.stat(str(path)).st_mode)
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def install_assessment_plan(src: Path, dst: Path) -> None:
    """Put the plan next to the AR, where its relative import-ap link points.

    Copied whenever it is missing or differs, so a newer plan also reaches
    report directories that already hold an older copy.
    """
    if not src.is_file():
        print(f"Warning: assessment plan not found: {src} — import-ap will not resolve",
              file=sys.stderr)
        return
    data = src.read_bytes()
    if dst.is_file() and dst.read_bytes() == data:
        return
    write_atomic(dst, data)


def control_id(raw: str, catalog: str) -> str:
    """Catalog control id as an OSCAL token."""
    cid = raw.strip()
    if catalog == "cis":
        return "cis_" + cid
    # NIST enhancement: AC-11(1) -> ac-11.1
    cid = re.sub(r"\((\d+)\)", r".\1", cid)
    return cid.lower()


def load_jsonl(path: Path) -> List[Dict]:
    """Findings, one JSON object per line.

    The script writes values from the audited system (file names, ...) byte
    for byte, so a line can hold bytes that are not UTF-8. Those are
    replaced with U+FFFD rather than losing every output to one file name.
    """
    findings: List[Dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"Warning: line {lineno} in {path} is not valid JSON — skipped: {exc}",
                      file=sys.stderr)
    return findings


def load_mapping(path: Path) -> Dict:
    if not path.exists():
        print(f"Warning: mapping file not found: {path} — control links will be empty",
              file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def controls_for(mapping: Dict, check_id: str, catalog: str) -> List[str]:
    entry = mapping.get(check_id, {})
    return [control_id(c, catalog) for c in entry.get(catalog, [])] if isinstance(entry, dict) else []


def load_profile_controls(profile_path: Path) -> List[str]:
    """
    Control ids selected by an OSCAL Profile (include-controls/with-ids).
    Returns an empty list (= no filtering) if the profile cannot be parsed.
    """
    try:
        with open(profile_path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:  # noqa: BLE001 - any unreadable profile means "no filter"
        print(f"Warning: cannot read profile {profile_path}: {exc}", file=sys.stderr)
        return []
    controls: List[str] = []
    for imp in doc.get("profile", {}).get("imports", []):
        for sel in imp.get("include-controls", []):
            controls.extend(c.lower() for c in sel.get("with-ids", []))
    return controls


def risk_level(points: int) -> str:
    """Same tiers as the script's severity (CRITICAL/HIGH/MEDIUM/LOW)."""
    if points >= 20:
        return "very-high"
    if points >= 10:
        return "high"
    if points >= 5:
        return "moderate"
    return "low"


# ---------------------------------------------------------------------------
# OSCAL document builders
# ---------------------------------------------------------------------------

def _build_metadata(hostname: str, ubuntu_version: str, tool_version: str) -> Dict:
    return {
        "title": f"Ubuntu Security Audit — {hostname} (Ubuntu {ubuntu_version})",
        "last-modified": utc_now(),
        "version": "1.0",
        "oscal-version": OSCAL_VERSION,
        "props": [
            prop("tool", TOOL_NAME),
            prop("tool-version", tool_version),
            prop("target-hostname", hostname),
            prop("target-os", f"Ubuntu {ubuntu_version}"),
        ],
        "roles": [
            {"id": "assessor", "title": "Security Assessor"},
        ],
        "parties": [
            {
                "uuid": make_uuid(),
                "type": "organization",
                "name": f"{TOOL_NAME} contributors",
                "remarks": f"Maintainers of {TOOL_NAME} {tool_version}, the automated assessment tool",
            }
        ],
    }


def _tool_component(tool_version: str) -> Dict:
    return {
        "uuid": make_uuid(),
        "type": "software",
        "title": TOOL_NAME,
        "description": f"{TOOL_NAME} {tool_version}: automated security audit for Ubuntu LTS.",
        "props": [prop("version", tool_version)],
        "status": {"state": "operational"},
    }


def _status_text(item: Dict) -> str:
    status = item.get("status")
    if status == "error":
        return "did not complete"
    if status in NOT_ASSESSED:
        return f"not assessed ({status})"
    return status or "unknown"


def _build_observation(item: Dict, controls: List[str], catalog: str,
                       other_ids: Dict[str, List[str]]) -> Dict:
    """One OSCAL observation per audit finding."""
    check_id = item.get("check_id", "unknown")
    status = item.get("status")
    description = item.get("evidence", "") or f"Automated check '{check_id}' executed"
    if status == "error":
        description = f"The check did not complete: {description}"
    elif status in NOT_ASSESSED:
        reason = item.get("evidence", "") or "no reason recorded"
        description = f"Not assessed: {NOT_ASSESSED[status]}. Reason: {reason}"
    props = [
        prop("check-id", check_id),
        prop("status", item.get("status", "unknown")),
        prop("score-pts", item.get("points", 0)),
    ]
    for fw, ids in other_ids.items():
        props.extend(prop(f"{fw}-control", cid) for cid in ids)
    obs: Dict[str, Any] = {
        "uuid": make_uuid(),
        "title": item.get("title", check_id),
        "description": description,
        "props": props,
        "methods": ["TEST"],
        "collected": item.get("timestamp", utc_now()),
    }
    if controls:
        obs["relevant-evidence"] = [{
            "description": (
                f"Automated check '{check_id}' mapped to {catalog.upper()} control(s): "
                f"{', '.join(controls)}. Status: {_status_text(item)}."
            )
        }]
    if not is_assessed(item):
        obs["remarks"] = "Not assessed, so no finding or risk is derived from this observation."
    elif not controls:
        obs["remarks"] = (f"No {catalog.upper()} control is mapped to check '{check_id}', "
                          f"so no finding is derived from this observation.")
    return obs


def _build_findings(item: Dict, obs_uuid: str, controls: List[str],
                    risk_uuid: Optional[str]) -> List[Dict]:
    """One finding per mapped control (OSCAL findings target one objective).

    None for a check that was not assessed, or that maps to no control in
    the catalog: there is no objective to make a finding about.
    """
    if not controls or not is_assessed(item):
        return []
    status = item.get("status")
    # A check that did not complete cannot be called satisfied.
    state = "satisfied" if status == "satisfied" else "not-satisfied"
    check_id = item.get("check_id", "unknown")

    description = item.get("evidence", "") or ""
    if status == "error":
        description = f"The check did not complete, so compliance is unknown. {description}".strip()
    elif item.get("remediation") and state == "not-satisfied":
        description += f"\n\nRemediation: {item['remediation']}"
    if not description:
        description = f"Automated check '{check_id}': {state}."

    out = []
    for target in (f"{c}_obj" for c in controls):
        finding: Dict[str, Any] = {
            "uuid": make_uuid(),
            "title": item.get("title", check_id),
            "description": description,
            "props": [prop("check-id", check_id)],
            "target": {
                "type": "objective-id",
                "target-id": target,
                "status": {"state": state},
            },
            "related-observations": [{"observation-uuid": obs_uuid}],
        }
        if risk_uuid:
            finding["related-risks"] = [{"risk-uuid": risk_uuid}]
        out.append(finding)
    return out


def _build_risk(item: Dict, obs_uuid: str, tool_uuid: str) -> Optional[Dict]:
    """An OSCAL risk for each not-satisfied finding that costs points."""
    if item.get("status") != "not-satisfied":
        return None
    points = item.get("points", 0)
    if points <= 0:
        return None
    level = risk_level(points)
    return {
        "uuid": make_uuid(),
        "title": f"Risk: {item.get('title', item.get('check_id'))}",
        "description": item.get("evidence", "") or "See the related observation.",
        "statement": item.get("remediation", "") or "See finding description.",
        "status": "open",
        "characterizations": [{
            "origin": {"actors": [{"type": "tool", "actor-uuid": tool_uuid}]},
            "facets": [
                {"name": "likelihood", "system": NS, "value": level},
                {"name": "impact", "system": NS, "value": level},
            ],
        }],
        "related-observations": [{"observation-uuid": obs_uuid}],
    }


def build_assessment_results(
    findings: List[Dict],
    mapping: Dict,
    catalog: str,
    hostname: str,
    ubuntu_version: str,
    audit_start: str,
    audit_end: str,
    tool_version: str = "unknown",
    frameworks: Iterable[str] = (),
    ap_href: str = f"./{AP_NAME}",
) -> Dict:
    """Assemble the complete OSCAL Assessment Results document."""
    tool = _tool_component(tool_version)
    others = [fw for fw in frameworks if fw in FRAMEWORKS and fw != catalog]

    observations: List[Dict] = []
    ar_findings: List[Dict] = []
    risks: List[Dict] = []
    assessed_controls: set = set()
    not_assessed_controls: set = set()

    for item in findings:
        check_id = item.get("check_id", "unknown")
        controls = controls_for(mapping, check_id, catalog)
        (assessed_controls if is_assessed(item) else not_assessed_controls).update(controls)
        entry = mapping.get(check_id, {}) if isinstance(mapping.get(check_id), dict) else {}
        other_ids = {fw: list(entry.get(fw, [])) for fw in others if entry.get(fw)}

        obs = _build_observation(item, controls, catalog, other_ids)
        observations.append(obs)
        risk = _build_risk(item, obs["uuid"], tool["uuid"])
        if risk:
            risks.append(risk)
        ar_findings.extend(_build_findings(item, obs["uuid"], controls,
                                           risk["uuid"] if risk else None))

    # Reviewed = assessed by at least one check. OSCAL needs a selection
    # here; with nothing assessed it stays the plan's (include-all).
    selection: Dict[str, Any]
    if assessed_controls:
        selection = {
            "description": "Controls with at least one check that was assessed in this run.",
            "include-controls": [{"control-id": c} for c in sorted(assessed_controls)],
        }
    else:
        selection = {
            "description": "No control was assessed in this run; the scope is left as planned.",
            "include-all": {},
        }
    excluded = sorted(not_assessed_controls - assessed_controls)
    if excluded:
        selection["exclude-controls"] = [{"control-id": c} for c in excluded]
        selection["remarks"] = ("Excluded: every check for these controls was skipped or not "
                                "applicable in this run, so they were not assessed and have no finding.")

    total = len(findings)
    n = status_counts(findings)

    result: Dict[str, Any] = {
        "uuid": make_uuid(),
        "title": f"Security Assessment of {hostname}",
        "description": (
            f"Automated security assessment of Ubuntu {ubuntu_version} on host '{hostname}'. "
            f"Catalog: {catalog.upper()}. Checks recorded: {total}. Satisfied: {n['satisfied']}. "
            f"Not-satisfied: {n['not-satisfied']}. Did not complete: {n['error']}. "
            f"Not assessed: {n['skipped']} skipped, {n['not-applicable']} not applicable."
        ),
        "start": audit_start,
        "end": audit_end,
        "props": [
            prop("catalog", catalog),
            prop("total-checks", total),
            prop("satisfied", n["satisfied"]),
            prop("not-satisfied", n["not-satisfied"]),
            prop("incomplete", n["error"]),
            prop("skipped", n["skipped"]),
            prop("not-applicable", n["not-applicable"]),
        ],
        "local-definitions": {"components": [tool]},
        "reviewed-controls": {"control-selections": [selection]},
    }
    # OSCAL does not allow these lists to be empty.
    if observations:
        result["observations"] = observations
    if ar_findings:
        result["findings"] = ar_findings
    if risks:
        result["risks"] = risks

    return {
        "assessment-results": {
            "uuid": make_uuid(),
            "metadata": _build_metadata(hostname, ubuntu_version, tool_version),
            "import-ap": {"href": ap_href},
            "results": [result],
        }
    }


# ---------------------------------------------------------------------------
# Delta comparison
# ---------------------------------------------------------------------------

def compute_delta(new_ar: Dict, old_ar_path: Path) -> None:
    """Compare new AR against a previous one and print a change summary."""
    try:
        with open(old_ar_path, encoding="utf-8") as fh:
            old_ar = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"Delta: cannot read previous AR {old_ar_path}: {exc}", file=sys.stderr)
        return

    def extract_findings(ar: Dict) -> Dict[str, str]:
        """{check-id/target-id: state}; a check failing any target is failing."""
        out: Dict[str, str] = {}
        for result in ar.get("assessment-results", {}).get("results", []):
            for f in result.get("findings", []):
                check = next((p["value"] for p in f.get("props", []) if p.get("name") == "check-id"), "")
                tid = f.get("target", {}).get("target-id", f.get("uuid", "?"))
                key = f"{check}/{tid}" if check else tid
                out[key] = f.get("target", {}).get("status", {}).get("state", "unknown")
        return out

    old_findings = extract_findings(old_ar)
    new_findings = extract_findings(new_ar)
    old_ids, new_ids = set(old_findings), set(new_findings)

    resolved = [i for i in old_ids & new_ids
                if old_findings[i] == "not-satisfied" and new_findings[i] == "satisfied"]
    new_issues = [i for i in old_ids & new_ids
                  if old_findings[i] == "satisfied" and new_findings[i] == "not-satisfied"]
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)

    print(f"\n=== Delta vs {old_ar_path.name} ===")
    print(f"  Resolved (were failing, now passing): {len(resolved)}")
    for i in sorted(resolved):
        print(f"    ✓ {i}")
    print(f"  Newly failing (were passing, now failing): {len(new_issues)}")
    for i in sorted(new_issues):
        print(f"    ✗ {i}")
    if added:
        print(f"  New checks (not in previous run): {len(added)}")
        for i in added:
            print(f"    + {i}")
    if removed:
        print(f"  No finding in current run (not run, skipped or not applicable): {len(removed)}")
        for i in removed:
            print(f"    - {i}")
    print()


# ---------------------------------------------------------------------------
# Optional compliance-trestle validation
# ---------------------------------------------------------------------------

def validate_with_trestle(ar_path: Path) -> bool:
    """Validate the generated AR against the OSCAL models in compliance-trestle.

    Without trestle nothing is validated, which is a failure: --validate is
    used as a gate, and a gate must not pass on a check it did not make.
    """
    try:
        from trestle.oscal.assessment_results import AssessmentResults  # type: ignore
    except ImportError as exc:
        print(f"OSCAL schema validation: NOT RUN — --validate needs compliance-trestle, "
              f"which cannot be imported ({exc}). Install it with: "
              f"pip install -r {SCRIPT_DIR / 'requirements-optional.txt'}. "
              f"The AR was written to {ar_path} but has not been validated.",
              file=sys.stderr)
        return False
    try:
        with open(ar_path, encoding="utf-8") as fh:
            raw = json.load(fh)
        data = raw.get("assessment-results", raw)
        if hasattr(AssessmentResults, "model_validate"):
            AssessmentResults.model_validate(data)
        else:  # pydantic v1-based trestle
            AssessmentResults.parse_obj(data)
        print("OSCAL schema validation: PASSED  (compliance-trestle)")
        return True
    except Exception as exc:  # noqa: BLE001 - report any validation error
        print(f"OSCAL schema validation: FAILED  — {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate OSCAL 1.1.2 Assessment Results from ubuntu-sec-audit findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--findings", required=True, metavar="JSONL",
                   help="Path to the JSONL findings file produced by ubuntu-sec-audit.sh")
    p.add_argument("--mapping", required=True, metavar="JSON",
                   help="Path to mappings/control-mapping.json")
    p.add_argument("--catalog", choices=["nist", "cis"], default="nist",
                   help="Control catalog to reference (default: nist)")
    p.add_argument("--frameworks", default="",
                   help="Comma-separated frameworks; ids of those other than the catalog "
                        "are added as props (e.g. nist,iso27001,soc2)")
    p.add_argument("--hostname", default="unknown", help="Target system hostname")
    p.add_argument("--ubuntu-version", default="unknown", help="Ubuntu version string, e.g. 24.04")
    p.add_argument("--tool-version", default="unknown", help="ubuntu-sec-audit version")
    p.add_argument("--audit-start", default=None, help="Audit start timestamp ISO 8601 (default: now)")
    p.add_argument("--audit-end", default=None, help="Audit end timestamp ISO 8601 (default: now)")
    p.add_argument("--output", required=True, metavar="FILE", help="Output path for the OSCAL AR JSON file")
    p.add_argument("--assessment-plan", default=str(DEFAULT_AP), metavar="AP_JSON",
                   help=f"Assessment Plan copied next to the output as {AP_NAME} (import-ap)")
    p.add_argument("--profile", default=None, metavar="OSCAL_PROFILE",
                   help="OSCAL Profile JSON to filter which checks appear in the AR")
    p.add_argument("--validate", action="store_true",
                   help="Validate output with compliance-trestle; exits non-zero if the AR is "
                        "invalid or trestle is not installed (pip install compliance-trestle)")
    p.add_argument("--compare", default=None, metavar="PREV_AR",
                   help="Path to a previous OSCAL AR for delta comparison")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
        return 1

    mapping = load_mapping(Path(args.mapping))
    findings = load_jsonl(findings_path)
    if not findings:
        print("Warning: findings file is empty — AR will contain no observations", file=sys.stderr)

    if args.profile:
        profile_controls = load_profile_controls(Path(args.profile))
        if profile_controls:
            wanted = {control_id(c, args.catalog) if args.catalog == "nist" else c
                      for c in profile_controls}
            before = len(findings)
            findings = [
                f for f in findings
                if not controls_for(mapping, f.get("check_id", ""), args.catalog)
                or set(controls_for(mapping, f.get("check_id", ""), args.catalog)) & wanted
            ]
            print(f"Profile filtering ({args.profile}): {len(findings)}/{before} findings retained "
                  f"({len(profile_controls)} controls selected)")
        else:
            print("Warning: profile file produced no control IDs — no filtering applied", file=sys.stderr)

    ar = build_assessment_results(
        findings=findings,
        mapping=mapping,
        catalog=args.catalog,
        hostname=args.hostname,
        ubuntu_version=args.ubuntu_version,
        audit_start=args.audit_start or utc_now(),
        audit_end=args.audit_end or utc_now(),
        tool_version=args.tool_version,
        frameworks=[fw.strip() for fw in args.frameworks.split(",") if fw.strip()],
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(ar, fh, indent=2, ensure_ascii=False)

    install_assessment_plan(Path(args.assessment_plan), output_path.parent / AP_NAME)

    result = ar["assessment-results"]["results"][0]
    n = status_counts(findings)
    print(f"OSCAL AR written to : {output_path}")
    print(f"Catalog             : {args.catalog.upper()}")
    print(f"Findings            : {len(findings)} checks — {n['satisfied']} satisfied, "
          f"{n['not-satisfied']} not-satisfied, {n['error']} did not complete, "
          f"{n['skipped'] + n['not-applicable']} not assessed")
    print(f"Risks               : {len(result.get('risks', []))} open risk(s)")

    if args.compare:
        compute_delta(ar, Path(args.compare))

    if args.validate and not validate_with_trestle(output_path):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
