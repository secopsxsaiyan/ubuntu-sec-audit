#!/usr/bin/env python3
"""
oscal_generate.py — OSCAL Assessment Results generator for ubuntu-sec-audit.

Reads the JSONL findings file produced by ubuntu-sec-audit.sh (--oscal mode) and
emits a complete, schema-valid OSCAL 1.1.2 Assessment Results document.

Requirements: Python 3.6+ stdlib only (json, uuid, argparse, pathlib, sys, datetime).
Optional: pip install compliance-trestle   →  enables --validate flag.

Usage:
  python3 oscal/oscal_generate.py \\
      --findings /home/user/sec-audit-findings-20250115-1030.jsonl \\
      --mapping  mappings/control-mapping.json \\
      --catalog  nist \\
      --hostname myserver \\
      --ubuntu-version 24.04 \\
      --audit-start 2025-01-15T10:00:00Z \\
      --audit-end   2025-01-15T10:30:00Z \\
      --output   /home/user/oscal-ar-20250115.json

  # With OSCAL profile filtering:
  python3 oscal/oscal_generate.py ... --profile oscal/profiles/sshd-only.json

  # With compliance-trestle schema validation:
  python3 oscal/oscal_generate.py ... --validate

  # Delta comparison against a previous run:
  python3 oscal/oscal_generate.py ... --compare /home/user/oscal-ar-20250101.json
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

OSCAL_VERSION = "1.1.2"
TOOL_NAME = "ubuntu-sec-audit"
TOOL_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def make_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_jsonl(path: Path) -> List[Dict]:
    findings: List[Dict] = []
    with open(path) as fh:
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
    with open(path) as fh:
        return json.load(fh)


def load_profile_controls(profile_path: Path) -> List[str]:
    """
    Extract the set of included control-ids from an OSCAL Profile JSON.
    Supports both profile.imports[*].include-controls[*].with-ids and
    profile.imports[*].include-controls with individual control-id fields.
    Returns an empty list (= no filtering) if the profile cannot be parsed.
    """
    try:
        with open(profile_path) as fh:
            doc = json.load(fh)
    except Exception as exc:
        print(f"Warning: cannot read profile {profile_path}: {exc}", file=sys.stderr)
        return []

    controls: List[str] = []
    imports = doc.get("profile", {}).get("imports", [])
    for imp in imports:
        # OSCAL profile format: include-controls is a list of selection objects
        for sel in imp.get("include-controls", []):
            # with-ids: ["ac-2", "ac-3", ...]
            controls.extend(c.lower() for c in sel.get("with-ids", []))
    return controls


# ---------------------------------------------------------------------------
# OSCAL document builders
# ---------------------------------------------------------------------------

def _build_metadata(hostname: str, ubuntu_version: str) -> Dict:
    return {
        "title": f"Ubuntu Security Audit — {hostname} (Ubuntu {ubuntu_version})",
        "last-modified": utc_now(),
        "version": TOOL_VERSION,
        "oscal-version": OSCAL_VERSION,
        "props": [
            {"name": "tool", "value": TOOL_NAME},
            {"name": "tool-version", "value": TOOL_VERSION},
            {"name": "target-hostname", "value": hostname},
            {"name": "target-os", "value": f"Ubuntu {ubuntu_version}"}
        ],
        "roles": [
            {"id": "assessor",   "title": "Security Assessor"},
            {"id": "tool",       "title": "Automated Assessment Tool"}
        ],
        "parties": [
            {
                "uuid": make_uuid(),
                "type": "tool",
                "name": TOOL_NAME,
                "remarks": f"Automated security audit — {TOOL_NAME} {TOOL_VERSION}"
            }
        ]
    }


def _build_observation(item: Dict, controls: List[str], catalog: str) -> Dict:
    """Build a single OSCAL observation from one audit finding."""
    obs: Dict[str, Any] = {
        "uuid": make_uuid(),
        "title": item.get("title", item.get("check_id", "unknown")),
        "description": (
            item.get("evidence", "")
            or f"Automated check '{item.get('check_id','unknown')}' executed"
        ),
        "methods": ["TEST"],
        "collected": item.get("timestamp", utc_now()),
        "props": [
            {"name": "check-id",  "value": item.get("check_id", "unknown")},
            {"name": "status",    "value": item.get("status", "unknown")},
            {"name": "score-pts", "value": str(item.get("points", 0))}
        ]
    }

    if controls:
        catalog_upper = catalog.upper()
        obs["relevant-evidence"] = [
            {
                "description": (
                    f"Automated check '{item.get('check_id')}' mapped to "
                    f"{catalog_upper} control(s): {', '.join(controls)}. "
                    f"Status: {item.get('status','unknown')}."
                )
            }
        ]

    return obs


def _build_finding(item: Dict, obs_uuid: str, controls: List[str]) -> Dict:
    """Build a single OSCAL finding linked to an observation."""
    state = "not-satisfied" if item.get("status") == "not-satisfied" else "satisfied"
    check_id = item.get("check_id", "unknown")

    description = item.get("evidence", "") or ""
    if item.get("remediation") and state == "not-satisfied":
        description += f"\n\nRemediation: {item['remediation']}"

    finding: Dict[str, Any] = {
        "uuid": make_uuid(),
        "title": item.get("title", check_id),
        "description": description,
        "target": {
            "type": "objective-id",
            "target-id": f"{check_id}-obj",
            "status": {"state": state}
        },
        "related-observations": [{"observation-uuid": obs_uuid}]
    }

    return finding


def _build_risk(item: Dict, obs_uuid: str) -> Optional[Dict]:
    """Build an OSCAL risk entry for not-satisfied findings with a positive score."""
    if item.get("status") != "not-satisfied":
        return None
    points = item.get("points", 0)
    if points <= 0:
        return None

    level = "high" if points >= 10 else "medium"
    return {
        "uuid": make_uuid(),
        "title": f"Risk: {item.get('title', item.get('check_id'))}",
        "description": item.get("evidence", "") or "",
        "statement": item.get("remediation", "") or "See finding description.",
        "status": "open",
        "characterizations": [
            {
                "origin": {
                    "actors": [
                        {
                            "type": "tool",
                            "actor-uuid": make_uuid(),
                            "title": TOOL_NAME
                        }
                    ]
                },
                "facets": [
                    {
                        "name": "likelihood",
                        "system": "http://csrc.nist.gov/ns/oscal/unknown",
                        "value": level
                    },
                    {
                        "name": "impact",
                        "system": "http://csrc.nist.gov/ns/oscal/unknown",
                        "value": level
                    }
                ]
            }
        ],
        "related-observations": [{"observation-uuid": obs_uuid}]
    }


def build_assessment_results(
    findings: List[Dict],
    mapping: Dict,
    catalog: str,
    hostname: str,
    ubuntu_version: str,
    audit_start: str,
    audit_end: str
) -> Dict:
    """Assemble the complete OSCAL Assessment Results document."""

    observations: List[Dict] = []
    ar_findings: List[Dict] = []
    risks: List[Dict] = []
    all_controls: set = set()

    for item in findings:
        check_id = item.get("check_id", "unknown")
        # Retrieve controls from mapping; fall back gracefully
        raw_controls = mapping.get(check_id, {}).get(catalog, [])
        controls = [c.lower() for c in raw_controls]
        all_controls.update(controls)

        obs = _build_observation(item, controls, catalog)
        observations.append(obs)

        ar_findings.append(_build_finding(item, obs["uuid"], controls))

        risk = _build_risk(item, obs["uuid"])
        if risk:
            risks.append(risk)

    # reviewed-controls: list every control seen across all checks
    if all_controls:
        control_selections = [
            {
                "include-controls": [
                    {"control-id": cid} for cid in sorted(all_controls)
                ]
            }
        ]
    else:
        control_selections = [{"include-all": {}}]

    # Stats for description
    total = len(findings)
    n_fail = sum(1 for f in findings if f.get("status") == "not-satisfied")
    n_pass = total - n_fail

    return {
        "assessment-results": {
            "uuid": make_uuid(),
            "metadata": _build_metadata(hostname, ubuntu_version),
            "import-ap": {
                "href": "./assessment-plan.json"
            },
            "results": [
                {
                    "uuid": make_uuid(),
                    "title": f"Security Assessment of {hostname}",
                    "description": (
                        f"Automated security assessment of Ubuntu {ubuntu_version} "
                        f"on host '{hostname}'. "
                        f"Catalog: {catalog.upper()}. "
                        f"Checks run: {total}. "
                        f"Satisfied: {n_pass}. Not-satisfied: {n_fail}."
                    ),
                    "start": audit_start,
                    "end": audit_end,
                    "props": [
                        {"name": "catalog",     "value": catalog},
                        {"name": "total-checks","value": str(total)},
                        {"name": "satisfied",   "value": str(n_pass)},
                        {"name": "not-satisfied","value": str(n_fail)}
                    ],
                    "reviewed-controls": {
                        "control-selections": control_selections
                    },
                    "observations": observations,
                    "findings": ar_findings,
                    "risks": risks
                }
            ]
        }
    }


# ---------------------------------------------------------------------------
# Delta comparison
# ---------------------------------------------------------------------------

def compute_delta(new_ar: Dict, old_ar_path: Path) -> None:
    """Compare new AR against a previous one and print a change summary."""
    try:
        with open(old_ar_path) as fh:
            old_ar = json.load(fh)
    except Exception as exc:
        print(f"Delta: cannot read previous AR {old_ar_path}: {exc}", file=sys.stderr)
        return

    def extract_findings(ar: Dict) -> Dict[str, str]:
        """Return {target-id: state} for all findings."""
        out: Dict[str, str] = {}
        for result in ar.get("assessment-results", {}).get("results", []):
            for f in result.get("findings", []):
                tid = f.get("target", {}).get("target-id", f.get("uuid", "?"))
                state = f.get("target", {}).get("status", {}).get("state", "unknown")
                out[tid] = state
        return out

    old_findings = extract_findings(old_ar)
    new_findings = extract_findings(new_ar)

    old_ids = set(old_findings)
    new_ids = set(new_findings)

    resolved   = [i for i in old_ids & new_ids
                  if old_findings[i] == "not-satisfied" and new_findings[i] == "satisfied"]
    new_issues = [i for i in old_ids & new_ids
                  if old_findings[i] == "satisfied" and new_findings[i] == "not-satisfied"]
    added      = sorted(new_ids - old_ids)
    removed    = sorted(old_ids - new_ids)

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
        print(f"  Removed checks (not in current run): {len(removed)}")
        for i in removed:
            print(f"    - {i}")
    print()


# ---------------------------------------------------------------------------
# Optional compliance-trestle validation
# ---------------------------------------------------------------------------

def validate_with_trestle(ar_path: Path) -> bool:
    """Validate the generated AR against the OSCAL schema via compliance-trestle."""
    try:
        from trestle.oscal.assessment_results import AssessmentResults  # type: ignore
        with open(ar_path) as fh:
            raw = json.load(fh)
        ar_data = raw.get("assessment-results", raw)
        AssessmentResults(**ar_data)
        print("OSCAL schema validation: PASSED  (compliance-trestle)")
        return True
    except ImportError:
        print("OSCAL schema validation: SKIPPED "
              "(pip install compliance-trestle to enable --validate)")
        return True
    except Exception as exc:
        print(f"OSCAL schema validation: FAILED  — {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate OSCAL 1.1.2 Assessment Results from ubuntu-sec-audit findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("--findings",       required=True, metavar="JSONL",
                   help="Path to the JSONL findings file produced by ubuntu-sec-audit.sh")
    p.add_argument("--mapping",        required=True, metavar="JSON",
                   help="Path to mappings/control-mapping.json")
    p.add_argument("--catalog",        choices=["nist", "cis"], default="nist",
                   help="Control catalog to reference (default: nist)")
    p.add_argument("--hostname",       default="unknown",
                   help="Target system hostname")
    p.add_argument("--ubuntu-version", default="unknown",
                   help="Ubuntu version string, e.g. 24.04")
    p.add_argument("--audit-start",    default=None,
                   help="Audit start timestamp ISO 8601 (default: now)")
    p.add_argument("--audit-end",      default=None,
                   help="Audit end timestamp ISO 8601 (default: now)")
    p.add_argument("--output",         required=True, metavar="FILE",
                   help="Output path for the OSCAL AR JSON file")
    p.add_argument("--profile",        default=None, metavar="OSCAL_PROFILE",
                   help="OSCAL Profile JSON to filter which checks appear in the AR")
    p.add_argument("--validate",       action="store_true",
                   help="Validate output with compliance-trestle (requires: pip install compliance-trestle)")
    p.add_argument("--compare",        default=None, metavar="PREV_AR",
                   help="Path to a previous OSCAL AR for delta comparison")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # --- Resolve paths ---
    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"Error: findings file not found: {findings_path}", file=sys.stderr)
        return 1

    mapping_path = Path(args.mapping)
    mapping = load_mapping(mapping_path)

    # --- Load findings ---
    findings = load_jsonl(findings_path)
    if not findings:
        print("Warning: findings file is empty — AR will contain no observations", file=sys.stderr)

    # --- Optional profile filtering ---
    if args.profile:
        profile_controls = load_profile_controls(Path(args.profile))
        if profile_controls:
            profile_set = set(profile_controls)
            before = len(findings)
            findings = [
                f for f in findings
                if not set(c.lower() for c in mapping.get(f.get("check_id",""), {}).get(args.catalog, []))
                   or set(c.lower() for c in mapping.get(f.get("check_id",""), {}).get(args.catalog, []))
                      & profile_set
            ]
            print(f"Profile filtering ({args.profile}): "
                  f"{len(findings)}/{before} findings retained "
                  f"({len(profile_controls)} controls selected)")
        else:
            print("Warning: profile file produced no control IDs — no filtering applied",
                  file=sys.stderr)

    # --- Timestamps ---
    audit_start = args.audit_start or utc_now()
    audit_end   = args.audit_end   or utc_now()

    # --- Build OSCAL AR ---
    ar = build_assessment_results(
        findings=findings,
        mapping=mapping,
        catalog=args.catalog,
        hostname=args.hostname,
        ubuntu_version=args.ubuntu_version,
        audit_start=audit_start,
        audit_end=audit_end,
    )

    # --- Write output ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(ar, fh, indent=2, ensure_ascii=False)

    total    = len(findings)
    n_fail   = sum(1 for f in findings if f.get("status") == "not-satisfied")
    n_pass   = total - n_fail
    n_risks  = len(ar["assessment-results"]["results"][0]["risks"]) if findings else 0

    print(f"OSCAL AR written to : {output_path}")
    print(f"Catalog             : {args.catalog.upper()}")
    print(f"Findings            : {total} total — {n_pass} satisfied, {n_fail} not-satisfied")
    print(f"Risks               : {n_risks} open risk(s)")

    # --- Optional delta ---
    if args.compare:
        compute_delta(ar, Path(args.compare))

    # --- Optional validation ---
    if args.validate:
        ok = validate_with_trestle(output_path)
        if not ok:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
