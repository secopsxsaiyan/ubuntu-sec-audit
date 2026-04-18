#!/usr/bin/env python3
"""
update_ssp.py — Update an OSCAL System Security Plan with assessment findings.

Reads assessment findings (JSONL) and the control mapping, then updates the
implemented-requirements in an existing SSP to reflect current evidence:
  - "satisfied" findings  → status "implemented", adds evidence remark
  - "not-satisfied"       → status "partial",      adds remediation remark

Requirements: Python 3.6+ stdlib only.

Usage:
  python3 oscal/update_ssp.py \\
      --ssp       ssp.json \\
      --findings  sec-audit-findings-20250115.jsonl \\
      --mapping   mappings/control-mapping.json \\
      --catalog   nist \\
      --output    ssp-updated.json

  # Dry-run (print changes, do not write):
  python3 oscal/update_ssp.py --ssp ssp.json --findings findings.jsonl \\
      --mapping mappings/control-mapping.json --catalog nist --dry-run
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_jsonl(path: Path) -> List[Dict]:
    findings = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return findings


def build_control_status_map(
    findings: List[Dict], mapping: Dict, catalog: str
) -> Dict[str, Dict]:
    """
    Returns {control_id: {"state": "implemented|partial", "evidence": "...", "remediation": "..."}}
    aggregated across all findings.  A control is "partial" if ANY finding for it is not-satisfied.
    """
    ctrl_map: Dict[str, Dict] = {}
    for item in findings:
        check_id = item.get("check_id", "")
        controls = [c.lower() for c in mapping.get(check_id, {}).get(catalog, [])]
        for ctrl in controls:
            if ctrl not in ctrl_map:
                ctrl_map[ctrl] = {
                    "state": "implemented",
                    "evidence": [],
                    "remediation": []
                }
            if item.get("status") == "not-satisfied":
                ctrl_map[ctrl]["state"] = "partial"
                if item.get("remediation"):
                    ctrl_map[ctrl]["remediation"].append(
                        f"[{item.get('check_id')}] {item['remediation']}"
                    )
            if item.get("evidence"):
                ctrl_map[ctrl]["evidence"].append(
                    f"[{item.get('check_id')} @ {item.get('timestamp','')}] "
                    f"{item['evidence']}"
                )
    return ctrl_map


def update_ssp(ssp: Dict, ctrl_map: Dict, dry_run: bool = False) -> Dict:
    """
    Walk the SSP implemented-requirements and update each with assessment evidence.
    Returns the modified SSP dict and a summary of changes.
    """
    ssp_body = ssp.get("system-security-plan", {})
    ctrl_impl = ssp_body.get("control-implementation", {})
    impl_reqs = ctrl_impl.get("implemented-requirements", [])

    changes = 0
    skipped = 0

    for req in impl_reqs:
        ctrl_id = req.get("control-id", "").lower()
        if ctrl_id not in ctrl_map:
            skipped += 1
            continue

        info = ctrl_map[ctrl_id]
        timestamp = utc_now()

        # Build evidence remark
        evidence_text = "\n".join(info["evidence"][:5])  # cap at 5 entries
        if len(info["evidence"]) > 5:
            evidence_text += f"\n... and {len(info['evidence'])-5} more."

        new_remark = (
            f"[ubuntu-sec-audit {timestamp}] "
            f"Assessment status: {info['state']}.\n"
        )
        if evidence_text:
            new_remark += f"Evidence:\n{evidence_text}\n"
        if info["remediation"]:
            new_remark += f"Required actions:\n" + "\n".join(info["remediation"][:3])

        if not dry_run:
            existing = req.get("remarks", "")
            # Prepend new assessment block, preserve history
            req["remarks"] = new_remark + (
                f"\n--- Previous ---\n{existing}" if existing else ""
            )

        action = "UPDATED" if info["state"] == "implemented" else "PARTIAL"
        print(f"  {action}: {ctrl_id} — {info['state']}")
        changes += 1

    print(f"\nSSP update: {changes} control(s) updated, {skipped} not in findings map.")
    return ssp


def main() -> int:
    p = argparse.ArgumentParser(
        description="Update OSCAL SSP implemented-requirements with audit evidence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("--ssp",      required=True, metavar="SSP_JSON",
                   help="Path to existing OSCAL SSP JSON")
    p.add_argument("--findings", required=True, metavar="JSONL",
                   help="Path to JSONL findings from ubuntu-sec-audit.sh --oscal")
    p.add_argument("--mapping",  required=True, metavar="JSON",
                   help="Path to mappings/control-mapping.json")
    p.add_argument("--catalog",  choices=["nist", "cis"], default="nist")
    p.add_argument("--output",   required=True, metavar="FILE",
                   help="Output path for updated SSP JSON")
    p.add_argument("--dry-run",  action="store_true",
                   help="Print changes without writing the output file")
    args = p.parse_args()

    ssp_path     = Path(args.ssp)
    findings_path = Path(args.findings)
    mapping_path  = Path(args.mapping)

    for path, name in [(ssp_path, "SSP"), (findings_path, "findings"), (mapping_path, "mapping")]:
        if not path.exists():
            print(f"Error: {name} file not found: {path}", file=sys.stderr)
            return 1

    with open(ssp_path) as fh:
        ssp = json.load(fh)
    findings = load_jsonl(findings_path)
    with open(mapping_path) as fh:
        mapping = json.load(fh)

    ctrl_map = build_control_status_map(findings, mapping, args.catalog)
    print(f"Control map built: {len(ctrl_map)} unique control(s) from {len(findings)} findings\n")

    updated_ssp = update_ssp(ssp, ctrl_map, dry_run=args.dry_run)

    if not args.dry_run:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(updated_ssp, fh, indent=2, ensure_ascii=False)
        print(f"\nUpdated SSP written to: {output_path}")
    else:
        print("\n[dry-run] No file written.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
