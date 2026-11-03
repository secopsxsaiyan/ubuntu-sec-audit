#!/usr/bin/env python3
"""
update_ssp.py — Update an OSCAL System Security Plan with assessment findings.

Reads assessment findings (JSONL) and the control mapping, then prepends a
dated remark to each matching implemented-requirement in an existing SSP:
  - every mapped check satisfied  -> "Assessment status: implemented" + evidence
  - any check not satisfied       -> "Assessment status: partial" + remediation
  - any check that did not complete (status "error"), or whose status this
    script does not know -> "partial", because compliance could not be
    confirmed
  - checks that were skipped or do not apply to the host were not assessed:
    they change neither the status nor the evidence of any control, and a
    control that only such checks map to is left as it is.
Control ids from the mapping are converted to OSCAL ids (SC-28(1) -> sc-28.1,
CIS numbers -> cis_<number>) the same way oscal_generate.py writes them.

Remarks history: earlier remarks stay below the new one, separated by a
"--- Previous ---" line. Only the newest 10 assessment remarks written by
this script are kept per control (MAX_HISTORY); remarks written by people
are always kept.

When a control was updated, metadata.last-modified is set to the time of
the run. The SSP is written to a temporary file in the output directory and
then renamed over the output, so --output may be the --ssp file itself and
an interrupted run never leaves a truncated SSP.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oscal_generate import NOT_ASSESSED, control_id, load_jsonl, write_atomic  # noqa: E402

# Remarks written by this script start with TOOL_TAG; HISTORY_SEP separates
# one remark from the next older one.
TOOL_TAG = "[ubuntu-sec-audit "
HISTORY_SEP = "\n--- Previous ---\n"
MAX_HISTORY = 10  # assessment remarks by this script kept per control


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_control_status_map(
    findings: List[Dict], mapping: Dict, catalog: str
) -> Dict[str, Dict]:
    """
    Returns {control_id: {"state": "implemented|partial", "evidence": [...], "remediation": [...]}}
    aggregated across the assessed findings. A control is "partial" if ANY
    assessed check for it is not satisfied. Checks that were skipped or not
    applicable are left out.
    """
    ctrl_map: Dict[str, Dict] = {}
    for item in findings:
        status = item.get("status")
        if status in NOT_ASSESSED:
            continue
        check_id = item.get("check_id", "")
        entry = mapping.get(check_id, {})
        controls = [control_id(c, catalog) for c in entry.get(catalog, [])] if isinstance(entry, dict) else []
        for ctrl in controls:
            info = ctrl_map.setdefault(ctrl, {"state": "implemented", "evidence": [], "remediation": []})
            if status == "not-satisfied":
                info["state"] = "partial"
                if item.get("remediation"):
                    info["remediation"].append(f"[{check_id}] {item['remediation']}")
            elif status == "error":
                info["state"] = "partial"
                info["remediation"].append(
                    f"[{check_id}] the check did not complete - fix the error and re-run the audit"
                )
            elif status != "satisfied":
                info["state"] = "partial"
                info["remediation"].append(
                    f"[{check_id}] unknown status {status!r} - compliance could not be confirmed"
                )
            if item.get("evidence"):
                info["evidence"].append(
                    f"[{check_id} @ {item.get('timestamp', '')}] {item['evidence']}"
                )
    return ctrl_map


def with_history(new_remark: str, existing: str) -> str:
    """NEW_REMARK above EXISTING, keeping at most MAX_HISTORY remarks by
    this script (newest first) and every remark written by someone else."""
    # Evidence comes from the audited system; it must not fake a separator.
    new_remark = new_remark.replace(HISTORY_SEP, "\n-- Previous --\n")
    parts = [new_remark] + (existing.split(HISTORY_SEP) if existing else [])
    kept: List[str] = []
    ours = 0
    for part in parts:
        if part.startswith(TOOL_TAG):
            ours += 1
            if ours > MAX_HISTORY:
                continue
        kept.append(part)
    return HISTORY_SEP.join(kept)


def update_ssp(ssp: Dict, ctrl_map: Dict, dry_run: bool = False) -> Dict:
    """
    Walk the SSP implemented-requirements and update each with assessment
    evidence; set metadata.last-modified when anything changed.
    Returns the modified SSP dict.
    """
    ssp_body = ssp.get("system-security-plan", {})
    ctrl_impl = ssp_body.get("control-implementation", {})
    impl_reqs = ctrl_impl.get("implemented-requirements", [])
    timestamp = utc_now()

    changes = 0
    skipped = 0

    for req in impl_reqs:
        ctrl_id = req.get("control-id", "").lower()
        if ctrl_id not in ctrl_map:
            skipped += 1
            continue

        info = ctrl_map[ctrl_id]

        # Build evidence remark
        evidence_text = "\n".join(info["evidence"][:5])  # cap at 5 entries
        if len(info["evidence"]) > 5:
            evidence_text += f"\n... and {len(info['evidence'])-5} more."

        new_remark = (
            f"{TOOL_TAG}{timestamp}] "
            f"Assessment status: {info['state']}.\n"
        )
        if evidence_text:
            new_remark += f"Evidence:\n{evidence_text}\n"
        if info["remediation"]:
            new_remark += "Required actions:\n" + "\n".join(info["remediation"][:3])

        if not dry_run:
            req["remarks"] = with_history(new_remark, req.get("remarks", ""))

        action = "UPDATED" if info["state"] == "implemented" else "PARTIAL"
        print(f"  {action}: {ctrl_id} — {info['state']}")
        changes += 1

    if changes and not dry_run and isinstance(ssp_body.get("metadata"), dict):
        ssp_body["metadata"]["last-modified"] = timestamp

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
                   help="Output path for updated SSP JSON (may be the --ssp file)")
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

    with open(ssp_path, encoding="utf-8") as fh:
        ssp = json.load(fh)
    findings = load_jsonl(findings_path)
    with open(mapping_path, encoding="utf-8") as fh:
        mapping = json.load(fh)

    ctrl_map = build_control_status_map(findings, mapping, args.catalog)
    n_not_assessed = sum(1 for f in findings if f.get("status") in NOT_ASSESSED)
    print(f"Control map built: {len(ctrl_map)} unique control(s) from {len(findings)} findings"
          f" ({n_not_assessed} skipped or not applicable, ignored)\n")

    updated_ssp = update_ssp(ssp, ctrl_map, dry_run=args.dry_run)

    if not args.dry_run:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(updated_ssp, indent=2, ensure_ascii=False) + "\n"
        write_atomic(output_path, data.encode("utf-8"))
        print(f"\nUpdated SSP written to: {output_path}")
    else:
        print("\n[dry-run] No file written.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
