#!/usr/bin/env python3
"""Verdict for the integration test.

Usage: check_expected.py FINDINGS_JSONL EXPECTED_TXT

Every check listed in EXPECTED_TXT (one per line, # comments allowed) must
appear in the findings file with at least one "not-satisfied" record.
Missing checks fail the run, so a broken or empty audit can never pass.
"""
import json
import sys


def main(findings_path: str, expected_path: str) -> int:
    failing = set()
    seen = set()
    with open(findings_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"  INVALID  line {lineno}: {exc}")
                return 1
            seen.add(obj["check_id"])
            if obj.get("status") == "not-satisfied":
                failing.add(obj["check_id"])

    with open(expected_path, encoding="utf-8") as fh:
        expected = [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]

    passed = failed = missing = 0
    for check in expected:
        if check in failing:
            print(f"  PASS  {check}")
            passed += 1
        elif check in seen:
            print(f"  FAIL  {check}  (ran but did not detect the expected issue)")
            failed += 1
        else:
            print(f"  MISSING  {check}  (no finding recorded)")
            missing += 1

    print(f"\n  Results: {passed} passed  {failed} failed  {missing} missing")
    return 0 if (failed == 0 and missing == 0 and passed > 0) else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
