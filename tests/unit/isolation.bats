#!/usr/bin/env bats
# An unexpected failure inside one check must not end the audit, and the
# check must not be reported as passing.

load test_helper

setup() {
    load_audit
    check_fake_crash() {
        local x
        x=$(false | cat)          # pipefail makes this assignment fail
        echo "after crash" > "$BATS_TEST_TMPDIR/continued"
    }
    check_fake_next() { echo ran > "$BATS_TEST_TMPDIR/next-ran"; }
    check_fake_crash_after_issue() {
        report_issue 4 "Real problem" "d" "echo fix"
        false
    }
}

run_strict() {
    # Run like main() does: errexit, nounset and pipefail all on.
    set -euo pipefail
    _run_check check_fake_crash
    _run_check check_fake_next
    set +euo pipefail
}

@test "a crashing check does not stop the following checks" {
    run_strict
    [ -f "$BATS_TEST_TMPDIR/next-ran" ]
}

@test "a crashing check is recorded as error, not satisfied" {
    run_strict
    run findings_tsv
    [[ "$output" == *"$(printf 'check_fake_crash\terror')"* ]]
    [[ "$output" != *"$(printf 'check_fake_crash\tsatisfied')"* ]]
    [ "${CHECK_STATUS[check_fake_crash]}" = "error" ]
}

@test "the error is reported with the check name" {
    # Not `run run_strict`: bats runs that inside an || list, where bash
    # suppresses ERR traps. main() calls _run_check directly, as here.
    run_strict > "$BATS_TEST_TMPDIR/out.txt" 2>&1
    grep -q "check_fake_crash: unexpected error" "$BATS_TEST_TMPDIR/out.txt"
}

@test "issues found before a crash are kept and the check stays not-satisfied" {
    set -euo pipefail
    _run_check check_fake_crash_after_issue
    set +euo pipefail
    assert_issue "Real problem"
    [ "${CHECK_STATUS[check_fake_crash_after_issue]}" = "not-satisfied" ]
}

@test "errexit is restored after a check" {
    set -e
    _run_check check_fake_next
    [[ $- == *e* ]]
}
