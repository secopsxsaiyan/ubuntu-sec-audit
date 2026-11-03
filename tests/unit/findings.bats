#!/usr/bin/env bats
# Findings pipeline: check IDs, pass/fail records, JSON encoding, mapping,
# verify summary and delta report.

load test_helper

setup() {
    load_audit
    check_fake_fail() { report_issue 5 "Fake problem" "it is broken" "echo fix"; }
    check_fake_pass() { print_status OK "all good"; }
    check_fake_twice() {
        report_issue 3 "First problem" "a" "echo a"
        report_issue 3 "Second problem" "b" "echo b"
    }
}

@test "a failing check is recorded under its own check id, once" {
    _run_check check_fake_fail
    run findings_tsv
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf 'check_fake_fail\tnot-satisfied')" ]
}

@test "a passing check is recorded as satisfied, once" {
    _run_check check_fake_pass
    run findings_tsv
    [ "$output" = "$(printf 'check_fake_pass\tsatisfied')" ]
}

@test "a check with two issues gets two not-satisfied records and no satisfied one" {
    _run_check check_fake_twice
    run findings_tsv
    [ "${#lines[@]}" -eq 2 ]
    [ "${lines[0]}" = "$(printf 'check_fake_twice\tnot-satisfied')" ]
    [ "${lines[1]}" = "$(printf 'check_fake_twice\tnot-satisfied')" ]
    [ "${CHECK_IDS[0]}" = "check_fake_twice" ]
    [ "${CHECK_IDS[1]}" = "check_fake_twice" ]
}

@test "report_issue attaches control IDs for every selected framework" {
    cat > "$BATS_TEST_TMPDIR/map.json" <<'EOF'
{"_comment": "x",
 "check_fake_fail": {"nist": ["AC-1", "AC-2"], "cis": ["5.1.1"], "iso27001": ["A.5.1"], "soc2": []}}
EOF
    CONTROL_MAP_FILE="$BATS_TEST_TMPDIR/map.json"
    PATH="$ORIG_PATH" load_control_map
    FRAMEWORKS=(nist iso27001 soc2)
    _run_check check_fake_fail
    [ "${CTRL_IDS_ALL[0]}" = "nist:AC-1,AC-2|iso27001:A.5.1" ]
}

@test "report_issue does not start a python process per finding" {
    CONTROL_MAP_FILE="$REPO_ROOT/mappings/control-mapping.json"
    PATH="$ORIG_PATH" load_control_map
    mock_cmd python3 'echo called >> "'"$BATS_TEST_TMPDIR"'/python-calls"; exit 1'
    _run_check check_fake_twice
    [ ! -e "$BATS_TEST_TMPDIR/python-calls" ]
}

@test "findings are valid JSON with special characters and without python3" {
    rm -f "$MOCK_BIN/python3"
    record_finding check_x 'Title "quoted" \ back' not-satisfied $'line1\nline2\ttab\x01ctl' 'sed -i "s/a/b/" /etc/x' 7
    PATH="$ORIG_PATH" run python3 -c '
import json, sys
o = json.loads(open(sys.argv[1]).read())
assert o["check_id"] == "check_x", o
assert o["title"] == "Title \"quoted\" \\ back", o["title"]
assert o["evidence"] == "line1\nline2\ttab\x01ctl", repr(o["evidence"])
assert o["remediation"] == "sed -i \"s/a/b/\" /etc/x"
assert o["points"] == 7
assert o["status"] == "not-satisfied"
print("ok")
' "$FINDINGS_FILE"
    [ "$status" -eq 0 ]
    [ "$output" = "ok" ]
}

@test "verify summary counts fixed and still-failing checks" {
    VERIFY_MODE=1
    VERIFY_CHECKS=(check_fake_pass check_fake_fail)
    _run_check check_fake_pass
    _run_check check_fake_fail
    run _verify_counts
    [ "$output" = "1 1" ]
}

@test "delta report lists fixed, regressed and new failures" {
    printf '%s\n' '{"check_id": "check_a", "status": "not-satisfied"}' \
                  '{"check_id": "check_b", "status": "satisfied"}' > "$BATS_TEST_TMPDIR/prev.jsonl"
    printf '%s\n' '{"check_id": "check_a", "status": "satisfied"}' \
                  '{"check_id": "check_b", "status": "not-satisfied"}' \
                  '{"check_id": "check_c", "status": "not-satisfied"}' > "$BATS_TEST_TMPDIR/cur.jsonl"
    run _print_delta_report "$BATS_TEST_TMPDIR/cur.jsonl" "$BATS_TEST_TMPDIR/prev.jsonl"
    [[ "$output" == *"Fixed"*"check_a"* ]]
    [[ "$output" == *"Regressed"*"check_b"* ]]
    [[ "$output" == *"New failures"*"check_c"* ]]
}

@test "delta report treats a check with any failure as failing" {
    printf '%s\n' '{"check_id": "check_a", "status": "not-satisfied"}' > "$BATS_TEST_TMPDIR/prev.jsonl"
    printf '%s\n' '{"check_id": "check_a", "status": "not-satisfied"}' \
                  '{"check_id": "check_a", "status": "satisfied"}' > "$BATS_TEST_TMPDIR/cur.jsonl"
    run _print_delta_report "$BATS_TEST_TMPDIR/cur.jsonl" "$BATS_TEST_TMPDIR/prev.jsonl"
    [[ "$output" != *"Fixed"* ]]
}
