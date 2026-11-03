#!/usr/bin/env bats
# Command-line parsing, the wizard, the OS guard and output locations.

load test_helper

setup() {
    load_audit
}

@test "--catalog does not replace the --framework list, in either order" {
    parse_args --framework nist,iso27001 --catalog cis </dev/null >/dev/null
    [ "${FRAMEWORKS[*]}" = "nist iso27001" ]
    [ "$OSCAL_CATALOG" = "cis" ]
    FRAMEWORKS=(nist)
    parse_args --catalog cis --framework nist,soc2 </dev/null >/dev/null
    [ "${FRAMEWORKS[*]}" = "nist soc2" ]
    [ "$OSCAL_CATALOG" = "cis" ]
}

@test "without --catalog the OSCAL catalog follows the primary framework" {
    parse_args --framework cis,nist </dev/null >/dev/null
    [ "$OSCAL_CATALOG" = "cis" ]
    parse_args --framework iso27001 </dev/null >/dev/null
    [ "$OSCAL_CATALOG" = "nist" ]
}

@test "unknown check names are rejected with the list of valid ones" {
    run parse_args --check check_umask,check_bogus </dev/null
    [ "$status" -ne 0 ]
    [[ "$output" == *"Unknown check: check_bogus"* ]]
    [[ "$output" == *"check_umask"* ]]
    run parse_args --skip check_nope </dev/null
    [ "$status" -ne 0 ]
}

@test "deep check names are accepted by --check" {
    parse_args --check check_deep_suid </dev/null >/dev/null
    [ "${RUN_ONLY[*]}" = "check_deep_suid" ]
}

@test "the old check_debsecan name still works and maps to check_security_updates" {
    run parse_args --skip check_debsecan </dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == *"check_security_updates"* ]]
    parse_args --skip check_debsecan </dev/null >/dev/null
    [ "${SKIP_CHECKS[*]}" = "check_security_updates" ]
}

@test "any flag counts as intent, so the wizard does not start on its own" {
    parse_args --skip-apt-update </dev/null >/dev/null
    [ "$_FLAGS_SET" -eq 1 ]
    _FLAGS_SET=0
    parse_args --verbose </dev/null >/dev/null
    [ "$_FLAGS_SET" -eq 1 ]
}

@test "the wizard offers the values already given as its defaults" {
    SKIP_APT_UPDATE=1
    FRAMEWORKS=(cis iso27001)
    OUTPUT_DIR="/srv/audits"
    DEEP=1
    # Not a pipe: that would run the wizard in a subshell and lose its effects.
    _interactive_wizard >/dev/null < <(printf '\n\n\n\n\n\n')
    [ "$SKIP_APT_UPDATE" -eq 1 ]
    [ "${FRAMEWORKS[*]}" = "cis iso27001" ]
    [ "$OUTPUT_DIR" = "/srv/audits" ]
    [ "$DEEP" -eq 1 ]
}

@test "OS guard reads /etc/os-release (lsb_release is not needed)" {
    refute command -v lsb_release
    fixture /etc/os-release $'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"'
    run _check_os_version
    [ "$status" -eq 0 ]
    [ "$ubuntu_ver" = "" ] || true
    fixture /etc/os-release $'ID=ubuntu\nVERSION_ID="18.04"'
    run _check_os_version
    [ "$status" -ne 0 ]
    fixture /etc/os-release $'ID=debian\nVERSION_ID="12"'
    run _check_os_version
    [ "$status" -ne 0 ]
    fixture /etc/os-release $'ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22.04"'
    run _check_os_version
    [ "$status" -eq 0 ]
}

@test "AUDIT_REPORT_DIR is created when it does not exist" {
    OUTPUT_DIR=""
    AUDIT_REPORT_DIR="$BATS_TEST_TMPDIR/new/reports"
    _resolve_report_dir >/dev/null
    [ "$REPORT_DIR" = "$AUDIT_REPORT_DIR" ]
    [ -d "$REPORT_DIR" ]
}

@test "a relative --output-dir is rejected" {
    OUTPUT_DIR="relative/dir"
    run _resolve_report_dir
    [ "$status" -ne 0 ]
    [[ "$output" == *"must be an absolute path"* ]]
}

@test "verify mode reads the newest earlier findings file, never the current one" {
    REPORT_DIR="$BATS_TEST_TMPDIR/out"
    local old="$REPORT_DIR/sec-audit-findings-20260101-000000.jsonl"
    local prev="$REPORT_DIR/sec-audit-findings-20260102-000000.jsonl"
    FINDINGS_FILE="$REPORT_DIR/sec-audit-findings-20260103-000000.jsonl"
    : > "$old"; touch -d '2026-01-01' "$old"
    : > "$prev"; touch -d '2026-01-02' "$prev"
    : > "$FINDINGS_FILE"
    [ "$(_previous_findings_file)" = "$prev" ]
}

@test "verify mode reads failed checks without python3" {
    rm -f "$MOCK_BIN/python3"
    printf '%s\n' '{"check_id": "check_a", "title": "x \"status\": \"satisfied\"", "status": "not-satisfied"}' \
                  '{"check_id": "check_b", "title": "y", "status": "satisfied"}' > "$BATS_TEST_TMPDIR/prev.jsonl"
    run _failed_checks_in "$BATS_TEST_TMPDIR/prev.jsonl"
    [ "$output" = "check_a" ]
}

@test "webhook URLs are shown without their secret path or credentials" {
    [ "$(_redact_url 'https://hooks.slack.com/services/T000/B000/XXXX?x=1')" = "https://hooks.slack.com/..." ]
    [ "$(_redact_url 'https://user:pw@example.com:8443/hook')" = "https://example.com:8443/..." ]
}
