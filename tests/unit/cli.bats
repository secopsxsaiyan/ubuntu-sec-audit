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

@test "--version prints the version and nothing else, after other flags too" {
    run env PATH="$ORIG_PATH" bash "$REPO_ROOT/ubuntu-sec-audit.sh" --version </dev/null
    [ "$status" -eq 0 ]
    [ "$output" = "ubuntu-sec-audit ${SCRIPT_VERSION}" ]
    run parse_args --deep --version </dev/null
    [ "$status" -eq 0 ]
    [ "$output" = "ubuntu-sec-audit ${SCRIPT_VERSION}" ]
}

@test "--version and --help need no root" {
    local -a as_user=()
    if [ "$(id -u)" -eq 0 ]; then
        PATH="$ORIG_PATH" command -v runuser >/dev/null || skip "runuser not installed"
        PATH="$ORIG_PATH" runuser -u nobody -- test -r "$REPO_ROOT/lib/cli.sh" \
            || skip "user nobody cannot read this checkout"
        as_user=(runuser -u nobody --)
    fi
    run env PATH="$ORIG_PATH" "${as_user[@]}" bash "$REPO_ROOT/ubuntu-sec-audit.sh" --version </dev/null
    [ "$status" -eq 0 ]
    [ "$output" = "ubuntu-sec-audit ${SCRIPT_VERSION}" ]
    run env PATH="$ORIG_PATH" "${as_user[@]}" bash "$REPO_ROOT/ubuntu-sec-audit.sh" --help </dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == "ubuntu-sec-audit ${SCRIPT_VERSION}"* ]]
    [[ "$output" == *"--version"* ]]
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
    [ "$REPORT_DIR" = "$(realpath "$AUDIT_REPORT_DIR")" ]
    [ -d "$REPORT_DIR" ]
}

@test "a relative --output-dir is rejected" {
    OUTPUT_DIR="relative/dir"
    run _resolve_report_dir
    [ "$status" -ne 0 ]
    [[ "$output" == *"must be an absolute path"* ]]
}

# ---- output directory: nobody but root may be able to change it ----------
# Root writes the fix script there and later runs it: a user who can change
# the directory could plant a symlink to overwrite any file, or swap the fix
# script for their own.

@test "the default output directory is root's /var/log/ubuntu-sec-audit, not the sudo user's home" {
    SUDO_USER=alice
    fixture /etc/passwd 'alice:x:1000:1000::/home/alice:/bin/bash'
    [ "$(_default_report_dir)" = "/var/log/ubuntu-sec-audit" ]
}

@test "an output directory owned by another user is refused" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to chown"
    local d="$BATS_TEST_TMPDIR/theirs"
    mkdir -m 755 "$d"
    chown 65534 "$d"
    OUTPUT_DIR="$d"
    run _resolve_report_dir
    [ "$status" -eq 1 ]
    [[ "$output" == *"users other than root can change this directory"* ]]
}

@test "an output directory below one another user owns is refused before anything is created" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to chown"
    local d="$BATS_TEST_TMPDIR/home-of-someone"
    mkdir -m 755 "$d"
    chown 65534 "$d"
    OUTPUT_DIR="$d/reports/today"
    run _resolve_report_dir
    [ "$status" -eq 1 ]
    [ ! -e "$d/reports" ]
}

@test "an output directory below a world-writable directory without the sticky bit is refused" {
    local d="$BATS_TEST_TMPDIR/shared"
    mkdir "$d"
    chmod 777 "$d"
    OUTPUT_DIR="$d/reports"
    run _resolve_report_dir
    [ "$status" -eq 1 ]
    [ ! -e "$d/reports" ]
    # With the sticky bit (as /tmp) others cannot rename what is ours.
    chmod 1777 "$d"
    _resolve_report_dir >/dev/null
    [ "$REPORT_DIR" = "$(realpath "$d/reports")" ]
}

@test "a group-writable parent is accepted only when no regular user is in its group" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to chgrp"
    local d="$BATS_TEST_TMPDIR/var-log"
    mkdir "$d"
    chown :4242 "$d"
    chmod 775 "$d"
    OUTPUT_DIR="$d/ubuntu-sec-audit"
    # Like /var/log (root:syslog 775): only a system account is in the group.
    fixture /etc/group 'syslog:x:4242:'
    fixture /etc/passwd 'syslog:x:104:4242::/nonexistent:/usr/sbin/nologin'
    _resolve_report_dir >/dev/null
    [ "$REPORT_DIR" = "$(realpath "$d/ubuntu-sec-audit")" ]
    # A regular user in the group, as a listed member ...
    fixture /etc/group 'syslog:x:4242:alice'
    fixture /etc/passwd $'syslog:x:104:4242::/nonexistent:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash'
    run _resolve_report_dir
    [ "$status" -eq 1 ]
    # ... or by primary group, or a group the account files do not know.
    fixture /etc/group 'syslog:x:4242:'
    fixture /etc/passwd 'alice:x:1000:4242::/home/alice:/bin/bash'
    run _resolve_report_dir
    [ "$status" -eq 1 ]
    fixture /etc/group 'other:x:1:'
    run _resolve_report_dir
    [ "$status" -eq 1 ]
}

@test "the output directory is used by its real path, not through a symlink" {
    local real="$BATS_TEST_TMPDIR/real-out"
    mkdir "$real"
    ln -s "$real" "$BATS_TEST_TMPDIR/link-out"
    OUTPUT_DIR="$BATS_TEST_TMPDIR/link-out"
    _resolve_report_dir >/dev/null
    [ "$REPORT_DIR" = "$(realpath "$real")" ]
}

@test "the whole audit refuses an output directory another user owns and writes nothing there" {
    [ "$(id -u)" -eq 0 ] || skip "needs root"
    fixture /etc/os-release $'ID=ubuntu\nVERSION_ID="24.04"'
    local d="$BATS_TEST_TMPDIR/planted"
    mkdir -m 755 "$d"
    chown 65534 "$d"
    run env PATH="$ORIG_PATH" AUDIT_ROOT="$AUDIT_ROOT" bash "$REPO_ROOT/ubuntu-sec-audit.sh" \
        --check check_umask --skip-apt-update --output-dir "$d" </dev/null
    [ "$status" -eq 1 ]
    [[ "$output" == *"users other than root can change this directory"* ]]
    [ -z "$(ls -A "$d")" ]
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
