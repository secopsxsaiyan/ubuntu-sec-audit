#!/usr/bin/env bats
# Deep mode: unattended runs, one check id per deep check, accurate results
# and manual-only remediations for risky changes.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# mock_dpkg_owner PATTERN... — dpkg-query -S reports paths matching any
# PATTERN (shell glob) as owned by a package; others are not found.
mock_dpkg_owner() {
    local pats="$*"
    mock_cmd dpkg-query '
set -f   # the patterns are globs for case, not for the filesystem
[ "$1" = "-S" ] || exit 0
shift
rc=1
for p in "$@"; do
    for pat in '"$pats"'; do
        case "$p" in $pat) echo "somepkg: $p"; rc=0 ;; esac
    done
done
exit $rc'
}

@test "prompt_install does not prompt or abort without a terminal" {
    # In a strict shell like main(): read on a closed stdin used to abort.
    run bash -c "source '$REPO_ROOT/ubuntu-sec-audit.sh'; set -euo pipefail
                 prompt_install sometool-that-is-missing somepkg; echo still-running" </dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == *"not installed"*"non-interactive"* ]]
    [[ "$output" == *"still-running"* ]]
}

@test "deep checks are recorded under their own check ids" {
    run_deep_checks </dev/null >/dev/null 2>&1
    run findings_tsv
    [[ "$output" == *"check_deep_suid"* ]]
    [[ "$output" == *"check_deep_world_writable_dirs"* ]]
    [[ "$output" == *"check_deep_sudo_timeout"* ]]
    [[ "$output" != *"run_deep_checks"* ]]
}

@test "--check selects individual deep checks" {
    RUN_ONLY=(check_deep_sudo_timeout)
    run_deep_checks </dev/null >/dev/null 2>&1
    run findings_tsv
    [ "$output" = "$(printf 'check_deep_sudo_timeout\tsatisfied')" ]
}

@test "SUID: only binaries no package owns are flagged, and the fix is manual" {
    mkdir -p "$AUDIT_ROOT/usr/lib/snapd" "$AUDIT_ROOT/usr/local/bin"
    touch "$AUDIT_ROOT/usr/lib/snapd/snap-confine" "$AUDIT_ROOT/usr/local/bin/evil"
    chmod 4755 "$AUDIT_ROOT/usr/lib/snapd/snap-confine" "$AUDIT_ROOT/usr/local/bin/evil"
    mock_dpkg_owner '/usr/lib/snapd/*'
    _run_check check_deep_suid
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/usr/local/bin/evil"* ]]
    [[ "$d" != *"snap-confine"* ]]
    run executable_lines <<< "$(remediation_for "SUID")"
    [ -z "$output" ]
}

@test "SGID: package-owned binaries such as plocate are not flagged" {
    mkdir -p "$AUDIT_ROOT/usr/bin"
    touch "$AUDIT_ROOT/usr/bin/plocate"
    chmod 2755 "$AUDIT_ROOT/usr/bin/plocate"
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_sgid
    refute_issue "SGID"
}

@test "world-writable dirs with the sticky bit (like /var/crash) are not flagged" {
    mkdir -p "$AUDIT_ROOT/var/crash" "$AUDIT_ROOT/var/bad"
    chmod 3777 "$AUDIT_ROOT/var/crash"
    chmod 0777 "$AUDIT_ROOT/var/bad"
    _run_check check_deep_world_writable_dirs
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/var/bad"* ]]
    [[ "$d" != *"/var/crash"* ]]
}

@test "unowned files: the chown fix is manual" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to create unowned files"
    mkdir -p "$AUDIT_ROOT/srv"
    touch "$AUDIT_ROOT/srv/orphan"
    chown 54321:54321 "$AUDIT_ROOT/srv/orphan"
    _run_check check_deep_unowned
    assert_issue "no valid owner"
    run executable_lines <<< "$(remediation_for "no valid owner")"
    [ -z "$output" ]
}

@test "sudo timeout: unset means sudo's default of 15 minutes and passes" {
    fixture /etc/sudoers "Defaults env_reset"
    _run_check check_deep_sudo_timeout
    refute_issue "Sudo password timeout"
    fixture /etc/sudoers "Defaults timestamp_timeout=30"
    _run_check check_deep_sudo_timeout
    assert_issue "Sudo password timeout"
}

rkhunter_mock() {
    mock_cmd rkhunter '
[ "$1" = "--update" ] && exit 0
log=""
while [ $# -gt 0 ]; do [ "$1" = "--logfile" ] && log="$2"; shift; done
cat > "$log" <<EOF
[12:00:00] Info: Starting test name '"'"'rootkits'"'"'
[12:00:01] Rootkit checks...
[12:00:02]   Checking for Suspect files                         [ None found ]
'"$1"'
EOF
exit 0'
}

@test "rkhunter: only real warnings are findings" {
    rkhunter_mock ""
    _run_check check_deep_rkhunter
    refute_issue "rkhunter"
}

@test "rkhunter: a warning is a finding, and the fix does not re-baseline" {
    rkhunter_mock "[12:00:03] Warning: The file properties have changed:"
    _run_check check_deep_rkhunter
    assert_issue "rkhunter detected warnings"
    run executable_lines <<< "$(remediation_for "rkhunter")"
    [[ "$output" != *"--propupd"* ]]
}

@test "ClamAV: a successful quiet freshclam is not reported as a failure" {
    mock_cmd systemctl 'exit 3'
    mock_cmd freshclam 'exit 0'
    mock_cmd clamscan 'echo "----------- SCAN SUMMARY -----------"; echo "Infected files: 0"; exit 0'
    _run_check check_deep_clamav
    refute_issue "ClamAV virus definitions may be outdated"
    refute_issue "ClamAV"
}

@test "ClamAV: a scan that stops early is reported, not treated as clean" {
    mock_cmd systemctl 'exit 0'
    mock_cmd clamscan 'exit 124'
    _run_check check_deep_clamav
    assert_issue "ClamAV scan did not complete"
}

@test "Lynis: findings come from the report's warning[] entries" {
    mock_cmd lynis '
rep=""
while [ $# -gt 0 ]; do [ "$1" = "--report-file" ] && rep="$2"; shift; done
printf "%s\n" "hardening_index=70" "suggestion[]=SSH-7408|Harden SSH|-|-|" > "$rep"
echo "[WARNING]: Test MAIL-8818 had a long execution"'
    _run_check check_deep_lynis
    refute_issue "Lynis"
}

@test "Lynis: a warning[] entry is a finding" {
    mock_cmd lynis '
rep=""
while [ $# -gt 0 ]; do [ "$1" = "--report-file" ] && rep="$2"; shift; done
printf "%s\n" "warning[]=FIRE-4512|iptables module(s) loaded, but no rules active|-|-|" > "$rep"'
    _run_check check_deep_lynis
    assert_issue "Lynis reported 1 warning"
    [[ "$(printf '%s\n' "${ISSUES[@]}")" == *"FIRE-4512"* ]]
}

@test "user SSH keys: one finding for all keys, files outside .ssh ignored" {
    # /home and /root are check_secrets'; this check covers the other homes.
    fixture /etc/passwd $'a:x:901:901::/var/lib/a:/bin/sh\nb:x:902:902::/srv/b/:/bin/sh'
    fixture /var/lib/a/.ssh/id_rsa "-----BEGIN RSA PRIVATE KEY-----"
    fixture /srv/b/.ssh/id_ed25519 "-----BEGIN OPENSSH PRIVATE KEY-----"
    fixture /var/lib/a/src/id_generator.py "-----BEGIN RSA PRIVATE KEY-----"
    chmod 644 "$AUDIT_ROOT/var/lib/a/.ssh/id_rsa" "$AUDIT_ROOT/srv/b/.ssh/id_ed25519" "$AUDIT_ROOT/var/lib/a/src/id_generator.py"
    _run_check check_deep_user_ssh_keys
    [ "${#TITLES[@]}" -eq 1 ]
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"id_rsa"* && "$d" == *"id_ed25519"* ]]
    [[ "$d" != *"id_generator.py"* ]]
}

@test "capabilities: only files no package owns are flagged" {
    mock_cmd getcap 'printf "%s\n" "/usr/bin/ping cap_net_raw=ep" "/usr/local/bin/x cap_sys_admin=ep"'
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_capabilities
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/usr/local/bin/x"* ]]
    [[ "$d" != *"/usr/bin/ping"* ]]
}
