#!/usr/bin/env bats
# System checks: outcomes on hosts where a check does not apply or cannot
# run, files read under AUDIT_ROOT, and remediations that are safe, manual
# where they cannot be automated, and make their own check pass.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# status_of CHECK — the status recorded for CHECK in the findings file.
status_of() { findings_tsv | awk -F'\t' -v c="$1" '$1 == c {print $2}'; }

# points_of TITLE — the points of the first issue whose title contains TITLE.
points_of() {
    local i
    for i in "${!TITLES[@]}"; do
        if [[ "${TITLES[$i]}" == *"$1"* ]]; then
            grep -oE '\(([0-9]+) pts\)' <<< "${ISSUES[$i]}" | head -n 1 | tr -dc '0-9'
            return 0
        fi
    done
    return 1
}

# run_remediation TITLE SED_EXPR... — run TITLE's remediation as a script,
# with sudo passed through and paths rewritten by the sed expressions so it
# only touches the fixture tree and mocks. Sets $status and $output.
run_remediation() {
    local title="$1" r e
    shift
    local -a args=()
    for e in "$@"; do args+=(-e "$e"); done
    r=$(remediation_for "$title")
    mock_cmd sudo '"$@"'
    if [[ ${#args[@]} -gt 0 ]]; then
        sed "${args[@]}" <<< "$r" > "$T/fix.sh"
    else
        printf '%s\n' "$r" > "$T/fix.sh"
    fi
    run bash "$T/fix.sh"
}

# ---- checks that do not apply, or cannot run, are not "satisfied" ---------

@test "grub: a host without GRUB is not applicable" {
    _run_check check_grub_password
    refute_issue "GRUB bootloader not password protected"
    [ "$(status_of check_grub_password)" = "not-applicable" ]
}

@test "grub: GRUB without a password is still reported" {
    fixture /etc/default/grub 'GRUB_DEFAULT=0'
    _run_check check_grub_password
    assert_issue "GRUB bootloader not password protected"
}

@test "kernel lockdown: a kernel without the lockdown LSM is not applicable" {
    _run_check check_kernel_lockdown
    [ "$(status_of check_kernel_lockdown)" = "not-applicable" ]
}

@test "service hardening: without systemctl the check is skipped" {
    _run_check check_systemd_service_hardening
    [ "$(status_of check_systemd_service_hardening)" = "skipped" ]
}

@test "security updates: without apt-get the check is skipped" {
    _run_check check_security_updates
    [ "$(status_of check_security_updates)" = "skipped" ]
}

# ---- rsyslog reads /var/log/syslog under the audited root -----------------

rsyslog_running() {
    mock_cmd dpkg 'echo "ii  rsyslog  8.2312.0-3ubuntu9  amd64  reliable system and kernel logging daemon"'
    mock_cmd systemctl 'exit 0'
}

@test "rsyslog: a current /var/log/syslog under the audited root passes" {
    rsyslog_running
    fixture /var/log/syslog "Nov  3 10:00:00 host kernel: hello"
    _run_check check_rsyslog
    refute_issue "rsyslog"
    [ "$(status_of check_rsyslog)" = "satisfied" ]
}

@test "rsyslog: a stale /var/log/syslog under the audited root fails" {
    rsyslog_running
    fixture /var/log/syslog "Nov  3 08:00:00 host kernel: hello"
    touch -d '-2 hours' "$AUDIT_ROOT/var/log/syslog"
    _run_check check_rsyslog
    assert_issue "rsyslog running but syslog output stale"
}

# ---- Secure Boot ------------------------------------------------------------

# efi_fixture 0|1 — a UEFI host whose SecureBoot variable holds the value.
efi_fixture() {
    mkdir -p "$AUDIT_ROOT/sys/firmware/efi/efivars"
    printf "\\x06\\x00\\x00\\x00\\x0$1" \
        > "$AUDIT_ROOT/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}

@test "secure boot: a non-UEFI host is not applicable" {
    _run_check check_secure_boot
    [ "$(status_of check_secure_boot)" = "not-applicable" ]
}

@test "secure boot: disabled Secure Boot is read under the audited root and its fix is manual" {
    efi_fixture 0
    _run_check check_secure_boot
    assert_issue "Secure Boot disabled"
    local r
    r=$(remediation_for "Secure Boot disabled")
    _is_manual_remediation "$r"
    [[ "$r" == *"mokutil --sb-state"* ]]
}

@test "secure boot: enabled Secure Boot passes" {
    efi_fixture 1
    _run_check check_secure_boot
    refute_issue "Secure Boot"
    [ "$(status_of check_secure_boot)" = "satisfied" ]
}

# ---- disk encryption ----------------------------------------------------------

@test "disk encryption: both findings are manual (verify commands are not a fix)" {
    mock_cmd findmnt 'echo /dev/sda1'
    mock_cmd lsblk 'if [ "$1" = "-s" ]; then printf "part\ndisk\n"; else printf "sda disk\nsda1 part\n"; fi'
    mock_cmd blkid 'echo "/dev/sda1: TYPE=\"ext4\""'
    _run_check check_disk_encryption
    _is_manual_remediation "$(remediation_for "No disk encryption detected")"

    TITLES=(); REMEDIATIONS=(); ISSUES=()
    mock_cmd lsblk 'if [ "$1" = "-s" ]; then printf "part\ndisk\n"; else printf "sda disk\nsda1 part\nsdb1 part\nsecret crypt\n"; fi'
    mock_cmd blkid 'echo "/dev/sdb1: TYPE=\"crypto_LUKS\""'
    _run_check check_disk_encryption
    _is_manual_remediation "$(remediation_for "Root filesystem encryption not confirmed")"
}
