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
    local r
    r=$(remediation_for "No disk encryption detected")
    _is_manual_remediation "$r"

    TITLES=(); REMEDIATIONS=(); ISSUES=()
    mock_cmd lsblk 'if [ "$1" = "-s" ]; then printf "part\ndisk\n"; else printf "sda disk\nsda1 part\nsdb1 part\nsecret crypt\n"; fi'
    mock_cmd blkid 'if [ $# -gt 0 ]; then echo "$1: TYPE=\"ext4\""; else echo "/dev/sdb1: TYPE=\"crypto_LUKS\""; fi'
    _run_check check_disk_encryption
    r=$(remediation_for "Root filesystem encryption not confirmed")
    _is_manual_remediation "$r"
}

# ---- AIDE ---------------------------------------------------------------------

@test "aide: the install fix does not pull in a mail server through Recommends" {
    _run_check check_aide
    assert_issue "AIDE not installed"
    run grep -E 'apt-get( .*)? install' <<< "$(remediation_for "AIDE not installed")"
    [ "$status" -eq 0 ]
    refute grep -v -- '--no-install-recommends' <<< "$output"
}

@test "aide: a missing schedule is fixed without re-initialising the baseline" {
    mock_cmd aide 'exit 0'
    fixture /var/lib/aide/aide.db "baseline"
    _run_check check_aide
    # No fix reported for this host may rebuild (and so silently accept) the baseline.
    run printf '%s\n' "${REMEDIATIONS[@]}"
    [[ "$output" != *aideinit* ]]
    [[ "$output" != *"--init"* ]]
    [[ "$output" != *"aide.db"* ]]
    [[ "$output" == *"enable --now dailyaidecheck.timer"* ]]
    assert_issue "AIDE integrity checks not scheduled"
    refute_issue "AIDE database not initialised"
}

@test "aide: an enabled dailyaidecheck.timer counts as scheduled" {
    mock_cmd aide 'exit 0'
    mock_cmd systemctl '[ "$1 $2 $3" = "is-enabled --quiet dailyaidecheck.timer" ] && exit 0; exit 1'
    fixture /usr/lib/systemd/system/dailyaidecheck.timer "[Timer]"
    fixture /var/lib/aide/aide.db "baseline"
    _run_check check_aide
    refute_issue "AIDE"
    [ "$(status_of check_aide)" = "satisfied" ]
}

@test "aide: with the timer disabled, aide-common's cron job does not count (it defers to the timer)" {
    mock_cmd aide 'exit 0'
    mock_cmd systemctl 'exit 1'
    fixture /lib/systemd/system/dailyaidecheck.timer "[Timer]"
    fixture /etc/cron.daily/dailyaidecheck '#!/bin/sh'
    chmod 755 "$AUDIT_ROOT/etc/cron.daily/dailyaidecheck"
    fixture /var/lib/aide/aide.db "baseline"
    _run_check check_aide
    assert_issue "AIDE integrity checks not scheduled"
}

@test "aide: aide-common's daily cron job counts where there is no timer (20.04)" {
    mock_cmd aide 'exit 0'
    fixture /etc/cron.daily/aide '#!/bin/sh'
    chmod 755 "$AUDIT_ROOT/etc/cron.daily/aide"
    fixture /var/lib/aide/aide.db "baseline"
    _run_check check_aide
    refute_issue "AIDE"
}

@test "aide: the database fix never overwrites a baseline that exists when it runs" {
    mock_cmd aide 'exit 0'
    mock_cmd systemctl '[ "$1 $2 $3" = "is-enabled --quiet dailyaidecheck.timer" ] && exit 0; exit 1'
    fixture /usr/lib/systemd/system/dailyaidecheck.timer "[Timer]"
    _run_check check_aide
    assert_issue "AIDE database not initialised"
    refute_issue "not scheduled"
    mock_cmd aideinit 'echo ran >> "'"$T"'/aideinit.log"; echo new > "'"$AUDIT_ROOT"'/var/lib/aide/aide.db.new"'
    local -a rw=("s#/var/lib/aide#${AUDIT_ROOT}/var/lib/aide#g" "s#/usr/sbin/aideinit#aideinit#g")
    # A baseline created between the audit and the fix is kept.
    fixture /var/lib/aide/aide.db "baseline"
    run_remediation "AIDE database not initialised" "${rw[@]}"
    [ ! -e "$T/aideinit.log" ]
    [ "$(cat "$AUDIT_ROOT/var/lib/aide/aide.db")" = "baseline" ]
    # Without one, it is built.
    rm "$AUDIT_ROOT/var/lib/aide/aide.db"
    run_remediation "AIDE database not initialised" "${rw[@]}"
    [ -s "$T/aideinit.log" ]
    [ -f "$AUDIT_ROOT/var/lib/aide/aide.db" ]
}

# ---- APT repositories -----------------------------------------------------------

@test "apt repos: trusted=yes among other bracket options is found" {
    fixture /etc/apt/sources.list "deb [arch=amd64 trusted=yes] http://repo.example.com/ubuntu noble main"
    _run_check check_apt_repos
    assert_issue "Insecure APT repositories configured"
}

@test "apt repos: only entries apt reads count (no comments, .save/.distUpgrade, disabled stanzas)" {
    fixture /etc/apt/sources.list $'# deb [trusted=yes] http://old.example.com/ubuntu noble main\ndeb http://archive.ubuntu.com/ubuntu noble main'
    fixture /etc/apt/sources.list.d/active.list "deb [ arch=amd64 trusted=yes ] http://repo.example.com/ubuntu noble main"
    fixture /etc/apt/sources.list.d/old.list.save "deb [trusted=yes] http://save.example.com/ubuntu noble main"
    fixture /etc/apt/sources.list.d/old.list.distUpgrade "deb [trusted=yes] http://dist.example.com/ubuntu noble main"
    fixture /etc/apt/sources.list.d/commented.sources $'Types: deb\nURIs: http://c.example.com/ubuntu\nSuites: noble\nComponents: main\n# Trusted: yes'
    fixture /etc/apt/sources.list.d/disabled.sources $'Types: deb\nURIs: http://d.example.com/ubuntu\nSuites: noble\nComponents: main\nTrusted: yes\nEnabled: no'
    fixture /etc/apt/sources.list.d/vendor.sources.save $'Types: deb\nURIs: http://v.example.com/ubuntu\nSuites: noble\nComponents: main\nTrusted: yes'
    _run_check check_apt_repos
    assert_issue "Insecure APT repositories configured"
    local r h
    r=$(remediation_for "Insecure APT repositories")
    [[ "$r" == *"/etc/apt/sources.list.d/active.list"*"repo.example.com"* ]]
    [[ "$r" != *"$AUDIT_ROOT"* ]]
    for h in old save dist c d v; do
        [[ "$r" != *"//${h}.example.com"* ]] || { echo "listed: $h.example.com"; return 1; }
    done
}

@test "apt repos: an enabled deb822 stanza with Trusted: yes is found" {
    fixture /etc/apt/sources.list.d/vendor.sources $'Types: deb\nURIs: http://ok.example.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/ok.gpg\n\nTypes: deb\nURIs: http://bad.example.com/ubuntu\nSuites: noble\nComponents: main\ntrusted: Yes'
    _run_check check_apt_repos
    assert_issue "Insecure APT repositories configured"
    [[ "$(remediation_for "Insecure APT repositories")" == *"/etc/apt/sources.list.d/vendor.sources"* ]]
}

@test "apt repos: allow-insecure and Allow-Weak are found in both formats" {
    fixture /etc/apt/sources.list.d/a.list "deb [allow-insecure=yes arch=amd64] http://a.example.com/ubuntu noble main"
    fixture /etc/apt/sources.list.d/b.sources $'Types: deb\nURIs: http://b.example.com/ubuntu\nSuites: noble\nComponents: main\nAllow-Weak: yes'
    _run_check check_apt_repos
    local r
    r=$(remediation_for "Insecure APT repositories")
    [[ "$r" == *"a.example.com"* ]]
    [[ "$r" == *"/etc/apt/sources.list.d/b.sources"* ]]
}

@test "apt repos: stock Ubuntu sources pass" {
    fixture /etc/apt/sources.list "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources"
    fixture /etc/apt/sources.list.d/ubuntu.sources $'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg'
    _run_check check_apt_repos
    refute_issue "Insecure APT repositories"
    [ "$(status_of check_apt_repos)" = "satisfied" ]
}

@test "apt repos: the fix is manual (it changes nothing, so it is never counted as applied)" {
    fixture /etc/apt/sources.list "deb [trusted=yes] http://repo.example.com/ubuntu noble main"
    _run_check check_apt_repos
    local r
    r=$(remediation_for "Insecure APT repositories")
    _is_manual_remediation "$r"
    [[ "$r" == *"apt-get update"* ]]
}

# ---- unattended-upgrades ----------------------------------------------------------

uu_installed() {
    mock_cmd dpkg 'echo "ii  unattended-upgrades  2.9.1+nmu4ubuntu1  all  automatic installation of security upgrades"'
    mock_cmd systemctl 'exit 0'
}

# uu_stock_50 [comment-out-security] — Ubuntu's stock 50unattended-upgrades
# (abridged), optionally with the -security origin commented out.
uu_stock_50() {
    local sec='	"${distro_id}:${distro_codename}-security";'
    [ "${1:-}" = "comment-out-security" ] && sec="//$sec"
    mkdir -p "$AUDIT_ROOT/etc/apt/apt.conf.d"
    cat > "$AUDIT_ROOT/etc/apt/apt.conf.d/50unattended-upgrades" <<EOF
// Automatically upgrade packages from these (origin:archive) pairs
//
// Note that in Ubuntu security updates may pull in new dependencies
// from non-security sources (e.g. chromium). By allowing the release
// pocket these get automatically pulled in.
Unattended-Upgrade::Allowed-Origins {
	"\${distro_id}:\${distro_codename}";
$sec
	// Extended Security Maintenance; doesn't necessarily exist for
	// every release and this system may not have it installed, but if
	// available, the policy for updates is such that unattended-upgrades
	// should also install from here by default.
	"\${distro_id}ESMApps:\${distro_codename}-apps-security";
	"\${distro_id}ESM:\${distro_codename}-infra-security";
//	"\${distro_id}:\${distro_codename}-updates";
//	"\${distro_id}:\${distro_codename}-proposed";
//	"\${distro_id}:\${distro_codename}-backports";
};

// Python regular expressions, matching packages to exclude from upgrading
Unattended-Upgrade::Package-Blacklist {
    // The following matches all packages starting with linux-
//  "linux-";
};

// Send email to this address for problems or packages upgrades
// If empty or unset then no email is sent, make sure that you
// have a working mail setup on your system. A package that provides
// 'mailx' must be installed. E.g. "user@example.com"
//Unattended-Upgrade::Mail "";
EOF
}

uu_auto() {
    fixture /etc/apt/apt.conf.d/20auto-upgrades $'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "'"$1"'";'
}

@test "unattended: Ubuntu's stock configuration passes" {
    uu_installed; uu_stock_50; uu_auto 1
    _run_check check_unattended
    refute_issue "Automatic security updates disabled"
    [ "$(status_of check_unattended)" = "satisfied" ]
}

@test "unattended: Unattended-Upgrade \"0\" fails even though the stock -security origin is present" {
    uu_installed; uu_stock_50; uu_auto 0
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"
}

@test "unattended: a //-commented -security origin does not count" {
    uu_installed; uu_stock_50 comment-out-security; uu_auto 1
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"
}

@test "unattended: apt.conf.d files are read in order and the last value wins" {
    uu_installed; uu_stock_50; uu_auto 1
    fixture /etc/apt/apt.conf.d/99local 'APT::Periodic::Unattended-Upgrade "0";'
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"

    TITLES=()
    rm "$AUDIT_ROOT/etc/apt/apt.conf.d/99local"
    fixture /etc/apt/apt.conf.d/10periodic 'APT::Periodic::Unattended-Upgrade "0";'
    # Files apt ignores (other extensions) do not count either.
    fixture /etc/apt/apt.conf.d/20auto-upgrades.dpkg-old 'APT::Periodic::Unattended-Upgrade "0";'
    _run_check check_unattended
    refute_issue "Automatic security updates disabled"
}

@test "unattended: scopes, block comments, # comments and #clear are understood" {
    uu_installed; uu_stock_50
    fixture /etc/apt/apt.conf.d/20auto-upgrades $'/* managed elsewhere:\nAPT::Periodic::Unattended-Upgrade "0";\n*/\nAPT {\n  Periodic {\n    Unattended-Upgrade "1";  // daily\n  };\n};\n# APT::Periodic::Unattended-Upgrade "0";'
    _run_check check_unattended
    refute_issue "Automatic security updates disabled"

    TITLES=()
    fixture /etc/apt/apt.conf.d/60local $'#clear Unattended-Upgrade::Allowed-Origins;\nUnattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-updates"; };'
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"

    TITLES=()
    fixture /etc/apt/apt.conf.d/61local 'Unattended-Upgrade::Origins-Pattern { "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu"; };'
    _run_check check_unattended
    refute_issue "Automatic security updates disabled"
}

@test "unattended: the fixes call systemctl by name (no /usr/bin/systemctl on unmerged /usr)" {
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"
    [[ "$(remediation_for "Automatic security updates disabled")" != *"/usr/bin/systemctl"* ]]

    TITLES=(); REMEDIATIONS=()
    uu_installed; uu_stock_50; uu_auto 0
    _run_check check_unattended
    local r
    r=$(remediation_for "Automatic security updates disabled")
    [[ "$r" != *"/usr/bin/systemctl"* ]]
    [[ "$r" == *"systemctl enable --now unattended-upgrades"* ]]
}

@test "unattended: the fix makes the check pass" {
    uu_installed; uu_stock_50 comment-out-security; uu_auto 0
    _run_check check_unattended
    assert_issue "Automatic security updates disabled"
    mock_cmd apt-config 'exit 0'
    run_remediation "Automatic security updates disabled" \
        "s#/etc/apt/#${AUDIT_ROOT}/etc/apt/#g" "s#/usr/bin/systemctl#systemctl#g"
    [ "$status" -eq 0 ]
    TITLES=()
    _run_check check_unattended
    refute_issue "Automatic security updates disabled"
}

# ---- pending (non-security) updates ------------------------------------------------

# apt_sim OUTPUT — apt-get whose simulations (-s) print OUTPUT; update succeeds.
apt_sim() {
    printf '%s\n' "$1" > "$T/sim.txt"
    mock_cmd apt-get 'case " $* " in *" -s "*) cat "'"$T"'/sim.txt" ;; esac; exit 0'
}

# apt_upgradable LINE... — what "apt list --upgradable" shows.
apt_upgradable() {
    printf '%s\n' "Listing..." "$@" > "$T/upgradable.txt"
    mock_cmd apt '[ "$1 $2" = "list --upgradable" ] && cat "'"$T"'/upgradable.txt"; exit 0'
}

SIM_SECURITY='Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])'
SIM_UPDATES='Inst tzdata [2024a-0ubuntu0.22.04] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Conf tzdata (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])'

@test "updates: a pending security update is left to check_security_updates" {
    apt_upgradable "libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.16 amd64 [upgradable from: 3.0.2-0ubuntu1.15]"
    apt_sim "$SIM_SECURITY"
    _run_check check_updates
    refute_issue "System not fully patched"
    [ "$(status_of check_updates)" = "satisfied" ]
}

@test "updates: phased updates that apt holds back are not counted as pending" {
    apt_upgradable "ubuntu-drivers-common/jammy-updates 1:0.9.6.2~0.22.04.6 amd64 [upgradable from: 1:0.9.6.2~0.22.04.5]"
    apt_sim $'Calculating upgrade...\nThe following packages have been kept back:\n  ubuntu-drivers-common\n0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.'
    _run_check check_updates
    refute_issue "System not fully patched"
}

@test "updates: other pending updates cost 6 points; with a security update both checks cost 16, not 22" {
    apt_upgradable "libssl3/jammy-updates,jammy-security 3.0.2-0ubuntu1.16 amd64 [upgradable from: 3.0.2-0ubuntu1.15]" \
                   "tzdata/jammy-updates 2024b-0ubuntu0.22.04 all [upgradable from: 2024a-0ubuntu0.22.04]"
    apt_sim "$SIM_SECURITY"$'\n'"$SIM_UPDATES"
    _run_check check_updates
    _run_check check_security_updates
    assert_issue "System not fully patched"
    assert_issue "Security updates pending"
    [ "$(points_of "System not fully patched")" -eq 6 ]
    [[ "$(printf '%s\n' "${ISSUES[@]}")" == *"1 package(s)"*"tzdata"* ]]
    [ "$SCORE" -eq 84 ]
}

@test "updates: without apt-get the check is skipped" {
    _run_check check_updates
    [ "$(status_of check_updates)" = "skipped" ]
}

@test "updates: the fix upgrades with apt-get and passes ShellCheck" {
    apt_sim "$SIM_UPDATES"
    _run_check check_updates
    local r
    r=$(remediation_for "System not fully patched")
    [[ "$r" == *"apt-get upgrade"* ]]
    PATH="$ORIG_PATH" command -v shellcheck >/dev/null || skip "shellcheck not installed"
    printf '#!/bin/bash\n%s\n' "$r" | PATH="$ORIG_PATH" shellcheck -S warning -
}
