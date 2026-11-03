#!/usr/bin/env bats
# SSH and login banner checks against the effective configuration as OpenSSH
# really prints it (sshd -T), and the safety of their fixes.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# A configuration that meets every requirement, in sshd -T vocabulary.
# OpenSSH prints "PermitRootLogin prohibit-password" as without-password.
compliant_conf() {
    printf '%s\n' \
        "permitrootlogin without-password" \
        "passwordauthentication no" \
        "pubkeyauthentication yes" \
        "maxauthtries 4" \
        "logingracetime 60" \
        "x11forwarding no" \
        "allowtcpforwarding no" \
        "clientaliveinterval 300" \
        "clientalivecountmax 2" \
        "permitemptypasswords no" \
        "hostbasedauthentication no" \
        "ignorerhosts yes" \
        "maxstartups 10:30:60" \
        "ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com" \
        "macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" \
        "kexalgorithms curve25519-sha256" \
        "banner /etc/issue.net" \
        "allowusers alice"
}

# sshd_reports SED_EXPR — mock sshd -T printing the compliant configuration
# edited by SED_EXPR (e.g. 's/^maxstartups .*/maxstartups 10:30:100/').
sshd_reports() {
    compliant_conf | sed "${1:-}" > "$T/sshd-T.out"
    mock_cmd sshd '[ "$1" = "-T" ] && cat "'"$T"'/sshd-T.out"'
    mock_cmd ssh 'exit 0'
}

status_of() { findings_tsv | awk -F'\t' -v c="$1" '$1 == c {print $2}' | sort -u; }

# The drop-in the SSH fix writes (the heredoc body).
dropin_of() {
    remediation_for "SSH configuration weaknesses" | sed -n "/<< 'SSHEOF'/,/^SSHEOF$/p" | sed '1d;$d'
}

@test "ssh: prohibit-password, printed by sshd -T as without-password, passes" {
    sshd_reports
    _run_check check_ssh
    refute_issue "SSH configuration weaknesses"
    [ "$(status_of check_ssh)" = "satisfied" ]
}

@test "ssh: PermitRootLogin yes still fails" {
    sshd_reports 's/^permitrootlogin .*/permitrootlogin yes/'
    _run_check check_ssh
    assert_issue "SSH configuration weaknesses"
}

@test "ssh: a failing sshd -T is not judged as an insecure configuration" {
    mock_cmd sshd 'echo "sshd: /etc/ssh/sshd_config line 3: Bad configuration option: Foo" >&2; exit 255'
    _run_check check_ssh
    refute_issue "SSH configuration weaknesses"
    [ "$(status_of check_ssh)" = "skipped" ]
    grep -q 'Bad configuration option' "$FINDINGS_FILE"
}

@test "ssh: without /run/sshd, sshd -T is retried in a private mount namespace" {
    compliant_conf > "$T/sshd-T.out"
    mock_cmd sshd 'if [ -d "'"$T"'/fake-run-sshd" ]; then cat "'"$T"'/sshd-T.out"; else echo "Missing privilege separation directory: /run/sshd" >&2; exit 255; fi'
    # The mock "namespace" provides the directory only while the command runs.
    mock_cmd unshare 'echo "$*" > "'"$T"'/unshare.args"; mkdir -p "'"$T"'/fake-run-sshd"; sshd -T; rc=$?; rm -r "'"$T"'/fake-run-sshd"; exit $rc'
    mock_cmd ssh 'exit 0'
    _run_check check_ssh
    grep -q -- '-m' "$T/unshare.args"
    refute_issue "SSH configuration weaknesses"
    [ "$(status_of check_ssh)" = "satisfied" ]
    [ ! -e "$T/fake-run-sshd" ]
}

@test "ssh: the fix writes only the settings that fail" {
    sshd_reports 's/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    run dropin_of
    [ "$output" = "MaxStartups 10:30:60" ]
}

@test "ssh: stricter settings are never weakened by the fix" {
    sshd_reports 's/^permitrootlogin .*/permitrootlogin no/; s/^maxauthtries .*/maxauthtries 2/; s/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    run dropin_of
    [[ "$output" != *PermitRootLogin* ]]
    [[ "$output" != *MaxAuthTries* ]]
    [[ "$output" == *"MaxStartups 10:30:60"* ]]
}

@test "ssh: settings the tool wrote on an earlier run are kept in its drop-in" {
    fixture /etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf $'# managed\nX11Forwarding no\nMaxStartups 10:30:100'
    sshd_reports 's/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    run dropin_of
    [[ "$output" == *"X11Forwarding no"* ]]
    [ "$(grep -c '^MaxStartups' <<< "$output")" -eq 1 ]
    [[ "$output" == *"MaxStartups 10:30:60"* ]]
}

@test "ssh: TCP forwarding is never disabled automatically (bastions, VS Code Remote)" {
    sshd_reports 's/^allowtcpforwarding .*/allowtcpforwarding yes/'
    _run_check check_ssh
    refute_issue "SSH configuration weaknesses"
    assert_issue "SSH access restrictions need review"
    run executable_lines <<< "$(remediation_for "SSH access restrictions need review")"
    [ -z "$output" ]
    [[ "$(remediation_for "SSH access restrictions need review")" == *"AllowTcpForwarding no"* ]]
}

@test "ssh: missing AllowUsers is a separate manual finding; the automatic fix can pass" {
    fixture /etc/group "sudo:x:27:alice,bob"
    sshd_reports '/^allowusers /d'
    _run_check check_ssh
    refute_issue "SSH configuration weaknesses"
    assert_issue "SSH access restrictions need review"
    [[ "$(remediation_for "SSH access restrictions need review")" == *"AllowUsers alice bob"* ]]
}

@test "ssh: a Match block that re-enables password or root login is reported" {
    sshd_reports
    fixture /etc/ssh/sshd_config $'Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nMatch User bob\n    PasswordAuthentication yes'
    _run_check check_ssh
    assert_issue "SSH Match blocks weaken authentication"
    [[ "$(issue_titles)" != *"SSH configuration weaknesses"* ]]
    run executable_lines <<< "$(remediation_for "SSH Match blocks")"
    [ -z "$output" ]
}

@test "ssh: a harmless Match block is not reported" {
    sshd_reports
    fixture /etc/ssh/sshd_config.d/10-sftp.conf $'Match Group sftp\n    ForceCommand internal-sftp\n    PasswordAuthentication no'
    _run_check check_ssh
    refute_issue "SSH Match blocks"
}

@test "ssh: points follow severity (password login 10, tuning only 5)" {
    sshd_reports 's/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    [ "${CHECK_POINTS[check_ssh]}" -eq 5 ]
    CHECK_POINTS=(); TITLES=()
    sshd_reports 's/^passwordauthentication .*/passwordauthentication yes/'
    _run_check check_ssh
    [ "${CHECK_POINTS[check_ssh]}" -eq 10 ]
}

# note_of INDEX — the Note part of a report entry.
note_of() { local e="${ISSUES[$1]}"; printf '%s' "${e#*'**Note**: '}"; }

@test "ssh: the report note has real line breaks, not a literal \\n" {
    sshd_reports 's/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    [[ "${ISSUES[0]}" == *'**Note**: '* ]]
    [[ "$(note_of 0)" != *'\n'* ]]
}

@test "ssh: with the real sshd, the fix's drop-in makes the check pass" {
    local real
    real=$(PATH="$ORIG_PATH" command -v sshd || true)
    [ -n "$real" ] || skip "openssh-server not installed"
    [ "$(id -u)" -eq 0 ] || skip "sshd -T needs root"
    [ -d /run/sshd ] || skip "sshd -T needs /run/sshd"
    # A stock-like configuration plus everything the tool's checks require
    # elsewhere, then the drop-in the fix writes, evaluated by real sshd.
    mkdir -p "$T/etc/ssh/sshd_config.d"
    PATH="$ORIG_PATH" ssh-keygen -q -t ed25519 -N '' -f "$T/etc/ssh/host_key"
    printf '%s\n' "Include $T/etc/ssh/sshd_config.d/*.conf" "HostKey $T/etc/ssh/host_key" \
        "KbdInteractiveAuthentication no" "UsePAM yes" "AllowUsers alice" \
        "AllowTcpForwarding no" "Banner /etc/issue.net" > "$T/etc/ssh/sshd_config"
    mock_cmd sshd "exec $real -f $T/etc/ssh/sshd_config \"\$@\""
    mock_cmd ssh "exec $(PATH="$ORIG_PATH" command -v ssh) \"\$@\""
    _run_check check_ssh
    assert_issue "SSH configuration weaknesses"
    dropin_of > "$T/etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf"
    TITLES=(); REMEDIATIONS=(); CHECK_FAILED=()
    _run_check check_ssh
    refute_issue "SSH configuration weaknesses"
}

# ---- login banners -------------------------------------------------------

good_issue() {
    fixture /etc/issue "Authorized use only. All activity may be monitored."
    fixture /etc/issue.net "Authorized use only. All activity may be monitored."
}

@test "banner: hosts without sshd are not asked for an SSH banner" {
    good_issue
    _run_check check_login_banner
    refute_issue "Login banners"
}

@test "banner: a missing /etc/motd is fine (Ubuntu's motd is dynamic)" {
    good_issue
    sshd_reports
    _run_check check_login_banner
    refute_issue "Login banners"
}

@test "banner: the stock /etc/issue reveals the OS and fails (CIS 1.7.2)" {
    fixture /etc/issue 'Ubuntu 24.04.1 LTS \n \l'
    fixture /etc/issue.net "Authorized use only."
    _run_check check_login_banner
    assert_issue "Login banners"
}

@test "banner: the SSH banner is set in a drop-in, which works without a Banner line" {
    good_issue
    sshd_reports 's/^banner .*/banner none/'
    _run_check check_login_banner
    assert_issue "Login banners"
    local r
    r=$(remediation_for "Login banners")
    [[ "$r" == *"/etc/ssh/sshd_config.d/01-ubuntu-sec-audit-banner.conf"* ]]
    [[ "$r" == *"Banner /etc/issue.net"* ]]
    [[ "$r" != *"sed -i"*"sshd_config"* ]]
    [[ "$(note_of 0)" != *'\n'* ]]
}

@test "banner: a failing sshd -T does not count as a missing SSH banner" {
    good_issue
    mock_cmd sshd 'echo boom >&2; exit 255'
    _run_check check_login_banner
    refute_issue "Login banners"
}

@test "ssh: the fix creates /run/sshd before validating with sshd -t" {
    sshd_reports 's/^maxstartups .*/maxstartups 10:30:100/'
    _run_check check_ssh
    local r
    r=$(remediation_for "SSH configuration weaknesses")
    grep -q 'mkdir -m 0755 /run/sshd' <<< "$r"
    [ "$(grep -n 'mkdir -m 0755 /run/sshd' <<< "$r" | cut -d: -f1)" -lt "$(grep -n 'sshd -t' <<< "$r" | head -1 | cut -d: -f1)" ]
}

@test "banner: a compliant /etc/issue is left alone when only the SSH banner is missing" {
    good_issue
    sshd_reports 's/^banner .*/banner none/'
    _run_check check_login_banner
    run executable_lines <<< "$(remediation_for "Login banners")"
    [[ "$output" != *"/etc/issue"* || "$output" == *"Banner /etc/issue.net"* ]]
    refute grep -qE 'tee[^|]*/etc/issue( |$)' <<< "$output"
    refute grep -qE 'tee /etc/issue\.net' <<< "$output"
    grep -q '01-ubuntu-sec-audit-banner.conf' <<< "$output"
}

@test "banner: only the file that fails is rewritten" {
    fixture /etc/issue "Authorized use only."
    fixture /etc/issue.net 'Ubuntu 24.04 LTS'
    _run_check check_login_banner
    run executable_lines <<< "$(remediation_for "Login banners")"
    grep -q '/etc/issue.net' <<< "$output"
    refute grep -qE '/etc/issue( |$)' <<< "$output"
}
