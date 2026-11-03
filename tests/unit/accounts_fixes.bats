#!/usr/bin/env bats
# Accounts, sudo, PAM, cron and shell-environment checks: accurate results,
# fixes that cannot lock anyone out, and fixes that make their check pass.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# status_of CHECK — the status recorded for CHECK in the findings file.
status_of() { findings_tsv | awk -F'\t' -v c="$1" '$1 == c {print $2}'; }

# issue_text — every reported issue (title, description, note), one string.
issue_text() { printf '%s\n' "${ISSUES[@]+"${ISSUES[@]}"}"; }

# apply_rem TEXT — run remediation TEXT against the fixture tree: paths under
# /etc are redirected to AUDIT_ROOT and sudo just runs the command.
apply_rem() {
    mock_cmd sudo '"$@"'
    sed -E "s#(^|[[:space:]'\"=])/etc/#\\1${AUDIT_ROOT}/etc/#g" <<< "$1" \
        | grep -v 'bash -l -c' > "$T/fix.sh"
    bash "$T/fix.sh" >/dev/null 2>&1 || true
}

# apply_fix TITLE — apply the remediation of the issue titled TITLE.
apply_fix() {
    local r
    r=$(remediation_for "$1")
    apply_rem "$r"
}

need_root() { [ "$(id -u)" -eq 0 ] || skip "needs root to set file owners"; }

# ---- 1. home directory permissions ---------------------------------------

@test "home dirs: a user's own home is fixed as that user; paths are the real ones" {
    need_root
    fixture /etc/login.defs "UID_MIN 1000"
    fixture /etc/passwd $'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash'
    mkdir -p "$AUDIT_ROOT/root" "$AUDIT_ROOT/home/alice"
    chmod 755 "$AUDIT_ROOT/root"
    chown 1000:1000 "$AUDIT_ROOT/home/alice"
    chmod 755 "$AUDIT_ROOT/home/alice"
    _run_check check_home_permissions
    assert_issue "Home directories have insecure permissions"
    run executable_lines <<< "$(remediation_for "Home directories")"
    [[ "$output" == *"[ -L /home/alice ] || sudo /usr/sbin/runuser -u alice -- /bin/chmod "*" -- /home/alice"* ]]
    [[ "$output" == *"[ -L /root ] || sudo /bin/chmod "*" -- /root"* ]]
    [[ "$output" != *"$AUDIT_ROOT"* ]]
}

@test "home dirs: a home its user does not own, a system path, a shared or sticky one is never chmod'ed" {
    need_root
    fixture /etc/login.defs "UID_MIN 1000"
    fixture /etc/passwd "$(printf '%s\n' \
        'root:x:0:0::/root:/bin/bash' \
        'deploy:x:1001:1001::/var/www:/bin/bash' \
        'app:x:1002:1002::/srv/app:/bin/bash' \
        'tmpu:x:1003:1003::/tmp:/bin/sh' \
        'base:x:1004:1004::/home:/bin/sh' \
        'shr:x:1005:1005::/home/drop:/bin/sh' \
        'ann:x:1006:1006::/home/team:/bin/sh' \
        'ben:x:1007:1007::/home/team:/bin/sh')"
    mkdir -p "$AUDIT_ROOT"/{root,var/www,srv/app,tmp,home/drop,home/team}
    chmod 700 "$AUDIT_ROOT/root"
    chmod 755 "$AUDIT_ROOT/var/www" "$AUDIT_ROOT/home"            # root-owned
    chown 1002:1002 "$AUDIT_ROOT/srv/app"; chmod 755 "$AUDIT_ROOT/srv/app"
    chmod 1777 "$AUDIT_ROOT/tmp"
    chown 1005:1005 "$AUDIT_ROOT/home/drop"; chmod 1777 "$AUDIT_ROOT/home/drop"
    chown 1006:1006 "$AUDIT_ROOT/home/team"; chmod 775 "$AUDIT_ROOT/home/team"
    _run_check check_home_permissions
    assert_issue "Home directories have insecure permissions"
    local d r
    d=$(issue_text)
    for p in /var/www /srv/app /tmp /home/drop /home/team; do
        [[ "$d" == *"$p"* ]] || { echo "not reported: $p"; return 1; }
    done
    r=$(remediation_for "Home directories")
    [[ "$r" == *"/var/www"* ]]                       # named for a person ...
    run executable_lines <<< "$r"
    refute grep -q 'chmod' <<< "$output"           # ... but never changed
    _is_manual_remediation "$r"
}

@test "home dirs: the group-writable branch follows the same ownership rule" {
    need_root
    fixture /etc/login.defs "UID_MIN 1000"
    fixture /etc/passwd $'carol:x:1008:1008::/home/carol:/bin/bash\nsvc:x:1009:1009::/var/lib/svc:/bin/bash'
    mkdir -p "$AUDIT_ROOT/home/carol" "$AUDIT_ROOT/var/lib/svc"
    chown 1008:1008 "$AUDIT_ROOT/home/carol"; chmod 770 "$AUDIT_ROOT/home/carol"
    chmod 770 "$AUDIT_ROOT/var/lib/svc"                            # root-owned
    _run_check check_home_permissions
    local d
    d=$(issue_text)
    [[ "$d" == *"/home/carol"*"group-writable"* ]]
    [[ "$d" == *"/var/lib/svc"* ]]
    run executable_lines <<< "$(remediation_for "Home directories")"
    [[ "$output" == *"runuser -u carol -- /bin/chmod "*" -- /home/carol"* ]]
    [[ "$output" != *"/var/lib/svc"* ]]
}

# ---- 2. deep: empty passwords --------------------------------------------

@test "empty passwords: every account is locked, only system accounts lose their shell" {
    fixture /etc/login.defs "UID_MIN 1000"
    fixture /etc/passwd $'root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/bash'
    fixture /etc/shadow $'root::19000:0:99999:7:::\ndaemon::19000:0:99999:7:::\nadmin::19000:0:99999:7:::'
    _run_check check_deep_empty_passwords
    local r
    r=$(remediation_for "empty passwords")
    [[ "$r" == *"passwd -l root"* ]]
    [[ "$r" == *"passwd -l daemon"* ]]
    [[ "$r" == *"passwd -l admin"* ]]
    [[ "$r" == *"usermod -s /usr/sbin/nologin daemon"* ]]
    [[ "$r" != *"nologin root"* ]]
    [[ "$r" != *"nologin admin"* ]]
}

# ---- 3. PAM lockout without pam_faillock (Ubuntu 20.04) -------------------

@test "lockout: without pam_faillock.so the advice is pam_tally2, and manual" {
    fixture /lib/x86_64-linux-gnu/security/pam_tally2.so ""
    fixture /etc/pam.d/common-auth "auth [success=1 default=ignore] pam_unix.so nullok_secure"
    _run_check check_pam_lockout
    assert_issue "No PAM brute-force lockout configured"
    local r
    r=$(remediation_for "No PAM brute-force lockout")
    [[ "$r" != *"pam_faillock.so"* ]]
    [[ "$r" != *"faillock.conf"* ]]
    [[ "$r" == *"pam_tally2.so"*"deny="* ]]
    _is_manual_remediation "$r"
}

@test "lockout: with pam_faillock.so the advice stays pam_faillock" {
    fixture /usr/lib/x86_64-linux-gnu/security/pam_faillock.so ""
    fixture /etc/pam.d/common-auth "auth [success=1 default=ignore] pam_unix.so nullok"
    _run_check check_pam_lockout
    local r
    r=$(remediation_for "No PAM brute-force lockout")
    [[ "$r" == *"/usr/share/pam-configs/faillock"* ]]
    [[ "$r" != *"pam_tally2"* ]]
}

@test "lockout: pam_tally2 with deny=5 passes; without deny it does not lock anyone" {
    fixture /lib/x86_64-linux-gnu/security/pam_tally2.so ""
    fixture /etc/pam.d/common-auth "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900"
    _run_check check_pam_lockout
    refute_issue "lockout"
    refute_issue "pam_tally2"
    fixture /etc/pam.d/common-auth "auth required pam_tally2.so onerr=fail audit silent"
    _run_check check_pam_lockout
    assert_issue "pam_tally2 configured but lockout thresholds too permissive"
    TITLES=()
    fixture /etc/pam.d/common-auth "auth required pam_tally2.so deny=10"
    _run_check check_pam_lockout
    assert_issue "pam_tally2 configured but lockout thresholds too permissive"
    _is_manual_remediation "$(remediation_for "pam_tally2")"
}

# ---- 4. password length (CIS 5.3.3.2.2: minlen >= 14) ----------------------

@test "pwquality: minlen 12 and the default 8 fail; 14 passes and the fix writes 14" {
    fixture /etc/pam.d/common-password "password requisite pam_pwquality.so retry=3"
    fixture /etc/security/pwquality.conf "minlen = 12"
    _run_check check_pam_pwquality
    assert_issue "minlen too low"
    [[ "$(remediation_for "minlen too low")" == *"minlen = 14"* ]]
    TITLES=()
    fixture /etc/security/pwquality.conf "# nothing set"
    _run_check check_pam_pwquality
    assert_issue "minlen too low"
    TITLES=()
    fixture /etc/security/pwquality.conf "minlen = 14"
    _run_check check_pam_pwquality
    refute_issue "minlen too low"
}

# ---- 5. root PATH (CIS 5.4.2.5) -------------------------------------------

@test "root PATH: a root-owned group-writable directory is flagged" {
    mkdir -p "$T/p/ok" "$T/p/grp"
    chmod 755 "$T/p/ok"; chmod 775 "$T/p/grp"
    AUDIT_ROOT=""
    mock_cmd env "printf '%s' '$T/p/ok:$T/p/grp'"
    _run_check check_root_path
    assert_issue "Dangerous entries in root PATH"
    [[ "$(issue_text)" == *"$T/p/grp"* ]]
    [[ "$(issue_text)" != *"$T/p/ok "* ]]
}

@test "root PATH: directories not owned by root or group/world-writable are flagged; read under AUDIT_ROOT" {
    need_root
    mkdir -p "$AUDIT_ROOT"/{usr/bin,usr/sbin,opt/grp,opt/user,opt/ww}
    chmod 755 "$AUDIT_ROOT"/usr/bin "$AUDIT_ROOT"/usr/sbin
    chmod 775 "$AUDIT_ROOT/opt/grp"
    chown 1000:1000 "$AUDIT_ROOT/opt/user"; chmod 755 "$AUDIT_ROOT/opt/user"
    chmod 1777 "$AUDIT_ROOT/opt/ww"
    ln -s usr/bin "$AUDIT_ROOT/bin"
    mock_cmd env "printf '%s' '/usr/sbin:/usr/bin:/bin:/opt/grp:/opt/user:/opt/ww:/no/such/dir'"
    _run_check check_root_path
    assert_issue "Dangerous entries in root PATH"
    local d
    d=$(issue_text)
    [[ "$d" == *"/opt/grp"* && "$d" == *"/opt/user"* && "$d" == *"/opt/ww"* ]]
    [[ "$d" != *"/usr/bin ("* && "$d" != *": /bin ("* && "$d" != *"/usr/sbin"* ]]
    [[ "$d" != *"/no/such/dir"* ]]
    [[ "$(remediation_for "root PATH")" != *"$AUDIT_ROOT"* ]]
}

@test "root PATH: root-owned 755 directories (and the /bin symlink) pass; '.' still fails" {
    mkdir -p "$AUDIT_ROOT"/usr/bin "$AUDIT_ROOT"/usr/sbin
    chmod 755 "$AUDIT_ROOT"/usr/bin "$AUDIT_ROOT"/usr/sbin
    ln -s usr/bin "$AUDIT_ROOT/bin"
    mock_cmd env "printf '%s' '/usr/sbin:/usr/bin:/bin'"
    _run_check check_root_path
    refute_issue "root PATH"
    mock_cmd env "printf '%s' '/usr/bin:.'"
    _run_check check_root_path
    assert_issue "Dangerous entries in root PATH"
}

# ---- 6. idle timeout: the first readonly assignment wins -------------------

@test "TMOUT: an earlier 'readonly TMOUT=1800' wins over a later TMOUT=900" {
    fixture /etc/profile.d/10-tmout.sh 'readonly TMOUT=1800'
    fixture /etc/profile.d/99-idle-timeout.sh $'TMOUT=900\nreadonly TMOUT\nexport TMOUT'
    _run_check check_idle_timeout
    assert_issue "Idle session timeout not configured"
    [[ "$(issue_text)" == *"1800"* ]]
}

@test "TMOUT: 'readonly TMOUT' before any value leaves it unset" {
    fixture /etc/profile.d/10-lock.sh 'readonly TMOUT'
    fixture /etc/profile.d/99-idle-timeout.sh $'TMOUT=900\nreadonly TMOUT\nexport TMOUT'
    _run_check check_idle_timeout
    assert_issue "Idle session timeout not configured"
}

@test "TMOUT: without readonly the last assignment still wins" {
    fixture /etc/profile.d/10-tmout.sh 'export TMOUT=1800'
    fixture /etc/profile.d/99-idle-timeout.sh $'TMOUT=900\nreadonly TMOUT\nexport TMOUT'
    _run_check check_idle_timeout
    refute_issue "Idle session timeout"
}

@test "TMOUT: the fix overrides an earlier readonly setting, and the check then passes" {
    fixture /etc/profile.d/10-tmout.sh $'if true; then\n    readonly TMOUT=1800\nfi\nexport TMOUT'
    _run_check check_idle_timeout
    assert_issue "Idle session timeout not configured"
    local r
    r=$(remediation_for "Idle session timeout not configured")
    apply_rem "$r"
    bash -n "$AUDIT_ROOT/etc/profile.d/10-tmout.sh"
    TITLES=()
    _run_check check_idle_timeout
    refute_issue "Idle session timeout"
    # Running the fix again changes nothing.
    cp "$AUDIT_ROOT/etc/profile.d/10-tmout.sh" "$T/before"
    apply_rem "$r"
    diff "$T/before" "$AUDIT_ROOT/etc/profile.d/10-tmout.sh"
}

# ---- 7. failed logins -----------------------------------------------------

mock_failures() {
    mock_cmd journalctl 'for i in 1 2 3 4 5 6 7 8 9 10; do echo "sshd[9]: Failed password for root from 203.0.113.9 port 2222 ssh2"; done'
}

@test "failed logins: mitigated by an active fail2ban sshd jail, not a finding" {
    mock_failures
    mock_cmd fail2ban-client '[ "$1" = status ] && [ "$2" = sshd ] && { echo "Status for the jail: sshd"; exit 0; }; exit 1'
    _run_check check_failed_logins
    refute_issue "failed login"
    [ "$(status_of check_failed_logins)" = "satisfied" ]
}

@test "failed logins: without a jail it is a finding whose fix points elsewhere" {
    mock_failures
    mock_cmd fail2ban-client 'echo "Sorry but the jail sshd does not exist" >&2; exit 255'
    _run_check check_failed_logins
    assert_issue "High failed login count"
    local r
    r=$(remediation_for "High failed login count")
    [[ "$r" == *"check_fail2ban"* ]]
    [[ "$r" == *"PasswordAuthentication no"* ]]
    run executable_lines <<< "$r"
    [ -z "$output" ]
}

# ---- 8. users & sudo ------------------------------------------------------

users_fixture() {
    fixture /etc/passwd "root:x:0:0:root:/root:/bin/bash"
    fixture /etc/shadow "root:*:19000:0:99999:7:::"
}

@test "NOPASSWD: only rules that allow ALL commands are flagged" {
    users_fixture
    fixture /etc/sudoers $'deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app\nops ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: ALL'
    _run_check check_users
    refute_issue "NOPASSWD"
    local rule
    for rule in '%admins ALL=(ALL:ALL) NOPASSWD:ALL' \
                'alice ALL=(ALL) NOPASSWD: /bin/ls, ALL' \
                'bob ALL = (root) NOPASSWD:SETENV: ALL' \
                'carol ALL=(ALL) NOPASSWD: ALL # admin'; do
        TITLES=()
        fixture /etc/sudoers "$rule"
        _run_check check_users
        assert_issue "Users with NOPASSWD sudo"
    done
}

@test "NOPASSWD: sudoers.d files that sudo ignores are not scanned" {
    users_fixture
    fixture /etc/sudoers '#includedir /etc/sudoers.d'
    fixture /etc/sudoers.d/README "# alice ALL=(ALL) NOPASSWD: ALL"
    fixture /etc/sudoers.d/90-old.bak "alice ALL=(ALL) NOPASSWD: ALL"
    fixture "/etc/sudoers.d/90-edit~" "alice ALL=(ALL) NOPASSWD: ALL"
    _run_check check_users
    refute_issue "NOPASSWD"
    fixture /etc/sudoers.d/90-cloud-init-users "ubuntu ALL=(ALL) NOPASSWD:ALL"
    _run_check check_users
    assert_issue "Users with NOPASSWD sudo"
    [[ "$(issue_text)" == *"/etc/sudoers.d/90-cloud-init-users"* ]]
    [[ "$(issue_text)" != *"90-old.bak"* ]]
}

@test "an empty password field in /etc/passwd is flagged and locked" {
    fixture /etc/passwd $'root:x:0:0:root:/root:/bin/bash\nu::1001:1001::/home/u:/bin/bash\nl:!:1002:1002::/home/l:/bin/bash\ns:*:1003:1003::/home/s:/bin/sh'
    fixture /etc/shadow "root:*:19000:0:99999:7:::"
    fixture /etc/sudoers ""
    _run_check check_users
    assert_issue "empty password field in /etc/passwd"
    local r
    r=$(remediation_for "empty password field")
    [[ "$r" == *"pwconv"* ]]
    [[ "$r" == *"passwd -l u"* ]]
    [[ "$r" != *"passwd -l l"* && "$r" != *"passwd -l s"* && "$r" != *"passwd -l root"* ]]
}

# ---- 9. cron (CIS 2.4.1.2 - 2.4.1.7) --------------------------------------

cron_tree() {   # cron_tree CRONTAB_MODE DIR_MODE
    mkdir -p "$AUDIT_ROOT"/etc/cron.{d,hourly,daily,weekly,monthly}
    touch "$AUDIT_ROOT/etc/crontab"
    chmod "$1" "$AUDIT_ROOT/etc/crontab"
    chmod "$2" "$AUDIT_ROOT"/etc/cron.{d,hourly,daily,weekly,monthly}
}

@test "cron: stock 644 crontab and 755 directories fail, with fixes on the real paths" {
    cron_tree 644 755
    _run_check check_cron
    assert_issue "Insecure cron directory or script permissions"
    local d p r
    d=$(issue_text)
    for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ "$d" == *"$p "* ]] || { echo "not reported: $p"; return 1; }
    done
    r=$(remediation_for "Insecure cron")
    run executable_lines <<< "$r"
    [[ "$output" == *"chmod og-rwx -- /etc/crontab"* ]]
    [[ "$output" == *"chmod og-rwx -- /etc/cron.d"* ]]
    [[ "$r" != *"$AUDIT_ROOT"* ]]
}

@test "cron: 600 crontab and 700 root:root directories pass" {
    cron_tree 600 700
    _run_check check_cron
    refute_issue "cron"
    [ "$(status_of check_cron)" = "satisfied" ]
}

@test "cron: a crontab owned by another group fails and is chowned to root" {
    need_root
    cron_tree 600 700
    chown 0:1000 "$AUDIT_ROOT/etc/crontab"
    _run_check check_cron
    assert_issue "Insecure cron"
    run executable_lines <<< "$(remediation_for "Insecure cron")"
    [[ "$output" == *"chown root:root -- /etc/crontab"* ]]
}

@test "cron: a world-writable cron script under AUDIT_ROOT is reported by its real path" {
    cron_tree 600 700
    touch "$AUDIT_ROOT/etc/cron.daily/backup"
    chmod 0757 "$AUDIT_ROOT/etc/cron.daily/backup"
    _run_check check_cron
    assert_issue "Insecure cron"
    [[ "$(issue_text)" == *"world-writable: /etc/cron.daily/backup"* ]]
    [[ "$(remediation_for "Insecure cron")" == *"/etc/cron.daily/backup"* ]]
    [[ "$(remediation_for "Insecure cron")" != *"$AUDIT_ROOT"* ]]
}

@test "cron: the fix makes the check pass" {
    cron_tree 644 755
    _run_check check_cron
    apply_fix "Insecure cron"
    TITLES=()
    _run_check check_cron
    refute_issue "cron"
    [ "$(stat -c '%a' "$AUDIT_ROOT/etc/crontab")" = "600" ]
    [ "$(stat -c '%a' "$AUDIT_ROOT/etc/cron.d")" = "700" ]
}

@test "cron: without cron files the check is not applicable" {
    _run_check check_cron
    [ "$(status_of check_cron)" = "not-applicable" ]
}

# ---- 10. deep: sudo timestamp_timeout --------------------------------------

@test "sudo timeout: commented lines and files sudo ignores do not count" {
    fixture /etc/sudoers $'# Defaults timestamp_timeout=30\n#includedir /etc/sudoers.d'
    fixture /etc/sudoers.d/old.bak "Defaults timestamp_timeout=60"
    fixture "/etc/sudoers.d/10-x~" "Defaults timestamp_timeout=60"
    _run_check check_deep_sudo_timeout
    refute_issue "Sudo password timeout"
}

@test "sudo timeout: the last Defaults in parse order wins" {
    fixture /etc/sudoers $'Defaults timestamp_timeout=30\n#includedir /etc/sudoers.d'
    fixture /etc/sudoers.d/50-short "Defaults env_reset, timestamp_timeout=5"
    _run_check check_deep_sudo_timeout
    refute_issue "Sudo password timeout"
    fixture /etc/sudoers.d/10-a "Defaults timestamp_timeout=5"
    fixture /etc/sudoers.d/50-short "Defaults        timestamp_timeout=-1"
    _run_check check_deep_sudo_timeout
    assert_issue "Sudo password timeout"
    [[ "$(issue_text)" == *"-1"* ]]
}

@test "sudo timeout: a per-user Defaults overrides the global one and is reported" {
    fixture /etc/sudoers $'Defaults timestamp_timeout=5\nDefaults:alice timestamp_timeout=60'
    _run_check check_deep_sudo_timeout
    assert_issue "Sudo password timeout"
    [[ "$(issue_text)" == *"alice"* ]]
}

@test "sudo timeout: the fix installs a validated drop-in that wins, so the check passes" {
    need_root
    fixture /etc/sudoers $'Defaults timestamp_timeout=30\n#includedir /etc/sudoers.d'
    fixture /etc/sudoers.d/90-long "Defaults timestamp_timeout=45"
    _run_check check_deep_sudo_timeout
    assert_issue "Sudo password timeout"
    local r
    r=$(remediation_for "Sudo password timeout")
    [[ "$r" == *"visudo -cf"* ]]
    apply_fix "Sudo password timeout"
    local f="$AUDIT_ROOT/etc/sudoers.d/zz-ubuntu-sec-audit-timeout"
    [ -f "$f" ]
    [ "$(stat -c '%a %U %G' "$f")" = "440 root root" ]
    TITLES=()
    _run_check check_deep_sudo_timeout
    refute_issue "Sudo password timeout"
}

@test "sudo timeout: a drop-in visudo rejects is never installed" {
    fixture /etc/sudoers "Defaults timestamp_timeout=30"
    _run_check check_deep_sudo_timeout
    local r
    r=$(remediation_for "Sudo password timeout")
    mock_cmd sudo '"$@"'
    mock_cmd visudo 'exit 1'
    sed -E -e "s#(^|[[:space:]])/etc/#\\1${AUDIT_ROOT}/etc/#g" -e 's#/usr/sbin/visudo#visudo#g' \
        <<< "$r" > "$T/fix.sh"
    mkdir -p "$AUDIT_ROOT/etc/sudoers.d"
    bash "$T/fix.sh" >/dev/null 2>&1 || true
    [ ! -e "$AUDIT_ROOT/etc/sudoers.d/zz-ubuntu-sec-audit-timeout" ]
}
