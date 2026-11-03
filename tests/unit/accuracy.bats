#!/usr/bin/env bats
# Checks must pass on compliant systems (including stock Ubuntu defaults
# that are compliant) and keep passing after their own fix is applied.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# ---- umask ---------------------------------------------------------------

@test "umask: 027 from login.defs passes (mawk-compatible parsing)" {
    fixture /etc/login.defs $'# comment\nUMASK\t\t027'
    _run_check check_umask
    refute_issue "Weak default umask"
}

@test "umask: the value the fix writes passes" {
    fixture /etc/login.defs "UMASK           027"
    _run_check check_umask
    refute_issue "Weak default umask"
}

@test "umask: 077 passes, 022 and 000 fail" {
    fixture /etc/login.defs "UMASK 077"
    _run_check check_umask
    refute_issue "Weak default umask"
    fixture /etc/login.defs "UMASK 022"
    _run_check check_umask
    assert_issue "Weak default umask"
    TITLES=()
    fixture /etc/login.defs "UMASK 000"
    _run_check check_umask
    assert_issue "Weak default umask"
}

# ---- password quality ----------------------------------------------------

@test "pwquality: minlen = 12 in pwquality.conf (the fix's format) passes" {
    fixture /etc/pam.d/common-password "password requisite pam_pwquality.so retry=3"
    fixture /etc/security/pwquality.conf $'# minlen = 8\nminlen = 12'
    _run_check check_pam_pwquality
    refute_issue "minlen too low"
    refute_issue "No PAM password complexity"
}

@test "pwquality: minlen = 6 fails" {
    fixture /etc/pam.d/common-password "password requisite pam_pwquality.so retry=3"
    fixture /etc/security/pwquality.conf "minlen = 6"
    _run_check check_pam_pwquality
    assert_issue "minlen too low"
}

# ---- account lockout -----------------------------------------------------

@test "faillock: settings with spaces in faillock.conf pass" {
    fixture /etc/pam.d/common-auth "auth requisite pam_faillock.so preauth"
    fixture /etc/security/faillock.conf $'# deny = 3\ndeny = 5\nunlock_time = 900'
    _run_check check_pam_lockout
    refute_issue "pam_faillock configured but lockout thresholds too permissive"
    refute_issue "No PAM brute-force lockout"
}

@test "faillock: a commented-out pam_faillock line does not count" {
    fixture /etc/pam.d/common-auth "# auth requisite pam_faillock.so preauth"
    _run_check check_pam_lockout
    assert_issue "No PAM brute-force lockout configured"
}

@test "faillock: PAM is changed only by hand; faillock.conf is written" {
    fixture /etc/pam.d/common-auth "auth [success=1 default=ignore] pam_unix.so"
    _run_check check_pam_lockout
    local r
    r=$(remediation_for "No PAM brute-force lockout")
    run executable_lines <<< "$r"
    [[ "$output" == *"/etc/security/faillock.conf"* ]]
    [[ "$output" != *"pam-auth-update"* ]]
    [[ "$r" == *"/usr/share/pam-configs/faillock"* ]]
}

# ---- journald ------------------------------------------------------------

@test "journald: stock config (#Storage=auto) with /var/log/journal passes" {
    fixture /etc/systemd/journald.conf $'[Journal]\n#Storage=auto'
    mkdir -p "$AUDIT_ROOT/var/log/journal"
    _run_check check_journald
    refute_issue "journald"
}

@test "journald: auto without /var/log/journal and explicit volatile both fail" {
    fixture /etc/systemd/journald.conf $'[Journal]\n#Storage=auto'
    _run_check check_journald
    assert_issue "journald logs may be volatile"
    TITLES=()
    fixture /etc/systemd/journald.conf $'[Journal]\nStorage=volatile'
    _run_check check_journald
    assert_issue "journald logs not persistent"
}

@test "journald: a drop-in overrides the main file" {
    fixture /etc/systemd/journald.conf $'[Journal]\nStorage=volatile'
    fixture /etc/systemd/journald.conf.d/50-persist.conf $'[Journal]\nStorage=persistent'
    _run_check check_journald
    refute_issue "journald"
}

# ---- DNS -----------------------------------------------------------------

@test "dns: the fix's resolved drop-in makes the check pass" {
    mock_cmd systemctl 'exit 0'
    mock_cmd resolvectl 'printf "Global\n       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\n"'
    fixture /etc/systemd/resolved.conf $'[Resolve]\n#DNSSEC=no'
    fixture /etc/systemd/resolved.conf.d/99-hardening.conf $'[Resolve]\nDNSSEC=allow-downgrade\nDNSOverTLS=opportunistic'
    _run_check check_dns_security
    refute_issue "DNS security not fully configured"
}

@test "dns: stock config fails" {
    mock_cmd systemctl 'exit 0'
    fixture /etc/systemd/resolved.conf $'[Resolve]\n#DNSSEC=no\n#DNSOverTLS=no'
    _run_check check_dns_security
    assert_issue "DNS security not fully configured"
}

# ---- SSH -----------------------------------------------------------------

# A weak KEX makes the fix write a KexAlgorithms line (it writes only the
# settings that fail).
weak_sshd() {
    mock_cmd sshd 'printf "%s\n" "permitrootlogin yes" "passwordauthentication yes" "kexalgorithms diffie-hellman-group14-sha1,curve25519-sha256"'
}

@test "ssh: the drop-in sorts first so it wins over 50-cloud-init.conf" {
    weak_sshd
    _run_check check_ssh
    local r
    r=$(remediation_for "SSH configuration weaknesses")
    [[ "$r" == *"/etc/ssh/sshd_config.d/00-"*".conf"* ]]
    [[ "$r" != *"99-hardening.conf"* ]]
}

@test "ssh: post-quantum key exchange is kept when OpenSSH supports it" {
    weak_sshd
    mock_cmd ssh '[ "$1 $2" = "-Q kex" ] && printf "%s\n" curve25519-sha256 curve25519-sha256@libssh.org sntrup761x25519-sha512@openssh.com mlkem768x25519-sha256 diffie-hellman-group16-sha512 diffie-hellman-group18-sha512'
    _run_check check_ssh
    run grep -E '^KexAlgorithms ' <<< "$(remediation_for "SSH configuration weaknesses")"
    [ "$output" = "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512" ]
}

@test "ssh: algorithms OpenSSH does not support are left out" {
    weak_sshd
    mock_cmd ssh '[ "$1 $2" = "-Q kex" ] && printf "%s\n" curve25519-sha256 diffie-hellman-group16-sha512'
    _run_check check_ssh
    run grep -E '^KexAlgorithms ' <<< "$(remediation_for "SSH configuration weaknesses")"
    [ "$output" = "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512" ]
}

# ---- auditd --------------------------------------------------------------

@test "auditd: rules are written to rules.d so they survive reloads" {
    mock_cmd auditctl 'echo "No rules"'
    mock_cmd systemctl 'exit 1'
    _run_check check_auditd
    local r
    r=$(remediation_for "auditd configuration incomplete")
    [[ "$r" == *"/etc/audit/rules.d/"* ]]
    run executable_lines <<< "$r"
    refute grep -qE 'auditctl -w|auditctl -a' <<< "$output"
}

# ---- kernel sysctls ------------------------------------------------------

# sysctl_fixture "key value" ... — every hardened key compliant unless overridden.
sysctl_fixture() {
    cat > "$T/sysctl.txt" <<'EOF'
kernel.randomize_va_space 2
fs.protected_hardlinks 1
fs.protected_symlinks 1
kernel.dmesg_restrict 1
kernel.kptr_restrict 2
kernel.yama.ptrace_scope 1
fs.protected_fifos 1
fs.protected_regular 1
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.default.accept_redirects 0
net.ipv4.conf.all.send_redirects 0
net.ipv4.conf.all.secure_redirects 0
net.ipv4.conf.default.secure_redirects 0
net.ipv4.conf.all.accept_source_route 0
net.ipv4.conf.default.accept_source_route 0
net.ipv4.conf.all.log_martians 1
net.ipv4.conf.default.log_martians 1
net.ipv4.tcp_syncookies 1
net.ipv4.conf.all.rp_filter 1
net.ipv4.conf.default.rp_filter 1
net.ipv4.ip_forward 0
net.ipv6.conf.all.forwarding 0
net.ipv6.conf.all.accept_redirects 0
net.ipv6.conf.default.accept_redirects 0
net.ipv6.conf.all.accept_source_route 0
net.ipv6.conf.default.accept_source_route 0
kernel.unprivileged_bpf_disabled 1
net.core.bpf_jit_harden 2
kernel.kexec_load_disabled 1
kernel.perf_event_paranoid 3
kernel.sysrq 0
net.ipv4.tcp_timestamps 0
net.ipv4.icmp_echo_ignore_broadcasts 1
net.ipv4.icmp_ignore_bogus_error_responses 1
net.ipv4.tcp_rfc1337 1
EOF
    local kv
    for kv in "$@"; do
        sed -i "/^${kv%% *} /d" "$T/sysctl.txt"
        echo "$kv" >> "$T/sysctl.txt"
    done
    mock_cmd sysctl 'k="${*: -1}"; awk -v k="$k" '"'"'$1==k {print $2; f=1} END {exit !f}'"'"' "'"$T"'/sysctl.txt"'
}

@test "sysctl: stricter-than-required values pass (Ubuntu's bpf default is 2)" {
    sysctl_fixture "kernel.yama.ptrace_scope 3" "kernel.unprivileged_bpf_disabled 2" \
                   "kernel.perf_event_paranoid 4" "fs.protected_regular 2"
    _run_check check_kernel
    refute_issue "Kernel sysctl hardening incomplete"
}

@test "sysctl: the fix keeps stricter current values instead of lowering them" {
    sysctl_fixture "kernel.yama.ptrace_scope 3" "net.ipv4.ip_forward 1"
    _run_check check_kernel
    local r
    r=$(remediation_for "Kernel sysctl hardening incomplete")
    [[ "$r" == *"kernel.yama.ptrace_scope = 3"* ]]
    [[ "$r" == *"net.ipv4.ip_forward = 0"* ]]
}

@test "sysctl: secure ICMP redirects must be off (CIS 3.3.6)" {
    sysctl_fixture "net.ipv4.conf.all.secure_redirects 1"
    _run_check check_kernel
    assert_issue "Kernel sysctl hardening incomplete"
    [[ "$(remediation_for "Kernel sysctl")" == *"net.ipv4.conf.all.secure_redirects = 0"* ]]
}

# ---- core dumps ----------------------------------------------------------

core_fixture() {
    fixture /etc/security/limits.d/99-no-coredump.conf "* hard core 0"
    mock_cmd sysctl 'case "${*: -1}" in fs.suid_dumpable) echo 0 ;; kernel.core_pattern) echo "'"$1"'" ;; esac'
}

@test "core dumps: apport is flagged and the fix disables it without needing systemd-coredump" {
    core_fixture '|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E'
    _run_check check_core_dumps
    local r
    r=$(remediation_for "Core dump restrictions")
    [[ "$r" == *"apport"* ]]
    [[ "$r" == *"kernel.core_pattern = |/bin/false"* ]]
    [[ "$r" != *"systemd-coredump"* ]]
    [[ "$r" != *"tee -a /etc/sysctl.d"* ]]
}

@test "core dumps: |/bin/false passes" {
    core_fixture '|/bin/false'
    _run_check check_core_dumps
    refute_issue "Core dump restrictions"
}

# ---- disk encryption -----------------------------------------------------

@test "disk encryption: LVM on LUKS (Ubuntu's encrypted install) counts as encrypted root" {
    mock_cmd findmnt 'echo /dev/mapper/ubuntu--vg-ubuntu--lv'
    mock_cmd lsblk 'if [ "$1" = "-s" ]; then printf "lvm\ncrypt\npart\ndisk\n"; else printf "nvme0n1 disk\nnvme0n1p3 part\ndm_crypt-0 crypt\nubuntu--vg-ubuntu--lv lvm\n"; fi'
    mock_cmd blkid 'echo "/dev/nvme0n1p3: UUID=\"x\" TYPE=\"crypto_LUKS\""'
    _run_check check_disk_encryption
    refute_issue "encryption"
}

@test "disk encryption: no LUKS is reported once, without arithmetic errors" {
    mock_cmd findmnt 'echo /dev/sda1'
    mock_cmd lsblk 'if [ "$1" = "-s" ]; then printf "part\ndisk\n"; else printf "sda disk\nsda1 part\n"; fi'
    mock_cmd blkid 'echo "/dev/sda1: TYPE=\"ext4\""'
    _run_check check_disk_encryption > "$T/out.txt" 2>&1
    assert_issue "No disk encryption detected"
    refute grep -q "syntax error" "$T/out.txt"
}

# ---- firewall ------------------------------------------------------------

@test "firewall: nftables chains without a filtering input policy are not a firewall" {
    mock_cmd nft 'printf "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n\tchain DOCKER {\n\t}\n}\n"'
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
}

@test "firewall: an inet table with a dropping input chain covers IPv4 and IPv6" {
    mock_cmd nft 'printf "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t}\n}\n"'
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv4)"
    refute_issue "No Active Firewall (IPv6)"
}

# ---- secrets -------------------------------------------------------------

@test "secrets: only keys inside .ssh count as SSH keys, and only they are fixed" {
    fixture /home/alice/project/id_utils.py "print('not a key')"
    fixture /home/alice/.ssh/id_ed25519 "-----BEGIN OPENSSH PRIVATE KEY-----"
    chmod 644 "$AUDIT_ROOT/home/alice/project/id_utils.py" "$AUDIT_ROOT/home/alice/.ssh/id_ed25519"
    _run_check check_secrets
    local d r
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *".ssh/id_ed25519"* ]]
    [[ "$d" != *"id_utils.py"* ]]
    r=$(remediation_for "Exposed credentials")
    [[ "$r" == *"[ -L ${AUDIT_ROOT}/home/alice/.ssh/id_ed25519 ] || sudo /bin/chmod 600 -- ${AUDIT_ROOT}/home/alice/.ssh/id_ed25519"* ]]
    [[ "$r" != *"-exec chmod"* ]]
}

# ---- critical file permissions ------------------------------------------

@test "permissions: /etc/shadow at 600 (stricter than 640) passes" {
    fixture /etc/shadow "root:*:1::::::"
    fixture /etc/passwd "root:x:0:0::/root:/bin/bash"
    chmod 600 "$AUDIT_ROOT/etc/shadow"
    chmod 644 "$AUDIT_ROOT/etc/passwd"
    _run_check check_permissions
    refute_issue "Weak critical file permissions"
}

@test "permissions: world-readable /etc/shadow fails" {
    fixture /etc/shadow "root:*:1::::::"
    fixture /etc/passwd "root:x:0:0::/root:/bin/bash"
    chmod 644 "$AUDIT_ROOT/etc/shadow" "$AUDIT_ROOT/etc/passwd"
    _run_check check_permissions
    assert_issue "Weak critical file permissions"
}

# ---- idle timeout --------------------------------------------------------

@test "TMOUT: 'readonly TMOUT=900' and 'declare -xr TMOUT=600' are recognised" {
    fixture /etc/profile.d/tmout.sh $'readonly TMOUT=900\nexport TMOUT'
    _run_check check_idle_timeout
    refute_issue "Idle session timeout"
    fixture /etc/profile.d/tmout.sh 'declare -xr TMOUT=600'
    _run_check check_idle_timeout
    refute_issue "Idle session timeout"
}

@test "TMOUT: the fix's own file passes; 1800 fails" {
    fixture /etc/profile.d/99-idle-timeout.sh $'TMOUT=900\nreadonly TMOUT\nexport TMOUT'
    _run_check check_idle_timeout
    refute_issue "Idle session timeout"
    fixture /etc/profile.d/99-idle-timeout.sh $'TMOUT=1800\nreadonly TMOUT'
    _run_check check_idle_timeout
    assert_issue "Idle session timeout"
}

# ---- mounts --------------------------------------------------------------

@test "mounts: the /var/tmp fix keeps it on disk (bind mount, not tmpfs)" {
    mock_cmd mount 'printf "%s\n" "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec)" "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec)"'
    mkdir -p "$AUDIT_ROOT/var/tmp"
    _run_check check_mount_options
    local r
    r=$(remediation_for "Insecure mount options")
    [[ "$r" == *"/var/tmp /var/tmp none"*"bind"* ]]
    [[ "$r" != *"tmpfs /var/tmp"* ]]
}

# ---- home directories ----------------------------------------------------

@test "home dirs: taken from /etc/passwd; /root's subdirectories are not homes" {
    fixture /etc/login.defs "UID_MIN 1000"
    fixture /etc/passwd $'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash'
    mkdir -p "$AUDIT_ROOT/root/snap" "$AUDIT_ROOT/home/alice" "$AUDIT_ROOT/home/bob"
    chmod 700 "$AUDIT_ROOT/root"; chmod 755 "$AUDIT_ROOT/root/snap"
    chmod 750 "$AUDIT_ROOT/home/alice"; chmod 755 "$AUDIT_ROOT/home/bob"
    _run_check check_home_permissions
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/home/bob"* ]]
    [[ "$d" != *"/root/snap"* ]]
    [[ "$d" != *"/home/alice"* ]]
}
