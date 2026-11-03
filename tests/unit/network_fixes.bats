#!/usr/bin/env bats
# Network checks: firewall detection and its fixes, IPv6 state, kernel
# forwarding and module hardening, and deprecated listening services.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# ---- helpers -------------------------------------------------------------

# nft_ruleset TEXT — "nft list ruleset" prints TEXT.
nft_ruleset() {
    printf '%s\n' "$1" > "$T/ruleset.nft"
    mock_cmd nft 'cat "'"$T"'/ruleset.nft"'
}

# nft_input_chain FAMILY POLICY RULE... — one input-hook chain in table
# "FAMILY filter" with the given policy and rules.
nft_input_chain() {
    local fam="$1" pol="$2" text
    shift 2
    text=$(printf 'table %s filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy %s;\n' "$fam" "$pol")
    text+=$'\n'$(printf '\t\t%s\n' "$@")
    text+=$'\n'$(printf '\t}\n}')
    nft_ruleset "$text"
}

# ufw_state active|inactive — a ufw whose state lives in a file (so a fix can
# change it); every call is logged to $T/ufw.log.
ufw_state() {
    echo "$1" > "$T/ufw.state"
    mock_cmd ufw 'echo "$*" >> "'"$T"'/ufw.log"
case "$*" in
    status*) echo "Status: $(cat "'"$T"'/ufw.state")"; echo "Logging: on (low)"
             if [ -s "'"$T"'/ufw.rules" ]; then echo; echo "To  Action  From"; echo "--  ------  ----"; cat "'"$T"'/ufw.rules"; fi ;;
    "show added")
             [ -e "'"$T"'/ufw.show-fails" ] && exit 1
             echo "Added user rules (see '"'"'ufw status'"'"' for running firewall):"
             cat "'"$T"'/ufw.added" 2>/dev/null ;;
    disable) echo inactive > "'"$T"'/ufw.state" ;;
    *enable) echo active > "'"$T"'/ufw.state" ;;
esac
exit 0'
}

# sshd_port N — "sshd -T" reports port N.
sshd_port() { mock_cmd sshd 'echo "port '"$1"'"'; }

# ss_listening LINE... — "ss -tulpn" lists these sockets (Netid State
# Recv-Q Send-Q Local Peer Process), after its header line.
ss_listening() {
    {
        echo "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        printf '%s\n' "$@"
    } > "$T/ss.out"
    mock_cmd ss 'cat "'"$T"'/ss.out"'
}

# Sockets of a stock server: loopback resolver and chrony, DHCP client.
SS_STOCK=(
    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))'
    'udp UNCONN 0 0 10.0.0.5%eth0:68 0.0.0.0:* users:(("systemd-network",pid=480,fd=22))'
    'udp UNCONN 0 0 [::1]:323 [::]:* users:(("chronyd",pid=600,fd=6))'
    'tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=14))'
)
SS_SSH_2222=(
    'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=900,fd=3))'
    'tcp LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=900,fd=4))'
)
SS_NGINX=(
    'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1000,fd=6),("nginx",pid=1001,fd=6))'
    'tcp LISTEN 0 511 [::]:80 [::]:* users:(("nginx",pid=1000,fd=7))'
)

# xtables CMD RULES — CMD (iptables/ip6tables) prints RULES for "-S INPUT"
# and the matching chain header for "-nL INPUT".
xtables() {
    local cmd="$1" pol
    printf '%s\n' "$2" > "$T/$cmd.rules"
    pol=$(awk '$1 == "-P" {print $3}' "$T/$cmd.rules")
    mock_cmd "$cmd" "case \"\$*\" in
    '-S INPUT') cat '$T/$cmd.rules' ;;
    '-nL INPUT') echo 'Chain INPUT (policy $pol)' ;;
    *) exit 1 ;;
esac"
}

# local_fix TITLE — that issue's remediation, rewritten to run against the
# fixture tree: command paths lose their /usr/sbin-style prefix (so mocks
# run, never the real tools) and /etc paths point into AUDIT_ROOT.
local_fix() {
    remediation_for "$1" | sed -E \
        -e 's#(^|[[:space:]|;&({])/(usr/)?s?bin/([A-Za-z0-9._-]+)#\1\3#g' \
        -e "s#(^|[[:space:]'])/etc/#\\1${AUDIT_ROOT}/etc/#g"
}

# apply_fix TITLE — run that issue's remediation (see local_fix).
apply_fix() {
    mock_cmd sudo '"$@"'
    local_fix "$1" > "$T/fix.sh"
    bash "$T/fix.sh" >> "$T/fix.out" 2>&1 || true
}

# ---- firewall: the IPv6 fix must not lock anyone out ---------------------

@test "firewall: the IPv6 fix enables IPv6 in an active UFW and allows SSH before reloading" {
    ufw_state active
    echo "2222/tcp                   ALLOW       Anywhere" > "$T/ufw.rules"
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv6)"
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=yes' "$AUDIT_ROOT/etc/default/ufw"
    # SSH is allowed (for IPv6 too) before the reload applies IPv6 rules ...
    run grep -E '^(allow 2222/tcp|reload)$' "$T/ufw.log"
    [ "${lines[0]}" = "allow 2222/tcp" ]
    [ "${lines[1]}" = "reload" ]
    # ... and UFW is never switched off and on again.
    refute grep -qE '(^|[[:space:]])(enable|disable)$' "$T/ufw.log"
}

@test "firewall: the IPv6 fix adds every UFW rule again, so services stay reachable over IPv6" {
    ufw_state active
    printf '%s\n' "2222/tcp                   ALLOW       Anywhere" \
        "80/tcp                     ALLOW       Anywhere" > "$T/ufw.rules"
    # What "ufw show added" prints: rules added while IPV6=no are IPv4-only.
    printf '%s\n' "ufw allow 2222/tcp" "ufw allow 80/tcp" "ufw allow 'Nginx Full'" \
        "ufw allow from 10.0.0.0/8 to any port 5432 proto tcp comment 'db clients'" > "$T/ufw.added"
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=yes' "$AUDIT_ROOT/etc/default/ufw"
    # Each rule is added again (quoted names intact) before the reload.
    run grep -nE '^(allow 80/tcp|allow Nginx Full|allow from 10.0.0.0/8 to any port 5432 proto tcp comment db clients|reload)$' "$T/ufw.log"
    [ "${#lines[@]}" -eq 4 ]
    [[ "${lines[3]}" == *":reload" ]]
}

@test "firewall: the IPv6 fix changes nothing when the UFW rules cannot be listed" {
    ufw_state active
    echo "2222/tcp                   ALLOW       Anywhere" > "$T/ufw.rules"
    touch "$T/ufw.show-fails"
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=no' "$AUDIT_ROOT/etc/default/ufw"
    refute grep -qE '^(allow|limit|reload)' "$T/ufw.log"
}

@test "firewall: the IPv6 fix keeps a rate-limited SSH rule rate-limited" {
    ufw_state active
    echo "2222/tcp                   LIMIT       Anywhere" > "$T/ufw.rules"
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=yes' "$AUDIT_ROOT/etc/default/ufw"
    grep -qx 'limit 2222/tcp' "$T/ufw.log"
    refute grep -qx 'allow 2222/tcp' "$T/ufw.log"
}

@test "firewall: the IPv6 fix never opens SSH that is limited to certain sources" {
    ufw_state active
    echo "2222/tcp                   ALLOW       10.0.0.0/8" > "$T/ufw.rules"
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=no' "$AUDIT_ROOT/etc/default/ufw"
    refute grep -qE '^(allow|limit|reload)' "$T/ufw.log"
    grep -qi 'specific sources' "$T/fix.out"
}

@test "firewall: without an SSH rule the IPv6 fix changes nothing (an IPv6 session could be cut)" {
    ufw_state active
    sshd_port 2222
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=no' "$AUDIT_ROOT/etc/default/ufw"
    refute grep -qE '^(allow|limit|reload)' "$T/ufw.log"
}

@test "firewall: the IPv6 fix leaves UFW alone if it is not active when applied" {
    ufw_state active
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv6)"
    ufw_state inactive
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv6)"
    grep -qx 'IPV6=no' "$AUDIT_ROOT/etc/default/ufw"
    refute grep -qv '^status' "$T/ufw.log"
    [ "$(cat "$T/ufw.state")" = "inactive" ]
}

@test "firewall: with UFW inactive and IPv4 filtered by nftables, the IPv6 fix is manual" {
    ufw_state inactive
    nft_input_chain ip drop "ct state established,related accept" "tcp dport 22 accept"
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
    _is_manual_remediation "$(remediation_for "No Active Firewall (IPv6)")"
}

@test "firewall: with no firewall at all, the IPv6 fix is manual and the IPv4 fix covers IPv6" {
    ufw_state inactive
    sshd_port 2222
    ss_listening "${SS_STOCK[@]}" "${SS_SSH_2222[@]}"
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
    _is_manual_remediation "$(remediation_for "No Active Firewall (IPv6)")"
    # Only SSH listens (loopback and the DHCP client do not count): the IPv4
    # fix runs, turns on IPv6 filtering and allows SSH before enabling UFW.
    refute _is_manual_remediation "$(remediation_for "No Active Firewall (IPv4)")"
    mock_cmd apt-get 'exit 0'
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv4)"
    grep -qx 'IPV6=yes' "$AUDIT_ROOT/etc/default/ufw"
    run grep -E '^(allow 2222/tcp|--force enable)$' "$T/ufw.log"
    [ "${lines[0]}" = "allow 2222/tcp" ]
    [ "${lines[1]}" = "--force enable" ]
}

# ---- firewall: enabling one must not cut off running services -----------

@test "firewall: with other services listening, enabling the firewall is manual and lists each one" {
    ufw_state inactive
    sshd_port 2222
    ss_listening "${SS_STOCK[@]}" "${SS_SSH_2222[@]}" "${SS_NGINX[@]}" \
        'udp UNCONN 0 0 *:51820 *:*' \
        'tcp LISTEN 0 200 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=1100,fd=5))' \
        'tcp LISTEN 0 4096 *:8080 *:* users:(("my app$(id)",pid=1300,fd=6))'
    _run_check check_firewall
    local fix
    fix=$(remediation_for "No Active Firewall (IPv4)")
    _is_manual_remediation "$fix"
    # Every service reachable now gets an allow rule to keep or drop (IPv4
    # and IPv6 sockets of one port once), SSH included ...
    [ "$(grep -c 'ufw allow 80/tcp   # nginx$' <<< "$fix")" -eq 1 ]
    grep -q 'ufw allow 51820/udp   # ?$' <<< "$fix"
    grep -q 'ufw allow 2222/tcp$' <<< "$fix"
    # ... and process names cannot inject anything into the fix script.
    grep -q 'ufw allow 8080/tcp   # my?app??id?$' <<< "$fix"
    # Loopback-only services and the DHCP client are not listed.
    refute grep -qE 'allow (5432|53|68|323)/' <<< "$fix"
    # The note in the report names them too.
    printf '%s\n' "${ISSUES[@]}" | grep -qF '80/tcp (nginx)'
}

@test "firewall: when the listening services cannot be listed (no ss), enabling the firewall is manual" {
    ufw_state inactive
    sshd_port 2222
    _run_check check_firewall
    _is_manual_remediation "$(remediation_for "No Active Firewall (IPv4)")"
    grep -q 'could not be listed' <<< "$(remediation_for "No Active Firewall (IPv4)")"
}

@test "firewall: the IPv4 fix does not enable UFW when a service started listening after the audit" {
    ufw_state inactive
    sshd_port 2222
    ss_listening "${SS_STOCK[@]}" "${SS_SSH_2222[@]}"
    fixture /etc/default/ufw "IPV6=yes"
    _run_check check_firewall
    refute _is_manual_remediation "$(remediation_for "No Active Firewall (IPv4)")"
    # nginx started between the audit and the fix.
    ss_listening "${SS_STOCK[@]}" "${SS_SSH_2222[@]}" "${SS_NGINX[@]}"
    mock_cmd apt-get 'echo "apt-get $*" >> "'"$T"'/ufw.log"'
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv4)"
    # Nothing was changed, not even ufw installed.
    [ ! -s "$T/ufw.log" ]
    [ "$(cat "$T/ufw.state")" = "inactive" ]
    grep -q 'UFW not enabled' "$T/fix.out"
    grep -q '^80/tcp' "$T/fix.out"
}

@test "firewall: the IPv4 fix does not enable UFW when ss fails when it runs" {
    ufw_state inactive
    sshd_port 2222
    ss_listening "${SS_SSH_2222[@]}"
    _run_check check_firewall
    mock_cmd ss 'exit 1'
    mock_cmd apt-get 'exit 0'
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv4)"
    [ "$(cat "$T/ufw.state")" = "inactive" ]
    refute grep -q 'enable' "$T/ufw.log"
}

@test "firewall: the listener filter fits in single quotes in the fix script" {
    [[ "$_FW_LISTENER_AWK" != *"'"* ]]
}

# ---- firewall: what counts as filtering ----------------------------------

@test "firewall: fail2ban's nftables ban chain is not a firewall" {
    nft_ruleset "$(printf '%s\n' 'table inet f2b-table {' \
        $'\tset addr-set-sshd {' $'\t\ttype ipv4_addr' $'\t\telements = { 192.0.2.10 }' $'\t}' \
        $'\tchain f2b-chain {' \
        $'\t\ttype filter hook input priority filter - 1; policy accept;' \
        $'\t\ttcp dport { 22 } ip saddr @addr-set-sshd reject with icmp port-unreachable' \
        $'\t}' '}')"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
}

@test "firewall: CrowdSec's nftables ban chains are not a firewall" {
    nft_ruleset "$(printf '%s\n' 'table ip crowdsec {' \
        $'\tset crowdsec-blacklists { type ipv4_addr; flags timeout; }' \
        $'\tchain crowdsec-chain {' \
        $'\t\ttype filter hook input priority filter; policy accept;' \
        $'\t\tip saddr @crowdsec-blacklists drop' $'\t}' '}' \
        'table ip6 crowdsec6 {' \
        $'\tchain crowdsec6-chain {' \
        $'\t\ttype filter hook input priority filter; policy accept;' \
        $'\t\tip6 saddr @crowdsec6-blacklists drop' $'\t}' '}')"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
}

@test "firewall: a policy-accept input chain that drops only some traffic is not a firewall" {
    nft_input_chain inet accept "ct state established,related accept" "tcp dport 23 drop"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
}

@test "firewall: a policy-accept input chain ending in an unconditional drop or reject is a firewall" {
    local last
    for last in 'drop' 'counter packets 12 bytes 3456 drop' \
                'reject with icmpx type admin-prohibited' 'log prefix "nft-in: " counter reject'; do
        TITLES=()
        nft_input_chain inet accept "ct state established,related accept" "tcp dport 22 accept" "$last"
        _run_check check_firewall
        refute_issue "No Active Firewall (IPv4)"
        refute_issue "No Active Firewall (IPv6)"
    done
}

@test "firewall: an iptables ruleset ending in an unconditional REJECT/DROP is a firewall" {
    xtables iptables "$(printf '%s\n' '-P INPUT ACCEPT' '-A INPUT -i lo -j ACCEPT' \
        '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' \
        '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT' \
        '-A INPUT -j REJECT --reject-with icmp-host-prohibited')"
    xtables ip6tables "$(printf '%s\n' '-P INPUT ACCEPT' '-A INPUT -i lo -j ACCEPT' \
        '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT' '-A INPUT -j DROP')"
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv4)"
    refute_issue "No Active Firewall (IPv6)"
}

@test "firewall: iptables rules that only reject some traffic or jump to fail2ban are not a firewall" {
    xtables iptables "$(printf '%s\n' '-P INPUT ACCEPT' \
        '-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd' \
        '-A INPUT -p tcp -m tcp --dport 23 -j REJECT --reject-with tcp-reset')"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
}

@test "firewall: an iptables DROP policy is a firewall" {
    xtables iptables "$(printf '%s\n' '-P INPUT DROP' '-A INPUT -i lo -j ACCEPT')"
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv4)"
}

# ---- firewall: IPv6 disabled, unreadable rulesets, AUDIT_ROOT ------------

@test "firewall: no IPv6 finding when the kernel was booted with ipv6.disable=1" {
    fixture /proc/cmdline "BOOT_IMAGE=/boot/vmlinuz-6.8.0-31-generic root=UUID=0 ro ipv6.disable=1 quiet"
    ufw_state active
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv6)"
}

@test "firewall: no IPv6 finding when IPv6 is disabled by sysctl" {
    mock_cmd sysctl '[ "${*: -1}" = net.ipv6.conf.all.disable_ipv6 ] && echo 1'
    nft_input_chain ip drop "tcp dport 22 accept"
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv4)"
    refute_issue "No Active Firewall (IPv6)"
}

@test "firewall: IPv6 is still checked while it is enabled" {
    fixture /proc/cmdline "BOOT_IMAGE=/boot/vmlinuz root=UUID=0 ro quiet"
    mock_cmd sysctl '[ "${*: -1}" = net.ipv6.conf.all.disable_ipv6 ] && echo 0'
    nft_input_chain ip drop "tcp dport 22 accept"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv6)"
}

@test "firewall: an nft that cannot read the ruleset is not an error" {
    set -o pipefail   # as in a real run: main() sets it
    mock_cmd nft 'echo "netlink: Error: Operation not permitted" >&2; exit 1'
    ufw_state active
    fixture /etc/default/ufw "IPV6=yes"
    _run_check check_firewall
    [ "${CHECK_ERRORS[check_firewall]:-0}" -eq 0 ]
    [ "${CHECK_STATUS[check_firewall]}" = "satisfied" ]
}

@test "firewall: UFW's IPV6 setting is read from the audited root" {
    ufw_state active
    fixture /etc/default/ufw $'# Set to yes to apply rules to support IPv6\nIPV6=yes'
    _run_check check_firewall
    refute_issue "No Active Firewall (IPv6)"
    TITLES=()
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv6)"
}

# ---- IPv6 exposure -------------------------------------------------------

@test "ipv6: a kernel booted with ipv6.disable=1 reports IPv6 as disabled" {
    fixture /proc/cmdline "BOOT_IMAGE=/boot/vmlinuz root=UUID=0 ro ipv6.disable=1"
    fixture /etc/default/grub 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"'
    _run_check check_ipv6_exposure
    grep -q "IPv6 disabled at boot" "$REPORT_FILE"
    refute grep -q "IPv6 is active" "$REPORT_FILE"
}

@test "ipv6: a kernel without an IPv6 stack reports IPv6 as disabled" {
    mkdir -p "$AUDIT_ROOT/proc/sys/net/ipv4"
    _run_check check_ipv6_exposure
    grep -q "IPv6 disabled at boot" "$REPORT_FILE"
    refute grep -q "IPv6 is active" "$REPORT_FILE"
}

@test "ipv6: the GRUB parameter is read from /etc/default/grub under the audited root" {
    mock_cmd sysctl 'echo 1'
    fixture /etc/default/grub 'GRUB_CMDLINE_LINUX="ipv6.disable=1"'
    _run_check check_ipv6_exposure
    grep -q "fully hardened" "$REPORT_FILE"
}

@test "ipv6: the GRUB parameter is found in /etc/default/grub.d (cloud images)" {
    mock_cmd sysctl 'echo 1'
    fixture /etc/default/grub 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"'
    fixture /etc/default/grub.d/50-cloudimg-settings.cfg \
        'GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0 ipv6.disable=1"'
    _run_check check_ipv6_exposure
    grep -q "fully hardened" "$REPORT_FILE"
}

@test "ipv6: a grub.d file appending to the command line keeps the parameter" {
    mock_cmd sysctl 'echo 1'
    fixture /etc/default/grub 'GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1"'
    fixture /etc/default/grub.d/90-local.cfg \
        'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT console=ttyS0"'
    _run_check check_ipv6_exposure
    grep -q "fully hardened" "$REPORT_FILE"
}

@test "ipv6: a grub.d file overriding the command line drops the parameter" {
    mock_cmd sysctl 'echo 1'
    fixture /etc/default/grub 'GRUB_CMDLINE_LINUX_DEFAULT="quiet ipv6.disable=1"'
    fixture /etc/default/grub.d/50-cloudimg-settings.cfg \
        'GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0"'
    _run_check check_ipv6_exposure
    refute grep -q "fully hardened" "$REPORT_FILE"
    grep -q "sysctl only" "$REPORT_FILE"
}

@test "ipv6: active IPv6 is still reported as active" {
    fixture /proc/cmdline "BOOT_IMAGE=/boot/vmlinuz root=UUID=0 ro quiet"
    mkdir -p "$AUDIT_ROOT/proc/sys/net/ipv6"
    mock_cmd sysctl 'echo 0'
    _run_check check_ipv6_exposure
    grep -q "IPv6 is active" "$REPORT_FILE"
}

# ---- kernel sysctls ------------------------------------------------------

# kernel_sysctls "key value"... — sysctl reports every hardened key as
# compliant, except as overridden; "key -" makes a key absent.
kernel_sysctls() {
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
        [[ "${kv#* }" == "-" ]] || echo "$kv" >> "$T/sysctl.txt"
    done
    mock_cmd sysctl 'k="${*: -1}"; awk -v k="$k" '"'"'$1==k {print $2; f=1} END {exit !f}'"'"' "'"$T"'/sysctl.txt"'
}

@test "kernel: net.ipv6 sysctls are not required when IPv6 is disabled at boot" {
    fixture /proc/cmdline "BOOT_IMAGE=/boot/vmlinuz root=UUID=0 ro ipv6.disable=1"
    kernel_sysctls "net.ipv6.conf.all.forwarding -" "net.ipv6.conf.all.accept_redirects -" \
        "net.ipv6.conf.default.accept_redirects -" "net.ipv6.conf.all.accept_source_route -" \
        "net.ipv6.conf.default.accept_source_route -"
    _run_check check_kernel
    refute_issue "Kernel sysctl hardening incomplete"
}

@test "kernel: net.ipv6 sysctls are not required when IPv6 is disabled by sysctl" {
    kernel_sysctls "net.ipv6.conf.all.disable_ipv6 1" "net.ipv6.conf.all.accept_redirects 1"
    _run_check check_kernel
    refute_issue "Kernel sysctl hardening incomplete"
}

@test "kernel: net.ipv6 sysctls are still checked while IPv6 is enabled" {
    kernel_sysctls "net.ipv6.conf.all.disable_ipv6 0" "net.ipv6.conf.all.accept_redirects 1"
    _run_check check_kernel
    assert_issue "Kernel sysctl hardening incomplete"
}

# forwarding_needed_by CMD... — after CMD sets something up, IP forwarding
# being on is not a finding.
forwarding_needed_by() {
    rm -rf "$AUDIT_ROOT"
    mkdir -p "$AUDIT_ROOT"
    rm -f "$MOCK_BIN"/{docker,kubelet,libvirtd,podman,incus,lxd}
    TITLES=()
    kernel_sysctls "net.ipv4.ip_forward 1" "net.ipv6.conf.all.forwarding 1"
    "$@"
    _run_check check_kernel
    refute_issue "Kernel sysctl hardening incomplete"
}

@test "kernel: IP forwarding is not flagged for LXD, Incus, Kubernetes, libvirt, podman or WireGuard" {
    forwarding_needed_by mkdir -p "$AUDIT_ROOT/var/snap/lxd/common/lxd/storage-pools/default"
    forwarding_needed_by mock_cmd incus
    forwarding_needed_by mock_cmd kubelet
    forwarding_needed_by fixture /lib/systemd/system/kubelet.service "[Unit]"
    forwarding_needed_by mock_cmd libvirtd
    forwarding_needed_by mock_cmd podman
    forwarding_needed_by fixture /etc/wireguard/wg0.conf "[Interface]"
    forwarding_needed_by mock_cmd docker
}

@test "kernel: IP forwarding is reported but never turned off by the fix" {
    kernel_sysctls "net.ipv4.ip_forward 1" "kernel.sysrq 1"
    _run_check check_kernel
    assert_issue "Kernel sysctl hardening incomplete"
    local r
    r=$(remediation_for "Kernel sysctl hardening incomplete")
    run executable_lines <<< "$r"
    [[ "$output" == *"kernel.sysrq = 0"* ]]
    [[ "$output" != *"ip_forward"* ]]
    [[ "$output" != *"forwarding"* ]]
    # Turning it off is explained as a manual step instead.
    [[ "$r" == *"net.ipv4.ip_forward = 0"* ]]
}

@test "kernel: when only IP forwarding is on, the sysctl fix is manual" {
    kernel_sysctls "net.ipv4.ip_forward 1"
    _run_check check_kernel
    assert_issue "Kernel sysctl hardening incomplete"
    _is_manual_remediation "$(remediation_for "Kernel sysctl hardening incomplete")"
}

# ---- kernel module blacklist ---------------------------------------------

# blacklist_all_but MOD... — every module the check wants blacklisted is,
# except MOD...
blacklist_all_but() {
    local m lines=""
    for m in usb-storage cramfs freevxfs jffs2 hfs hfsplus squashfs udf dccp sctp rds tipc; do
        [[ " $* " == *" $m "* ]] && continue
        lines+="blacklist $m"$'\n'
    done
    fixture /etc/modprobe.d/local.conf "$lines"
}

@test "kernel modules: a loaded module is never blacklisted automatically" {
    blacklist_all_but usb-storage cramfs
    mkdir -p "$AUDIT_ROOT/sys/module/usb_storage"
    _run_check check_kernel
    assert_issue "Dangerous kernel modules not blacklisted"
    local r
    r=$(remediation_for "Dangerous kernel modules not blacklisted")
    run executable_lines <<< "$r"
    [[ "$output" == *"blacklist cramfs"* ]]
    [[ "$output" != *"usb-storage"* ]]
    # It is listed for a person to handle.
    [[ "$r" == *"usb-storage"* ]]
}

@test "kernel modules: when every missing module is loaded, the fix is manual" {
    blacklist_all_but usb-storage
    mkdir -p "$AUDIT_ROOT/sys/module/usb_storage"
    _run_check check_kernel
    assert_issue "Dangerous kernel modules not blacklisted"
    _is_manual_remediation "$(remediation_for "Dangerous kernel modules not blacklisted")"
}

@test "kernel modules: udf is not required on Azure / Hyper-V" {
    blacklist_all_but udf
    fixture /sys/class/dmi/id/sys_vendor "Microsoft Corporation"
    _run_check check_kernel
    refute_issue "Dangerous kernel modules not blacklisted"
    # ... but still is elsewhere.
    fixture /sys/class/dmi/id/sys_vendor "QEMU"
    _run_check check_kernel
    assert_issue "Dangerous kernel modules not blacklisted"
}

@test "kernel modules: the initramfs is rebuilt only when the blacklist changed" {
    blacklist_all_but cramfs
    _run_check check_kernel
    mock_cmd update-initramfs 'echo "$*" >> "'"$T"'/initramfs.log"'
    mock_cmd modprobe 'exit 0'
    apply_fix "Dangerous kernel modules not blacklisted"
    apply_fix "Dangerous kernel modules not blacklisted"
    grep -qx 'blacklist cramfs' "$AUDIT_ROOT/etc/modprobe.d/99-hardening-blacklist.conf"
    [ "$(grep -c 'blacklist cramfs' "$AUDIT_ROOT/etc/modprobe.d/99-hardening-blacklist.conf")" -eq 1 ]
    [ "$(grep -c . "$T/initramfs.log")" -eq 1 ]
}

# ---- open ports ----------------------------------------------------------

# ss_lines LINE... — "ss -tulpn" lists these sockets.
ss_lines() {
    {
        echo "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
        printf '%s\n' "$@"
    } > "$T/ss.txt"
    mock_cmd ss 'cat "'"$T"'/ss.txt"'
}

# proc_exe PID PATH — /proc/PID/exe points at PATH in the fixture tree.
proc_exe() {
    mkdir -p "$AUDIT_ROOT/proc/$1"
    ln -s "$2" "$AUDIT_ROOT/proc/$1/exe"
}

DEPRECATED="Deprecated or plaintext network services listening"

@test "open ports: without ss or netstat the check is skipped, not passed" {
    _run_check check_open_ports
    [ "${CHECK_STATUS[check_open_ports]}" = "skipped" ]
}

@test "open ports: a syslog server on 514/udp is not a deprecated service" {
    ss_lines 'udp   UNCONN 0      0            0.0.0.0:514        0.0.0.0:*    users:(("rsyslogd",pid=812,fd=6))' \
             'udp   UNCONN 0      0               [::]:514           [::]:*    users:(("rsyslogd",pid=812,fd=7))'
    _run_check check_open_ports
    refute_issue "$DEPRECATED"
}

@test "open ports: netstat output is matched on protocol too (tcp6, 514/udp)" {
    printf '%s\n' 'Active Internet connections (only servers)' \
        'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name' \
        'tcp6       0      0 :::23                   :::*                    LISTEN      900/inetd' \
        'udp        0      0 0.0.0.0:514             0.0.0.0:*                           812/rsyslogd' \
        > "$T/netstat.txt"
    mock_cmd netstat 'cat "'"$T"'/netstat.txt"'
    _run_check check_open_ports
    assert_issue "$DEPRECATED"
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"Telnet"*"on 23/tcp"* ]]
    [[ "$d" != *"514"* ]]
}

@test "open ports: rexec, rlogin and rsh are named by protocol and port" {
    ss_lines 'tcp LISTEN 0 128 0.0.0.0:512 0.0.0.0:* users:(("in.rexecd",pid=1001,fd=3))' \
             'tcp LISTEN 0 128 0.0.0.0:513 0.0.0.0:* users:(("in.rlogind",pid=1002,fd=3))' \
             'tcp LISTEN 0 128 0.0.0.0:514 0.0.0.0:* users:(("in.rshd",pid=1003,fd=3))'
    _run_check check_open_ports
    assert_issue "$DEPRECATED"
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    # Every "<label> (...) on PORT/tcp" names the right service.
    run grep -oE '[A-Za-z]+ \([^)]*\) on 512/tcp' <<< "$d"
    [ "${#lines[@]}" -gt 0 ]
    refute grep -qv '^rexec ' <<< "$output"
    run grep -oE '[A-Za-z]+ \([^)]*\) on 513/tcp' <<< "$d"
    [ "${#lines[@]}" -gt 0 ]
    refute grep -qv '^rlogin ' <<< "$output"
    run grep -oE '[A-Za-z]+ \([^)]*\) on 514/tcp' <<< "$d"
    [ "${#lines[@]}" -gt 0 ]
    refute grep -qv '^rsh ' <<< "$output"
}

@test "open ports: the fix stops and removes the package that owns the listener" {
    ss_lines 'tcp LISTEN 0 32 0.0.0.0:21 0.0.0.0:* users:(("vsftpd",pid=4242,fd=3))'
    proc_exe 4242 /usr/sbin/vsftpd
    mock_cmd dpkg 'case "$1 $2" in
    "-S /usr/sbin/vsftpd") echo "vsftpd: /usr/sbin/vsftpd" ;;
    "-L vsftpd") printf "%s\n" /usr/sbin/vsftpd /usr/lib/systemd/system/vsftpd.service ;;
    *) exit 1 ;;
esac'
    _run_check check_open_ports
    local r
    r=$(remediation_for "$DEPRECATED")
    refute _is_manual_remediation "$r"
    run executable_lines <<< "$r"
    [[ "$output" == *"systemctl disable --now vsftpd.service"* ]]
    [[ "$output" == *"apt-get purge -y vsftpd"* ]]
    # Only what was found is touched.
    [[ "$output" != *"telnetd"* ]]
    [[ "$output" != *"ufw"* ]]
}

@test "open ports: a service run by inetd is removed through its own package, only while SSH runs" {
    ss_lines 'tcp LISTEN 0 64 0.0.0.0:23 0.0.0.0:* users:(("inetd",pid=900,fd=7))'
    proc_exe 900 /usr/sbin/inetd
    fixture /etc/inetd.conf "$(printf '%s\n' \
        $'#<off># ftp\tstream\ttcp\tnowait\troot\t/usr/sbin/tcpd\t/usr/sbin/in.ftpd' \
        $'telnet\tstream\ttcp\tnowait\ttelnetd\t/usr/sbin/tcpd\t/usr/sbin/in.telnetd')"
    mock_cmd dpkg 'case "$1 $2" in
    "-S /usr/sbin/inetd") echo "openbsd-inetd: /usr/sbin/inetd" ;;
    "-S /usr/sbin/in.telnetd") echo "telnetd: /usr/sbin/in.telnetd" ;;
    *) exit 1 ;;
esac'
    _run_check check_open_ports
    local r
    r=$(remediation_for "$DEPRECATED")
    run executable_lines <<< "$r"
    [[ "$output" == *"apt-get purge -y telnetd"* ]]
    [[ "$output" != *"openbsd-inetd"* ]]
    # Telnet is a remote login: it is removed only while SSH is running.
    mock_cmd apt-get 'echo "apt-get $*" >> "'"$T"'/apt.log"'
    mock_cmd systemctl 'exit 3'
    apply_fix "$DEPRECATED"
    [ ! -e "$T/apt.log" ]
    mock_cmd systemctl '[ "$1 $2 $3" = "is-active --quiet ssh.socket" ]'
    apply_fix "$DEPRECATED"
    grep -qx 'apt-get purge -y telnetd' "$T/apt.log"
}

@test "open ports: the fix is manual when the owning package is unknown" {
    ss_lines 'udp UNCONN 0 0 0.0.0.0:69 0.0.0.0:*'
    _run_check check_open_ports
    assert_issue "$DEPRECATED"
    _is_manual_remediation "$(remediation_for "$DEPRECATED")"
}

@test "open ports: a socket held by systemd is never fixed by removing systemd" {
    ss_lines 'tcp LISTEN 0 4096 *:23 *:* users:(("systemd",pid=1,fd=50))'
    proc_exe 1 /usr/lib/systemd/systemd
    mock_cmd dpkg 'if [ "$1 $2" = "-S /usr/lib/systemd/systemd" ]; then echo "systemd: /usr/lib/systemd/systemd"; else exit 1; fi'
    _run_check check_open_ports
    local r
    r=$(remediation_for "$DEPRECATED")
    _is_manual_remediation "$r"
    [[ "$r" != *"purge -y systemd"* ]]
}

@test "kernel: a seeded but unused LXD snap does not hide IP forwarding" {
    mkdir -p "$AUDIT_ROOT/var/snap/lxd/common/lxd/storage-pools"
    mock_cmd lxd
    kernel_sysctls "net.ipv4.ip_forward 1" "net.ipv6.conf.all.forwarding 1"
    _run_check check_kernel
    assert_issue "Kernel sysctl hardening incomplete"
}

@test "open ports: an interpreter's package is never purged to close a port" {
    ss_lines 'tcp LISTEN 0 32 0.0.0.0:21 0.0.0.0:* users:(("python3",pid=4242,fd=3))'
    proc_exe 4242 /usr/bin/python3.12
    mock_cmd dpkg 'case "$1 $2" in
    "-S /usr/bin/python3.12") echo "python3.12-minimal: /usr/bin/python3.12" ;;
    *) exit 1 ;;
esac'
    _run_check check_open_ports
    local r
    r=$(remediation_for "$DEPRECATED")
    refute grep -q 'apt-get purge' <<< "$(executable_lines <<< "$r")"
    [[ "$r" == *"python3"* ]]
}

@test "firewall: the IPv4 fix allows every port sshd listens on" {
    ufw_state inactive
    mock_cmd sshd '[ "$1" = "-T" ] && printf "%s\n" "port 22" "port 2222"'
    _run_check check_firewall
    run executable_lines <<< "$(remediation_for "No Active Firewall (IPv4)")"
    [[ "$output" == *"ufw allow 22/tcp"* ]]
    [[ "$output" == *"ufw allow 2222/tcp"* ]]
}

@test "firewall: when the SSH port cannot be read, the fix does not enable a firewall" {
    ufw_state inactive
    mock_cmd sshd 'echo "Missing privilege separation directory: /run/sshd" >&2; exit 255'
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    _is_manual_remediation "$(remediation_for "No Active Firewall (IPv4)")"
}

@test "firewall: a port set by ListenAddress host:port is allowed too" {
    ufw_state inactive
    mock_cmd sshd '[ "$1" = "-T" ] && printf "%s\n" "port 22" "listenaddress 0.0.0.0:2222" "listenaddress [::]:2222"'
    _run_check check_firewall
    run executable_lines <<< "$(remediation_for "No Active Firewall (IPv4)")"
    [[ "$output" == *"ufw allow 2222/tcp"* ]]
}

@test "firewall: an unknown SSH port is never presented as 22" {
    ufw_state inactive
    mock_cmd sshd 'echo "Missing privilege separation directory: /run/sshd" >&2; exit 255'
    _run_check check_firewall
    local r
    r=$(remediation_for "No Active Firewall (IPv4)")
    [[ "$r" != *"allow 22/tcp"* ]]
    [[ "$r" != *"detected: 22"* ]]
    [[ "$(printf '%s\n' "${ISSUES[@]}")" != *"detected: 22"* ]]
}

@test "firewall: with UFW active and the SSH port unknown, the IPv6 fix is manual" {
    ufw_state active
    echo "22/tcp                     ALLOW       Anywhere" > "$T/ufw.rules"
    fixture /etc/default/ufw "IPV6=no"
    mock_cmd sshd 'echo "Missing privilege separation directory: /run/sshd" >&2; exit 255'
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv6)"
    local r
    r=$(remediation_for "No Active Firewall (IPv6)")
    _is_manual_remediation "$r"
    [[ "$r" != *"allow 22/tcp"* ]]
}

@test "open ports: a package that does not ship the service is never purged (runtimes off any list)" {
    ss_lines 'tcp LISTEN 0 32 0.0.0.0:21 0.0.0.0:* users:(("java",pid=4242,fd=3))'
    proc_exe 4242 /usr/lib/jvm/temurin-17-jdk-amd64/bin/java
    mock_cmd dpkg 'case "$1 $2" in
    "-S /usr/lib/jvm/temurin-17-jdk-amd64/bin/java") echo "temurin-17-jdk: /usr/lib/jvm/temurin-17-jdk-amd64/bin/java" ;;
    "-L temurin-17-jdk") printf "%s\n" /usr/lib/jvm/temurin-17-jdk-amd64/bin/java ;;
    *) exit 1 ;;
esac'
    _run_check check_open_ports
    local r
    r=$(remediation_for "$DEPRECATED")
    refute grep -q 'apt-get purge' <<< "$(executable_lines <<< "$r")"
    [[ "$r" == *"java"* ]]
}
