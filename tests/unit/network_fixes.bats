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
    status*) echo "Status: $(cat "'"$T"'/ufw.state")"; echo "Logging: on (low)" ;;
    disable) echo inactive > "'"$T"'/ufw.state" ;;
    *enable) echo active > "'"$T"'/ufw.state" ;;
esac
exit 0'
}

# sshd_port N — "sshd -T" reports port N.
sshd_port() { mock_cmd sshd 'echo "port '"$1"'"'; }

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
    fixture /etc/default/ufw "IPV6=no"
    _run_check check_firewall
    assert_issue "No Active Firewall (IPv4)"
    assert_issue "No Active Firewall (IPv6)"
    _is_manual_remediation "$(remediation_for "No Active Firewall (IPv6)")"
    # The IPv4 fix turns on IPv6 filtering and allows SSH before enabling UFW.
    mock_cmd apt-get 'exit 0'
    : > "$T/ufw.log"
    apply_fix "No Active Firewall (IPv4)"
    grep -qx 'IPV6=yes' "$AUDIT_ROOT/etc/default/ufw"
    run grep -E '^(allow 2222/tcp|--force enable)$' "$T/ufw.log"
    [ "${lines[0]}" = "allow 2222/tcp" ]
    [ "${lines[1]}" = "--force enable" ]
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
