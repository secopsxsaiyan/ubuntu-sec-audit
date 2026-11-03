# shellcheck shell=bash
# check_firewall — standard check (sourced by ubuntu-sec-audit.sh)

# _nft_filtering_families — prints 4 and/or 6 for the address families whose
# inbound traffic an nftables input-hook chain filters: the chain has policy
# drop, or its last rule drops/rejects everything (only counter, log and
# comment may come with the verdict). Chains that drop only some packets do
# not count, nor do Docker's policy-accept chains, and the ban tables of
# fail2ban (f2b-*) and CrowdSec are ignored: they are not a firewall.
# Never fails, so an nft that cannot read the ruleset (no CAP_NET_ADMIN in a
# container) is not an error under pipefail.
_nft_filtering_families() {
    { nft list ruleset 2>/dev/null || true; } | awk '
        # unconditional(rule) — true if the rule is only drop/reject.
        function unconditional(r,   a, n, i, t) {
            gsub(/"[^"]*"/, "Q", r)
            sub(/^[ \t]+/, "", r)
            sub(/[ \t]+$/, "", r)
            n = split(r, a, /[ \t]+/)
            for (i = 1; i <= n; i++) {
                t = a[i]
                if (t == "counter" || t == "log") continue
                if (t == "packets" || t == "bytes" || t == "prefix" || t == "level" \
                    || t == "group" || t == "snaplen" || t == "queue-threshold" \
                    || t == "comment") { i++; continue }
                if (t == "flags") { i++; if (a[i] == "tcp" || a[i] == "ip") i++; continue }
                if (t == "drop") return (i == n)
                if (t == "reject") return 1     # "reject with ..." only names the reply
                return 0
            }
            return 0
        }
        /^[ \t]*table[ \t]/ {
            fam = $2
            ignore = ($3 ~ /^f2b-/ || $3 ~ /crowdsec/)
            in_chain = 0
            next
        }
        /^[ \t]*chain[ \t]/ { in_chain = 1; input = 0; pol = 0; last = ""; next }
        !in_chain { next }
        /^[ \t]*}[ \t]*$/ {
            if (input && !ignore && (pol || unconditional(last))) {
                if (fam == "ip" || fam == "inet") v4 = 1
                if (fam == "ip6" || fam == "inet") v6 = 1
            }
            in_chain = 0
            next
        }
        /hook[ \t]+input/ { input = 1; if ($0 ~ /policy[ \t]+drop/) pol = 1; next }
        /^[ \t]*policy[ \t]+drop/ { pol = 1; next }
        NF { last = $0 }
        END { printf "%s%s", (v4 ? "4" : ""), (v6 ? "6" : "") }'
}

# _xtables_filters CMD — true if CMD (iptables or ip6tables) drops inbound
# traffic: INPUT policy DROP, or an unconditional "-A INPUT -j DROP|REJECT"
# (no match options), as iptables-persistent rulesets end. Jumps to other
# chains (fail2ban's f2b-*) and rules with matches do not count.
_xtables_filters() {
    command -v "$1" >/dev/null 2>&1 || return 1
    { "$1" -S INPUT 2>/dev/null || true; } | awk '
        $1 == "-P" && $2 == "INPUT" && $3 == "DROP" { f = 1 }
        $1 == "-A" && $2 == "INPUT" && $3 == "-j" && ($4 == "DROP" || $4 == "REJECT") { f = 1 }
        END { exit !f }'
}

check_firewall() {
    print_status "INFO" "Checking firewall (IPv4 + IPv6)..."

    local ipv4_ok=0 ufw_active=0 ipv4_by=""

    # nftables families whose input hook chain actually filters ("4", "6").
    local nft_families=""
    if command -v nft >/dev/null 2>&1; then
        nft_families=$(_nft_filtering_families) || nft_families=""
    fi

    # The SSH port must be allowed before any fix turns filtering on.
    local ssh_port
    ssh_port=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)
    [[ "$ssh_port" =~ ^[0-9]+$ ]] || ssh_port="22"

    local ufw_status=""
    if command -v ufw >/dev/null 2>&1; then
        ufw_status=$(ufw status 2>/dev/null || true)
    fi

    if [[ "$ufw_status" == *"Status: active"* ]]; then
        print_status "OK" "UFW active (IPv4)"
        append_report "## Firewall\n- 🟢 UFW active (IPv4)"
        ipv4_ok=1
        ufw_active=1
        ipv4_by="UFW"
    elif [[ "$nft_families" == *4* ]]; then
        print_status "OK" "nftables filtering inbound traffic"
        append_report "## Firewall\n- 🟢 nftables input chain with drop policy/rules"
        ipv4_ok=1
        ipv4_by="nftables"
    elif _xtables_filters iptables; then
        print_status "OK" "iptables rules present"
        append_report "## Firewall\n- 🟢 iptables INPUT chain drops/rejects by default"
        ipv4_ok=1
        ipv4_by="iptables"
    fi

    if [[ $ipv4_ok -eq 0 ]]; then
        print_status "WARN" "No IPv4 firewall detected"
        append_report "## Firewall\n- 🔴 No active IPv4 firewall"

        # IPV6=yes (Ubuntu's default) is set before the SSH rule is added,
        # so the rule exists for IPv6 too and enabling UFW covers both.
        report_issue 15 \
            "No Active Firewall (IPv4)" \
            "Neither UFW, nftables, nor iptables rules are active" \
            "sudo /usr/bin/apt-get install -y ufw
sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo /usr/sbin/ufw default deny incoming
sudo /usr/sbin/ufw default allow outgoing
# SSH port auto-detected as ${ssh_port} - verify before applying:
sudo /usr/sbin/ufw allow ${ssh_port}/tcp
sudo /usr/sbin/ufw --force enable
sudo /usr/sbin/ufw status verbose" \
            0 \
            "⚠️ SSH port detected as ${ssh_port}. If wrong, update the allow rule BEFORE enabling UFW to avoid lockout. The fix also filters IPv6 (IPV6=yes in /etc/default/ufw)."
    fi

    # --- IPv6 firewall check ---
    local ipv6_ok=0 ipv6_off
    ipv6_off=$(_ipv6_off_reason)

    if [[ -n "$ipv6_off" ]]; then
        print_status "OK" "IPv6 is disabled (${ipv6_off}) - no IPv6 traffic to filter"
        append_report "## Firewall IPv6\n- 🟢 IPv6 disabled (${ipv6_off}); no IPv6 firewall needed"
        ipv6_ok=1
    fi

    if [[ $ipv6_ok -eq 0 && $ufw_active -eq 1 ]]; then
        if grep -qE '^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*"?yes"?[[:space:]]*$' \
            "${AUDIT_ROOT}/etc/default/ufw" 2>/dev/null; then
            print_status "OK" "UFW IPv6 enabled (/etc/default/ufw IPV6=yes)"
            append_report "## Firewall IPv6\n- 🟢 UFW managing IPv6"
            ipv6_ok=1
        else
            print_status "WARN" "UFW is active but IPV6=yes not set - IPv6 traffic unfiltered"
        fi
    fi

    if [[ $ipv6_ok -eq 0 && "$nft_families" == *6* ]]; then
        print_status "OK" "nftables filtering inbound IPv6 traffic"
        append_report "## Firewall IPv6\n- 🟢 nftables inet/ip6 input chain filtering"
        ipv6_ok=1
    fi

    if [[ $ipv6_ok -eq 0 ]] && _xtables_filters ip6tables; then
        print_status "OK" "ip6tables rules present (IPv6)"
        append_report "## Firewall IPv6\n- 🟢 ip6tables INPUT chain drops/rejects by default"
        ipv6_ok=1
    fi

    if [[ $ipv6_ok -eq 0 ]]; then
        print_status "WARN" "No IPv6 firewall rules detected"
        append_report "## Firewall IPv6\n- 🔴 No active IPv6 firewall"
        local v6_fix
        if [[ $ufw_active -eq 1 ]]; then
            # Only ever touches a UFW that is active when the fix runs, and
            # allows SSH for IPv6 before the reload starts filtering it.
            v6_fix="# Enable IPv6 in UFW (only while UFW is active; SSH port ${ssh_port} is allowed first):
if sudo /usr/sbin/ufw status 2>/dev/null | grep -q '^Status: active'; then
    sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
    sudo /usr/sbin/ufw allow ${ssh_port}/tcp
    sudo /usr/sbin/ufw reload
else
    echo 'UFW is not active - left unchanged; see the IPv4 firewall fix'
fi
# Verify:
sudo /usr/sbin/ufw status verbose"
        elif [[ $ipv4_ok -eq 0 ]]; then
            v6_fix="# MANUAL: no firewall is active, and enabling one is the IPv4 fix's job.
# The \"No Active Firewall (IPv4)\" fix enables UFW with IPV6=yes (Ubuntu's
# default) after allowing SSH (port ${ssh_port}), which filters IPv6 as well.
# Apply that fix; nothing else is needed for IPv6. Verify afterwards:
sudo /usr/sbin/ufw status verbose"
        else
            v6_fix="# MANUAL: IPv4 is filtered by ${ipv4_by}, but IPv6 is not. Add the same
# policy for IPv6 to that ruleset, allowing SSH (port ${ssh_port}) BEFORE the
# drop policy. With nftables, a \"table inet\" covers IPv4 and IPv6 at once.
# With ip6tables (save it with netfilter-persistent), for example:
sudo /usr/sbin/ip6tables -A INPUT -i lo -j ACCEPT
sudo /usr/sbin/ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo /usr/sbin/ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
sudo /usr/sbin/ip6tables -A INPUT -p tcp --dport ${ssh_port} -j ACCEPT
sudo /usr/sbin/ip6tables -P INPUT DROP
sudo /usr/sbin/netfilter-persistent save"
        fi
        report_issue 10 \
            "No Active Firewall (IPv6)" \
            "IPv6 traffic is unfiltered - UFW IPV6=yes not set and no nftables/ip6tables input chain drops by default" \
            "$v6_fix" \
            0 \
            "IPv6 is enabled on most Ubuntu systems by default; unfiltered IPv6 bypasses IPv4-only rules"
    fi

    # --- UFW logging check ---
    if [[ $ufw_active -eq 1 ]]; then
        local ufw_log_level
        ufw_log_level=$(ufw status verbose 2>/dev/null | awk '/^Logging:/ {print $2}' || true)
        if [[ -z "$ufw_log_level" || "$ufw_log_level" == "off" ]]; then
            print_status "WARN" "UFW logging is disabled - firewall events are not recorded"
            append_report "## Firewall Logging\n- 🔴 UFW logging is off"
            report_issue 5 \
                "UFW firewall logging disabled" \
                "UFW is active but logging is off - blocked/allowed connections are not recorded" \
                "sudo /usr/sbin/ufw logging low
# Verify:
sudo /usr/sbin/ufw status verbose | grep -i logging
sudo /usr/bin/tail -20 /var/log/ufw.log" \
                0 \
                "Recommended minimum is 'low'; use 'medium' on internet-facing systems"
        else
            print_status "OK" "UFW logging is enabled (level: ${ufw_log_level})"
            append_report "## Firewall Logging\n- 🟢 UFW logging enabled (level: ${ufw_log_level})"
        fi
    fi
}
