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

# awk program over "ss -tulpn" output: one "port/proto<TAB>process" line per
# port that a default-deny firewall would close, i.e. sockets listening on
# an address other than loopback, except the ports in -v skip=" P/proto ..."
# (SSH, allowed by the fix) and the DHCP (68/udp, 546/udp) and mDNS
# (5353/udp) client ports UFW's default rules already let through. Process
# names are reduced to safe characters: they end up in the fix script. The
# fix script runs it again just before enabling UFW, so it has no single
# quotes.
readonly _FW_LISTENER_AWK='
$1 !~ /^(tcp|udp)/ { next }
{
    proto = substr($1, 1, 3); addr = $5
    port = addr; sub(/^.*:/, "", port)
    host = addr; sub(/:[^:]*$/, "", host)
    if (port !~ /^[0-9]+$/) next
    if (host ~ /%lo$/ || host ~ /^127\./ || host ~ /^\[?::1\]?(%.*)?$/ || host ~ /^\[?::ffff:127\./) next
    if (proto == "udp" && (port == 68 || port == 546 || port == 5353)) next
    key = port "/" proto
    if (index(skip, " " key " ")) next
    proc = "?"
    if (match($0, /users:\(\("[^"]*"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
    gsub(/[^A-Za-z0-9._@:+-]/, "?", proc)
    if (!(key in name)) { name[key] = proc; order[++n] = key }
}
END { for (i = 1; i <= n; i++) print order[i] "\t" name[order[i]] }'

# _fw_other_listeners SKIP — the listeners a default-deny firewall would cut
# off (see _FW_LISTENER_AWK), sorted by port. Fails when they cannot be
# listed (no ss).
_fw_other_listeners() {
    command -v ss >/dev/null 2>&1 || return 1
    local out
    out=$(ss -tulpn 2>/dev/null) || return 1
    awk -v skip="$1" "$_FW_LISTENER_AWK" <<< "$out" | sort -t/ -k1,1n -k2,2
}

check_firewall() {
    print_status "INFO" "Checking firewall (IPv4 + IPv6)..."

    local ipv4_ok=0 ufw_active=0 ipv4_by=""

    # nftables families whose input hook chain actually filters ("4", "6").
    local nft_families=""
    if command -v nft >/dev/null 2>&1; then
        nft_families=$(_nft_filtering_families) || nft_families=""
    fi

    # Every port sshd listens on must be allowed before any fix turns
    # filtering on. If they cannot be read (sshd -T failed), the fixes that
    # would enable filtering are left to a person.
    local ssh_ports="" ssh_port ssh_known=1
    if command -v sshd >/dev/null 2>&1; then
        if _sshd_effective_config; then
            # "ListenAddress host:port" replaces Port for that address and
            # shows up only on its listenaddress line.
            ssh_ports=$(awk '$1 == "port" && $2 ~ /^[0-9]+$/ {print $2}
                             $1 == "listenaddress" { n = split($2, a, ":"); if (a[n] ~ /^[0-9]+$/) print a[n] }' \
                        <<< "$SSHD_CONF" | sort -un | tr '\n' ' ')
        fi
        [[ -n "${ssh_ports// /}" ]] || ssh_known=0
    fi
    local ssh_allow="" _p ports_label
    if [[ $ssh_known -eq 1 ]]; then
        ssh_ports="${ssh_ports:-22}"
        ssh_ports="${ssh_ports% }"
        for _p in $ssh_ports; do
            ssh_allow+="sudo /usr/sbin/ufw allow ${_p}/tcp"$'\n'
        done
        ports_label="SSH port(s) detected: ${ssh_ports}"
    else
        # Never guess: a wrong port in an allow rule is a lockout.
        ssh_ports="<ssh-port>"
        ssh_allow="sudo /usr/sbin/ufw allow <ssh-port>/tcp   # once for every port sshd listens on"$'\n'
        ports_label="SSH port(s) unknown (sshd -T failed)"
    fi
    ssh_port="${ssh_ports%% *}"
    local unknown_port_note="# MANUAL: the SSH port could not be read (sshd -T failed: ${SSHD_CONF_ERR:-no output}).
# Find the ports sshd listens on (sudo ss -tlnp | grep sshd) and allow each one
# BEFORE enabling a firewall, or you will be locked out. Then:"

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

        # A default-deny firewall cuts off every service it does not allow.
        # The fix enables UFW by itself only when nothing but SSH listens,
        # and checks that again when it runs; otherwise the services found
        # are listed for a person to decide on.
        local fw_skip=" " fw_others="" fw_listed=1 svc_allow="" svc_list="" _key _proc
        for _p in $ssh_ports; do fw_skip+="${_p}/tcp "; done
        fw_others=$(_fw_other_listeners "$fw_skip") || fw_listed=0
        while IFS=$'\t' read -r _key _proc; do
            [[ -n "$_key" ]] || continue
            [[ -n "$svc_allow" ]] || svc_allow="# Other services listening when the audit ran:"$'\n'
            svc_allow+="sudo /usr/sbin/ufw allow ${_key}   # ${_proc}"$'\n'
            svc_list+="${svc_list:+, }${_key} (${_proc})"
        done <<< "$fw_others"

        # IPV6=yes (Ubuntu's default) is set before the SSH rule is added,
        # so the rule exists for IPv6 too and enabling UFW covers both.
        local v4_fix="" v4_note="⚠️ ${ports_label}. If wrong, update the allow rules BEFORE enabling UFW to avoid lockout."
        if [[ $ssh_known -eq 0 ]]; then
            v4_fix="${unknown_port_note}"$'\n'
        elif [[ $fw_listed -eq 0 ]]; then
            v4_fix="# MANUAL: the listening services could not be listed (ss is missing), and a
# default-deny firewall cuts off every service it does not allow. Find them
# (sudo ss -tulpn), allow each one that must stay reachable, then:
"
            v4_note+=" The listening services could not be listed, so enabling the firewall is left to you."
        elif [[ -n "$svc_allow" ]]; then
            v4_fix="# MANUAL: services other than SSH are listening, and a default-deny firewall
# cuts off every service it does not allow. Keep the allow rule of each service
# that must stay reachable, drop the others, then run these commands:
"
            v4_note+=" Also listening (enabling the firewall is left to you): ${svc_list}."
        else
            v4_fix="# Only SSH was listening when the audit ran. Stop if another service
# listens now: the firewall would cut it off.
if ! _listening=\$(/bin/ss -tulpn 2>/dev/null); then
    echo '[WARN] Cannot list the listening ports (ss) - UFW not enabled'
    exit 1
fi
_others=\$(printf '%s\n' \"\$_listening\" | /usr/bin/awk -v skip='${fw_skip}' '${_FW_LISTENER_AWK}')
if [ -n \"\$_others\" ]; then
    echo '[WARN] Services other than SSH listen now - UFW not enabled, it would cut them off:'
    printf '%s\n' \"\$_others\"
    echo '       Allow each one that must stay reachable (sudo ufw allow <port>/<proto>), then: sudo ufw --force enable'
    exit 1
fi
"
        fi
        v4_fix+="sudo /usr/bin/apt-get install -y ufw
sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo /usr/sbin/ufw default deny incoming
sudo /usr/sbin/ufw default allow outgoing
# ${ports_label} - verify before applying:
${ssh_allow}${svc_allow}sudo /usr/sbin/ufw --force enable
sudo /usr/sbin/ufw status verbose"
        report_issue 15 \
            "No Active Firewall (IPv4)" \
            "Neither UFW, nftables, nor iptables rules are active" \
            "$v4_fix" \
            0 \
            "${v4_note} The fix also filters IPv6 (IPV6=yes in /etc/default/ufw)."
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
        if [[ $ufw_active -eq 1 && $ssh_known -eq 0 ]]; then
            v6_fix="${unknown_port_note}
#   set IPV6=yes in /etc/default/ufw, re-add each SSH rule (sudo ufw allow <port>/tcp)
#   and run: sudo ufw reload"
        elif [[ $ufw_active -eq 1 ]]; then
            # Only ever touches a UFW that is active when the fix runs. Rules
            # added while IPV6=no exist for IPv4 only, so the SSH rule is
            # re-added (same action, allow or limit), and then every other
            # rule ("ufw show added"), before the reload starts filtering
            # IPv6: services UFW allows stay reachable over IPv6. An SSH rule
            # limited to certain sources cannot be translated to IPv6, and
            # without any SSH rule an IPv6 session would be cut: both are
            # left to a person.
            v6_fix="# Enable IPv6 in UFW (only while UFW is active, keeping SSH port(s) ${ssh_ports} reachable):
if sudo /usr/sbin/ufw status 2>/dev/null | grep -q '^Status: active'; then
    _ssh_ok=1; _ssh_rules=''
    for _p in ${ssh_ports}; do
        _a=\$(sudo /usr/sbin/ufw status 2>/dev/null | awk -v p=\"\$_p\" '(\$1 == p \"/tcp\" || \$1 == p || (\$1 == \"OpenSSH\" && p == \"22\")) && (\$2 == \"ALLOW\" || \$2 == \"LIMIT\") && \$3 == \"Anywhere\" && NF == 3 {print tolower(\$2); exit}')
        if [ -n \"\$_a\" ]; then _ssh_rules=\"\$_ssh_rules \$_a:\$_p\"; else _ssh_ok=0; fi
    done
    if [ \"\$_ssh_ok\" -eq 1 ]; then
        if ! _added=\$(sudo /usr/sbin/ufw show added 2>/dev/null); then
            echo '[WARN] Cannot list the UFW rules (ufw show added) - IPv6 filtering not enabled'
            exit 1
        fi
        sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
        for _r in \$_ssh_rules; do sudo /usr/sbin/ufw \"\${_r%%:*}\" \"\${_r#*:}/tcp\"; done
        # Add every other rule again so it covers IPv6 too (rules limited to
        # IPv4 sources stay IPv4-only).
        printf '%s\n' \"\$_added\" | /bin/sed -n 's/^ufw //p' | /usr/bin/xargs -r -L 1 /usr/sbin/ufw
        sudo /usr/sbin/ufw reload
    else
        echo '[WARN] SSH (port(s) ${ssh_ports}) is only allowed from specific sources, or not at all: not enabling IPv6 filtering.'
        echo '       Add the IPv6 sources that need SSH (ufw allow from <ipv6-net> to any port <port> proto tcp),'
        echo '       then set IPV6=yes in /etc/default/ufw and run: sudo ufw reload'
        exit 1
    fi
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
