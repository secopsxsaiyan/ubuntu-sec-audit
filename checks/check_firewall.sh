# shellcheck shell=bash
# check_firewall — standard check (sourced by ubuntu-sec-audit.sh)

check_firewall() {
    print_status "INFO" "Checking firewall (IPv4 + IPv6)..."

    local ipv4_ok=0
    local ufw_active=0

    if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
        print_status "OK" "UFW active (IPv4)"
        append_report "## Firewall\n- 🟢 UFW active (IPv4)"
        ipv4_ok=1
        ufw_active=1
    elif command -v nft >/dev/null 2>&1 && sudo nft list ruleset | grep -q "chain"; then
        print_status "OK" "nftables active"
        append_report "## Firewall\n- 🟢 nftables active"
        ipv4_ok=1
    elif sudo iptables -nL | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
        print_status "OK" "iptables rules present"
        append_report "## Firewall\n- 🟢 iptables rules present"
        ipv4_ok=1
    fi

    if [[ $ipv4_ok -eq 0 ]]; then
        print_status "WARN" "No IPv4 firewall detected"
        append_report "## Firewall\n- 🔴 No active IPv4 firewall"

        local ssh_port
        ssh_port=$(sudo sshd -T 2>/dev/null | awk '/^port / {print $2}' | head -1 || echo "22")
        [[ -z "$ssh_port" ]] && ssh_port="22"

        report_issue 15 \
            "No Active Firewall (IPv4)" \
            "Neither UFW, nftables, nor iptables rules are active" \
            "sudo /usr/bin/apt-get install -y ufw
sudo /usr/sbin/ufw default deny incoming
sudo /usr/sbin/ufw default allow outgoing
# SSH port auto-detected as ${ssh_port} - verify before applying:
sudo /usr/sbin/ufw allow ${ssh_port}/tcp
sudo /usr/sbin/ufw --force enable
sudo /usr/sbin/ufw status verbose" \
            0 \
            "⚠️ SSH port detected as ${ssh_port}. If wrong, update the allow rule BEFORE enabling UFW to avoid lockout."
    fi

    # --- IPv6 firewall check ---
    local ipv6_ok=0

    if [[ $ufw_active -eq 1 ]]; then
        if grep -qE '^\s*IPV6\s*=\s*yes' /etc/default/ufw 2>/dev/null; then
            print_status "OK" "UFW IPv6 enabled (/etc/default/ufw IPV6=yes)"
            append_report "## Firewall IPv6\n- 🟢 UFW managing IPv6"
            ipv6_ok=1
        else
            print_status "WARN" "UFW is active but IPV6=yes not set - IPv6 traffic unfiltered"
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]] && command -v ip6tables >/dev/null 2>&1; then
        if sudo ip6tables -nL 2>/dev/null | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
            print_status "OK" "ip6tables rules present (IPv6)"
            append_report "## Firewall IPv6\n- 🟢 ip6tables rules present"
            ipv6_ok=1
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]]; then
        print_status "WARN" "No IPv6 firewall rules detected"
        append_report "## Firewall IPv6\n- 🔴 No active IPv6 firewall"
        report_issue 10 \
            "No Active Firewall (IPv6)" \
            "IPv6 traffic is unfiltered - UFW IPV6=yes not set and no ip6tables DROP/REJECT rules found" \
            "# Enable IPv6 in UFW (recommended):
sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo /usr/sbin/ufw disable && sudo /usr/sbin/ufw --force enable
# Verify:
sudo /usr/sbin/ufw status verbose
sudo /usr/sbin/ip6tables -L INPUT --line-numbers" \
            0 \
            "IPv6 is enabled on most Ubuntu systems by default; unfiltered IPv6 bypasses IPv4-only rules"
    fi

    # --- UFW logging check ---
    if [[ $ufw_active -eq 1 ]]; then
        local ufw_log_level
        ufw_log_level=$(sudo ufw status verbose 2>/dev/null | awk '/^Logging:/ {print $2}' || true)
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
