# shellcheck shell=bash
# check_dns_security — standard check (sourced by ubuntu-sec-audit.sh)

check_dns_security() {
    print_status "INFO" "Checking DNS security (systemd-resolved DNSSEC/DoT)..."
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        print_status "INFO" "systemd-resolved not active - skipping DNS security check"
        append_report "## DNS Security\n- ⚪ systemd-resolved not active"
        return
    fi

    local dns_issues=()
    local _need_dnssec=0 _need_dot=0

    # DNSSEC
    local dnssec_setting
    dnssec_setting=$(resolvectl status 2>/dev/null | awk '/DNSSEC setting:/ {print $NF}' | head -1 || \
                     grep -i '^DNSSEC=' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2 || \
                     echo "no")
    dnssec_setting=${dnssec_setting,,}
    if [[ "$dnssec_setting" != "yes" && "$dnssec_setting" != "allow-downgrade" ]]; then
        dns_issues+=("DNSSEC is '${dnssec_setting:-no}' - DNS responses are not validated (MITM/spoofing risk)")
        _need_dnssec=1
    fi

    # DNS over TLS
    local dot_setting
    dot_setting=$(grep -i '^DNSOverTLS=' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2 || echo "no")
    dot_setting=${dot_setting,,}
    if [[ "$dot_setting" != "yes" && "$dot_setting" != "opportunistic" ]]; then
        dns_issues+=("DNS over TLS is '${dot_setting:-no}' - DNS queries are sent in plaintext")
        _need_dot=1
    fi

    if [[ ${#dns_issues[@]} -eq 0 ]]; then
        print_status "OK" "DNSSEC and DNS over TLS are configured"
        append_report "## DNS Security\n- 🟢 DNSSEC and DNS over TLS enabled in systemd-resolved"
    else
        # Build a single drop-in conf with all needed settings (avoids duplicate [Resolve] headers)
        local dns_fix
        # Always write BOTH settings — writing only the currently-failing ones
        # overwrites the file on each run, losing previously-applied settings.
        dns_fix="sudo /bin/mkdir -p /etc/systemd/resolved.conf.d"$'\n'
        dns_fix+="sudo /usr/bin/tee /etc/systemd/resolved.conf.d/99-hardening.conf > /dev/null << 'DNSEOF'"$'\n'
        dns_fix+="[Resolve]"$'\n'
        dns_fix+="DNSSEC=allow-downgrade"$'\n'
        dns_fix+="DNSOverTLS=opportunistic"$'\n'
        dns_fix+="DNSEOF"$'\n'
        dns_fix+="sudo /bin/systemctl restart systemd-resolved"$'\n'
        dns_fix+="# Verify:
resolvectl status | grep -E 'DNSSEC|DNS over TLS'"
        local issue_list
        issue_list=$(printf ' - %s\n' "${dns_issues[@]}")
        print_status "WARN" "DNS security issues: ${#dns_issues[@]} found"
        append_report "## DNS Security\n- 🔴 DNS security issues: ${#dns_issues[@]}"
        report_issue 5 \
            "DNS security not fully configured" \
            "${#dns_issues[@]} DNS security issue(s) in systemd-resolved" \
            "$dns_fix" \
            0 \
            "Issues:\n${issue_list}\n\nDNSSEC validates DNS responses; DNS over TLS encrypts queries from eavesdropping"
    fi
}
