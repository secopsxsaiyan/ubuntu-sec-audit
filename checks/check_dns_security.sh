# shellcheck shell=bash
# check_dns_security — standard check (sourced by ubuntu-sec-audit.sh)
#
# Only the strict modes protect against an active man-in-the-middle:
# resolved.conf(5) documents DNSSEC=allow-downgrade and
# DNSOverTLS=opportunistic as open to downgrade attacks. The strict modes
# break name resolution when the upstream resolvers do not support them
# (why Ubuntu ships both off), so the fix is guidance, never applied blindly.

check_dns_security() {
    print_status "INFO" "Checking DNS security (systemd-resolved DNSSEC/DoT)..."
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        append_report "## DNS Security\n- ⚪ systemd-resolved not active - not applicable"
        _mark_not_applicable "systemd-resolved is not active"
        return 0
    fi

    local dns_issues=()

    # Effective settings from resolved.conf and its drop-ins (last wins).
    # resolvectl's output is not parsed: its format changed in systemd 249.
    # Ubuntu builds resolved with DNSSEC=no and DNSOverTLS=no by default.
    local dnssec_setting dot_setting
    dnssec_setting=$(_systemd_conf_value resolved DNSSEC)
    dnssec_setting="${dnssec_setting:-no}"
    dnssec_setting=${dnssec_setting,,}
    case "$dnssec_setting" in
        yes|y|true|t|on|1) ;;
        allow-downgrade)
            dns_issues+=("DNSSEC is 'allow-downgrade' - validation is dropped when the resolver seems not to support it, which an active man-in-the-middle can fake (downgrade)") ;;
        *)
            dns_issues+=("DNSSEC is '${dnssec_setting}' - DNS responses are not validated (spoofing risk)") ;;
    esac

    dot_setting=$(_systemd_conf_value resolved DNSOverTLS)
    dot_setting="${dot_setting:-no}"
    dot_setting=${dot_setting,,}
    case "$dot_setting" in
        yes|y|true|t|on|1) ;;
        opportunistic)
            dns_issues+=("DNS over TLS is 'opportunistic' - it falls back to plaintext, which an active man-in-the-middle can force (downgrade)") ;;
        *)
            dns_issues+=("DNS over TLS is '${dot_setting}' - DNS queries are sent in plaintext") ;;
    esac

    if [[ ${#dns_issues[@]} -eq 0 ]]; then
        print_status "OK" "DNSSEC and DNS over TLS are enforced"
        append_report "## DNS Security\n- 🟢 DNSSEC and DNS over TLS enforced in systemd-resolved"
        return 0
    fi

    local dns_fix
    dns_fix="# MANUAL: test on one host first - strict DNS settings break name resolution
# when the upstream resolvers do not support them (why Ubuntu ships them off).
# DNSSEC=allow-downgrade and DNSOverTLS=opportunistic do not stop an active
# man-in-the-middle (resolved.conf(5): both are open to downgrade attacks);
# only DNSSEC=yes and DNSOverTLS=yes do.
# 1. Choose upstream resolvers that support DNS over TLS and DNSSEC, and note
#    the name on their TLS certificate. Per-link servers (DHCP, netplan) are
#    used too and must support both, or be replaced in netplan.
# 2. Write the drop-in with your resolvers:
sudo /bin/mkdir -p /etc/systemd/resolved.conf.d
sudo /usr/bin/tee /etc/systemd/resolved.conf.d/99-hardening.conf > /dev/null << 'DNSEOF'
[Resolve]
DNS=<resolver-ip>#<tls-server-name>
DNSSEC=yes
DNSOverTLS=yes
DNSEOF
sudo /bin/systemctl restart systemd-resolved
# 3. Verify that lookups still work (internal names too: unsigned internal
#    zones may need a negative trust anchor, see dnssec-trust-anchors.d(5))
#    and that both modes are on:
resolvectl query ubuntu.com
resolvectl status | grep -E 'DNSSEC|DNS over TLS'
# 4. If lookups fail, roll back:
sudo /bin/rm -f /etc/systemd/resolved.conf.d/99-hardening.conf
sudo /bin/systemctl restart systemd-resolved"
    local issue_list
    issue_list=$(printf ' - %s\n' "${dns_issues[@]}")
    print_status "WARN" "DNS security issues: ${#dns_issues[@]} found"
    append_report "## DNS Security\n- 🔴 DNS security issues: ${#dns_issues[@]}"
    report_issue 5 \
        "DNS security not fully configured" \
        "${#dns_issues[@]} DNS security issue(s) in systemd-resolved" \
        "$dns_fix" \
        0 \
        "Issues:\n${issue_list}\n\nDNSSEC validates DNS responses; DNS over TLS encrypts queries. Only the strict modes hold against an active man-in-the-middle."
    return 0
}
