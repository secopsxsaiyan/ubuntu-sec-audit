# shellcheck shell=bash
# check_ipv6_exposure — standard check (sourced by ubuntu-sec-audit.sh)

check_ipv6_exposure() {
    print_status "INFO" "Checking IPv6 status..."

    local _sysctl_off _grub_off
    _sysctl_off=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
    _grub_off=0
    grep -qE 'ipv6\.disable=1' /etc/default/grub 2>/dev/null && _grub_off=1

    if [[ "$_sysctl_off" == "1" && "$_grub_off" == "1" ]]; then
        print_status "OK" "IPv6 fully disabled (sysctl + GRUB kernel parameter)"
        append_report "## IPv6 Status\n- 🟢 IPv6 disabled via sysctl and GRUB (fully hardened)"
        return
    fi

    if [[ "$_sysctl_off" == "1" && "$_grub_off" == "0" ]]; then
        print_status "WARN" "IPv6 disabled via sysctl but GRUB kernel parameter not set - will re-enable after kernel update"
        append_report "## IPv6 Status\n- 🟡 IPv6 disabled via sysctl only (GRUB parameter missing - not persistent across kernel updates)"
        append_report "  Run the fix script with \`--disable-ipv6\` to add the GRUB parameter."
        return
    fi

    # IPv6 is active — inventory addresses and listening services
    local _ipv6_addrs _ipv6_svcs
    _ipv6_addrs=$(ip -6 addr show 2>/dev/null \
        | awk '/inet6/ && !/^[[:space:]]*inet6 ::1/ {print "  " $2 " (" $NF ")"}' || true)
    _ipv6_svcs=$(ss -tulpn 2>/dev/null \
        | awk 'NR>1 && ($5 ~ /^\[/ || $5 ~ /^::/)' | awk '{print "  " $1 " " $5 " " $7}' || true)

    print_status "INFO" "IPv6 is active on this system"
    append_report "## IPv6 Status\n- ℹ️ IPv6 is active (not a scored issue - policy decision)"
    [[ -n "$_ipv6_addrs" ]] && append_report "### IPv6 Addresses\n\`\`\`\n${_ipv6_addrs}\n\`\`\`"
    [[ -n "$_ipv6_svcs"  ]] && append_report "### IPv6 Listening Services\n\`\`\`\n${_ipv6_svcs}\n\`\`\`"
    append_report "  To disable IPv6: run the fix script with \`--disable-ipv6\`"
}
