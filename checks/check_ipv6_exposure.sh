# shellcheck shell=bash
# check_ipv6_exposure — standard check (sourced by ubuntu-sec-audit.sh)

# _grub_cmdline — the kernel command line update-grub would generate:
# GRUB_CMDLINE_LINUX and GRUB_CMDLINE_LINUX_DEFAULT as left by
# /etc/default/grub and then /etc/default/grub.d/*.cfg in order (cloud images
# set GRUB_CMDLINE_LINUX_DEFAULT in 50-cloudimg-settings.cfg). The files are
# parsed, never sourced; "$VAR" / "${VAR}" references to either variable are
# expanded so appending assignments work.
_grub_cmdline() {
    local linux="" dflt="" f line val
    local re='^[[:space:]]*(export[[:space:]]+)?(GRUB_CMDLINE_LINUX(_DEFAULT)?)=(.*)$'
    for f in "${AUDIT_ROOT}/etc/default/grub" "${AUDIT_ROOT}/etc/default/grub.d/"*.cfg; do
        [[ -f "$f" ]] || continue
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ "$line" =~ $re ]] || continue
            val="${BASH_REMATCH[4]}"
            val="${val%"${val##*[![:space:]]}"}"
            if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then
                val="${val:1:${#val}-2}"
            fi
            val="${val//'${GRUB_CMDLINE_LINUX_DEFAULT}'/$dflt}"
            val="${val//'$GRUB_CMDLINE_LINUX_DEFAULT'/$dflt}"
            val="${val//'${GRUB_CMDLINE_LINUX}'/$linux}"
            val="${val//'$GRUB_CMDLINE_LINUX'/$linux}"
            if [[ "${BASH_REMATCH[2]}" == "GRUB_CMDLINE_LINUX" ]]; then
                linux="$val"
            else
                dflt="$val"
            fi
        done < "$f"
    done
    printf '%s %s\n' "$linux" "$dflt"
}

check_ipv6_exposure() {
    print_status "INFO" "Checking IPv6 status..."

    local _off _grub_off=0
    _off=$(_ipv6_off_reason)
    if _grub_cmdline | grep -qE '(^|[[:space:]])ipv6\.disable=1([[:space:]]|$)'; then
        _grub_off=1
    fi

    if [[ "$_off" == "boot" ]]; then
        if [[ $_grub_off -eq 1 ]]; then
            print_status "OK" "IPv6 disabled at boot (ipv6.disable=1 kernel parameter, set in GRUB)"
            append_report "## IPv6 Status\n- 🟢 IPv6 disabled at boot (kernel parameter ipv6.disable=1, persistent in the GRUB configuration)"
        else
            print_status "WARN" "IPv6 disabled at boot, but ipv6.disable=1 is not in the GRUB configuration"
            append_report "## IPv6 Status\n- 🟡 IPv6 disabled at boot, but ipv6.disable=1 is not in /etc/default/grub or /etc/default/grub.d - it may be lost when GRUB is regenerated"
        fi
        return 0
    fi

    if [[ "$_off" == "sysctl" ]]; then
        if [[ $_grub_off -eq 1 ]]; then
            print_status "OK" "IPv6 fully disabled (sysctl + GRUB kernel parameter)"
            append_report "## IPv6 Status\n- 🟢 IPv6 disabled via sysctl and GRUB (fully hardened)"
        else
            print_status "WARN" "IPv6 disabled via sysctl but GRUB kernel parameter not set - will re-enable after kernel update"
            append_report "## IPv6 Status\n- 🟡 IPv6 disabled via sysctl only (GRUB parameter missing - not persistent across kernel updates)"
            append_report "  Run the fix script with \`--disable-ipv6\` to add the GRUB parameter. On cloud images, /etc/default/grub.d/*.cfg overrides GRUB_CMDLINE_LINUX_DEFAULT: add ipv6.disable=1 to GRUB_CMDLINE_LINUX instead."
        fi
        return 0
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
    if [[ $_grub_off -eq 1 ]]; then
        append_report "  ipv6.disable=1 is set in the GRUB configuration and takes effect after a reboot."
    else
        append_report "  To disable IPv6: run the fix script with \`--disable-ipv6\`"
    fi
}
