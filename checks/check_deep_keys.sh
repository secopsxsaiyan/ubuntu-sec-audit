# shellcheck shell=bash
# check_deep_authorized_keys / _user_ssh_keys / _capabilities — deep checks

check_deep_authorized_keys() {
    print_status "INFO" "Checking authorized_keys files..."
    local auth_keys
    auth_keys=$(find "${AUDIT_ROOT}/home" "${AUDIT_ROOT}/root" \( -name authorized_keys -o -name authorized_keys2 \) \
                -type f 2>/dev/null | head -n 50 || true)
    if [[ -n "$auth_keys" ]]; then
        append_report "## Deep: SSH Authorized Keys\n\`\`\`\n$auth_keys\n\`\`\`"
    fi
}

check_deep_user_ssh_keys() {
    print_status "INFO" "Checking user SSH private key permissions..."
    # Only files inside .ssh directories: id_* elsewhere is just a name.
    local -a bad=()
    local keyfile kperms fix=""
    while IFS= read -r keyfile; do
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        if [[ -n "$kperms" ]] && (( (8#$kperms & 8#077) != 0 )); then
            bad+=("${keyfile} (${kperms})")
            fix+="sudo /bin/chmod 600 $(printf '%q' "$keyfile")"$'\n'
        fi
    done < <(find "${AUDIT_ROOT}/home" "${AUDIT_ROOT}/root" -type f -path '*/.ssh/*' -name 'id_*' ! -name '*.pub' 2>/dev/null || true)
    if [[ ${#bad[@]} -eq 0 ]]; then
        print_status "OK" "No world/group-readable user SSH private keys found"
        append_report "## Deep: SSH User Key Permissions\n- 🟢 User private SSH keys are properly restricted"
        return 0
    fi
    print_status "WARN" "${#bad[@]} user SSH private key(s) readable by group/others"
    append_report "## Deep: SSH User Key Permissions\n- 🔴 ${#bad[@]} key(s) readable by group/others"
    report_issue 10 \
        "User SSH private keys have insecure permissions" \
        "${#bad[@]} private key(s) readable by group/others (credential exposure):"$'\n'"$(printf '%s\n' "${bad[@]}")" \
        "${fix}# Verify:
#   stat -c '%n %a %U' <key>" \
        1
}

check_deep_capabilities() {
    if ! command -v getcap >/dev/null 2>&1; then
        _mark_skipped "getcap not installed"
        return 0
    fi
    print_status "INFO" "Scanning file capabilities..."
    # Package-owned capabilities (ping's cap_net_raw, ...) are expected.
    local -a roots=() files=()
    local -A caps=()
    local r path rest unexpected
    for r in /usr /opt /bin /sbin /lib /snap; do
        [[ -e "${AUDIT_ROOT}${r}" ]] && roots+=("${AUDIT_ROOT}${r}")
    done
    [[ ${#roots[@]} -gt 0 ]] || roots=("${AUDIT_ROOT:-/}")
    while read -r path rest; do
        [[ -n "$path" ]] || continue
        path="${path#"$AUDIT_ROOT"}"
        files+=("$path")
        caps["$path"]="${rest#= }"
    done < <(getcap -r "${roots[@]}" 2>/dev/null || true)
    unexpected=$(_dpkg_unowned "${files[@]+"${files[@]}"}")
    if [[ -z "$unexpected" ]]; then
        print_status "OK" "No file capabilities outside installed packages"
        append_report "## Deep: File Capabilities\n- 🟢 Only package-provided capabilities found"
        return 0
    fi
    local list="" f fix=""
    while IFS= read -r f; do
        list+=" - ${f} ${caps[$f]:-}"$'\n'
        fix+="#   sudo setcap -r $(printf '%q' "$f")"$'\n'
    done <<< "$unexpected"
    print_status "WARN" "File capabilities on files no package installed"
    append_report "## Deep: File Capabilities\n\`\`\`\n${list}\`\`\`"
    report_issue 5 \
        "Files with Linux capabilities set" \
        "Capabilities on files no package installed - unnecessary caps are privilege escalation vectors:"$'\n'"${list}" \
        "# Review each file; remove capabilities it does not need:
${fix}# Verify:
#   getcap -r /usr /opt 2>/dev/null" \
        1
}
