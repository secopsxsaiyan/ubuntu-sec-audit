# shellcheck shell=bash
# check_deep_suid / check_deep_sgid — deep checks (sourced by ubuntu-sec-audit.sh)
#
# SUID/SGID files that a package installed are expected (snap-confine,
# dbus-daemon-launch-helper, plocate, ...). Only files no package owns, and
# that are not on the allow-list, are reported. Removing the bit can break
# software, so the fix is a manual review.

# _scan_special_bits PERM WHITELIST_NAME — unexpected files with PERM set.
_scan_special_bits() {
    local perm="$1" f wl
    local -n _wl="$2"
    local -a found=()
    while IFS= read -r f; do
        found+=("${f#"$AUDIT_ROOT"}")
    done < <(find "${AUDIT_ROOT:-/}" -xdev -perm "$perm" -type f 2>/dev/null || true)
    [[ ${#found[@]} -gt 0 ]] || return 0
    local -A allowed=()
    for wl in "${_wl[@]}"; do allowed["$wl"]=1; done
    while IFS= read -r f; do
        [[ -n "${allowed[$f]:-}" ]] && continue
        printf '%s\n' "$f"
    done < <(_dpkg_unowned "${found[@]}")
}

# _report_special_bits LABEL CHMOD POINTS FILES — one finding for all FILES.
_report_special_bits() {
    local label="$1" mode="$2" points="$3" files="$4" f fix
    fix="# Review each file before changing it: what installed it, and does"$'\n'
    fix+="# anything need it to run with raised privileges?"$'\n'
    fix+="#   dpkg -S <file>; ls -l <file>; strings <file> | head"$'\n'
    fix+="# Then remove the bit from the ones that should not have it:"$'\n'
    while IFS= read -r f; do
        fix+="#   sudo chmod ${mode} $(printf '%q' "$f")"$'\n'
    done <<< "$files"
    report_issue "$points" \
        "Non-standard ${label} binaries found" \
        "${label} files not installed by any package - privilege-escalation vectors if exploited" \
        "$fix" \
        1 \
        "${label} files:\n$(sed 's/^/ - /' <<< "$files")"
}

check_deep_suid() {
    print_status "INFO" "Scanning SUID binaries (full filesystem - may take a while on large systems)..."
    local risky
    risky=$(_scan_special_bits -4000 SUID_WHITELIST)
    if [[ -n "$risky" ]]; then
        print_status "WARN" "Non-standard SUID binaries: $(grep -c . <<< "$risky")"
        _report_special_bits SUID u-s 14 "$risky"
    else
        print_status "OK" "No unexpected SUID binaries found"
        append_report "## Deep: SUID Binaries\n- 🟢 No non-package SUID binaries detected"
    fi
}

check_deep_sgid() {
    print_status "INFO" "Scanning SGID binaries (full filesystem)..."
    local risky
    risky=$(_scan_special_bits -2000 SGID_WHITELIST)
    if [[ -n "$risky" ]]; then
        print_status "WARN" "Non-standard SGID binaries: $(grep -c . <<< "$risky")"
        _report_special_bits SGID g-s 10 "$risky"
    else
        print_status "OK" "No unexpected SGID binaries found"
        append_report "## Deep: SGID Binaries\n- 🟢 No non-package SGID binaries detected"
    fi
}
