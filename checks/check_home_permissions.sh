# shellcheck shell=bash
# check_home_permissions — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: Home directory permissions (from review doc)
check_home_permissions() {
    print_status "INFO" "Checking home directory permissions..."
    local -a home_issues=()
    local home_fix=""

    while IFS= read -r dir; do
        local perms owner
        perms=$(stat -c '%a' "$dir" 2>/dev/null || true)
        owner=$(stat -c '%U' "$dir" 2>/dev/null || true)
        [[ -z "$perms" ]] && continue
        # Others should have no access (last octet)
        if (( (8#$perms & 8#007) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - others have access")
            home_fix+="sudo /bin/chmod 700 $(printf '%q' "$dir")   # ${owner}'s home"$'\n'
        # Group-writable is also a problem
        elif (( (8#$perms & 8#020) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - group-writable")
            home_fix+="sudo /bin/chmod g-w $(printf '%q' "$dir")"$'\n'
        fi
    done < <(find /home /root -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

    if [[ ${#home_issues[@]} -eq 0 ]]; then
        print_status "OK" "Home directory permissions are secure"
        append_report "## Home Directory Permissions\n- 🟢 All home directories are properly restricted"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${home_issues[@]}")
        print_status "WARN" "Home directory permission issues: ${#home_issues[@]} found"
        append_report "## Home Directory Permissions\n- 🔴 ${#home_issues[@]} home dir(s) with insecure permissions"
        home_fix+="# Verify after fixing:
/usr/bin/find /home /root -mindepth 1 -maxdepth 1 -type d -exec /usr/bin/stat -c '%n %a %U' {} \;"
        report_issue 6 \
            "Home directories have insecure permissions" \
            "Home directories accessible by other users - may expose SSH keys, config files, credentials" \
            "$home_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
