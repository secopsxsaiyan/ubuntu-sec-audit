# shellcheck shell=bash
# check_cron — standard check (sourced by ubuntu-sec-audit.sh)

check_cron() {
    print_status "INFO" "Checking cron job security..."

    local -a cron_issues=()
    local cron_fix=""

    local -a cron_dirs=(
        /etc/crontab
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.hourly
    )

    for path in "${cron_dirs[@]}"; do
        [[ ! -e "$path" ]] && continue
        local owner perms
        owner=$(stat -c '%U' "$path" 2>/dev/null || true)
        perms=$(stat -c '%a' "$path"  2>/dev/null || true)
        if [[ "$owner" != "root" ]]; then
            cron_issues+=("${path} is owned by '${owner}' (should be root)")
            cron_fix+="sudo /bin/chown root:root '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#002) != 0 )); then
            cron_issues+=("${path} is world-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod o-w '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#020) != 0 )); then
            cron_issues+=("${path} is group-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod g-w '${path}'"$'\n'
        fi
    done

    local ww_cron_scripts
    ww_cron_scripts=$(find /etc/cron.d /etc/cron.daily /etc/cron.weekly \
                           /etc/cron.monthly /etc/cron.hourly \
                      -type f -perm -002 2>/dev/null || true)
    if [[ -n "$ww_cron_scripts" ]]; then
        while IFS= read -r s; do
            cron_issues+=("cron script is world-writable: ${s}")
            cron_fix+="sudo /bin/chmod o-w $(printf '%q' "$s")"$'\n'
        done <<< "$ww_cron_scripts"
    fi

    if [[ ${#cron_issues[@]} -eq 0 ]]; then
        print_status "OK" "Cron directories and files are properly secured"
        append_report "## Cron Security\n- 🟢 Cron paths are root-owned and not world/group-writable"
    else
        print_status "WARN" "Cron security issues: ${#cron_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${cron_issues[@]}")
        append_report "## Cron Security\n- 🔴 ${#cron_issues[@]} cron issue(s) found"
        cron_fix+="# Verify permissions after fixing:
/usr/bin/stat -c '%n %a %U:%G' /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly"
        report_issue 8 \
            "Insecure cron directory or script permissions" \
            "Cron paths are not root-owned or are world/group-writable - enables privilege escalation via cron" \
            "$cron_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
