# shellcheck shell=bash
# check_cron — standard check (sourced by ubuntu-sec-audit.sh)

check_cron() {
    print_status "INFO" "Checking cron job security..."

    local -a cron_issues=()
    local cron_fix="" manual_fix=""

    # CIS 2.4.1.2-2.4.1.7: /etc/crontab is root:root with mode 600, and the
    # cron directories are root:root with mode 700 (or stricter). cron runs
    # these as root, so tightening them breaks nothing.
    local -a cron_paths=(
        /etc/crontab
        /etc/cron.hourly
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.d
    )
    local path real found=0 uid gid perms want problem bad_owner bad_mode line q
    for path in "${cron_paths[@]}"; do
        real="${AUDIT_ROOT}${path}"
        [[ -e "$real" ]] || continue
        found=1
        uid=$(stat -c '%u' -- "$real" 2>/dev/null || true)
        gid=$(stat -c '%g' -- "$real" 2>/dev/null || true)
        perms=$(stat -c '%a' -- "$real" 2>/dev/null || true)
        [[ -n "$perms" ]] || continue
        want=700
        [[ "$path" == /etc/crontab ]] && want=600
        problem="" bad_owner=0 bad_mode=0
        if [[ "$uid" != 0 || "$gid" != 0 ]]; then
            bad_owner=1
            problem="owned by ${uid}:${gid} (should be root:root)"
        fi
        if (( (8#$perms & 8#077) != 0 )); then
            bad_mode=1
            problem+="${problem:+, }mode ${perms} (should be ${want} or stricter)"
        fi
        [[ -n "$problem" ]] || continue
        cron_issues+=("${path} is ${problem}")
        # Changed directly only when nobody else can rename anything on the
        # path (and never through a symlink); otherwise a person does it.
        line=$(_safe_chmod_cmd root og-rwx "$path") || line=""
        if [[ -n "$line" ]]; then
            q=$(printf '%q' "$path")
            [[ $bad_owner -eq 1 ]] && cron_fix+="[ -L ${q} ] || sudo /bin/chown root:root -- ${q}"$'\n'
            [[ $bad_mode -eq 1 ]] && cron_fix+="${line}"$'\n'
        else
            manual_fix+="#   sudo chown root:root ${path}; sudo chmod og-rwx ${path}"$'\n'
        fi
    done

    if [[ $found -eq 0 ]]; then
        _mark_not_applicable "cron is not installed (no /etc/crontab or /etc/cron.* directories)"
        return 0
    fi

    local ww_cron_scripts s rel
    ww_cron_scripts=$(find "${AUDIT_ROOT}/etc/cron.d" "${AUDIT_ROOT}/etc/cron.daily" \
                           "${AUDIT_ROOT}/etc/cron.weekly" "${AUDIT_ROOT}/etc/cron.monthly" \
                           "${AUDIT_ROOT}/etc/cron.hourly" \
                      -type f -perm -002 2>/dev/null || true)
    while IFS= read -r s; do
        [[ -n "$s" ]] || continue
        rel="${s#"${AUDIT_ROOT}"}"
        cron_issues+=("cron script is world-writable: ${rel}")
        line=$(_safe_chmod_cmd root o-w "$rel") || line=""
        if [[ -n "$line" ]]; then
            cron_fix+="${line}"$'\n'
        else
            manual_fix+="#   sudo chmod o-w $(printf '%q' "$rel")   (after its directory is fixed)"$'\n'
        fi
    done <<< "$ww_cron_scripts"

    if [[ ${#cron_issues[@]} -eq 0 ]]; then
        print_status "OK" "Cron directories and files are properly secured"
        append_report "## Cron Security\n- 🟢 Cron paths are root:root with no group/other access"
    else
        print_status "WARN" "Cron security issues: ${#cron_issues[@]} found"
        local issue_list fix=""
        issue_list=$(printf ' - %s\n' "${cron_issues[@]}")
        append_report "## Cron Security\n- 🔴 ${#cron_issues[@]} cron issue(s) found"
        [[ -z "$cron_fix" ]] && fix="# MANUAL: a directory on these paths can be changed by other users."$'\n'
        fix+="$cron_fix"
        if [[ -n "$manual_fix" ]]; then
            fix+="# Fix by hand (a directory on the path is writable by other users):"$'\n'
            fix+="$manual_fix"
        fi
        fix+="# Verify permissions after fixing:
/usr/bin/stat -c '%n %a %U:%G' /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>/dev/null || true"
        report_issue 8 \
            "Insecure cron directory or script permissions" \
            "Cron files and directories must be root:root with no group/other access (crontab 600, directories 700), and cron scripts must not be world-writable - otherwise users can read or plant root cron jobs" \
            "$fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
