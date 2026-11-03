# shellcheck shell=bash
# check_root_path — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: Root PATH safety (Missing #19)
check_root_path() {
    print_status "INFO" "Checking root PATH safety..."
    local root_path
    # root's login PATH (what "sudo -i" or a root console gets); the
    # script's own PATH is only the fallback.
    # Root's profile runs here: no terminal input (a prompt or "exec tmux"
    # would block the audit) and a time limit.
    root_path=$(timeout 10 env -i HOME=/root bash -lc 'printf "%s" "$PATH"' </dev/null 2>/dev/null || true)
    root_path="${root_path:-$PATH}"

    local -a path_issues=()
    local path_fix=""

    # '.', empty and relative entries all resolve against the current directory.
    if echo "$root_path" | tr ':' '\n' | grep -qE '^([^/].*)?$'; then
        path_issues+=("Root PATH contains '.', an empty or a relative entry (current directory execution risk)")
        path_fix+="# Remove '.', empty (::) and relative entries from root's PATH; look in:"$'\n'
        path_fix+="#   sudo grep -rn 'PATH' /root/.bashrc /root/.profile /etc/environment /etc/profile /etc/profile.d"$'\n'
    fi

    # CIS 5.4.2.5: every directory in root's PATH is owned by root and is not
    # group- or world-writable (the sticky bit does not help: anyone who can
    # write there can add a binary). Missing directories are not reported.
    local dir dpath dperms duid problem
    while IFS= read -r dir; do
        [[ "$dir" == /* ]] || continue
        dpath="${AUDIT_ROOT}${dir}"
        [[ -d "$dpath" ]] || continue
        dperms=$(stat -L -c '%a' -- "$dpath" 2>/dev/null || true)
        duid=$(stat -L -c '%u' -- "$dpath" 2>/dev/null || true)
        [[ -n "$dperms" ]] || continue
        problem=""
        [[ "$duid" != 0 ]] && problem="not owned by root"
        if (( (8#$dperms & 8#022) != 0 )); then
            problem+="${problem:+, }group- or world-writable"
        fi
        [[ -n "$problem" ]] || continue
        path_issues+=("Directory in root PATH is ${problem}: ${dir} (mode ${dperms}, owner UID ${duid})")
        path_fix+="#   ${dir} (${problem}): remove it from root's PATH, or make it"$'\n'
        path_fix+="#     root-owned and not group/world-writable: sudo chown root:root ${dir}; sudo chmod go-w ${dir}"$'\n'
    done < <(echo "$root_path" | tr ':' '\n')

    if [[ ${#path_issues[@]} -eq 0 ]]; then
        print_status "OK" "Root PATH is safe (no '.', relative or writable directories)"
        append_report "## Root PATH Safety\n- 🟢 Root PATH contains no dangerous entries"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${path_issues[@]}")
        print_status "WARN" "Root PATH safety issues: ${#path_issues[@]} found"
        append_report "## Root PATH Safety\n- 🔴 ${#path_issues[@]} dangerous entry/entries in root PATH"
        # A person decides: another user or a service may rely on these
        # directories, and PATH is set in several files.
        path_fix="# MANUAL: fix root's PATH by hand."$'\n'"${path_fix}"
        path_fix+="# After fixing, verify:
sudo bash -c 'echo \$PATH'"
        report_issue 8 \
            "Dangerous entries in root PATH" \
            "Root's PATH contains '.', relative, non-root-owned or group/world-writable directories - classic privilege escalation vector" \
            "$path_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
