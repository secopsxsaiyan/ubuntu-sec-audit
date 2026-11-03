# shellcheck shell=bash
# check_root_path — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: Root PATH safety (Missing #19)
check_root_path() {
    print_status "INFO" "Checking root PATH safety..."
    local root_path
    # root's login PATH (what "sudo -i" or a root console gets); the
    # script's own PATH is only the fallback.
    root_path=$(env -i HOME=/root bash -lc 'printf "%s" "$PATH"' 2>/dev/null || true)
    root_path="${root_path:-$PATH}"

    local -a path_issues=()
    local path_fix=""

    # Check for . or empty components
    if echo "$root_path" | tr ':' '\n' | grep -qE '^\.?$'; then
        path_issues+=("Root PATH contains '.' or empty component (current directory execution risk)")
        path_fix+="# Remove '.' from root PATH in /root/.bashrc, /root/.profile, /etc/environment"$'\n'
        path_fix+="sudo /bin/grep -rn 'PATH.*\.' /root/.bashrc /root/.profile /etc/environment 2>/dev/null"$'\n'
    fi

    # Check for world-writable directories in PATH
    while IFS= read -r dir; do
        [[ -z "$dir" || "$dir" == "." ]] && continue
        if [[ -d "$dir" ]]; then
            local dperms downer
            dperms=$(stat -c '%a' "$dir" 2>/dev/null || true)
            downer=$(stat -c '%U' "$dir" 2>/dev/null || true)
            if [[ "$downer" != "root" ]] && (( (8#${dperms:-0} & 8#002) != 0 )); then
                path_issues+=("World-writable non-root directory in root PATH: $dir (${dperms}, owned by ${downer})")
                path_fix+="# Remove from PATH or fix permissions: $dir"$'\n'
            fi
        fi
    done < <(echo "$root_path" | tr ':' '\n')

    if [[ ${#path_issues[@]} -eq 0 ]]; then
        print_status "OK" "Root PATH is safe (no '.' or world-writable directories)"
        append_report "## Root PATH Safety\n- 🟢 Root PATH contains no dangerous entries"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${path_issues[@]}")
        print_status "WARN" "Root PATH safety issues: ${#path_issues[@]} found"
        append_report "## Root PATH Safety\n- 🔴 ${#path_issues[@]} dangerous entry/entries in root PATH"
        path_fix+="# After fixing, verify:
sudo bash -c 'echo \$PATH'"
        report_issue 8 \
            "Dangerous entries in root PATH" \
            "Root's PATH contains '.' or world-writable directories - classic privilege escalation vector" \
            "$path_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
