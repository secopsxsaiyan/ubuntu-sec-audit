# shellcheck shell=bash
# check_core_dumps — standard check (sourced by ubuntu-sec-audit.sh)

check_core_dumps() {
    print_status "INFO" "Checking core dump restrictions..."

    local -a core_issues=()
    local core_fix=""

    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ "$suid_dumpable" != "0" ]]; then
        core_issues+=("fs.suid_dumpable = ${suid_dumpable:-unset} (should be 0)")
        core_fix+="echo 'fs.suid_dumpable = 0' | sudo /usr/bin/tee /etc/sysctl.d/99-coredump.conf"$'\n'
        core_fix+="sudo /sbin/sysctl --system"$'\n'
    fi

    local limits_core
    limits_core=$(grep -rE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf \
                  /etc/security/limits.d/ 2>/dev/null || true)
    if [[ -z "$limits_core" ]]; then
        core_issues+=("No 'hard core 0' limit in /etc/security/limits.conf")
        core_fix+="echo '* hard core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
        core_fix+="echo '* soft core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
    fi

    if [[ -f /etc/systemd/coredump.conf ]]; then
        local storage_val
        storage_val=$(grep -E '^\s*Storage\s*=' /etc/systemd/coredump.conf 2>/dev/null \
                      | awk -F= '{print $2}' | tr -d ' ' || true)
        if [[ "$storage_val" != "none" ]]; then
            core_issues+=("systemd-coredump Storage=${storage_val:-default} - core dumps stored on disk")
            core_fix+="sudo /bin/sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/systemctl daemon-reload"$'\n'
        fi
    fi

    # NEW (Missing #18): kernel.core_pattern check
    local core_pattern
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")
    # Acceptable: systemd coredump handler or /dev/null; anything user-writable is a risk
    if [[ -n "$core_pattern" ]]; then
        local pattern_ok=0
        # Standard systemd handler
        [[ "$core_pattern" == "|/usr/lib/systemd/systemd-coredump"* ]] && pattern_ok=1
        # Disabled
        [[ "$core_pattern" == "/dev/null" ]] && pattern_ok=1
        # Core in root-owned dirs only
        [[ "$core_pattern" =~ ^/var/lib/systemd ]] && pattern_ok=1

        if [[ $pattern_ok -eq 0 ]]; then
            core_issues+=("kernel.core_pattern='${core_pattern}' - may point to user-writable path or unexpected handler")
            core_fix+="# Set core_pattern to systemd handler or disable entirely:"$'\n'
            core_fix+="echo 'kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h' | sudo /usr/bin/tee -a /etc/sysctl.d/99-coredump.conf"$'\n'
            core_fix+="sudo /sbin/sysctl --system"$'\n'
        fi
    fi

    if [[ ${#core_issues[@]} -eq 0 ]]; then
        print_status "OK" "Core dump restrictions are in place"
        append_report "## Core Dump Restrictions\n- 🟢 fs.suid_dumpable=0, hard core limit set, core_pattern safe"
    else
        print_status "WARN" "Core dump issues: ${#core_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${core_issues[@]}")
        append_report "## Core Dump Restrictions\n- 🔴 ${#core_issues[@]} core dump issue(s) found"
        core_fix+="# Verify after applying:
/sbin/sysctl fs.suid_dumpable kernel.core_pattern
/bin/grep -r 'core' /etc/security/limits.conf /etc/security/limits.d/"
        report_issue 6 \
            "Core dump restrictions missing or incomplete" \
            "Core dumps from privileged processes may expose sensitive memory (passwords, keys, tokens)" \
            "$core_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
