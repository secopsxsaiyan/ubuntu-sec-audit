# shellcheck shell=bash
# check_core_dumps — standard check (sourced by ubuntu-sec-audit.sh)

check_core_dumps() {
    print_status "INFO" "Checking core dump restrictions..."

    local -a core_issues=()
    local has_coredumpd=0
    [[ -x "${AUDIT_ROOT}/usr/lib/systemd/systemd-coredump" || -x "${AUDIT_ROOT}/lib/systemd/systemd-coredump" ]] \
        && has_coredumpd=1

    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || true)
    if [[ "$suid_dumpable" != "0" ]]; then
        core_issues+=("fs.suid_dumpable = ${suid_dumpable:-unset} (should be 0)")
    fi

    local limits_core
    limits_core=$(grep -rhE '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' \
                  "${AUDIT_ROOT}/etc/security/limits.conf" "${AUDIT_ROOT}/etc/security/limits.d/" 2>/dev/null || true)
    if [[ -z "$limits_core" ]]; then
        core_issues+=("No '* hard core 0' limit in /etc/security/limits.conf or limits.d")
    fi

    local storage_val=""
    if [[ $has_coredumpd -eq 1 ]]; then
        storage_val=$(_systemd_conf_value coredump Storage)
        if [[ "$storage_val" != "none" ]]; then
            core_issues+=("systemd-coredump Storage=${storage_val:-external} - core dumps stored on disk")
        fi
    fi

    # Safe handlers: discard (|/bin/false, /dev/null) or systemd-coredump
    # with Storage=none. Ubuntu's apport is flagged (CIS 1.5.5); it also
    # rewrites core_pattern whenever it starts, so it has to be disabled.
    local core_pattern pattern_ok=0 is_apport=0
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || true)
    case "$core_pattern" in
        "|/bin/false"*|"|/usr/bin/false"*|"/dev/null") pattern_ok=1 ;;
        "|/usr/lib/systemd/systemd-coredump"*|"|/lib/systemd/systemd-coredump"*)
            [[ "$storage_val" == "none" ]] && pattern_ok=1 ;;
        *apport*) is_apport=1 ;;
    esac
    if [[ $pattern_ok -eq 0 ]]; then
        if [[ $is_apport -eq 1 ]]; then
            core_issues+=("kernel.core_pattern hands crashes to apport (automatic error reporting is enabled)")
        else
            core_issues+=("kernel.core_pattern='${core_pattern:-unset}' - core dumps may be written to disk")
        fi
    fi

    if [[ ${#core_issues[@]} -eq 0 ]]; then
        print_status "OK" "Core dump restrictions are in place"
        append_report "## Core Dump Restrictions\n- 🟢 fs.suid_dumpable=0, hard core limit set, core_pattern safe"
        return 0
    fi

    local issue_list
    issue_list=$(printf ' - %s\n' "${core_issues[@]}")
    print_status "WARN" "Core dump issues: ${#core_issues[@]} found"
    append_report "## Core Dump Restrictions\n- 🔴 ${#core_issues[@]} core dump issue(s) found"

    # Files are written whole (not appended), so re-running is harmless.
    local core_fix=""
    if [[ $is_apport -eq 1 ]]; then
        core_fix+="# Disable apport first: it resets core_pattern whenever it starts."$'\n'
        core_fix+="sudo /bin/systemctl disable --now apport.service 2>/dev/null || true"$'\n'
        core_fix+="[ -f /etc/default/apport ] && sudo /bin/sed -i 's/^enabled=1/enabled=0/' /etc/default/apport"$'\n'
    fi
    core_fix+="sudo /usr/bin/tee /etc/sysctl.d/99-ubuntu-sec-audit-coredump.conf > /dev/null << 'COREEOF'
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
COREEOF
sudo /usr/bin/tee /etc/security/limits.d/99-no-coredump.conf > /dev/null << 'LIMITSEOF'
* hard core 0
* soft core 0
LIMITSEOF
"
    if [[ $has_coredumpd -eq 1 ]]; then
        core_fix+="sudo /bin/mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' | sudo /usr/bin/tee /etc/systemd/coredump.conf.d/99-ubuntu-sec-audit.conf > /dev/null
sudo /bin/systemctl daemon-reload
"
    fi
    core_fix+="sudo /sbin/sysctl --system > /dev/null
# Verify:
/sbin/sysctl fs.suid_dumpable kernel.core_pattern"

    report_issue 6 \
        "Core dump restrictions missing or incomplete" \
        "Core dumps from privileged processes may expose sensitive memory (passwords, keys, tokens)" \
        "$core_fix" \
        0 \
        "Issues:\n${issue_list}"
}
