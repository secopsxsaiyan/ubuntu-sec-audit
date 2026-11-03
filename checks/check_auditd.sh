# shellcheck shell=bash
# check_auditd — standard check (sourced by ubuntu-sec-audit.sh)

# Persistent rules: rules.d is what augenrules loads at boot and on reload
# (rules added with auditctl alone are dropped by the next augenrules --load).
_AUDIT_RULES_FIX="sudo /bin/mkdir -p /etc/audit/rules.d
sudo /usr/bin/tee /etc/audit/rules.d/50-ubuntu-sec-audit.rules > /dev/null << 'AUDITEOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
AUDITEOF
sudo /usr/sbin/augenrules --load"

check_auditd() {
    print_status "INFO" "Checking auditd audit framework..."
    if ! command -v auditctl >/dev/null 2>&1; then
        print_status "WARN" "auditd not installed"
        append_report "## Auditd\n- 🔴 auditd not installed"
        report_issue 7 \
            "auditd not installed" \
            "No kernel-level audit logging - privileged operations, login events and file accesses are not tracked" \
            "sudo /usr/bin/apt-get install -y auditd audispd-plugins
sudo /bin/systemctl enable --now auditd
${_AUDIT_RULES_FIX}" \
            0 \
            "auditd is required by CIS Benchmarks and most compliance frameworks (PCI-DSS, HIPAA, SOC 2)"
        return
    fi

    local audit_issues=()

    # Service running
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        audit_issues+=("auditd service is not running")
    fi

    # Enabled at boot
    if ! systemctl is-enabled --quiet auditd 2>/dev/null; then
        audit_issues+=("auditd not enabled at boot")
    fi

    # Check for minimum required rules
    local audit_rules
    audit_rules=$(auditctl -l 2>/dev/null || true)
    for watched in '/etc/passwd' '/etc/shadow' '/etc/sudoers'; do
        if ! grep -q "$watched" <<< "$audit_rules"; then
            audit_issues+=("No audit rule watching ${watched}")
        fi
    done

    # AU-11: audit log retention
    local _auditd_conf="${AUDIT_ROOT}/etc/audit/auditd.conf"
    if [[ -f "$_auditd_conf" ]]; then
        local _max_logs _max_size _action
        _max_logs=$(grep -i '^num_logs' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        _max_size=$(grep -i '^max_log_file[^_]' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        _action=$(grep -i '^max_log_file_action' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "")
        local _retention_ok=1
        local _ret_issues=()
        [[ "${_max_logs:-0}" -lt 5 ]] && { _retention_ok=0; _ret_issues+=("num_logs=${_max_logs:-unset} (need ≥5)"); }
        [[ "${_max_size:-0}" -lt 8 ]] && { _retention_ok=0; _ret_issues+=("max_log_file=${_max_size:-unset} MB (need ≥8)"); }
        [[ "${_action,,}" != "keep_logs" && "${_action,,}" != "rotate" ]] && \
            { _retention_ok=0; _ret_issues+=("max_log_file_action=${_action:-unset} (need keep_logs or rotate)"); }
        if [[ $_retention_ok -eq 0 ]]; then
            audit_issues+=("Audit log retention insufficient: $(IFS=', '; echo "${_ret_issues[*]}")")
        fi
    fi

    if [[ ${#audit_issues[@]} -eq 0 ]]; then
        print_status "OK" "auditd active, enabled at boot, essential rules present, and log retention configured"
        append_report "## Auditd\n- 🟢 auditd running with essential audit rules and adequate log retention"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${audit_issues[@]}")
        print_status "WARN" "auditd issues: ${#audit_issues[@]} found"
        append_report "## Auditd\n- 🔴 auditd issues: ${#audit_issues[@]}"
        report_issue 7 \
            "auditd configuration incomplete" \
            "${#audit_issues[@]} auditd issue(s) found" \
            "sudo /bin/systemctl enable --now auditd
${_AUDIT_RULES_FIX}
# AU-11: configure log retention (≥5 logs, ≥8 MB each, rotate on full)
sudo /bin/sed -i 's/^num_logs.*/num_logs = 5/'             /etc/audit/auditd.conf
sudo /bin/sed -i 's/^max_log_file .*/max_log_file = 8/'    /etc/audit/auditd.conf
sudo /bin/sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/' /etc/audit/auditd.conf
sudo /bin/systemctl restart auditd
# Verify:
grep -E 'num_logs|max_log_file' /etc/audit/auditd.conf" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
