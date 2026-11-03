# shellcheck shell=bash
# check_login_banner — standard check (sourced by ubuntu-sec-audit.sh)

check_login_banner() {
    print_status "INFO" "Checking login banners (/etc/issue, /etc/motd, SSH Banner)..."
    local -a banner_issues=()
    [[ ! -s "${AUDIT_ROOT}/etc/issue" ]] && banner_issues+=("/etc/issue is empty - no pre-login warning banner")
    [[ ! -s "${AUDIT_ROOT}/etc/motd" ]] && banner_issues+=("/etc/motd is empty - no post-login message of the day")
    # FIX: use sshd -T (effective runtime config) instead of reading /etc/ssh/sshd_config
    # directly, which misses drop-in files in /etc/ssh/sshd_config.d/
    local ssh_banner
    local _sshd_eff
    _sshd_eff=$(sshd -T 2>/dev/null || true)
    ssh_banner=$(awk '/^banner / {print $2}' <<< "$_sshd_eff" | head -1 || true)
    if [[ -z "$ssh_banner" || "${ssh_banner,,}" == "none" ]]; then
        banner_issues+=("SSH Banner directive not configured in sshd_config")
    fi
    if [[ ${#banner_issues[@]} -gt 0 ]]; then
        local issue_list
        issue_list=$(printf ' - %s\n' "${banner_issues[@]}")
        print_status "WARN" "Login banner issues: ${#banner_issues[@]} found"
        append_report "## Login Banners\n- 🟡 ${#banner_issues[@]} banner issue(s)"
        report_issue 3 \
            "Login banners missing or incomplete" \
            "Warning banners missing - required by CIS/legal best practice" \
            'BANNER="Authorized use only. Unauthorized access is prohibited and monitored."
echo "$BANNER" | sudo /usr/bin/tee /etc/issue /etc/issue.net /etc/motd
sudo /bin/sed -i "s|^#\?Banner.*|Banner /etc/issue.net|" /etc/ssh/sshd_config
sudo /bin/systemctl restart ssh
cat /etc/issue && sudo /usr/sbin/sshd -T | grep -i banner' \
            0 \
            "Issues:\n${issue_list}"
    else
        print_status "OK" "Login banners are configured"
        append_report "## Login Banners\n- 🟢 Banners present on /etc/issue, /etc/motd, and SSH"
    fi
}
