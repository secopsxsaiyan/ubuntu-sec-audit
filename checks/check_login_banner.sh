# shellcheck shell=bash
# check_login_banner — standard check (sourced by ubuntu-sec-audit.sh)
#
# CIS 1.7.2/1.7.3: /etc/issue and /etc/issue.net carry a warning and do not
# reveal the OS (\m \r \s \v escapes or the distribution name). /etc/motd is
# not required: Ubuntu builds the message of the day dynamically.

check_login_banner() {
    print_status "INFO" "Checking login banners (/etc/issue, /etc/issue.net, SSH Banner)..."
    local -a banner_issues=()
    local os_id f ssh_unknown=0 ssh_missing=0
    os_id=$(_os_release_field ID)
    os_id="${os_id:-ubuntu}"
    for f in /etc/issue /etc/issue.net; do
        if ! grep -q '[^[:space:]]' "${AUDIT_ROOT}${f}" 2>/dev/null; then
            banner_issues+=("${f} is missing or empty - no pre-login warning banner")
        elif grep -qiE -e '\\[mrsv]' -e "$os_id" "${AUDIT_ROOT}${f}" 2>/dev/null; then
            banner_issues+=("${f} reveals the operating system (\\m \\r \\s \\v or '${os_id}')")
        fi
    done

    # SSH banner, only when there is an SSH server whose effective
    # configuration can be read.
    if command -v sshd >/dev/null 2>&1; then
        if _sshd_effective_config; then
            local ssh_banner
            ssh_banner=$(awk '$1 == "banner" {print $2; exit}' <<< "$SSHD_CONF")
            if [[ -z "$ssh_banner" || "${ssh_banner,,}" == "none" ]]; then
                banner_issues+=("SSH Banner is not set")
                ssh_missing=1
            fi
        else
            ssh_unknown=1
        fi
    fi

    if [[ ${#banner_issues[@]} -eq 0 ]]; then
        if [[ $ssh_unknown -eq 1 ]]; then
            _mark_skipped "SSH banner not checked: sshd -T failed (${SSHD_CONF_ERR:-no output})"
            append_report "## Login Banners\n- ⚠️ /etc/issue files fine; SSH banner not checked (sshd -T failed)"
            return 0
        fi
        print_status "OK" "Login banners are configured"
        append_report "## Login Banners\n- 🟢 Warning banners present and do not reveal the OS"
        return 0
    fi

    local fix='BANNER="Authorized use only. Unauthorized access is prohibited and monitored."
printf '"'"'%s\n'"'"' "$BANNER" | sudo /usr/bin/tee /etc/issue /etc/issue.net > /dev/null'
    if [[ $ssh_missing -eq 1 ]]; then
        fix+='
# SSH banner in its own drop-in (works whether or not sshd_config has a
# Banner line; Ubuntu includes sshd_config.d/*.conf at the top):
sudo /bin/mkdir -p /etc/ssh/sshd_config.d
echo "Banner /etc/issue.net" | sudo /usr/bin/tee /etc/ssh/sshd_config.d/01-ubuntu-sec-audit-banner.conf > /dev/null
sudo /bin/chmod 600 /etc/ssh/sshd_config.d/01-ubuntu-sec-audit-banner.conf
if sudo /usr/sbin/sshd -t; then sudo /bin/systemctl restart ssh; fi
sudo /usr/sbin/sshd -T 2>/dev/null | grep -i "^banner" || true'
    fi
    print_status "WARN" "Login banner issues: ${#banner_issues[@]} found"
    append_report "## Login Banners\n- 🟡 ${#banner_issues[@]} banner issue(s)"
    report_issue 3 \
        "Login banners missing or incomplete" \
        "Warning banners missing or revealing the OS - required by CIS/legal best practice" \
        "$fix" \
        0 \
        "Issues:"$'\n'"$(printf ' - %s\n' "${banner_issues[@]}")"
}
