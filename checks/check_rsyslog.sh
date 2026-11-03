# shellcheck shell=bash
# check_rsyslog — standard check (sourced by ubuntu-sec-audit.sh)

check_rsyslog() {
    print_status "INFO" "Checking rsyslog installation and status..."

    if ! dpkg -l rsyslog 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "rsyslog is not installed"
        append_report "## Rsyslog\n- 🔴 rsyslog not installed"
        report_issue 4 \
            "rsyslog not installed" \
            "Traditional syslog daemon absent - SIEM agents, log shippers, and many audit tools depend on /var/log/syslog" \
            "sudo /usr/bin/apt-get install -y rsyslog
sudo /bin/systemctl enable --now rsyslog
sudo /bin/systemctl status rsyslog
# Verify syslog output:
sudo /usr/bin/logger 'rsyslog test'
sudo /usr/bin/tail -5 /var/log/syslog" \
            0
        return
    fi

    if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
        print_status "WARN" "rsyslog installed but not running"
        append_report "## Rsyslog\n- 🔴 rsyslog installed but inactive"
        report_issue 4 \
            "rsyslog installed but not running" \
            "rsyslog service is not active - /var/log/syslog and related files are not being written" \
            "sudo /bin/systemctl enable --now rsyslog
sudo /bin/systemctl status rsyslog" \
            0
        return
    fi

    # Verify /var/log/syslog is current (written within the last 60 minutes)
    local syslog_file="${AUDIT_ROOT}/var/log/syslog" syslog_recent
    syslog_recent=$(find "$syslog_file" -mmin -60 2>/dev/null || true)
    if [[ ! -f "$syslog_file" || -z "$syslog_recent" ]]; then
        print_status "WARN" "rsyslog active but /var/log/syslog is absent or stale (>60 min)"
        append_report "## Rsyslog\n- 🟡 rsyslog running but /var/log/syslog stale or absent"
        report_issue 3 \
            "rsyslog running but syslog output stale" \
            "/var/log/syslog is missing or has not been written in over 60 minutes despite rsyslog being active" \
            "sudo /bin/systemctl restart rsyslog
sudo /usr/bin/logger 'rsyslog test message'
sudo /usr/bin/tail -5 /var/log/syslog" \
            0
    else
        print_status "OK" "rsyslog active and /var/log/syslog is current"
        append_report "## Rsyslog\n- 🟢 rsyslog active, /var/log/syslog current"
    fi
}
