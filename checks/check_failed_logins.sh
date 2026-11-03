# shellcheck shell=bash
# check_failed_logins — standard check (sourced by ubuntu-sec-audit.sh)

check_failed_logins() {
    print_status "INFO" "Analyzing failed logins..."
    local fails
    fails=$(sudo journalctl -u ssh --since "1 day ago" 2>/dev/null \
            | awk '/Failed password/{c++} END{print c+0}')
    if [[ "$fails" -gt $FAILED_LOGIN_THRESHOLD ]]; then
        print_status "WARN" "Many failed login attempts"
        append_report "## Failed Logins\n- 🟡 $fails failed attempts (last 24h)"
        report_issue 6 \
            "High failed login count" \
            "Possible brute-force attack on SSH ($fails failures in 24h)" \
            "sudo /usr/bin/apt-get install -y fail2ban
sudo /bin/systemctl enable --now fail2ban
sudo /usr/bin/fail2ban-client status sshd
sudo /usr/bin/journalctl -u ssh --since '1 day ago' | /bin/grep 'Failed password' | /usr/bin/tail -20" \
            0 \
            "Review /var/log/auth.log and consider key-only SSH authentication"
    else
        print_status "OK" "No unusual failed logins"
        append_report "## Failed Logins\n- 🟢 Normal"
    fi
}
