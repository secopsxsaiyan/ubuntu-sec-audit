# shellcheck shell=bash
# check_fail2ban — standard check (sourced by ubuntu-sec-audit.sh)

check_fail2ban() {
    print_status "INFO" "Checking Fail2Ban installation and configuration..."

    if ! dpkg -l fail2ban 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Fail2Ban is not installed"
        append_report "## Fail2Ban\n- 🔴 fail2ban not installed"
        report_issue 6 \
            "Fail2Ban not installed" \
            "No automated IP banning on repeated authentication failures - brute-force attacks go unchecked at the OS level" \
            "sudo /usr/bin/apt-get install -y fail2ban
sudo /usr/bin/tee /etc/fail2ban/jail.d/hardening.conf > /dev/null << 'F2BEOF'
[DEFAULT]
allowipv6 = auto

[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
bantime  = 1d
findtime = 10m
F2BEOF
sudo /bin/systemctl enable --now fail2ban
sudo /bin/systemctl restart fail2ban
sudo /usr/bin/fail2ban-client status sshd" \
            0 \
            "Also consider CrowdSec as a community-driven alternative with shared blocklists"
        return
    fi

    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_status "WARN" "Fail2Ban installed but not running"
        append_report "## Fail2Ban\n- 🔴 fail2ban installed but inactive"
        report_issue 5 \
            "Fail2Ban installed but not running" \
            "fail2ban service is not active - no IP banning is occurring despite the package being present" \
            "# Fix allowipv6 config issue (common cause of fail2ban startup failures):
sudo /usr/bin/tee /etc/fail2ban/jail.d/hardening.conf > /dev/null << 'F2BEOF'
[DEFAULT]
allowipv6 = auto

[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
bantime  = 1d
findtime = 10m
F2BEOF
sudo /bin/systemctl enable --now fail2ban
sudo /bin/systemctl restart fail2ban
sudo /usr/bin/fail2ban-client status sshd" \
            0
        return
    fi

    local ssh_jail_status
    ssh_jail_status=$(sudo /usr/bin/fail2ban-client status sshd 2>/dev/null || true)
    if [[ -z "$ssh_jail_status" ]]; then
        print_status "WARN" "Fail2Ban active but sshd jail is not configured"
        append_report "## Fail2Ban\n- 🟡 fail2ban running but no sshd jail enabled"
        report_issue 4 \
            "Fail2Ban running without SSH jail" \
            "fail2ban is active but no sshd jail is enabled - SSH brute-force attempts are not being blocked" \
            "sudo /usr/bin/tee /etc/fail2ban/jail.d/hardening.conf > /dev/null << 'F2BEOF'
[DEFAULT]
allowipv6 = auto

[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
bantime  = 1d
findtime = 10m
F2BEOF
sudo /bin/systemctl restart fail2ban
sudo /usr/bin/fail2ban-client status sshd" \
            0
    else
        local banned_count
        banned_count=$(echo "$ssh_jail_status" | grep -oE 'Currently banned:[[:space:]]+[0-9]+' | grep -oE '[0-9]+' || echo "0")
        print_status "OK" "Fail2Ban active with sshd jail configured (currently banned: ${banned_count:-0} IPs)"
        append_report "## Fail2Ban\n- 🟢 fail2ban active, sshd jail enabled (banned: ${banned_count:-0})"
    fi
}
