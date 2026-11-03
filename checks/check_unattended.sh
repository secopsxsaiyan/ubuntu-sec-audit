# shellcheck shell=bash
# check_unattended — standard check (sourced by ubuntu-sec-audit.sh)

check_unattended() {
    print_status "INFO" "Checking unattended-upgrades..."
    if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Unattended-upgrades missing"
        append_report "## Automatic Updates\n- 🔴 Not installed"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades package is not installed" \
            "sudo /usr/bin/apt-get install -y unattended-upgrades
sudo /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'AUTOEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"7\";
APT::Periodic::Unattended-Upgrade \"1\";
AUTOEOF
sudo /usr/bin/systemctl enable --now unattended-upgrades" \
            0
        return
    fi

    # Accept either 50unattended-upgrades having the security origin uncommented,
    # OR our own 51-security-origins.conf override, OR 20auto-upgrades enabling upgrades.
    local _uu_enabled=0
    grep -qE '"[$][{]distro_id[}]:[$][{]distro_codename[}]-security"' \
        /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null && _uu_enabled=1
    grep -q 'Allowed-Origins.*security' \
        /etc/apt/apt.conf.d/51-security-origins.conf 2>/dev/null && _uu_enabled=1
    grep -qE 'Unattended-Upgrade.*"1"' \
        /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null && _uu_enabled=1

    if [[ $_uu_enabled -eq 1 ]]; then
        print_status "OK" "Unattended-upgrades installed and enabled for security"
        append_report "## Automatic Updates\n- 🟢 Enabled"
    else
        print_status "WARN" "Unattended-upgrades not configured for security updates"
        append_report "## Automatic Updates\n- 🔴 Security updates not enabled"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades installed but security updates not enabled" \
            "sudo /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'AUTOEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"7\";
APT::Periodic::Unattended-Upgrade \"1\";
AUTOEOF
# Append security origin using :: (apt.conf list-append syntax) — avoids editing 50unattended-upgrades
sudo /usr/bin/tee /etc/apt/apt.conf.d/51-security-origins.conf > /dev/null << 'ORIGEOF'
Unattended-Upgrade::Allowed-Origins:: \"\${distro_id}:\${distro_codename}-security\";
Unattended-Upgrade::Allowed-Origins:: \"\${distro_id}ESMApps:\${distro_codename}-apps-security\";
ORIGEOF
sudo /usr/bin/systemctl enable --now unattended-upgrades" \
            0
    fi
}
