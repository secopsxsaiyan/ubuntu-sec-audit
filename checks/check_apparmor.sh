# shellcheck shell=bash
# check_apparmor — standard check (sourced by ubuntu-sec-audit.sh)

check_apparmor() {
    print_status "INFO" "Checking AppArmor..."
    local enforced_count
    enforced_count=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}' || echo 0)
    if [[ "$enforced_count" -gt 0 ]]; then
        print_status "OK" "AppArmor enforced ($enforced_count profile(s) in enforce mode)"
        append_report "## AppArmor\n- 🟢 Enforced ($enforced_count profile(s))"
    else
        print_status "WARN" "AppArmor not enforcing"
        append_report "## AppArmor\n- 🔴 Not enforcing"
        report_issue 7 \
            "AppArmor disabled" \
            "AppArmor is not enforcing profiles" \
            "sudo /usr/bin/apt-get install -y apparmor apparmor-profiles apparmor-utils
sudo /bin/systemctl enable --now apparmor
sudo /usr/sbin/aa-enforce /etc/apparmor.d/*
sudo /usr/sbin/aa-status" \
            0
    fi
}
