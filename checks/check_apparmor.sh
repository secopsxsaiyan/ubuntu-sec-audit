# shellcheck shell=bash
# check_apparmor — standard check (sourced by ubuntu-sec-audit.sh)

check_apparmor() {
    print_status "INFO" "Checking AppArmor..."
    local enforced_count
    enforced_count=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}' || true)
    [[ "$enforced_count" =~ ^[0-9]+$ ]] || enforced_count=0
    if [[ "$enforced_count" -gt 0 ]]; then
        print_status "OK" "AppArmor enforced ($enforced_count profile(s) in enforce mode)"
        append_report "## AppArmor\n- 🟢 Enforced ($enforced_count profile(s))"
    else
        print_status "WARN" "AppArmor not enforcing"
        append_report "## AppArmor\n- 🔴 Not enforcing"
        # Profiles are not forced into enforce mode wholesale: packages ship
        # some in complain mode on purpose, and enforcing them can break apps.
        report_issue 7 \
            "AppArmor disabled" \
            "AppArmor is not enforcing profiles" \
            "sudo /usr/bin/apt-get install -y apparmor apparmor-utils
sudo /bin/systemctl enable --now apparmor
# Review profiles in complain mode and enforce them one at a time:
#   sudo aa-status
#   sudo aa-enforce /etc/apparmor.d/<profile>
sudo /usr/sbin/aa-status" \
            0
    fi
}
