# shellcheck shell=bash
# check_reboot — standard check (sourced by ubuntu-sec-audit.sh)

check_reboot() {
    print_status "INFO" "Checking if reboot is required..."
    if [[ -f "${AUDIT_ROOT}/var/run/reboot-required" ]]; then
        print_status "WARN" "Reboot required after updates"
        append_report "## Reboot Required\n- 🔴 System requires reboot"
        # Manual: rebooting from inside the fix script would stop it halfway.
        report_issue 5 \
            "Reboot required" \
            "Kernel or critical library updates applied - reboot needed" \
            "# Reboot in a maintenance window, after the other fixes:
#   sudo systemctl reboot
# Packages that requested the reboot:
#   cat /var/run/reboot-required.pkgs" \
            0
    else
        print_status "OK" "No reboot required"
        append_report "## Reboot Required\n- 🟢 System up to date"
    fi
}
