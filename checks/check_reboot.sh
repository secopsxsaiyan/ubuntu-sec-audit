# shellcheck shell=bash
# check_reboot — standard check (sourced by ubuntu-sec-audit.sh)

check_reboot() {
    print_status "INFO" "Checking if reboot is required..."
    if [[ -f /var/run/reboot-required ]]; then
        print_status "WARN" "Reboot required after updates"
        append_report "## Reboot Required\n- 🔴 System requires reboot"
        report_issue 5 \
            "Reboot required" \
            "Kernel or critical library updates applied - reboot needed" \
            "sudo reboot" \
            0
    else
        print_status "OK" "No reboot required"
        append_report "## Reboot Required\n- 🟢 System up to date"
    fi
}
