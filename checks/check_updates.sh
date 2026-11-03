# shellcheck shell=bash
# check_updates — standard check (sourced by ubuntu-sec-audit.sh)

check_updates() {
    print_status "INFO" "Checking package updates..."
    if [[ $SKIP_APT_UPDATE -eq 0 ]]; then
        apt-get update -qq || print_status "WARN" "apt-get update failed - using the cached package index"
    else
        print_status "INFO" "Skipping apt-get update (--skip-apt-update set)"
    fi
    if apt list --upgradable 2>/dev/null | grep -q upgradable; then
        print_status "WARN" "Updates available"
        append_report "## Package Updates\n- 🟡 Updates available"
        report_issue 12 \
            "System not fully patched" \
            "Outdated packages increase attack surface (CVEs)" \
            "sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y" \
            0 \
            "Reboot if kernel or libc was upgraded"
    else
        print_status "OK" "System up-to-date"
        append_report "## Package Updates\n- 🟢 Up-to-date"
    fi
}
