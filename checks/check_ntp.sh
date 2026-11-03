# shellcheck shell=bash
# check_ntp — standard check (sourced by ubuntu-sec-audit.sh)

check_ntp() {
    print_status "INFO" "Checking NTP time synchronization..."
    local ntp_ok=0

    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        local sync_status
        sync_status=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
        if [[ "$sync_status" == "yes" ]]; then
            print_status "OK" "systemd-timesyncd active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 systemd-timesyncd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v chronyc >/dev/null 2>&1; then
        if systemctl is-active --quiet chronyd 2>/dev/null && \
           chronyc tracking 2>/dev/null | grep -q "Leap status.*Normal"; then
            print_status "OK" "chrony is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 chrony synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v ntpq >/dev/null 2>&1; then
        if ntpq -p 2>/dev/null | grep -q '^\*'; then
            print_status "OK" "ntpd is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 ntpd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]]; then
        print_status "WARN" "NTP not synchronized or not running"
        append_report "## NTP Synchronization\n- 🔴 NTP not active or not synchronized"
        report_issue 5 \
            "NTP synchronization not active" \
            "System clock may drift - accurate time is essential for log correlation and audit trails" \
            "sudo /bin/systemctl enable --now systemd-timesyncd
sudo timedatectl set-ntp true
timedatectl status
timedatectl show --property=NTPSynchronized" \
            0
    fi
}
