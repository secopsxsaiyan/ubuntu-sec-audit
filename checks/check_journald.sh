# shellcheck shell=bash
# check_journald — standard check (sourced by ubuntu-sec-audit.sh)

check_journald() {
    print_status "INFO" "Checking journald log persistence..."
    # Effective Storage= across journald.conf and its drop-ins; systemd's
    # default is "auto" (persistent when /var/log/journal exists).
    local storage_val
    storage_val=$(_systemd_conf_value journald Storage)
    storage_val="${storage_val:-auto}"

    if [[ "$storage_val" == "persistent" ]]; then
        print_status "OK" "journald persistence enabled (Storage=persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=persistent"
    elif [[ "$storage_val" == "auto" && -d "${AUDIT_ROOT}/var/log/journal" ]]; then
        print_status "OK" "journald Storage=auto with /var/log/journal present (persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=auto + /var/log/journal exists"
    elif [[ "$storage_val" == "auto" ]]; then
        print_status "WARN" "journald Storage=auto but /var/log/journal does not exist - logs are volatile"
        append_report "## Journald Persistence\n- 🟡 Storage=auto but /var/log/journal missing"
        report_issue 4 \
            "journald logs may be volatile (Storage=auto, no /var/log/journal)" \
            "System logs are lost on reboot without /var/log/journal directory" \
            "sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
# Verify:
sudo /usr/bin/journalctl --disk-usage" \
            0
    else
        print_status "WARN" "journald Storage=${storage_val} - logs not persisted across reboots"
        append_report "## Journald Persistence\n- 🔴 Logs not persistent (Storage=${storage_val})"
        # A drop-in wins over journald.conf and any earlier drop-ins.
        report_issue 5 \
            "journald logs not persistent across reboots" \
            "Storage=${storage_val} - logs lost on reboot, hindering forensics and incident response" \
            "sudo /bin/mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\n' | sudo /usr/bin/tee /etc/systemd/journald.conf.d/99-ubuntu-sec-audit.conf > /dev/null
sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
sudo /usr/bin/journalctl --disk-usage" \
            0
    fi
}
