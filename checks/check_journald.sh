# shellcheck shell=bash
# check_journald — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: journald persistence (from review doc)
check_journald() {
    print_status "INFO" "Checking journald log persistence..."
    local storage_val
    storage_val=$(grep -hE '^\s*Storage\s*=' \
                  /etc/systemd/journald.conf \
                  /etc/systemd/journald.conf.d/*.conf 2>/dev/null \
                  | tail -1 | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$storage_val" == "persistent" ]]; then
        print_status "OK" "journald persistence enabled (Storage=persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=persistent"
    elif [[ "$storage_val" == "auto" && -d /var/log/journal ]]; then
        print_status "OK" "journald Storage=auto with /var/log/journal present (persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=auto + /var/log/journal exists"
    elif [[ "$storage_val" == "auto" && ! -d /var/log/journal ]]; then
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
        print_status "WARN" "journald Storage=${storage_val:-volatile} - logs not persisted across reboots"
        append_report "## Journald Persistence\n- 🔴 Logs not persistent (Storage=${storage_val:-volatile})"
        report_issue 5 \
            "journald logs not persistent across reboots" \
            "Storage=${storage_val:-unset} - logs lost on reboot, hindering forensics and incident response" \
            "sudo /bin/sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
sudo /usr/bin/journalctl --disk-usage" \
            0
    fi
}
