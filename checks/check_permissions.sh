# shellcheck shell=bash
# check_permissions — standard check (sourced by ubuntu-sec-audit.sh)

check_permissions() {
    print_status "INFO" "Checking critical permissions..."
    if [[ "$(stat -c %a /etc/shadow)" != "640" ]] || [[ "$(stat -c %a /etc/passwd)" != "644" ]]; then
        print_status "ERR" "Weak critical file permissions"
        append_report "## Critical Permissions\n- 🔴 /etc/shadow or /etc/passwd permissions incorrect"
        report_issue 10 \
            "Weak critical file permissions" \
            "/etc/shadow or /etc/passwd have incorrect permissions" \
            "sudo /bin/chmod 640 /etc/shadow
sudo /bin/chmod 644 /etc/passwd
sudo /bin/chown root:shadow /etc/shadow
sudo /bin/chown root:root /etc/passwd
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/shadow /etc/passwd" \
            0
    else
        print_status "OK" "Critical files properly permissioned"
        append_report "## Critical Permissions\n- 🟢 Correct permissions on /etc/shadow and /etc/passwd"
    fi

    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_cfg_perms sshd_cfg_owner sshd_cfg_group
        sshd_cfg_perms=$(stat -c '%a' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_owner=$(stat -c '%U' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_group=$(stat -c '%G' /etc/ssh/sshd_config  2>/dev/null || true)
        if [[ "$sshd_cfg_perms" != "600" || "$sshd_cfg_owner" != "root" || "$sshd_cfg_group" != "root" ]]; then
            print_status "WARN" "sshd_config permissions incorrect: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} (should be 600 root:root)"
            append_report "## Critical Permissions\n- 🔴 /etc/ssh/sshd_config: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group}"
            report_issue 8 \
                "sshd_config has insecure permissions" \
                "/etc/ssh/sshd_config is ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} - should be 600 root:root (CIS 5.2.1)" \
                "sudo /bin/chmod 600 /etc/ssh/sshd_config
sudo /bin/chown root:root /etc/ssh/sshd_config
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/ssh/sshd_config" \
                0
        else
            print_status "OK" "/etc/ssh/sshd_config permissions are correct (600 root:root)"
            append_report "## Critical Permissions\n- 🟢 /etc/ssh/sshd_config is 600 root:root"
        fi
    fi
}
