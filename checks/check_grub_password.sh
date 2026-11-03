# shellcheck shell=bash
# check_grub_password — standard check (sourced by ubuntu-sec-audit.sh)

check_grub_password() {
    print_status "INFO" "Checking GRUB bootloader password protection..."
    # Hosts that boot without GRUB (direct kernel boot, systemd-boot, ...)
    # have no GRUB menu to protect.
    if [[ ! -f "${AUDIT_ROOT}/boot/grub/grub.cfg" && ! -f "${AUDIT_ROOT}/etc/default/grub" ]]; then
        append_report "## GRUB Bootloader Password\n- ⚪ GRUB not installed - not applicable"
        _mark_not_applicable "GRUB is not installed (no /boot/grub/grub.cfg or /etc/default/grub)"
        return 0
    fi
    local grub_pw_set=0
    if grep -rqE '^[[:space:]]*password_pbkdf2[[:space:]]' \
        "${AUDIT_ROOT}/boot/grub/grub.cfg" "${AUDIT_ROOT}/etc/grub.d/" 2>/dev/null; then
        grub_pw_set=1
    fi
    if [[ $grub_pw_set -eq 1 ]]; then
        print_status "OK" "GRUB bootloader password is configured"
        append_report "## GRUB Bootloader Password\n- 🟢 GRUB password protection configured"
    else
        print_status "WARN" "GRUB bootloader has no password protection"
        append_report "## GRUB Bootloader Password\n- 🔴 GRUB not password protected"
        # Manual: the hash must come from the operator, and a superuser
        # without --unrestricted entries makes every boot wait for a password.
        report_issue 6 \
            "GRUB bootloader not password protected" \
            "Without a GRUB password, anyone with physical access can boot into recovery mode and gain root" \
            '# 1. Generate a password hash (interactive):
#      grub-mkpasswd-pbkdf2
# 2. Append to /etc/grub.d/40_custom, using the hash from step 1:
#      set superusers="root"
#      password_pbkdf2 root grub.pbkdf2.sha512.10000.<HASH>
# 3. Keep normal boots unattended: in /etc/grub.d/10_linux add --unrestricted
#    to the CLASS line, e.g.  CLASS="--class gnu-linux --class gnu --class os --unrestricted"
#    (editing entries and the GRUB shell still need the password).
# 4. sudo chmod 700 /etc/grub.d/40_custom && sudo update-grub
# 5. Verify before rebooting:
#      sudo grep -E "password_pbkdf2|superusers|unrestricted" /boot/grub/grub.cfg' \
            0 \
            "Physical access without a GRUB password bypasses all OS-level controls"
    fi
}
