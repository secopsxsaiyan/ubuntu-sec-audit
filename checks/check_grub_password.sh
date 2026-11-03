# shellcheck shell=bash
# check_grub_password — standard check (sourced by ubuntu-sec-audit.sh)

check_grub_password() {
    print_status "INFO" "Checking GRUB bootloader password protection..."
    local grub_pw_set=0
    if grep -rqE '^\s*password_pbkdf2\s' /boot/grub/grub.cfg /etc/grub.d/ 2>/dev/null; then
        grub_pw_set=1
    fi
    if [[ $grub_pw_set -eq 1 ]]; then
        print_status "OK" "GRUB bootloader password is configured"
        append_report "## GRUB Bootloader Password\n- 🟢 GRUB password protection configured"
    else
        print_status "WARN" "GRUB bootloader has no password protection"
        append_report "## GRUB Bootloader Password\n- 🔴 GRUB not password protected"
        report_issue 6 \
            "GRUB bootloader not password protected" \
            "Without a GRUB password, anyone with physical access can boot into recovery mode and gain root" \
            '# 1. Generate a GRUB password hash (run interactively):
grub-mkpasswd-pbkdf2
# 2. Add to /etc/grub.d/40_custom:
sudo /bin/tee -a /etc/grub.d/40_custom <<EOF
set superusers="root"
password_pbkdf2 root <PASTE_HASH_HERE>
EOF
sudo /bin/chmod 700 /etc/grub.d/40_custom
# 3. Rebuild grub.cfg:
sudo /usr/sbin/update-grub
# 4. Verify:
sudo /bin/grep -E "password_pbkdf2|superusers" /boot/grub/grub.cfg' \
            0 \
            "Physical access without a GRUB password bypasses all OS-level controls"
    fi
}
