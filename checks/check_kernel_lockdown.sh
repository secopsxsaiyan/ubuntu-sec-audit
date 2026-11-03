# shellcheck shell=bash
# check_kernel_lockdown — standard check (sourced by ubuntu-sec-audit.sh)

check_kernel_lockdown() {
    print_status "INFO" "Checking kernel lockdown mode..."
    if [[ ! -f /sys/kernel/security/lockdown ]]; then
        print_status "INFO" "Kernel lockdown not available on this kernel (requires 5.4+ with CONFIG_SECURITY_LOCKDOWN_LSM)"
        append_report "## Kernel Lockdown\n- ⚪ Lockdown LSM not available on this kernel"
        return
    fi

    local lockdown_state
    lockdown_state=$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oP '\[\K[^\]]+' || echo "none")

    if [[ "$lockdown_state" == "integrity" || "$lockdown_state" == "confidentiality" ]]; then
        print_status "OK" "Kernel lockdown enabled: ${lockdown_state}"
        append_report "## Kernel Lockdown\n- 🟢 Kernel lockdown active: ${lockdown_state}"
    else
        print_status "WARN" "Kernel lockdown is off (current: ${lockdown_state})"
        append_report "## Kernel Lockdown\n- 🔴 Kernel lockdown not enabled (current: ${lockdown_state})"
        report_issue 7 \
            "Kernel lockdown mode not enabled" \
            "Kernel lockdown=none: unsigned modules, /dev/mem access, and kexec are unrestricted" \
            "# Add lockdown=integrity to kernel boot parameters:
sudo /bin/sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lockdown=integrity\"/' /etc/default/grub
sudo /usr/sbin/update-grub
# Verify after reboot:
cat /sys/kernel/security/lockdown" \
            0 \
            "Lockdown 'integrity' blocks: loading unsigned modules, /dev/mem writes, kexec with unsigned images. Reboot required after GRUB change."
    fi
}
