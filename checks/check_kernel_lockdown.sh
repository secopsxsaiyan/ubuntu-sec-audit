# shellcheck shell=bash
# check_kernel_lockdown — standard check (sourced by ubuntu-sec-audit.sh)

check_kernel_lockdown() {
    print_status "INFO" "Checking kernel lockdown mode..."
    local lockdown_file="${AUDIT_ROOT}/sys/kernel/security/lockdown"
    if [[ ! -f "$lockdown_file" ]]; then
        print_status "INFO" "Kernel lockdown not available on this kernel (requires 5.4+ with CONFIG_SECURITY_LOCKDOWN_LSM)"
        append_report "## Kernel Lockdown\n- ⚪ Lockdown LSM not available on this kernel"
        return
    fi

    local lockdown_state
    lockdown_state=$(grep -oP '\[\K[^\]]+' "$lockdown_file" 2>/dev/null || true)
    lockdown_state="${lockdown_state:-none}"

    if [[ "$lockdown_state" == "integrity" || "$lockdown_state" == "confidentiality" ]]; then
        print_status "OK" "Kernel lockdown enabled: ${lockdown_state}"
        append_report "## Kernel Lockdown\n- 🟢 Kernel lockdown active: ${lockdown_state}"
    else
        print_status "WARN" "Kernel lockdown is off (current: ${lockdown_state})"
        append_report "## Kernel Lockdown\n- 🔴 Kernel lockdown not enabled (current: ${lockdown_state})"
        # Manual: lockdown refuses unsigned kernel modules (e.g. some DKMS
        # drivers), which can leave a host without storage or network.
        report_issue 7 \
            "Kernel lockdown mode not enabled" \
            "Kernel lockdown=none: unsigned modules, /dev/mem access, and kexec are unrestricted" \
            "# 1. Check that every loaded module is signed (no output = all signed):
#      for m in \$(lsmod | awk 'NR>1{print \$1}'); do modinfo -F signer \"\$m\" >/dev/null 2>&1 || echo \"\$m\"; done
# 2. Add lockdown=integrity to GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub
#    (only once), then: sudo update-grub
# 3. Reboot with console access available, then verify:
#      cat /sys/kernel/security/lockdown" \
            0 \
            "Lockdown 'integrity' blocks: loading unsigned modules, /dev/mem writes, kexec with unsigned images. Reboot required after GRUB change."
    fi
}
