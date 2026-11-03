# shellcheck shell=bash
# check_secure_boot — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: Secure Boot (Missing #17)
check_secure_boot() {
    print_status "INFO" "Checking Secure Boot status..."
    # Non-UEFI systems: skip
    if [[ ! -d /sys/firmware/efi ]]; then
        print_status "INFO" "Non-UEFI system - Secure Boot not applicable"
        append_report "## Secure Boot\n- ℹ️ Non-UEFI system - not applicable"
        return
    fi

    local sb_enabled=0
    if command -v mokutil >/dev/null 2>&1; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || true)
        echo "$sb_state" | grep -q "SecureBoot enabled" && sb_enabled=1
    fi
    # Fallback: read EFI variable directly
    if [[ $sb_enabled -eq 0 ]]; then
        local sb_efi="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        if [[ -f "$sb_efi" ]]; then
            local sb_byte
            sb_byte=$(od -An -t u1 "$sb_efi" 2>/dev/null | awk '{print $NF}' || true)
            [[ "$sb_byte" == "1" ]] && sb_enabled=1
        fi
    fi

    if [[ $sb_enabled -eq 1 ]]; then
        print_status "OK" "Secure Boot is enabled"
        append_report "## Secure Boot\n- 🟢 Secure Boot enabled"
    else
        print_status "WARN" "Secure Boot is disabled or not detectable"
        append_report "## Secure Boot\n- 🔴 Secure Boot disabled"
        report_issue 5 \
            "Secure Boot disabled" \
            "Secure Boot is not enabled - unsigned kernel modules and bootloaders can load" \
            "# Enable Secure Boot in UEFI/BIOS firmware settings
# Verify current state:
mokutil --sb-state
# Ensure Ubuntu's signed bootloader is in place:
sudo /usr/bin/apt-get install -y shim-signed grub-efi-amd64-signed linux-signed-generic
sudo /usr/sbin/update-grub" \
            0 \
            "Secure Boot requires UEFI firmware support and a signed kernel/bootloader"
    fi
}
