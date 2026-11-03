# shellcheck shell=bash
# check_secure_boot — standard check (sourced by ubuntu-sec-audit.sh)

check_secure_boot() {
    print_status "INFO" "Checking Secure Boot status..."
    if [[ ! -d "${AUDIT_ROOT}/sys/firmware/efi" ]]; then
        append_report "## Secure Boot\n- ⚪ Non-UEFI system - not applicable"
        _mark_not_applicable "not booted with UEFI firmware (no /sys/firmware/efi)"
        return 0
    fi

    local sb_enabled=0
    if command -v mokutil >/dev/null 2>&1; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || true)
        grep -q "SecureBoot enabled" <<< "$sb_state" && sb_enabled=1
    fi
    # Fallback: read the EFI variable directly (4 attribute bytes, then the value)
    if [[ $sb_enabled -eq 0 ]]; then
        local sb_efi="${AUDIT_ROOT}/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        if [[ -f "$sb_efi" ]]; then
            local sb_byte
            sb_byte=$(od -An -t u1 "$sb_efi" 2>/dev/null | awk '{print $NF}' || true)
            [[ "$sb_byte" == "1" ]] && sb_enabled=1
        fi
    fi

    if [[ $sb_enabled -eq 1 ]]; then
        print_status "OK" "Secure Boot is enabled"
        append_report "## Secure Boot\n- 🟢 Secure Boot enabled"
        return 0
    fi

    print_status "WARN" "Secure Boot is disabled or not detectable"
    append_report "## Secure Boot\n- 🔴 Secure Boot disabled"
    # Manual: Secure Boot is a firmware setting; nothing the OS runs can
    # turn it on, and the signed boot packages differ per architecture.
    report_issue 5 \
        "Secure Boot disabled" \
        "Secure Boot is not enabled - unsigned kernel modules and bootloaders can load" \
        "# MANUAL: Secure Boot is switched on in the UEFI firmware setup, not from Ubuntu.
# 1. Check that Ubuntu's signed boot chain is installed (the default on UEFI
#    installs): shim-signed, grub-efi-<arch>-signed for this architecture
#    (amd64 or arm64), and a signed kernel (Ubuntu's generic kernels are):
dpkg -l shim-signed 'grub-efi-*-signed' | grep '^ii'
# 2. Out-of-tree (DKMS) modules, e.g. some GPU or VirtualBox drivers, stop
#    loading unless they are signed with an enrolled machine owner key:
#      sudo update-secureboot-policy --enroll-key
# 3. Reboot into the firmware setup, enable Secure Boot, boot Ubuntu again:
#      sudo systemctl reboot --firmware-setup
# 4. Verify:
mokutil --sb-state" \
        0 \
        "Secure Boot requires UEFI firmware support and a signed kernel/bootloader"
    return 0
}
