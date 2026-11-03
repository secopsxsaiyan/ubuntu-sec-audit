# shellcheck shell=bash
# check_disk_encryption — standard check (sourced by ubuntu-sec-audit.sh)

check_disk_encryption() {
    print_status "INFO" "Checking disk encryption at rest (NIST SC-28)..."

    # Detect LUKS-encrypted block devices
    local _luks_devs=() _dev
    while IFS= read -r _dev; do
        [[ -n "$_dev" ]] && _luks_devs+=("$_dev")
    done < <(lsblk -o NAME,TYPE -rn 2>/dev/null | awk '$2=="crypt"{print $1}' || true)

    # Also count LUKS headers seen by blkid (one number, never "0\n0")
    local _luks_blkid
    _luks_blkid=$(blkid 2>/dev/null | grep -c 'TYPE="crypto_LUKS"' || true)
    _luks_blkid="${_luks_blkid:-0}"

    # Root is encrypted if any device under it is a crypt mapping. lsblk -s
    # walks the stack downwards, so LVM on LUKS (Ubuntu's encrypted install)
    # is recognised: lvm -> crypt -> part -> disk.
    local _root_encrypted=0 _root_dev
    _root_dev=$(findmnt -n -o SOURCE / 2>/dev/null || true)
    if [[ -n "$_root_dev" ]]; then
        if lsblk -s -n -o TYPE "$_root_dev" 2>/dev/null | grep -qx 'crypt'; then
            _root_encrypted=1
        fi
        if blkid "$_root_dev" 2>/dev/null | grep -q 'crypto_LUKS'; then
            _root_encrypted=1
        fi
    fi

    if [[ ${#_luks_devs[@]} -gt 0 || "$_luks_blkid" -gt 0 ]]; then
        local _enc_list
        _enc_list=$(blkid 2>/dev/null | grep 'crypto_LUKS' | awk -F: '{print $1}' || true)
        if [[ "$_root_encrypted" -eq 1 ]]; then
            print_status "OK" "Root filesystem is on an encrypted (LUKS) volume"
            append_report "## Disk Encryption (SC-28)\n- 🟢 Root filesystem encrypted with LUKS"
        else
            print_status "WARN" "LUKS volumes present but root filesystem may not be encrypted"
            append_report "## Disk Encryption (SC-28)\n- 🟡 LUKS volumes present but root filesystem encryption not confirmed"
            append_report "\`\`\`\n${_enc_list}\n\`\`\`"
            report_issue 5 \
                "Root filesystem encryption not confirmed" \
                "LUKS volumes exist but root (/) may not be encrypted - data at rest may be unprotected" \
                "# MANUAL: encryption is set up at install time or by hand per volume; nothing here can be run safely as-is.
# Verify which volumes are encrypted:
sudo /sbin/blkid | grep crypto_LUKS
lsblk -o NAME,FSTYPE,MOUNTPOINT
# Full-disk encryption must be configured at install time.
# For existing systems, encrypt non-root volumes (e.g. /home, /var):
# sudo /usr/sbin/cryptsetup luksFormat /dev/sdXN
# Add to /etc/crypttab and /etc/fstab, then update-initramfs -u
# Verify root is encrypted:
findmnt -n -o SOURCE / | xargs sudo /sbin/blkid" \
                0 \
                "Full-disk encryption protects data if physical media is lost or stolen (NIST SC-28)"
        fi
    else
        print_status "WARN" "No LUKS disk encryption detected - data at rest is unprotected"
        append_report "## Disk Encryption (SC-28)\n- 🔴 No LUKS encryption detected on any block device"
        report_issue 8 \
            "No disk encryption detected (NIST SC-28)" \
            "No LUKS-encrypted volumes found - all data at rest is unprotected if media is stolen" \
            "# MANUAL: encryption is set up at install time or by hand per volume; nothing here can be run safely as-is.
# Disk encryption must be set up at install time for the root filesystem.
# For data partitions on a running system:
# 1. Backup data first
# 2. Encrypt the partition:
#    sudo /usr/sbin/cryptsetup luksFormat /dev/sdXN
#    sudo /usr/sbin/cryptsetup open /dev/sdXN <name>
#    sudo /sbin/mkfs.ext4 /dev/mapper/<name>
# 3. Add entry to /etc/crypttab:
#    echo '<name> /dev/sdXN none luks' | sudo /usr/bin/tee -a /etc/crypttab
# 4. Add entry to /etc/fstab and update-initramfs:
#    sudo /usr/bin/update-initramfs -u
# Verify:
sudo /sbin/blkid | grep crypto_LUKS
lsblk -o NAME,FSTYPE,MOUNTPOINT" \
            0 \
            "NIST SC-28 requires protection of information at rest. Full-disk encryption must be configured at install time."
    fi
}
