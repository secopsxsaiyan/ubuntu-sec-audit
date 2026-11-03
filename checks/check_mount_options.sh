# shellcheck shell=bash
# check_mount_options — standard check (sourced by ubuntu-sec-audit.sh)

# _fstab_options_fix MOUNTPOINT DEFAULT_ENTRY — remediation lines that make
# the fstab entry for MOUNTPOINT carry nodev,nosuid,noexec: an active entry
# (any device: tmpfs, its own partition, a bind mount) gets the missing
# options in its 4th field, since a second entry for the same mount point
# would be ignored; without one, DEFAULT_ENTRY is added. Commented-out lines
# do not count. Idempotent.
_fstab_options_fix() {
    local m="$1" entry="$2" re
    re="${m//\//\\/}"
    printf '%s\n' \
        "if /bin/grep -qE \"^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+${m}[[:space:]]\" /etc/fstab; then" \
        "    for _opt in nodev nosuid noexec; do" \
        "        sudo /bin/sed -i -E \"/^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+${re}[[:space:]]/{/^[[:space:]]*([^[:space:]]+[[:space:]]+){3}([^[:space:]]*,)?\${_opt}(,|[[:space:]]|\$)/!s/^([[:space:]]*([^[:space:]]+[[:space:]]+){3}[^[:space:]]+)/\\1,\${_opt}/;}\" /etc/fstab" \
        "    done" \
        "else" \
        "    echo \"${entry}\" | sudo /usr/bin/tee -a /etc/fstab > /dev/null" \
        "fi"
}

check_mount_options() {
    print_status "INFO" "Checking /tmp, /dev/shm, /var/tmp mount options and sticky bit..."
    local -a mount_issues=()
    local mount_fix=""

    # /tmp: check mount options
    local tmp_mount_line
    tmp_mount_line=$(mount | grep -E ' /tmp ' || true)
    local tmp_flags_missing=()
    if [[ -z "$tmp_mount_line" ]]; then
        tmp_flags_missing+=("noexec" "nosuid" "nodev")
    else
        grep -q 'noexec' <<< "$tmp_mount_line" || tmp_flags_missing+=("noexec")
        grep -q 'nosuid' <<< "$tmp_mount_line" || tmp_flags_missing+=("nosuid")
        grep -q 'nodev'  <<< "$tmp_mount_line" || tmp_flags_missing+=("nodev")
    fi
    if [[ ${#tmp_flags_missing[@]} -gt 0 ]]; then
        mount_issues+=("/tmp missing: ${tmp_flags_missing[*]}")
        # An active fstab entry for /tmp (any device: tmpfs, its own
        # partition, ...) gets the missing options in its 4th field; a second
        # /tmp entry would be ignored. Without one, a tmpfs entry is added.
        # Remount only a mounted /tmp: on stock Ubuntu /tmp is a plain
        # directory, and mounting over it now would hide files in use.
        mount_fix+="$(_fstab_options_fix /tmp "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0")"$'\n'
        mount_fix+='if mountpoint -q /tmp; then
    sudo /bin/mount -o remount,noexec,nosuid,nodev /tmp
else
    echo "/tmp is not mounted separately yet: its /etc/fstab entry takes effect after a reboot"
fi
'
    fi

    # /tmp: sticky bit check
    local tmp_perms
    tmp_perms=$(stat -c '%a' "${AUDIT_ROOT}/tmp" 2>/dev/null || true)
    if [[ -n "$tmp_perms" ]] && (( (8#$tmp_perms & 8#1000) == 0 )); then
        mount_issues+=("/tmp is missing the sticky bit (perms: ${tmp_perms}) - users can delete each other's files")
        mount_fix+="sudo /bin/chmod +t /tmp"$'\n'
        mount_fix+="# Verify: stat -c '%a' /tmp   # should end in 1 (e.g. 1777)"$'\n'
    fi

    # /dev/shm and /var/tmp
    for mpoint in /dev/shm /var/tmp; do
        [[ ! -d "${AUDIT_ROOT}${mpoint}" ]] && continue
        local m_line m_missing=()
        m_line=$(mount | grep -E " ${mpoint} " || true)
        if [[ -z "$m_line" ]]; then
            m_missing+=("noexec" "nosuid" "nodev")
        else
            grep -q 'noexec' <<< "$m_line" || m_missing+=("noexec")
            grep -q 'nosuid' <<< "$m_line" || m_missing+=("nosuid")
            grep -q 'nodev'  <<< "$m_line" || m_missing+=("nodev")
        fi
        if [[ ${#m_missing[@]} -gt 0 ]]; then
            mount_issues+=("${mpoint} missing: ${m_missing[*]} (attackers abuse ${mpoint} for staging)")
            if [[ "$mpoint" == "/var/tmp" ]]; then
                # /var/tmp must survive reboots (FHS), so no tmpfs: bind-mount
                # it onto itself with the hardening options.
                local _fstab_entry="/var/tmp /var/tmp none bind,noexec,nosuid,nodev 0 0"
                mount_fix+="if ! mountpoint -q /var/tmp; then sudo /bin/mount --bind /var/tmp /var/tmp; fi"$'\n'
                mount_fix+="sudo /bin/mount -o remount,bind,noexec,nosuid,nodev /var/tmp"$'\n'
            else
                local _fstab_entry="tmpfs ${mpoint} tmpfs defaults,noexec,nosuid,nodev 0 0"
                mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev ${mpoint} 2>/dev/null || true"$'\n'
            fi
            # Persistent: options added to an existing entry, or one entry added
            mount_fix+="$(_fstab_options_fix "$mpoint" "$_fstab_entry")"$'\n'
        fi
    done

    if [[ ${#mount_issues[@]} -eq 0 ]]; then
        print_status "OK" "/tmp, /dev/shm, /var/tmp mount options and sticky bit are secure"
        append_report "## Mount Options\n- 🟢 /tmp, /dev/shm, /var/tmp: noexec/nosuid/nodev set, /tmp sticky bit present"
    else
        local mnt_issue_list
        mnt_issue_list=$(printf ' - %s\n' "${mount_issues[@]}")
        mount_fix+="# Verify all mounts:
/bin/mount | /bin/grep -E ' (/tmp|/dev/shm|/var/tmp) ' || true"
        print_status "WARN" "Mount option issues: ${#mount_issues[@]} found"
        append_report "## Mount Options\n- 🔴 ${#mount_issues[@]} mount issue(s) found"
        report_issue 10 \
            "Insecure mount options on /tmp, /dev/shm, or /var/tmp" \
            "${#mount_issues[@]} mount issue(s) - missing noexec/nosuid/nodev or sticky bit" \
            "$mount_fix" \
            0 \
            "Issues:\n${mnt_issue_list}"
    fi
}
