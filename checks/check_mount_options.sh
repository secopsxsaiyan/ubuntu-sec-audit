# shellcheck shell=bash
# check_mount_options — standard check (sourced by ubuntu-sec-audit.sh)

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
        mount_fix+="grep -qE '^tmpfs[[:space:]]+/tmp[[:space:]]' /etc/fstab || echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0' | sudo /usr/bin/tee -a /etc/fstab"$'\n'
        mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev /tmp"$'\n'
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
            # Persistent fstab entry, added once
            mount_fix+="grep -qE '[[:space:]]${mpoint}[[:space:]]' /etc/fstab || \\"$'\n'
            mount_fix+="  printf '${_fstab_entry}\\n' | sudo /usr/bin/tee -a /etc/fstab"$'\n'
        fi
    done

    if [[ ${#mount_issues[@]} -eq 0 ]]; then
        print_status "OK" "/tmp, /dev/shm, /var/tmp mount options and sticky bit are secure"
        append_report "## Mount Options\n- 🟢 /tmp, /dev/shm, /var/tmp: noexec/nosuid/nodev set, /tmp sticky bit present"
    else
        local mnt_issue_list
        mnt_issue_list=$(printf ' - %s\n' "${mount_issues[@]}")
        mount_fix+="# Verify all mounts:
/bin/mount | /bin/grep -E '/tmp|/dev/shm|/var/tmp'"
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
