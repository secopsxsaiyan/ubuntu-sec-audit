# shellcheck shell=bash
# check_deep_world_writable_files / _dirs / check_deep_unowned — deep checks

_WW_ROOTS=(/etc /var /home)

check_deep_world_writable_files() {
    print_status "INFO" "Scanning world-writable files..."
    local -a world_write=() roots=()
    local r f
    for r in "${_WW_ROOTS[@]}"; do roots+=("${AUDIT_ROOT}${r}"); done
    while IFS= read -r f; do
        world_write+=("$f")
    done < <(find "${roots[@]}" -xdev -perm -002 -type f 2>/dev/null || true)
    if [[ ${#world_write[@]} -eq 0 ]]; then
        print_status "OK" "No world-writable files in /etc, /var or /home"
        append_report "## Deep: World-Writable Files\n- 🟢 None found"
        return 0
    fi
    local fix="# Remove the world-write bit from each file - verify ownership first:"$'\n'
    for f in "${world_write[@]}"; do
        fix+="sudo /bin/chmod o-w $(printf '%q' "$f")"$'\n'
    done
    fix+="sudo /usr/bin/find /etc /var /home -xdev -perm -002 -type f 2>/dev/null"
    report_issue 16 \
        "World-writable files in sensitive dirs" \
        "Anyone on the system can modify these files" \
        "$fix" \
        1 \
        "World-writable files:\n$(printf ' - %s\n' "${world_write[@]}")"
}

check_deep_world_writable_dirs() {
    print_status "INFO" "Scanning world-writable directories..."
    # Directories with the sticky bit (like /tmp, /var/tmp, /var/crash) are
    # meant to be shared: users can only delete their own files there.
    local -a dirs=() roots=()
    local r d
    for r in "${_WW_ROOTS[@]}"; do roots+=("${AUDIT_ROOT}${r}"); done
    while IFS= read -r d; do
        dirs+=("$d")
    done < <(find "${roots[@]}" -xdev -type d -perm -002 ! -perm -1000 2>/dev/null || true)
    if [[ ${#dirs[@]} -eq 0 ]]; then
        print_status "OK" "No world-writable directories without the sticky bit"
        append_report "## Deep: World-Writable Directories\n- 🟢 None without the sticky bit"
        return 0
    fi
    local fix="# Remove the world-write bit (or, for a shared directory, add the sticky bit: chmod +t):"$'\n'
    for d in "${dirs[@]}"; do
        fix+="sudo /bin/chmod o-w $(printf '%q' "$d")"$'\n'
    done
    fix+="sudo /usr/bin/find /etc /var /home -xdev -type d -perm -002 ! -perm -1000 2>/dev/null"
    report_issue 12 \
        "World-writable directories in sensitive paths" \
        "Anyone can create or delete files in these directories (no sticky bit)" \
        "$fix" \
        1 \
        "World-writable directories:\n$(printf ' - %s\n' "${dirs[@]}")"
}

check_deep_unowned() {
    print_status "INFO" "Scanning for unowned files and directories (full filesystem - may take several minutes)..."
    local -a unowned=()
    local f
    while IFS= read -r f; do
        unowned+=("$f")
    done < <(find "${AUDIT_ROOT:-/}" -xdev \( -nouser -o -nogroup \) 2>/dev/null || true)
    if [[ ${#unowned[@]} -eq 0 ]]; then
        print_status "OK" "No unowned files or directories found"
        append_report "## Deep: Unowned Files & Directories\n- 🟢 All files and directories have valid owners and groups"
        return 0
    fi
    print_status "WARN" "Found ${#unowned[@]} unowned file(s)/dir(s) (no valid UID/GID)"
    append_report "## Deep: Unowned Files & Directories\n- 🔴 ${#unowned[@]} path(s) with no valid owner or group"
    # Manual: the right owner depends on what the files are (a deleted user,
    # an unpacked archive, a container volume, ...).
    report_issue 8 \
        "Files or directories with no valid owner/group" \
        "${#unowned[@]} path(s) have a UID/GID mapping to no existing user/group - can be hijacked if UID/GID reused" \
        "# Review the list in the note, then give each path its proper owner, e.g.
#   sudo chown <user>:<group> <path>
# To hand all of them to root after review (handles spaces in names):
#   sudo find / -xdev -nouser -print0 | sudo xargs -0 -r chown root
#   sudo find / -xdev -nogroup -print0 | sudo xargs -0 -r chgrp root" \
        1 \
        "Unowned paths (first 50):\n$(printf ' - %s\n' "${unowned[@]:0:50}")"
}
