# shellcheck shell=bash
# check_deep_suid / check_deep_sgid — deep checks (sourced by ubuntu-sec-audit.sh)
#
# Each check can report two findings:
#  - Shell-escape binaries (shells, interpreters, editors, find, ...) with the
#    bit set: they hand a shell, or any file, to every local user who runs
#    them, and "chmod u+s /usr/bin/find" is a classic persistence trick. No
#    Ubuntu package ships them that way, so they are critical even when a
#    package owns the file.
#  - Any other SUID/SGID file that no package installed. Package-owned ones
#    (snap-confine, dbus-daemon-launch-helper, plocate, ...) are expected:
#    package ownership is the allow-list.
# Both fixes are a manual review: removing a bit can break software, and a
# planted bit is evidence to investigate before it is cleaned up.

# Basenames (shell globs) of programs that give a shell or arbitrary file
# access when run with raised privileges (GTFOBins-style). None of them is
# ever legitimately SUID/SGID.
_SHELL_ESCAPE_BINS=(
    # shells
    sh bash rbash dash ash zsh 'zsh[0-9]*' ksh 'ksh[0-9]*' mksh csh tcsh fish busybox
    # interpreters
    'python*' 'perl*' 'ruby*' 'php*' 'lua*' luajit node nodejs 'tclsh*' wish expect
    irb jrunscript jjs awk gawk mawk nawk original-awk
    # editors and pagers
    vi 'vim*' rvim view ex ed nano pico 'emacs*' joe less more most pg man
    # file tools
    cp mv dd tee cat chmod chown chgrp install sed tar zip unzip cpio rsync
    # command runners and debuggers
    find env nice timeout xargs time stdbuf taskset ionice setarch flock script
    chroot nohup run-parts start-stop-daemon make watch strace ltrace gdb
    # services, containers, network
    systemctl docker nc 'nc.*' ncat netcat socat wget curl openssl nmap ip
)

# Container/VM storage that holds guest filesystems (not scanned).
_CONTAINER_STORAGE=(
    /var/lib/docker /var/lib/containerd /var/lib/containers /var/snap/docker
    /var/lib/lxc /var/lib/lxd /var/snap/lxd /var/lib/incus /var/lib/machines
    /var/lib/rancher /var/snap/microk8s /var/lib/kubelet
    '/home/*/.local/share/containers' /root/.local/share/containers
)

# Local disk filesystems scanned for SUID/SGID files (besides /).
_SPECIAL_BIT_FSTYPES="ext2,ext3,ext4,xfs,btrfs,zfs,f2fs,jfs"

# _is_shell_escape_bin PATH — PATH's name is a shell-escape binary.
_is_shell_escape_bin() {
    local name="${1##*/}" p
    for p in "${_SHELL_ESCAPE_BINS[@]}"; do
        # shellcheck disable=SC2053  # p is a glob pattern
        [[ "$name" == $p ]] && return 0
    done
    return 1
}

# _special_bit_roots — where to look, one per line: AUDIT_ROOT when set
# (tests), otherwise / and every local disk filesystem. find -xdev stays on
# one filesystem, and /home, /var or /opt are often separate ones.
_special_bit_roots() {
    if [[ -n "${AUDIT_ROOT:-}" ]]; then
        printf '%s\n' "$AUDIT_ROOT"
        return 0
    fi
    printf '/\n'
    command -v findmnt >/dev/null 2>&1 || return 0
    local t
    local -A seen=([/]=1)
    # -r hex-escapes unsafe characters (a space is \x20); %b decodes them.
    while IFS= read -r t; do
        printf -v t '%b' "$t"
        [[ "$t" == /* && "$t" != *$'\n'* ]] || continue
        [[ -z "${seen[$t]:-}" ]] || continue
        seen["$t"]=1
        printf '%s\n' "$t"
    done < <(findmnt -rn -o TARGET -t "$_SPECIAL_BIT_FSTYPES" 2>/dev/null || true)
}

# _file_list FILE... — " - FILE" lines for a note; a name with control
# characters (a newline could fake a second entry) is shown quoted.
_file_list() {
    local f
    for f in "$@"; do
        if [[ "$f" == *[[:cntrl:]]* ]]; then printf ' - %q\n' "$f"; else printf ' - %s\n' "$f"; fi
    done
}

# _chmod_comments CHMOD FILE... — commented "sudo chmod" lines, one per FILE.
_chmod_comments() {
    local mode="$1" f
    shift
    for f in "$@"; do printf '#   sudo chmod %s %q\n' "$mode" "$f"; done
}

# _report_special_bits LABEL CHMOD POINTS FILE... — one finding for all FILEs.
_report_special_bits() {
    local label="$1" mode="$2" points="$3" fix
    shift 3
    fix="# Review each file before changing it: what installed it, and does"$'\n'
    fix+="# anything need it to run with raised privileges?"$'\n'
    fix+="#   dpkg -S <file>; ls -l <file>; strings <file> | head"$'\n'
    fix+="# Then remove the bit from the ones that should not have it:"$'\n'
    fix+=$(_chmod_comments "$mode" "$@")
    report_issue "$points" \
        "Non-standard ${label} binaries found" \
        "${label} files not installed by any package - privilege-escalation vectors if exploited" \
        "$fix" \
        1 \
        "${label} files:\n$(_file_list "$@")"
}

# _report_shell_escapes LABEL CHMOD POINTS FILE... — one critical finding for
# shell-escape binaries with the bit set.
_report_shell_escapes() {
    local label="$1" mode="$2" points="$3" fix gain
    shift 3
    if [[ "$label" == "SUID" ]]; then gain="the file owner's (usually root's)"; else gain="the file group's"; fi
    fix="# MANUAL: no Ubuntu package sets this bit on these programs - treat it as a"$'\n'
    fix+="# possible compromise and investigate before removing it:"$'\n'
    fix+="#   stat <file>                      # when was the mode changed (Change:)?"$'\n'
    fix+="#   dpkg -S <file>; dpkg -V <pkg>     # the mode the package expects"$'\n'
    fix+="#   dpkg-statoverride --list <file>  # an override re-applies the bit on upgrade;"$'\n'
    fix+="#     sudo dpkg-statoverride --remove <file>   # remove it first"$'\n'
    fix+="# Then remove the bit:"$'\n'
    fix+=$(_chmod_comments "$mode" "$@")
    report_issue "$points" \
        "${label} bit on shell-escape binaries" \
        "${label} is set on programs that give a shell or arbitrary file access to whoever runs them - any local user gets ${gain} privileges. A classic persistence backdoor." \
        "$fix" \
        1 \
        "${label} shell-escape binaries:\n$(_file_list "$@")"
}

# _check_special_bits LABEL PERM CHMOD POINTS ESCAPE_POINTS — scan for files
# with PERM (-4000 or -2000) and report them as described at the top.
_check_special_bits() {
    local label="$1" perm="$2" mode="$3" points="$4" esc_points="$5" f
    local -a roots=() found=() escapes=() plain=() others=()
    mapfile -t roots < <(_special_bit_roots)
    # Container and VM image storage holds whole guest filesystems (their
    # su, passwd, ...): no host package owns those files, and only root
    # can reach them. Pruned so they are not reported as host binaries.
    local -a prune=() p
    for p in "${_CONTAINER_STORAGE[@]}"; do prune+=(-path "${AUDIT_ROOT}${p}" -o); done
    unset 'prune[-1]'
    while IFS= read -r -d '' f; do
        found+=("${f#"$AUDIT_ROOT"}")
    done < <(find "${roots[@]}" -xdev \( "${prune[@]}" \) -prune -o -perm "$perm" -type f -print0 2>/dev/null || true)

    for f in "${found[@]+"${found[@]}"}"; do
        if [[ "$f" == *[[:cntrl:]]* ]]; then
            # No package installs such a name; it would also split the
            # one-path-per-line package lookup and hide the real file.
            plain+=("$f")
        elif _is_shell_escape_bin "$f"; then
            # man-db's optional "setuid man" install makes man SUID to the
            # man user (not root): a supported setting, not a backdoor.
            if [[ "$label" == "SUID" && "${f##*/}" == "man" \
                  && "$(stat -c '%U' -- "${AUDIT_ROOT}${f}" 2>/dev/null || true)" == "man" ]]; then
                continue
            fi
            escapes+=("$f")
        else
            others+=("$f")
        fi
    done
    while IFS= read -r f; do
        [[ -n "$f" ]] && plain+=("$f")
    done < <(_dpkg_unowned "${others[@]+"${others[@]}"}")

    local lc="${label,,}"
    if [[ ${#escapes[@]} -gt 0 ]]; then
        print_status "WARN" "${label} shell-escape binaries: ${#escapes[@]}"
        _report_shell_escapes "$label" "$mode" "$esc_points" "${escapes[@]}"
    fi
    if [[ ${#plain[@]} -gt 0 ]]; then
        print_status "WARN" "Non-standard ${label} binaries: ${#plain[@]}"
        _report_special_bits "$label" "$mode" "$points" "${plain[@]}"
    fi
    if [[ ${#escapes[@]} -eq 0 && ${#plain[@]} -eq 0 ]]; then
        print_status "OK" "No unexpected ${label} binaries found"
        append_report "## Deep: ${label} Binaries\n- 🟢 No non-package ${lc} binaries and no ${lc} shell-escape binaries detected"
    fi
}

check_deep_suid() {
    print_status "INFO" "Scanning SUID binaries (all local filesystems - may take a while on large systems)..."
    _check_special_bits SUID -4000 u-s 14 25
}

check_deep_sgid() {
    print_status "INFO" "Scanning SGID binaries (all local filesystems)..."
    _check_special_bits SGID -2000 g-s 10 20
}
