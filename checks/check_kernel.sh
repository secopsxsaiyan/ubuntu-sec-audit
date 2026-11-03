# shellcheck shell=bash
# check_kernel — standard check (sourced by ubuntu-sec-audit.sh)

check_kernel() {
    print_status "INFO" "Checking kernel/sysctl hardening (extended)..."

    # Required value per key: "N" means exactly N; ">=N" means N or a stricter
    # (higher) value. Stricter settings such as ptrace_scope=3 or Ubuntu's
    # default unprivileged_bpf_disabled=2 pass and are never lowered.
    declare -A SYSCTL_CHECKS=(
        ["kernel.randomize_va_space"]="2"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="2"
        ["kernel.yama.ptrace_scope"]=">=1"
        ["fs.protected_fifos"]=">=1"
        ["fs.protected_regular"]=">=1"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.tcp_syncookies"]=">=1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv6.conf.all.forwarding"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.default.accept_source_route"]="0"
        ["kernel.unprivileged_bpf_disabled"]=">=1"
        ["net.core.bpf_jit_harden"]="2"
        ["kernel.kexec_load_disabled"]="1"
        ["kernel.perf_event_paranoid"]=">=3"
        ["kernel.sysrq"]="0"
        ["net.ipv4.tcp_timestamps"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_rfc1337"]="1"
    )

    # Docker requires ip_forward; skip those keys to avoid false positives and broken fixes
    if command -v docker >/dev/null 2>&1 || dpkg -l docker-ce 2>/dev/null | grep -q '^ii'; then
        unset 'SYSCTL_CHECKS[net.ipv4.ip_forward]'
        unset 'SYSCTL_CHECKS[net.ipv6.conf.all.forwarding]'
        print_status "INFO" "Docker detected - skipping net.ipv4.ip_forward / net.ipv6.conf.all.forwarding checks"
    fi

    local -a sysctl_failures=()
    local -a keys=()
    local -A target=()   # value written by the fix: current if compliant, else required
    mapfile -t keys < <(printf '%s\n' "${!SYSCTL_CHECKS[@]}" | sort)

    local key spec want actual ok
    for key in "${keys[@]}"; do
        spec="${SYSCTL_CHECKS[$key]}"
        want="${spec#>=}"
        actual=$(sysctl -n "$key" 2>/dev/null || true)
        ok=0
        if [[ "$spec" == ">="* ]]; then
            [[ "$actual" =~ ^[0-9]+$ ]] && (( actual >= want )) && ok=1
        else
            [[ "$actual" == "$want" ]] && ok=1
        fi
        if [[ $ok -eq 1 ]]; then
            target["$key"]="$actual"
        else
            target["$key"]="$want"
            sysctl_failures+=("${key} = ${actual:-unset} (expected ${spec/>=/>= })")
        fi
    done

    if [[ ${#sysctl_failures[@]} -eq 0 ]]; then
        print_status "OK" "All kernel sysctl hardening checks passed"
        append_report "## Kernel Hardening\n- 🟢 ASLR, hardlinks, symlinks, dmesg, kptr, ptrace_scope, redirects, source_route, log_martians, syncookies, rp_filter all hardened"
    else
        print_status "WARN" "Kernel sysctl issues: ${#sysctl_failures[@]} found"
        local fail_list
        fail_list=$(printf ' - %s\n' "${sysctl_failures[@]}")
        append_report "## Kernel Hardening\n- 🔴 ${#sysctl_failures[@]} sysctl(s) not hardened"

        # Write every key (not just failing ones) so re-runs never drop
        # earlier settings, using the current value where it is already
        # compliant so stricter settings are kept.
        local sysctl_all_lines="" _k
        for _k in "${keys[@]}"; do
            sysctl_all_lines+="${_k} = ${target[$_k]}"$'\n'
        done

        local sysctl_fix_content
        sysctl_fix_content="sudo /bin/mkdir -p /etc/sysctl.d"$'\n'
        sysctl_fix_content+="sudo /usr/bin/tee /etc/sysctl.d/99-hardening.conf > /dev/null << 'SYSCTLEOF'"$'\n'
        sysctl_fix_content+="${sysctl_all_lines}"
        sysctl_fix_content+="SYSCTLEOF"$'\n'
        sysctl_fix_content+="sudo /sbin/sysctl --system 2>&1 | grep -v 'No such file' || true"$'\n'
        sysctl_fix_content+="# Verify current values:"$'\n'
        sysctl_fix_content+="$(printf 'sudo /sbin/sysctl %s 2>/dev/null || true\n' "${keys[@]}")"

        report_issue 9 \
            "Kernel sysctl hardening incomplete" \
            "${#sysctl_failures[@]} sysctl parameter(s) are not set to secure values" \
            "$sysctl_fix_content" \
            0 \
            "Non-compliant values:\n${fail_list}"
    fi

    # Kernel module blacklist check (CIS-aligned)
    local -a required_blacklisted=("usb-storage" "cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "dccp" "sctp" "rds" "tipc")
    local -a not_blacklisted=()
    # squashfs is required by snapd; skip the blacklist check if snaps are present
    local snaps_active=false
    if command -v snap &>/dev/null && snap list &>/dev/null 2>&1 && [[ $(snap list 2>/dev/null | wc -l) -gt 1 ]]; then
        snaps_active=true
    fi
    for mod in "${required_blacklisted[@]}"; do
        if [[ "$mod" == "squashfs" && "$snaps_active" == true ]]; then
            continue
        fi
        # modprobe treats - and _ alike (usb-storage == usb_storage).
        if ! grep -rqE "^[[:space:]]*blacklist[[:space:]]+${mod//-/[-_]}([[:space:]]|\$)" \
            "${AUDIT_ROOT}/etc/modprobe.d/" 2>/dev/null; then
            not_blacklisted+=("$mod")
        fi
    done
    if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
        local mod_list mod_fix
        mod_list=$(printf ' - %s\n' "${not_blacklisted[@]}")
        mod_fix="# Blacklist dangerous/unnecessary kernel modules:"$'\n'
        for mod in "${not_blacklisted[@]}"; do
            mod_fix+="grep -qxF 'blacklist ${mod}' /etc/modprobe.d/99-hardening-blacklist.conf 2>/dev/null || echo 'blacklist ${mod}' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
            mod_fix+="grep -qxF 'install ${mod} /bin/false' /etc/modprobe.d/99-hardening-blacklist.conf 2>/dev/null || echo 'install ${mod} /bin/false' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
        done
        mod_fix+="sudo /usr/bin/update-initramfs -u
/sbin/modprobe --showconfig | /bin/grep -E 'blacklist|install.*false'"
        print_status "WARN" "Kernel module blacklist incomplete: ${#not_blacklisted[@]} module(s) not blacklisted"
        append_report "## Kernel Module Blacklist\n- 🔴 ${#not_blacklisted[@]} dangerous module(s) not blacklisted"
        report_issue 6 \
            "Dangerous kernel modules not blacklisted" \
            "${#not_blacklisted[@]} module(s) can be loaded on demand (attack surface / CIS requirement)" \
            "$mod_fix" \
            0 \
            "Modules not blacklisted:\n${mod_list}"
    else
        print_status "OK" "All recommended kernel modules are blacklisted"
        append_report "## Kernel Module Blacklist\n- 🟢 Dangerous modules blacklisted"
    fi
}
