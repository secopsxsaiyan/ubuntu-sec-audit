# shellcheck shell=bash
# check_kernel — standard check (sourced by ubuntu-sec-audit.sh)

# _has_unit_file NAME — true if a systemd unit file NAME is installed.
_has_unit_file() {
    local d
    for d in /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
        [[ -e "${AUDIT_ROOT}${d}/$1" ]] && return 0
    done
    return 1
}

# _forwarding_users — installed software that needs IP forwarding (container
# runtimes, Kubernetes, VM NAT, VPN gateways), one name per line; empty when
# there is none. Never fails.
_forwarding_users() {
    local r="${AUDIT_ROOT}" f
    if command -v docker >/dev/null 2>&1 || command -v dockerd >/dev/null 2>&1 \
        || _has_unit_file docker.service \
        || dpkg -l docker-ce 2>/dev/null | grep -q '^ii'; then
        echo "Docker"
    fi
    # Only an initialised LXD (it has a storage pool): Ubuntu server images
    # seed the lxd snap whether or not it is ever used.
    if compgen -G "$r/var/snap/lxd/common/lxd/storage-pools/*" >/dev/null \
       || compgen -G "$r/var/lib/lxd/storage-pools/*" >/dev/null; then
        echo "LXD"
    fi
    if [[ -d "$r/var/lib/incus" ]] || command -v incus >/dev/null 2>&1 \
        || _has_unit_file incus.service; then
        echo "Incus"
    fi
    if command -v kubelet >/dev/null 2>&1 || _has_unit_file kubelet.service \
        || [[ -d "$r/etc/kubernetes" || -d "$r/var/snap/microk8s" || -d "$r/etc/rancher/k3s" ]]; then
        echo "Kubernetes"
    fi
    if command -v libvirtd >/dev/null 2>&1 || command -v virtqemud >/dev/null 2>&1 \
        || _has_unit_file libvirtd.service || _has_unit_file virtqemud.service; then
        echo "libvirt"
    fi
    if command -v podman >/dev/null 2>&1 || _has_unit_file podman.service \
        || _has_unit_file podman.socket; then
        echo "podman"
    fi
    for f in "$r/etc/wireguard/"*.conf; do
        if [[ -f "$f" ]]; then
            echo "WireGuard"
            break
        fi
    done
    return 0
}

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

    # Containers, Kubernetes, VM NAT and VPN gateways need IP forwarding;
    # don't flag it there. Elsewhere it is reported, but never switched off
    # by the fix (a person decides, see below).
    local -A fwd_key=([net.ipv4.ip_forward]=1 [net.ipv6.conf.all.forwarding]=1)
    local -a fwd_users=()
    mapfile -t fwd_users < <(_forwarding_users)
    if [[ ${#fwd_users[@]} -gt 0 ]]; then
        unset 'SYSCTL_CHECKS[net.ipv4.ip_forward]'
        unset 'SYSCTL_CHECKS[net.ipv6.conf.all.forwarding]'
        local fwd_names
        fwd_names=$(printf '%s, ' "${fwd_users[@]}")
        print_status "INFO" "${fwd_names%, } detected - IP forwarding is needed; skipping net.ipv4.ip_forward / net.ipv6.conf.all.forwarding checks"
    fi

    # With IPv6 off, net.ipv6.* keys are missing (disabled at boot) or moot;
    # they are not evaluated, but still written so they apply if IPv6 returns.
    local ipv6_off
    ipv6_off=$(_ipv6_off_reason)
    if [[ -n "$ipv6_off" ]]; then
        print_status "INFO" "IPv6 is disabled (${ipv6_off}) - not checking net.ipv6.* sysctls"
    fi

    local -a sysctl_failures=() fwd_failures=()
    local -a keys=() file_keys=()
    local -A target=()   # value written by the fix: current if compliant, else required
    mapfile -t keys < <(printf '%s\n' "${!SYSCTL_CHECKS[@]}" | sort)

    local key spec want actual ok
    for key in "${keys[@]}"; do
        spec="${SYSCTL_CHECKS[$key]}"
        want="${spec#>=}"
        if [[ -z "${fwd_key[$key]:-}" ]]; then
            file_keys+=("$key")
        fi
        if [[ -n "$ipv6_off" && "$key" == net.ipv6.* ]]; then
            target["$key"]="$want"
            continue
        fi
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
            if [[ -n "${fwd_key[$key]:-}" ]]; then
                fwd_failures+=("${key} = ${actual:-unset}")
            fi
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

        local sysctl_fix_content=""
        if [[ ${#sysctl_failures[@]} -gt ${#fwd_failures[@]} ]]; then
            # Write every key (not just failing ones) so re-runs never drop
            # earlier settings, using the current value where it is already
            # compliant so stricter settings are kept. The forwarding keys
            # are never written: see the manual part below.
            local sysctl_all_lines="" _k
            for _k in "${file_keys[@]}"; do
                sysctl_all_lines+="${_k} = ${target[$_k]}"$'\n'
            done
            sysctl_fix_content="sudo /bin/mkdir -p /etc/sysctl.d"$'\n'
            sysctl_fix_content+="sudo /usr/bin/tee /etc/sysctl.d/99-hardening.conf > /dev/null << 'SYSCTLEOF'"$'\n'
            sysctl_fix_content+="${sysctl_all_lines}"
            sysctl_fix_content+="SYSCTLEOF"$'\n'
            sysctl_fix_content+="sudo /sbin/sysctl --system 2>&1 | grep -v 'No such file' || true"$'\n'
            sysctl_fix_content+="# Verify current values:"$'\n'
            sysctl_fix_content+="$(printf 'sudo /sbin/sysctl %s 2>/dev/null || true\n' "${file_keys[@]}")"$'\n'
        else
            sysctl_fix_content="# MANUAL: only IP forwarding is not hardened, and it is never turned off automatically."$'\n'
        fi
        if [[ ${#fwd_failures[@]} -gt 0 ]]; then
            local fwd_desc
            fwd_desc=$(printf '%s, ' "${fwd_failures[@]}")
            sysctl_fix_content+="# IP forwarding is on (${fwd_desc%, }). It is NOT changed"$'\n'
            sysctl_fix_content+="# automatically: containers (Docker, LXD/Incus, podman), Kubernetes, libvirt"$'\n'
            sysctl_fix_content+="# NAT and VPN gateways (WireGuard) need it. Only if this host routes nothing:"$'\n'
            sysctl_fix_content+="#   echo 'net.ipv4.ip_forward = 0' | sudo /usr/bin/tee /etc/sysctl.d/98-no-forwarding.conf"$'\n'
            sysctl_fix_content+="#   echo 'net.ipv6.conf.all.forwarding = 0' | sudo /usr/bin/tee -a /etc/sysctl.d/98-no-forwarding.conf"$'\n'
            sysctl_fix_content+="#   sudo /sbin/sysctl --system"$'\n'
        fi

        report_issue 9 \
            "Kernel sysctl hardening incomplete" \
            "${#sysctl_failures[@]} sysctl parameter(s) are not set to secure values" \
            "${sysctl_fix_content%$'\n'}" \
            0 \
            "Non-compliant values:\n${fail_list}"
    fi

    # Kernel module blacklist check (CIS-aligned)
    local -a required_blacklisted=("usb-storage" "cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "dccp" "sctp" "rds" "tipc")
    local -a not_blacklisted=() auto_mods=() loaded_mods=()
    # squashfs is required by snapd; skip the blacklist check if snaps are present
    local snaps_active=false
    if command -v snap &>/dev/null && snap list &>/dev/null 2>&1 && [[ $(snap list 2>/dev/null | wc -l) -gt 1 ]]; then
        snaps_active=true
    fi
    # Azure / Hyper-V provisioning media (the ovf-env ISO) needs udf.
    local hyperv=false vendor
    vendor=$(cat "${AUDIT_ROOT}/sys/class/dmi/id/sys_vendor" 2>/dev/null || true)
    if [[ "$vendor" == "Microsoft Corporation"* ]]; then
        hyperv=true
    fi
    local mod
    for mod in "${required_blacklisted[@]}"; do
        if [[ "$mod" == "squashfs" && "$snaps_active" == true ]]; then
            continue
        fi
        if [[ "$mod" == "udf" && "$hyperv" == true ]]; then
            continue
        fi
        # modprobe treats - and _ alike (usb-storage == usb_storage).
        if ! grep -rqE "^[[:space:]]*blacklist[[:space:]]+${mod//-/[-_]}([[:space:]]|\$)" \
            "${AUDIT_ROOT}/etc/modprobe.d/" 2>/dev/null; then
            not_blacklisted+=("$mod")
            # A loaded (or built-in) module is in use: blacklisting it could
            # leave the host unable to boot (e.g. root on USB storage).
            if [[ -e "${AUDIT_ROOT}/sys/module/${mod//-/_}" ]]; then
                loaded_mods+=("$mod")
            else
                auto_mods+=("$mod")
            fi
        fi
    done
    if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
        local mod_list mod_fix=""
        local conf="/etc/modprobe.d/99-hardening-blacklist.conf"
        mod_list=$(printf ' - %s\n' "${not_blacklisted[@]}")
        if [[ ${#auto_mods[@]} -gt 0 ]]; then
            mod_fix="# Blacklist dangerous/unnecessary kernel modules (none of these is loaded now):"$'\n'
            mod_fix+="_mods_added=0"$'\n'
            for mod in "${auto_mods[@]}"; do
                mod_fix+="grep -qxF 'blacklist ${mod}' ${conf} 2>/dev/null || { echo 'blacklist ${mod}' | sudo /usr/bin/tee -a ${conf} > /dev/null; _mods_added=1; }"$'\n'
                mod_fix+="grep -qxF 'install ${mod} /bin/false' ${conf} 2>/dev/null || { echo 'install ${mod} /bin/false' | sudo /usr/bin/tee -a ${conf} > /dev/null; _mods_added=1; }"$'\n'
            done
            mod_fix+="# Rebuild the initramfs only if the blacklist changed:"$'\n'
            mod_fix+="if [ \"\$_mods_added\" -eq 1 ]; then sudo /usr/bin/update-initramfs -u; fi"$'\n'
            mod_fix+="/sbin/modprobe --showconfig | /bin/grep -E 'blacklist|install.*false' || true"$'\n'
        else
            mod_fix="# MANUAL: every module below is loaded now; blacklisting a module in use can leave the system unable to boot."$'\n'
        fi
        if [[ ${#loaded_mods[@]} -gt 0 ]]; then
            mod_fix+="# Loaded now, so NOT blacklisted automatically: ${loaded_mods[*]}"$'\n'
            mod_fix+="# Check what uses them (lsmod; findmnt; lsblk -o NAME,TRAN). If one is not needed -"$'\n'
            mod_fix+="# and the system does not boot from it - blacklist it by hand and rebuild the initramfs:"$'\n'
            for mod in "${loaded_mods[@]}"; do
                mod_fix+="#   echo 'blacklist ${mod}' | sudo /usr/bin/tee -a ${conf}"$'\n'
                mod_fix+="#   echo 'install ${mod} /bin/false' | sudo /usr/bin/tee -a ${conf}"$'\n'
            done
            mod_fix+="#   sudo /usr/bin/update-initramfs -u"$'\n'
        fi
        print_status "WARN" "Kernel module blacklist incomplete: ${#not_blacklisted[@]} module(s) not blacklisted"
        append_report "## Kernel Module Blacklist\n- 🔴 ${#not_blacklisted[@]} dangerous module(s) not blacklisted"
        report_issue 6 \
            "Dangerous kernel modules not blacklisted" \
            "${#not_blacklisted[@]} module(s) can be loaded on demand (attack surface / CIS requirement)" \
            "${mod_fix%$'\n'}" \
            0 \
            "Modules not blacklisted:\n${mod_list}"
    else
        print_status "OK" "All recommended kernel modules are blacklisted"
        append_report "## Kernel Module Blacklist\n- 🟢 Dangerous modules blacklisted"
    fi
}
