# shellcheck shell=bash
# check_open_ports — standard check (sourced by ubuntu-sec-audit.sh)

# _deprecated_service PROTO PORT — label of a deprecated plaintext service on
# PROTO/PORT (names as in /etc/services), empty for anything else. Matching
# on the protocol matters: 514/udp is syslog, 514/tcp is rsh.
_deprecated_service() {
    case "$1/$2" in
        tcp/21)  echo "FTP (plaintext file transfer)" ;;
        tcp/23)  echo "Telnet (plaintext remote login)" ;;
        udp/69)  echo "TFTP (unauthenticated file transfer)" ;;
        tcp/512) echo "rexec (exec: plaintext remote execution)" ;;
        tcp/513) echo "rlogin (login: plaintext remote login)" ;;
        tcp/514) echo "rsh (shell: unauthenticated remote shell)" ;;
    esac
}

# _inetd_service_name PROTO PORT — the service's name in /etc/inetd.conf.
_inetd_service_name() {
    case "$1/$2" in
        tcp/21)  echo "ftp" ;;
        tcp/23)  echo "telnet" ;;
        udp/69)  echo "tftp" ;;
        tcp/512) echo "exec" ;;
        tcp/513) echo "login" ;;
        tcp/514) echo "shell" ;;
    esac
}

# _pkg_owning PATH — the installed package that owns PATH (also under its
# other spelling on merged-/usr systems); empty if none.
_pkg_owning() {
    local p alt pkg=""
    for p in "$1" "$(_usrmerge_alias "$1")"; do
        [[ -n "$p" ]] || continue
        pkg=$(dpkg -S "$p" 2>/dev/null | grep -v '^diversion' | head -n 1 | cut -d: -f1 || true)
        [[ -n "$pkg" ]] && break
    done
    alt="${pkg%%,*}"
    [[ "$alt" =~ ^[a-z0-9][a-z0-9+.-]+$ ]] && printf '%s' "$alt"
    return 0
}

# _pkg_removable PKG — false for packages that must never be purged to close
# a port (init, superservers that host other services, essential packages).
_pkg_removable() {
    case "$1" in
        ""|systemd|systemd-*|init|init-system-helpers|sysvinit-*|openssh-*|dbus*|\
        libc6|libc-bin|coreutils|util-linux|bash|dash|busybox*|sudo|snapd|\
        xinetd|openbsd-inetd|inetutils-inetd|rlinetd|\
        python*|libpython*|perl|perl-*|libperl*|ruby*|libruby*|nodejs|libnode*|\
        openjdk-*|default-jre*|default-jdk*|php*|lua*|liblua*|tcl*|guile-*|mono-*|\
        dotnet*|golang-*|erlang-*|elixir|r-base*)
            # Interpreters and runtimes run many programs: the listener is a
            # script, and purging its interpreter would remove half the system.
            return 1 ;;
    esac
    [[ "$(dpkg-query -W -f='${Essential}' "$1" 2>/dev/null || true)" != "yes" ]]
}

# _listener_package PID PROTO PORT — the package to remove to close PROTO/PORT
# held by PID: the owner of /proc/PID/exe or, when that is inetd, of the
# server inetd.conf runs for the service. Empty when it cannot be determined
# or must not be removed.
_listener_package() {
    local pid="$1" proto="$2" port="$3" exe pkg name prog
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    exe=$(readlink "${AUDIT_ROOT}/proc/${pid}/exe" 2>/dev/null || true)
    exe="${exe% (deleted)}"
    [[ "$exe" == /* ]] || return 0
    pkg=$(_pkg_owning "$exe")
    case "$pkg" in
        openbsd-inetd|inetutils-inetd|rlinetd)
            name=$(_inetd_service_name "$proto" "$port")
            prog=$(awk -v s="$name" -v p="$proto" '
                $1 ~ /^#/ { next }
                {
                    n = $1; sub(/^.*:/, "", n)
                    if (n == s && index($3, p) == 1) {
                        prog = $6
                        if (prog ~ /\/tcpd$/) prog = $7
                        print prog
                        exit
                    }
                }' "${AUDIT_ROOT}/etc/inetd.conf" 2>/dev/null || true)
            pkg=""
            [[ "$prog" == /* ]] && pkg=$(_pkg_owning "$prog")
            ;;
    esac
    if _pkg_removable "$pkg"; then
        printf '%s' "$pkg"
    fi
    return 0
}

# _pkg_units PKG — systemd service/socket units PKG ships, space separated.
_pkg_units() {
    dpkg -L "$1" 2>/dev/null \
        | grep -E '/systemd/system/[A-Za-z0-9_.-]+\.(service|socket)$' \
        | sed 's#.*/##' | sort -u | tr '\n' ' ' || true
}

check_open_ports() {
    print_status "INFO" "Checking open ports and service versions..."
    local raw_ports port_tool="ss"
    if command -v ss >/dev/null 2>&1; then
        raw_ports=$(ss -tulpn 2>/dev/null | tail -n +2 || true)
    elif command -v netstat >/dev/null 2>&1; then
        raw_ports=$(netstat -tulpn 2>/dev/null | tail -n +2 || true)
        port_tool="netstat"
    else
        print_status "WARN" "No tool to list ports (ss/netstat missing)"
        append_report "## Open Ports & Services\n- ⚠️ Cannot list listening ports (ss/netstat missing)"
        _mark_skipped "neither ss nor netstat is installed"
        return 0
    fi

    if [[ -z "$raw_ports" ]]; then
        print_status "OK" "No listening services"
        append_report "## Open Ports & Services\n- 🟢 No listening services"
        return
    fi

    print_status "INFO" "Listening services detected (service + version shown below)"

    local section="## Open Ports & Running Services\n\n"
    section+="| Proto | Listen Address:Port         | PID   | Process Name     | Version                  |\n"
    section+="|-------|-----------------------------|-------|------------------|-------------------------|\n"

    local count=0
    local -a deprecated_services=() remove_pkgs=() manual_steps=()
    local -A seen=() pkg_seen=() remote_pkg=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local proto listen pid_raw process_raw
        if [[ "$port_tool" == "ss" ]]; then
            proto=$(awk '{print $1}' <<< "$line")
            listen=$(awk '{print $5}' <<< "$line")
            pid_raw=$(grep -oE 'pid=[0-9]+' <<< "$line" | head -1 | cut -d= -f2 || echo "-")
            # FIX: more robust process name extraction: handle spaces or special chars in name
            # ss format: users:(("name",pid=N,fd=N)) — extract first quoted name field
            process_raw=$(grep -oP 'users:\(\("([^"]+)"' <<< "$line" | head -1 | grep -oP '"([^"]+)"$' | tr -d '"' || echo "unknown")
            [[ -z "$pid_raw" ]] && pid_raw="-"
            [[ -z "$process_raw" ]] && process_raw="unknown"
        else
            read -r proto listen pid_raw process_raw < <(
                awk '{
                    proto=$1; addr=$4
                    pid="-"; proc="unknown"
                    n=split($NF,a,"/")
                    if (n>=2) { pid=a[1]; proc=a[2] }
                    print proto, addr, pid, proc
                }' <<< "$line"
            )
        fi
        # Header lines (netstat prints two) are not sockets.
        [[ "$proto" == tcp* || "$proto" == udp* ]] || continue
        count=$((count + 1))
        # Process names end up in report notes and fix-script comments.
        process_raw="${process_raw//[^A-Za-z0-9._@:+-]/?}"
        local version="N/A"
        [[ "$pid_raw" != "-" ]] && version=$(get_service_version "$process_raw" "$pid_raw" || echo "N/A")
        [[ ${#version} -gt 28 ]] && version="${version:0:25}..."
        section+="| $proto | $listen | $pid_raw | $process_raw | $version |\n"

        if echo "$listen" | grep -qE '^(\[?::\]?|0\.0\.0\.0|\*):'; then
            print_status "WARN" "Service '$process_raw' is bound to ALL interfaces on $listen - consider restricting to 127.0.0.1 if not intentional"
        fi

        # FIX: robust port extraction supporting all address formats:
        #   IPv4  0.0.0.0:22   127.0.0.1:22
        #   IPv6  [::]:22      [::1]:22      *:22
        local port_num proto_base label
        port_num=$(echo "$listen" | grep -oE ':([0-9]+)$' | tr -d ':' || true)
        proto_base="${proto%6}"
        label=$(_deprecated_service "$proto_base" "$port_num")
        [[ -n "$label" ]] || continue
        # IPv4 and IPv6 sockets of one process are one finding.
        [[ -n "${seen["${proto_base}/${port_num}/${pid_raw}"]:-}" ]] && continue
        seen["${proto_base}/${port_num}/${pid_raw}"]=1

        local pkg
        pkg=$(_listener_package "$pid_raw" "$proto_base" "$port_num")
        deprecated_services+=("${label} on ${port_num}/${proto_base} - process: ${process_raw} (pid ${pid_raw})${pkg:+, package ${pkg}}")
        if [[ -n "$pkg" ]]; then
            if [[ -z "${pkg_seen[$pkg]:-}" ]]; then
                pkg_seen["$pkg"]=1
                remove_pkgs+=("$pkg")
            fi
            case "${proto_base}/${port_num}" in
                tcp/23|tcp/512|tcp/513|tcp/514) remote_pkg["$pkg"]=1 ;;
            esac
        else
            manual_steps+=("#   ${label} on ${port_num}/${proto_base}: process ${process_raw} (pid ${pid_raw}) - find what provides it (sudo /bin/ss -tulpn | grep ':${port_num} '; systemctl list-sockets), then stop, disable and remove it")
        fi
    done <<< "$raw_ports"

    append_report "$section"
    if [[ $count -gt 0 ]]; then
        print_status "INFO" "Found $count listening service(s) - full table in report"
    fi

    # Report deprecated services as a single issue
    if [[ ${#deprecated_services[@]} -gt 0 ]]; then
        local dep_list fix="" pkg units
        dep_list=$(printf ' - %s\n' "${deprecated_services[@]}")
        if [[ ${#remove_pkgs[@]} -gt 0 ]]; then
            fix="# Stop, disable and remove the packages that provide the services found:"$'\n'
            for pkg in "${remove_pkgs[@]}"; do
                units=$(_pkg_units "$pkg")
                local cmds=""
                [[ -n "${units// /}" ]] && cmds+="sudo /bin/systemctl disable --now ${units% } 2>/dev/null || true"$'\n'
                cmds+="sudo /usr/bin/apt-get purge -y ${pkg}"
                if [[ -n "${remote_pkg[$pkg]:-}" ]]; then
                    # A remote-login service may be how someone gets in: keep
                    # it unless SSH is there to replace it.
                    fix+="if sudo /bin/systemctl is-active --quiet ssh.service || sudo /bin/systemctl is-active --quiet ssh.socket; then"$'\n'
                    fix+="    ${cmds//$'\n'/$'\n'    }"$'\n'
                    fix+="else"$'\n'
                    fix+="    echo '[WARN] SSH is not running - ${pkg} kept so remote logins still work; set up SSH, then re-run this fix'"$'\n'
                    fix+="fi"$'\n'
                else
                    fix+="${cmds}"$'\n'
                fi
            done
            if [[ ${#manual_steps[@]} -gt 0 ]]; then
                fix+="# Not removed automatically (the providing package could not be determined):"$'\n'
                fix+="$(printf '%s\n' "${manual_steps[@]}")"$'\n'
            fi
        else
            fix="# MANUAL: the package providing these services could not be determined from the listening process."$'\n'
            fix+="$(printf '%s\n' "${manual_steps[@]}")"$'\n'
        fi
        local ports_re
        ports_re=$(printf '%s\n' "${!seen[@]}" | cut -d/ -f2 | sort -un | paste -sd'|' -)
        fix+="# Verify nothing listens on these ports any more:"$'\n'
        fix+="sudo /bin/ss -tulpn | grep -E ':(${ports_re})[[:space:]]' || true"

        print_status "WARN" "Deprecated/plaintext protocol services detected: ${#deprecated_services[@]}"
        append_report "## Deprecated Network Services\n- 🔴 ${#deprecated_services[@]} plaintext/deprecated protocol(s) listening"
        report_issue 15 \
            "Deprecated or plaintext network services listening" \
            "${#deprecated_services[@]} deprecated service(s) detected - these transmit credentials in cleartext and/or lack authentication" \
            "$fix" \
            0 \
            "Services detected:\n${dep_list}\n\nReplace with: SFTP/SCP (not FTP), SSH (not Telnet/rsh/rlogin/rexec)"
    fi
}
