# shellcheck shell=bash
# check_open_ports — standard check (sourced by ubuntu-sec-audit.sh)

check_open_ports() {
    print_status "INFO" "Checking open ports and service versions..."
    local raw_ports port_tool="ss"
    if command -v ss >/dev/null 2>&1; then
        raw_ports=$(sudo ss -tulpn 2>/dev/null | tail -n +2)
    elif command -v netstat >/dev/null 2>&1; then
        raw_ports=$(sudo netstat -tulpn 2>/dev/null | tail -n +2)
        port_tool="netstat"
    else
        print_status "WARN" "No tool to list ports (ss/netstat missing)"
        append_report "## Open Ports & Services\n- ⚠️ Cannot list listening ports"
        return
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
    local -a deprecated_services=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        count=$((count + 1))
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
        local port_num
        port_num=$(echo "$listen" | grep -oE ':([0-9]+)$' | tr -d ':' || true)
        case "$port_num" in
            21)  deprecated_services+=("FTP (plaintext file transfer) on port 21 - process: $process_raw") ;;
            23)  deprecated_services+=("Telnet (plaintext shell) on port 23 - process: $process_raw") ;;
            69)  deprecated_services+=("TFTP (unauthenticated file transfer) on port 69 - process: $process_raw") ;;
            513) deprecated_services+=("rsh/exec (no auth, plaintext) on port 513 - process: $process_raw") ;;
            514) deprecated_services+=("rlogin (no auth, plaintext) on port 514 - process: $process_raw") ;;
        esac
    done <<< "$raw_ports"

    append_report "$section"
    if [[ $count -gt 0 ]]; then
        print_status "INFO" "Found $count listening service(s) - full table in report"
    fi

    # Report deprecated services as a single issue
    if [[ ${#deprecated_services[@]} -gt 0 ]]; then
        local dep_list
        dep_list=$(printf ' - %s\n' "${deprecated_services[@]}")
        print_status "WARN" "Deprecated/plaintext protocol services detected: ${#deprecated_services[@]}"
        append_report "## Deprecated Network Services\n- 🔴 ${#deprecated_services[@]} plaintext/deprecated protocol(s) listening"
        report_issue 15 \
            "Deprecated or plaintext network services listening" \
            "${#deprecated_services[@]} deprecated service(s) detected - these transmit credentials in cleartext and/or lack authentication" \
            "# Stop and disable deprecated services:
sudo /bin/systemctl disable --now inetd xinetd telnet.socket 2>/dev/null || true
sudo /usr/bin/apt-get purge -y telnetd telnet nis rsh-server rsh-client atftpd tftpd tftp xinetd inetd 2>/dev/null || true
sudo /usr/bin/apt-get autoremove -y
# Block at firewall level even if already purged:
sudo /usr/sbin/ufw deny 21/tcp
sudo /usr/sbin/ufw deny 23/tcp
sudo /usr/sbin/ufw deny 69/udp
sudo /usr/sbin/ufw deny 513/tcp
sudo /usr/sbin/ufw deny 514/tcp
# Verify no longer listening:
sudo ss -tulpn | grep -E ':21|:23|:69|:513|:514'" \
            0 \
            "Services detected:\n${dep_list}\n\nReplace with: SFTP/SCP (not FTP), SSH (not Telnet/rsh/rlogin)"
    fi
}
