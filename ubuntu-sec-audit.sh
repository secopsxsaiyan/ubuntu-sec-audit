#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# ubuntu-sec-audit.sh - Ubuntu LTS Security Audit (Standard + Deep mode)
# CIS/Lynis aligned - WITH EXACT REMEDIATION COMMANDS
# Deep mode includes FULL ClamAV antivirus scan + Lynis + rkhunter + debsums
# Zero dependencies in Standard mode.
# Requires: Ubuntu 20.04+, run as sudo
# =============================================================================

set -euo pipefail

# ERR trap fires on any unexpected non-zero exit; INT/TERM for user interrupts
_INTERRUPTED=0
trap 'echo -e "\n\033[0;31m[✗] Unexpected error on line ${LINENO} (exit code: $?). Aborting.\033[0m"; exit 1' ERR
trap '_INTERRUPTED=1; echo -e "\n\033[0;33m[⚠] Audit interrupted. Report saved if possible.\033[0m"; exit 1' INT TERM

# ====================== NAMED CONSTANTS ======================
readonly FAILED_LOGIN_THRESHOLD=5
readonly MIN_UBUNTU_VERSION="20.04"

# ====================== CONFIG & GLOBALS ======================
SCORE=100
DEEP=0
VERBOSE=0
SKIP_APT_UPDATE=0
ISSUE_COUNT=0
DEEP_ISSUE_COUNT=0
SUDO_PID=""

# Arrays to collect issues, remediations, and titles separately
declare -a ISSUES=()
declare -a REMEDIATIONS=()
declare -a TITLES=()

# Colors & emojis (tput fallback to ANSI)
if command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
    BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
    BOLD='\033[1m'; RESET='\033[0m'
fi

# SUID whitelist - paths resolved by readlink -f at runtime to handle /bin -> /usr/bin symlinks
SUID_WHITELIST=(
    "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/gpasswd" "/usr/bin/chsh"
    "/usr/bin/chfn" "/usr/bin/chage" "/usr/bin/mount" "/usr/bin/umount" "/usr/bin/newgrp"
    "/usr/bin/pkexec" "/usr/lib/openssh/ssh-keysign" "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/bin/fusermount3"
)

# SGID whitelist
SGID_WHITELIST=(
    "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent" "/usr/bin/bsd-write"
    "/usr/bin/crontab" "/usr/bin/expiry" "/usr/sbin/unix_chkpwd"
    "/usr/lib/openssh/ssh-keysign" "/usr/bin/chage" "/usr/bin/dotlockfile"
    "/usr/bin/lockfile" "/usr/sbin/pam_extrausers_chkpwd"
)

# ====================== HELPER FUNCTIONS ======================
print_status() {
    local type="$1" msg="$2"
    case "$type" in
        OK)   echo -e "${GREEN}[✓]${RESET} $msg" ;;
        WARN) echo -e "${YELLOW}[⚠]${RESET} $msg" ;;
        ERR)  echo -e "${RED}[✗]${RESET} $msg" ;;
        INFO) echo -e "${BLUE}[i]${RESET} $msg" ;;
    esac
}

append_report() {
    printf '%b\n' "$1" >> "$REPORT_FILE"
}

report_issue() {
    local points="$1"
    local title="$2"
    local description="$3"
    local remediation="$4"
    local is_deep="${5:-0}"
    local note="${6:-}"

    SCORE=$((SCORE - points))
    [[ $SCORE -lt 0 ]] && SCORE=0

    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    [[ "$is_deep" -eq 1 ]] && DEEP_ISSUE_COUNT=$((DEEP_ISSUE_COUNT + 1))

    local entry="### 🔴 ${title} (${points} pts)
**Issue**: ${description}
**Remediation**:
\`\`\`bash
${remediation}
\`\`\`
${note:+**Note**: ${note}}"

    ISSUES+=("$entry")
    TITLES+=("$title")
    REMEDIATIONS+=("$remediation")
    append_report "$entry"

    if [[ "$VERBOSE" -eq 1 ]]; then
        print_status "WARN" "${title}"
    fi
    return 0
}

prompt_install() {
    local tool="$1" pkg="${2:-$1}"
    if ! command -v "$tool" >/dev/null 2>&1; then
        print_status "WARN" "$tool not found."
        read -r -p "   Install now? (y/N) " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            # FIX: honour --skip-apt-update flag; don't unconditionally run apt-get update
            if [[ "$SKIP_APT_UPDATE" -eq 0 ]]; then
                sudo apt-get update -qq
            fi
            sudo apt-get install -y "$pkg" && print_status "OK" "$tool installed."
        else
            print_status "INFO" "Skipping $tool (install manually later)."
        fi
    fi
}

# ====================== LOCAL SERVICE VERSION DETECTION ======================
get_service_version() {
    local prog="$1"
    local pid="${2:-}"

    local bin
    bin=$(basename "$prog" 2>/dev/null || echo "$prog")

    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        if [[ -n "$exe" ]]; then
            local pkg
            pkg=$(dpkg -S "$exe" 2>/dev/null | head -n1 | cut -d: -f1 || true)
            if [[ -n "$pkg" ]]; then
                dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null && return
            fi
        fi
    fi

    case "$bin" in
        sshd)
            local sshd_ver ssh_ver
            sshd_ver=$(timeout 2 sshd -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            ssh_ver=$(timeout 2 ssh -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            if [[ "$sshd_ver" != "N/A" ]]; then
                echo "sshd:${sshd_ver} client:${ssh_ver}"
            else
                echo "client:${ssh_ver}"
            fi
            ;;
        nginx)
            timeout 2 nginx -v 2>&1 | head -n1 | sed 's/.*nginx version: nginx\///' || echo "N/A"
            ;;
        apache2|httpd)
            timeout 2 apache2 -v 2>&1 | grep -o 'Apache/[0-9.]*' || echo "N/A"
            ;;
        mysqld|mariadbd)
            timeout 2 mysqld --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        postgres|postmaster)
            timeout 2 postgres --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        *)
            local pkg
            pkg=$(dpkg -l "*${bin}*" 2>/dev/null | grep '^ii' | head -n1 | awk '{print $2}' || true)
            [[ -n "$pkg" ]] && dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "N/A"
            ;;
    esac
}

# ====================== CLI PARSING ======================
usage() {
    cat << EOF
Usage: sudo $0 [OPTIONS]
Options:
  --deep              Enable Deep mode (extra checks + optional tools)
  --verbose           Show detailed output for every check
  --quick             Force Standard mode (default)
  --skip-apt-update   Skip apt-get update (use cached package index)
  --help              Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep)             DEEP=1 ;;
        --verbose)          VERBOSE=1 ;;
        --quick)            DEEP=0 ;;
        --skip-apt-update)  SKIP_APT_UPDATE=1 ;;
        --help)             usage; exit 0 ;;
        *)                  echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# ====================== UBUNTU VERSION GUARD ======================
print_status "INFO" "Checking Ubuntu version compatibility..."
ubuntu_ver=$(lsb_release -rs 2>/dev/null || echo "")
# FIX: use dpkg --compare-versions instead of fragile awk lexical string compare
# (awk < on "9.04" vs "20.04" fails lexically; dpkg uses proper version semantics)
if dpkg --compare-versions "${ubuntu_ver:-0}" lt "$MIN_UBUNTU_VERSION" 2>/dev/null; then
    print_status "ERR" "Ubuntu ${MIN_UBUNTU_VERSION}+ required. Detected: ${ubuntu_ver:-unknown}"
    exit 1
fi
print_status "OK" "Ubuntu ${ubuntu_ver} - compatible"

# ====================== REPORT FILE SETUP ======================
if [[ -n "${AUDIT_REPORT_DIR:-}" ]]; then
    REPORT_DIR="$AUDIT_REPORT_DIR"
    [[ "$REPORT_DIR" =~ ^/ ]] || { echo "AUDIT_REPORT_DIR must be an absolute path"; exit 1; }
elif [[ -n "${SUDO_USER:-}" ]]; then
    REPORT_DIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    REPORT_DIR="$HOME"
fi
if [[ ! -w "$REPORT_DIR" ]]; then
    REPORT_DIR="/tmp"
    print_status "WARN" "Home directory not writable - saving report to /tmp"
fi
REPORT_FILE="${REPORT_DIR}/sec-audit-report-$(date +%Y%m%d-%H%M).md"

# ====================== SUDO & KEEP-ALIVE ======================
print_status "INFO" "Requesting sudo access (one-time)..."
sudo -v || { print_status "ERR" "Sudo required. Exiting."; exit 1; }

( while true; do
    if ! sudo -n true 2>/dev/null; then
        echo -e "\n${YELLOW}[⚠]${RESET} sudo keep-alive: credentials may have expired - some later checks may fail" >&2
    fi
    sleep 55
  done ) &
SUDO_PID=$!
trap '[[ -n "${SUDO_PID:-}" ]] && kill "$SUDO_PID" 2>/dev/null; [[ "${_INTERRUPTED:-0}" -eq 0 ]] && echo -e "\n\033[0;33m[⚠] Audit complete or unexpectedly exited.\033[0m"' EXIT

# ====================== REPORT HEADER ======================
(umask 177; : > "$REPORT_FILE")
cat > "$REPORT_FILE" << EOF
# Ubuntu Security Audit Report
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Hostname:** $(hostname)
**Ubuntu Release:** $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
**Mode:** $([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")

## Executive Summary
EOF

# ====================== CHECK FUNCTIONS ======================

check_updates() {
    print_status "INFO" "Checking package updates..."
    if [[ $SKIP_APT_UPDATE -eq 0 ]]; then
        sudo apt-get update -qq
    else
        print_status "INFO" "Skipping apt-get update (--skip-apt-update set)"
    fi
    if apt list --upgradable 2>/dev/null | grep -q upgradable; then
        print_status "WARN" "Updates available"
        append_report "## Package Updates\n- 🟡 Updates available"
        report_issue 12 \
            "System not fully patched" \
            "Outdated packages increase attack surface (CVEs)" \
            "sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y" \
            0 \
            "Reboot if kernel or libc was upgraded"
    else
        print_status "OK" "System up-to-date"
        append_report "## Package Updates\n- 🟢 Up-to-date"
    fi
}

check_firewall() {
    print_status "INFO" "Checking firewall (IPv4 + IPv6)..."

    local ipv4_ok=0
    local ufw_active=0

    if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
        print_status "OK" "UFW active (IPv4)"
        append_report "## Firewall\n- 🟢 UFW active (IPv4)"
        ipv4_ok=1
        ufw_active=1
    elif command -v nft >/dev/null 2>&1 && sudo nft list ruleset | grep -q "chain"; then
        print_status "OK" "nftables active"
        append_report "## Firewall\n- 🟢 nftables active"
        ipv4_ok=1
    elif sudo iptables -nL | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
        print_status "OK" "iptables rules present"
        append_report "## Firewall\n- 🟢 iptables rules present"
        ipv4_ok=1
    fi

    if [[ $ipv4_ok -eq 0 ]]; then
        print_status "WARN" "No IPv4 firewall detected"
        append_report "## Firewall\n- 🔴 No active IPv4 firewall"

        local ssh_port
        ssh_port=$(sudo sshd -T 2>/dev/null | awk '/^port / {print $2}' | head -1 || echo "22")
        [[ -z "$ssh_port" ]] && ssh_port="22"

        report_issue 15 \
            "No Active Firewall (IPv4)" \
            "Neither UFW, nftables, nor iptables rules are active" \
            "sudo /usr/bin/apt-get install -y ufw
sudo /usr/sbin/ufw default deny incoming
sudo /usr/sbin/ufw default allow outgoing
# SSH port auto-detected as ${ssh_port} - verify before applying:
sudo /usr/sbin/ufw allow ${ssh_port}/tcp
sudo /usr/sbin/ufw --force enable
sudo /usr/sbin/ufw status verbose" \
            0 \
            "⚠️ SSH port detected as ${ssh_port}. If wrong, update the allow rule BEFORE enabling UFW to avoid lockout."
    fi

    # --- IPv6 firewall check ---
    local ipv6_ok=0

    if [[ $ufw_active -eq 1 ]]; then
        if grep -qE '^\s*IPV6\s*=\s*yes' /etc/default/ufw 2>/dev/null; then
            print_status "OK" "UFW IPv6 enabled (/etc/default/ufw IPV6=yes)"
            append_report "## Firewall IPv6\n- 🟢 UFW managing IPv6"
            ipv6_ok=1
        else
            print_status "WARN" "UFW is active but IPV6=yes not set - IPv6 traffic unfiltered"
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]] && command -v ip6tables >/dev/null 2>&1; then
        if sudo ip6tables -nL 2>/dev/null | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
            print_status "OK" "ip6tables rules present (IPv6)"
            append_report "## Firewall IPv6\n- 🟢 ip6tables rules present"
            ipv6_ok=1
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]]; then
        print_status "WARN" "No IPv6 firewall rules detected"
        append_report "## Firewall IPv6\n- 🔴 No active IPv6 firewall"
        report_issue 10 \
            "No Active Firewall (IPv6)" \
            "IPv6 traffic is unfiltered - UFW IPV6=yes not set and no ip6tables DROP/REJECT rules found" \
            "# Enable IPv6 in UFW (recommended):
sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo /usr/sbin/ufw disable && sudo /usr/sbin/ufw --force enable
# Verify:
sudo /usr/sbin/ufw status verbose
sudo /usr/sbin/ip6tables -L INPUT --line-numbers" \
            0 \
            "IPv6 is enabled on most Ubuntu systems by default; unfiltered IPv6 bypasses IPv4-only rules"
    fi

    # --- UFW logging check ---
    if [[ $ufw_active -eq 1 ]]; then
        local ufw_log_level
        ufw_log_level=$(sudo ufw status verbose 2>/dev/null | awk '/^Logging:/ {print $2}' || true)
        if [[ -z "$ufw_log_level" || "$ufw_log_level" == "off" ]]; then
            print_status "WARN" "UFW logging is disabled - firewall events are not recorded"
            append_report "## Firewall Logging\n- 🔴 UFW logging is off"
            report_issue 5 \
                "UFW firewall logging disabled" \
                "UFW is active but logging is off - blocked/allowed connections are not recorded" \
                "sudo /usr/sbin/ufw logging low
# Verify:
sudo /usr/sbin/ufw status verbose | grep -i logging
sudo /usr/bin/tail -20 /var/log/ufw.log" \
                0 \
                "Recommended minimum is 'low'; use 'medium' on internet-facing systems"
        else
            print_status "OK" "UFW logging is enabled (level: ${ufw_log_level})"
            append_report "## Firewall Logging\n- 🟢 UFW logging enabled (level: ${ufw_log_level})"
        fi
    fi
}

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

check_ssh() {
    print_status "INFO" "Checking SSH hardening (extended)..."
    if ! command -v sshd >/dev/null 2>&1; then
        print_status "OK" "SSH not installed"
        return
    fi

    local sshd_conf
    sshd_conf=$(sudo sshd -T 2>/dev/null)

    local ssh_issues=()
    local ssh_fixes=""

    # Check 1: PermitRootLogin
    if ! grep -qE 'permitrootlogin (no|prohibit-password)' <<< "$sshd_conf"; then
        ssh_issues+=("PermitRootLogin is not set to 'no' or 'prohibit-password'")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 2: PasswordAuthentication
    # Warn about disabling password auth without verifying keys
    if ! grep -qE 'passwordauthentication no' <<< "$sshd_conf"; then
        ssh_issues+=("PasswordAuthentication is enabled")
        ssh_fixes+="# ⚠️  BEFORE APPLYING: verify SSH keys are installed for all admin accounts"$'\n'
        ssh_fixes+="#    Run from another terminal: ssh -o PasswordAuthentication=no user@host"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 3: MaxAuthTries (CIS: ≤ 4)
    local max_auth_tries
    max_auth_tries=$(awk '/^maxauthtries / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$max_auth_tries" || "$max_auth_tries" -gt 4 ]]; then
        ssh_issues+=("MaxAuthTries is ${max_auth_tries:-unset} (should be ≤ 4)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 4: LoginGraceTime (CIS: ≤ 60 seconds)
    local grace_time
    grace_time=$(awk '/^logingracetime / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$grace_time" || "$grace_time" -eq 0 || "$grace_time" -gt 60 ]]; then
        ssh_issues+=("LoginGraceTime is ${grace_time:-unset} (should be 1–60 seconds)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 5: X11Forwarding
    if grep -qE 'x11forwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("X11Forwarding is enabled (unnecessary attack surface)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 6: AllowTcpForwarding
    if grep -qE 'allowtcpforwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("AllowTcpForwarding is enabled (can tunnel unauthorised traffic)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 7: ClientAlive settings (idle timeout)
    local client_interval client_count
    client_interval=$(awk '/^clientaliveinterval / {print $2}' <<< "$sshd_conf" | head -1)
    client_count=$(awk '/^clientalivecountmax / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$client_interval" || "$client_interval" -eq 0 ]]; then
        ssh_issues+=("ClientAliveInterval is 0 (no idle session timeout)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 8: SSHv1 disabled
    if grep -qE '^protocol\s+.*\b1\b' <<< "$sshd_conf"; then
        ssh_issues+=("SSHv1 is enabled - it is deprecated and cryptographically broken")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?Protocol.*/Protocol 2/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 9: SSH host private key file permissions (must be 600, root-owned)
    while IFS= read -r keyfile; do
        local kperms kowner
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        if [[ "$kperms" != "600" || "$kowner" != "root" ]]; then
            ssh_issues+=("Host private key ${keyfile}: perms=${kperms:-?}, owner=${kowner:-?} (should be 600 root)")
            ssh_fixes+="sudo /bin/chmod 600 $(printf '%q' "$keyfile")"$'\n'
            ssh_fixes+="sudo /bin/chown root:root $(printf '%q' "$keyfile")"$'\n'
        fi
    done < <(find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' ! -name '*.pub' 2>/dev/null)

    # Check 10: Weak ciphers, MACs, and KEX algorithms
    local weak_ciphers=("3des-cbc" "blowfish-cbc" "cast128-cbc" "arcfour" "arcfour128" "arcfour256"
                        "aes128-cbc" "aes192-cbc" "aes256-cbc" "rijndael-cbc@lysator.liu.se")
    local weak_macs=("hmac-md5" "hmac-md5-96" "hmac-sha1-96"
                     "umac-64@openssh.com" "hmac-md5-etm@openssh.com" "hmac-md5-96-etm@openssh.com"
                     "umac-64-etm@openssh.com" "hmac-sha1-96-etm@openssh.com")
    local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group14-sha1"
                    "diffie-hellman-group-exchange-sha1" "gss-gex-sha1-" "gss-group1-sha1-"
                    "gss-group14-sha1-")

    local active_ciphers active_macs active_kex
    active_ciphers=$(awk '/^ciphers / {print $2}' <<< "$sshd_conf" | tr ',' '\n' || true)
    active_macs=$(awk '/^macs / {print $2}'    <<< "$sshd_conf" | tr ',' '\n' || true)
    active_kex=$(awk '/^kexalgorithms / {print $2}' <<< "$sshd_conf" | tr ',' '\n' || true)

    local -a crypto_issues=() bad_ciphers=() bad_macs=() bad_kex=()

    for c in "${weak_ciphers[@]}"; do
        if grep -qxF "$c" <<< "$active_ciphers"; then
            bad_ciphers+=("$c"); crypto_issues+=("Weak cipher active: ${c}")
        fi
    done
    for m in "${weak_macs[@]}"; do
        if grep -qxF "$m" <<< "$active_macs"; then
            bad_macs+=("$m"); crypto_issues+=("Weak MAC active: ${m}")
        fi
    done
    for k in "${weak_kex[@]}"; do
        if echo "$active_kex" | grep -q "^${k}"; then
            bad_kex+=("$k"); crypto_issues+=("Weak KEX active: ${k}")
        fi
    done

    if [[ ${#crypto_issues[@]} -gt 0 ]]; then
        ssh_issues+=("Weak crypto algorithms in use (${#crypto_issues[@]} issue(s)) - see note")
        # FIX: write to a drop-in file instead of tee -a /etc/ssh/sshd_config.
        # tee -a can create duplicate/conflicting Ciphers/MACs/KexAlgorithms directives
        # if partial entries already exist, causing sshd to refuse to start.
        # Ubuntu 20.04+ natively supports /etc/ssh/sshd_config.d/ include fragments.
        # The drop-in takes precedence over the main config and is idempotent on re-run.
        ssh_fixes+='# Write crypto hardening to a drop-in file (safe, idempotent, Ubuntu 20.04+):'$'\n'
        ssh_fixes+='sudo /bin/mkdir -p /etc/ssh/sshd_config.d'$'\n'
        ssh_fixes+='sudo /usr/bin/tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null << '"'"'SSHEOF'"'"$'\n'
        ssh_fixes+='Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'$'\n'
        ssh_fixes+='MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com'$'\n'
        ssh_fixes+='KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'$'\n'
        ssh_fixes+='SSHEOF'$'\n'
        ssh_fixes+='sudo /bin/chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf'$'\n'
        ssh_fixes+='sudo /bin/chown root:root /etc/ssh/sshd_config.d/99-hardening.conf'$'\n'
        # Ensure main sshd_config has an Include directive (Ubuntu 22.04+ includes it by default)
        ssh_fixes+='# Ensure the main sshd_config includes the drop-in directory (Ubuntu 22.04+ does this by default):'$'\n'
        ssh_fixes+='grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \'$'\n'
        ssh_fixes+='  sudo /bin/sed -i '"'"'1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|'"'"' /etc/ssh/sshd_config'$'\n'
    fi

    # NEW Check 11: PermitEmptyPasswords (must be no)
    if ! grep -qE 'permitemptypasswords no' <<< "$sshd_conf"; then
        ssh_issues+=("PermitEmptyPasswords is not explicitly set to 'no'")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 12: HostbasedAuthentication (must be no)
    if grep -qE 'hostbasedauthentication yes' <<< "$sshd_conf"; then
        ssh_issues+=("HostbasedAuthentication is enabled (allows host-trust logins)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 13: IgnoreRhosts (must be yes)
    if grep -qE 'ignorerhosts no' <<< "$sshd_conf"; then
        ssh_issues+=("IgnoreRhosts is disabled - .rhosts files are honoured (legacy trust risk)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 14: MaxStartups (CIS: 10:30:60)
    local max_startups
    max_startups=$(awk '/^maxstartups / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$max_startups" ]]; then
        ssh_issues+=("MaxStartups is unset (default 10:30:100 allows unauthenticated connection floods)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 15: AllowUsers / AllowGroups restriction
    if ! grep -qE '^(allowusers|allowgroups)\s' <<< "$sshd_conf"; then
        ssh_issues+=("No AllowUsers or AllowGroups directive - any valid system user can attempt SSH login")
        ssh_fixes+="# Restrict SSH to specific users or group (choose one approach):"$'\n'
        ssh_fixes+="# echo 'AllowGroups sshusers' | sudo /usr/bin/tee -a /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="# sudo /usr/sbin/groupadd sshusers && sudo /usr/sbin/usermod -aG sshusers <yourusername>"$'\n'
    fi

    if [[ ${#ssh_issues[@]} -eq 0 ]]; then
        print_status "OK" "SSH fully hardened (all extended checks passed)"
        append_report "## SSH Hardening\n- 🟢 All SSH hardening checks passed"
    else
        print_status "WARN" "SSH hardening issues: ${#ssh_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${ssh_issues[@]}")
        append_report "## SSH Hardening\n- 🔴 Weak SSH config (${#ssh_issues[@]} issue(s))"

        ssh_fixes+="# Validate config before restarting:
sudo /usr/sbin/sshd -t
sudo /bin/systemctl restart ssh
# Verify:
sudo /usr/sbin/sshd -T | grep -E 'permitroot|passwordauth|maxauth|logingrace|x11|tcpforward|clientalive|permitempty|hostbased|ignorerhosts|maxstartups|allowusers|allowgroups'"

        local combined_note="Issues:\n${issue_list}\n\nAlso consider Fail2Ban or key-only auth"
        combined_note+=$'\n\n⚠️ BEFORE disabling PasswordAuthentication: verify working SSH keys from another terminal'
        [[ ${#crypto_issues[@]} -gt 0 ]] && combined_note+=$'\n\nWeak crypto details:\n'"$(printf ' - %s\n' "${crypto_issues[@]}")"
        report_issue 10 \
            "SSH configuration weaknesses found" \
            "SSH daemon is not fully hardened: ${#ssh_issues[@]} setting(s) out of compliance" \
            "$ssh_fixes" \
            0 \
            "$combined_note"
    fi
}

check_users() {
    print_status "INFO" "Checking users & sudo..."
    local sudoers
    sudoers=$(sudo grep -E '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true)
    if [[ -n "$sudoers" ]]; then
        print_status "WARN" "Users with NOPASSWD sudo found"
        append_report "## Users & Sudo\n- 🟡 Full sudo privileges found"
        report_issue 8 \
            "Users with NOPASSWD sudo" \
            "Users can run any command as root without password" \
            "# Open sudoers safely with visudo - do NOT edit /etc/sudoers directly
sudo /usr/sbin/visudo
# Find and remove or restrict lines matching NOPASSWD, e.g.:
#   username ALL=(ALL) NOPASSWD: ALL   <-- remove or change to:
#   username ALL=(ALL) ALL" \
            0
    else
        print_status "OK" "No dangerous sudoers"
        append_report "## Users & Sudo\n- 🟢 No dangerous sudo privileges"
    fi

    local plain_pw_users
    plain_pw_users=$(awk -F: '($2 != "x" && $2 != "*" && $2 != "!" && $2 != "") {print $1}' /etc/passwd || true)
    if [[ -n "$plain_pw_users" ]]; then
        print_status "ERR" "Accounts with plaintext passwords in /etc/passwd"
        append_report "## Users & Sudo\n- 🔴 Accounts with plaintext passwords in /etc/passwd"
        report_issue 15 \
            "Plaintext passwords in /etc/passwd" \
            "These accounts have passwords stored directly in /etc/passwd (pre-shadow format - critical risk)" \
            "/usr/sbin/pwconv
# Verify no plaintext passwords remain:
/usr/bin/awk -F: '(\$2 != \"x\" && \$2 != \"*\" && \$2 != \"!\" && \$2 != \"\") {print \$1}' /etc/passwd" \
            0 \
            "Affected accounts: $(echo "$plain_pw_users" | tr '\n' ' ')"
    fi

    local locked_with_shell
    locked_with_shell=$(
        while IFS=: read -r user pw _rest; do
            [[ "$pw" == '!'* ]] || continue
            shell=$(awk -F: -v u="$user" '$1==u {print $7}' /etc/passwd 2>/dev/null || true)
            [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/dash" ]] \
                && echo "$user ($shell)"
        done < /etc/shadow 2>/dev/null || true
    )
    if [[ -n "$locked_with_shell" ]]; then
        print_status "WARN" "Locked accounts with interactive login shells detected"
        append_report "## Users & Sudo\n- 🟡 Locked accounts retain interactive shells"
        report_issue 5 \
            "Locked accounts with interactive login shells" \
            "Accounts are locked in shadow but still have /bin/bash or similar" \
            "$(echo "$locked_with_shell" | awk '{print "sudo /usr/sbin/usermod -s /usr/sbin/nologin " $1}')
# Verify:
/usr/bin/awk -F: '(\$7 ~ /bash|sh|dash/) {print \$1, \$7}' /etc/passwd" \
            0 \
            "Affected accounts: $(echo "$locked_with_shell" | tr '\n' ' ')"
    fi

    local uid0_count
    uid0_count=$(awk -F: '$3==0 {print}' /etc/passwd | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        print_status "ERR" "Multiple root (UID 0) accounts found"
        append_report "## Users & Sudo\n- 🔴 Multiple UID 0 accounts"
        report_issue 12 \
            "Multiple UID 0 accounts" \
            "More than one account with root privileges (privilege escalation risk)" \
            "/usr/bin/awk -F: '\$3==0 {print \$1}' /etc/passwd
# For each unexpected UID 0 account (NOT root), lock it:
sudo /usr/sbin/usermod -L <username>
sudo /usr/sbin/usermod -s /usr/sbin/nologin <username>" \
            0
    fi
}

check_permissions() {
    print_status "INFO" "Checking critical permissions..."
    if [[ "$(stat -c %a /etc/shadow)" != "640" ]] || [[ "$(stat -c %a /etc/passwd)" != "644" ]]; then
        print_status "ERR" "Weak critical file permissions"
        append_report "## Critical Permissions\n- 🔴 /etc/shadow or /etc/passwd permissions incorrect"
        report_issue 10 \
            "Weak critical file permissions" \
            "/etc/shadow or /etc/passwd have incorrect permissions" \
            "sudo /bin/chmod 640 /etc/shadow
sudo /bin/chmod 644 /etc/passwd
sudo /bin/chown root:shadow /etc/shadow
sudo /bin/chown root:root /etc/passwd
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/shadow /etc/passwd" \
            0
    else
        print_status "OK" "Critical files properly permissioned"
        append_report "## Critical Permissions\n- 🟢 Correct permissions on /etc/shadow and /etc/passwd"
    fi

    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_cfg_perms sshd_cfg_owner sshd_cfg_group
        sshd_cfg_perms=$(stat -c '%a' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_owner=$(stat -c '%U' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_group=$(stat -c '%G' /etc/ssh/sshd_config  2>/dev/null || true)
        if [[ "$sshd_cfg_perms" != "600" || "$sshd_cfg_owner" != "root" || "$sshd_cfg_group" != "root" ]]; then
            print_status "WARN" "sshd_config permissions incorrect: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} (should be 600 root:root)"
            append_report "## Critical Permissions\n- 🔴 /etc/ssh/sshd_config: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group}"
            report_issue 8 \
                "sshd_config has insecure permissions" \
                "/etc/ssh/sshd_config is ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} - should be 600 root:root (CIS 5.2.1)" \
                "sudo /bin/chmod 600 /etc/ssh/sshd_config
sudo /bin/chown root:root /etc/ssh/sshd_config
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/ssh/sshd_config" \
                0
        else
            print_status "OK" "/etc/ssh/sshd_config permissions are correct (600 root:root)"
            append_report "## Critical Permissions\n- 🟢 /etc/ssh/sshd_config is 600 root:root"
        fi
    fi
}

check_unattended() {
    print_status "INFO" "Checking unattended-upgrades..."
    if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Unattended-upgrades missing"
        append_report "## Automatic Updates\n- 🔴 Not installed"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades package is not installed" \
            "sudo /usr/bin/apt-get install -y unattended-upgrades
sudo /usr/sbin/dpkg-reconfigure -pmedium unattended-upgrades
/usr/bin/systemctl is-enabled unattended-upgrades" \
            0
        return
    fi

    if grep -qE '"${distro_id}:${distro_codename}-security"' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
        print_status "OK" "Unattended-upgrades installed and enabled for security"
        append_report "## Automatic Updates\n- 🟢 Enabled"
    else
        print_status "WARN" "Unattended-upgrades not configured for security updates"
        append_report "## Automatic Updates\n- 🔴 Security updates not enabled"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades installed but security updates not enabled" \
            "sudo /usr/sbin/dpkg-reconfigure -pmedium unattended-upgrades
# Or manually ensure this line is uncommented in /etc/apt/apt.conf.d/50unattended-upgrades:
#   \"\${distro_id}:\${distro_codename}-security\";
sudo /bin/grep -n 'security' /etc/apt/apt.conf.d/50unattended-upgrades" \
            0
    fi
}

check_apparmor() {
    print_status "INFO" "Checking AppArmor..."
    local enforced_count
    enforced_count=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}' || echo 0)
    if [[ "$enforced_count" -gt 0 ]]; then
        print_status "OK" "AppArmor enforced ($enforced_count profile(s) in enforce mode)"
        append_report "## AppArmor\n- 🟢 Enforced ($enforced_count profile(s))"
    else
        print_status "WARN" "AppArmor not enforcing"
        append_report "## AppArmor\n- 🔴 Not enforcing"
        report_issue 7 \
            "AppArmor disabled" \
            "AppArmor is not enforcing profiles" \
            "sudo /usr/bin/apt-get install -y apparmor apparmor-profiles apparmor-utils
sudo /bin/systemctl enable --now apparmor
sudo /usr/sbin/aa-enforce /etc/apparmor.d/*
sudo /usr/sbin/aa-status" \
            0
    fi
}

check_failed_logins() {
    print_status "INFO" "Analyzing failed logins..."
    local fails
    fails=$(sudo journalctl -u ssh --since "1 day ago" 2>/dev/null \
            | awk '/Failed password/{c++} END{print c+0}')
    if [[ "$fails" -gt $FAILED_LOGIN_THRESHOLD ]]; then
        print_status "WARN" "Many failed login attempts"
        append_report "## Failed Logins\n- 🟡 $fails failed attempts (last 24h)"
        report_issue 6 \
            "High failed login count" \
            "Possible brute-force attack on SSH ($fails failures in 24h)" \
            "sudo /usr/bin/apt-get install -y fail2ban
sudo /bin/systemctl enable --now fail2ban
sudo /usr/bin/fail2ban-client status sshd
sudo /usr/bin/journalctl -u ssh --since '1 day ago' | /bin/grep 'Failed password' | /usr/bin/tail -20" \
            0 \
            "Review /var/log/auth.log and consider key-only SSH authentication"
    else
        print_status "OK" "No unusual failed logins"
        append_report "## Failed Logins\n- 🟢 Normal"
    fi
}

check_kernel() {
    print_status "INFO" "Checking kernel/sysctl hardening (extended)..."

    declare -A SYSCTL_CHECKS=(
        ["kernel.randomize_va_space"]="2"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="2"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv6.conf.all.forwarding"]="0"
    )

    local -a sysctl_failures=()
    local sysctl_fix_lines=""

    for key in "${!SYSCTL_CHECKS[@]}"; do
        local expected="${SYSCTL_CHECKS[$key]}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "")
        if [[ "$actual" != "$expected" ]]; then
            sysctl_failures+=("${key} = ${actual:-unset} (expected ${expected})")
            sysctl_fix_lines+="${key} = ${expected}"$'\n'
        fi
    done

    if [[ ${#sysctl_failures[@]} -eq 0 ]]; then
        print_status "OK" "All kernel sysctl hardening checks passed"
        append_report "## Kernel Hardening\n- 🟢 ASLR, hardlinks, symlinks, dmesg, kptr, redirects, syncookies, rp_filter all hardened"
    else
        print_status "WARN" "Kernel sysctl issues: ${#sysctl_failures[@]} found"
        local fail_list
        fail_list=$(printf ' - %s\n' "${sysctl_failures[@]}")
        append_report "## Kernel Hardening\n- 🔴 ${#sysctl_failures[@]} sysctl(s) not hardened"

        local sysctl_fix_content
        sysctl_fix_content="printf '%s' '${sysctl_fix_lines}' | sudo /usr/bin/tee /etc/sysctl.d/99-hardening.conf
sudo /sbin/sysctl --system
$(printf 'sudo /sbin/sysctl %s\n' "${!SYSCTL_CHECKS[@]}")"

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
    for mod in "${required_blacklisted[@]}"; do
        if ! grep -rqE "^\s*blacklist\s+${mod}\b" /etc/modprobe.d/ 2>/dev/null; then
            not_blacklisted+=("$mod")
        fi
    done
    if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
        local mod_list mod_fix
        mod_list=$(printf ' - %s\n' "${not_blacklisted[@]}")
        mod_fix="# Blacklist dangerous/unnecessary kernel modules:"$'\n'
        for mod in "${not_blacklisted[@]}"; do
            mod_fix+="echo 'blacklist ${mod}' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
            mod_fix+="echo 'install ${mod} /bin/false' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
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

check_reboot() {
    print_status "INFO" "Checking if reboot is required..."
    if [[ -f /var/run/reboot-required ]]; then
        print_status "WARN" "Reboot required after updates"
        append_report "## Reboot Required\n- 🔴 System requires reboot"
        report_issue 5 \
            "Reboot required" \
            "Kernel or critical library updates applied - reboot needed" \
            "sudo reboot" \
            0
    else
        print_status "OK" "No reboot required"
        append_report "## Reboot Required\n- 🟢 System up to date"
    fi
}

check_cron() {
    print_status "INFO" "Checking cron job security..."

    local -a cron_issues=()
    local cron_fix=""

    local -a cron_dirs=(
        /etc/crontab
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.hourly
    )

    for path in "${cron_dirs[@]}"; do
        [[ ! -e "$path" ]] && continue
        local owner perms
        owner=$(stat -c '%U' "$path" 2>/dev/null || true)
        perms=$(stat -c '%a' "$path"  2>/dev/null || true)
        if [[ "$owner" != "root" ]]; then
            cron_issues+=("${path} is owned by '${owner}' (should be root)")
            cron_fix+="sudo /bin/chown root:root '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#002) != 0 )); then
            cron_issues+=("${path} is world-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod o-w '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#020) != 0 )); then
            cron_issues+=("${path} is group-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod g-w '${path}'"$'\n'
        fi
    done

    local ww_cron_scripts
    ww_cron_scripts=$(find /etc/cron.d /etc/cron.daily /etc/cron.weekly \
                           /etc/cron.monthly /etc/cron.hourly \
                      -type f -perm -002 2>/dev/null || true)
    if [[ -n "$ww_cron_scripts" ]]; then
        while IFS= read -r s; do
            cron_issues+=("cron script is world-writable: ${s}")
            cron_fix+="sudo /bin/chmod o-w $(printf '%q' "$s")"$'\n'
        done <<< "$ww_cron_scripts"
    fi

    if [[ ${#cron_issues[@]} -eq 0 ]]; then
        print_status "OK" "Cron directories and files are properly secured"
        append_report "## Cron Security\n- 🟢 Cron paths are root-owned and not world/group-writable"
    else
        print_status "WARN" "Cron security issues: ${#cron_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${cron_issues[@]}")
        append_report "## Cron Security\n- 🔴 ${#cron_issues[@]} cron issue(s) found"
        cron_fix+="# Verify permissions after fixing:
/usr/bin/stat -c '%n %a %U:%G' /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly"
        report_issue 8 \
            "Insecure cron directory or script permissions" \
            "Cron paths are not root-owned or are world/group-writable - enables privilege escalation via cron" \
            "$cron_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

check_pam_lockout() {
    print_status "INFO" "Checking PAM brute-force lockout (faillock/tally2)..."

    local pam_ok=0

    if grep -rqE 'pam_faillock' /etc/pam.d/ 2>/dev/null; then
        local faillock_deny unlock_time
        faillock_deny=$(grep -rhoE 'deny=[0-9]+' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null \
                        | grep -oE '[0-9]+' | sort -n | tail -1 || true)
        unlock_time=$(grep -rhoE 'unlock_time=[0-9]+' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null \
                      | grep -oE '[0-9]+' | head -1 || true)
        if [[ -z "$faillock_deny" || "$faillock_deny" -gt 5 || -z "$unlock_time" ]]; then
            print_status "WARN" "pam_faillock present but thresholds not strict enough (deny=${faillock_deny:-unset}, unlock_time=${unlock_time:-unset})"
            append_report "## PAM Brute-Force Lockout\n- 🟡 pam_faillock present but not strict enough"
            report_issue 5 \
                "pam_faillock configured but lockout thresholds too permissive" \
                "deny= is ${faillock_deny:-unset} (should be ≤ 5) and/or unlock_time= is ${unlock_time:-unset}" \
                "echo -e 'deny = 5\nunlock_time = 900' | sudo /usr/bin/tee /etc/security/faillock.conf
sudo /usr/sbin/faillock --user root
/bin/grep -r pam_faillock /etc/pam.d/" \
                0
        else
            print_status "OK" "pam_faillock is configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
            append_report "## PAM Brute-Force Lockout\n- 🟢 pam_faillock configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
        fi
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 ]] && grep -rqE 'pam_tally2' /etc/pam.d/ 2>/dev/null; then
        print_status "OK" "pam_tally2 is configured in PAM"
        append_report "## PAM Brute-Force Lockout\n- 🟢 pam_tally2 configured"
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 ]]; then
        print_status "WARN" "No PAM brute-force lockout configured"
        append_report "## PAM Brute-Force Lockout\n- 🔴 No pam_faillock or pam_tally2 found"
        report_issue 8 \
            "No PAM brute-force lockout configured" \
            "pam_faillock is not active - accounts are not locked after repeated failed logins" \
            "sudo /usr/bin/apt-get install -y libpam-faillock
sudo /usr/sbin/pam-auth-update --enable faillock
echo -e 'deny = 5\nunlock_time = 900' | sudo /usr/bin/tee /etc/security/faillock.conf
sudo /usr/sbin/faillock --user root
/bin/grep -r pam_faillock /etc/pam.d/" \
            0 \
            "Also consider Fail2Ban as a complementary layer"
    fi
}

check_core_dumps() {
    print_status "INFO" "Checking core dump restrictions..."

    local -a core_issues=()
    local core_fix=""

    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ "$suid_dumpable" != "0" ]]; then
        core_issues+=("fs.suid_dumpable = ${suid_dumpable:-unset} (should be 0)")
        core_fix+="echo 'fs.suid_dumpable = 0' | sudo /usr/bin/tee /etc/sysctl.d/99-coredump.conf"$'\n'
        core_fix+="sudo /sbin/sysctl --system"$'\n'
    fi

    local limits_core
    limits_core=$(grep -rE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf \
                  /etc/security/limits.d/ 2>/dev/null || true)
    if [[ -z "$limits_core" ]]; then
        core_issues+=("No 'hard core 0' limit in /etc/security/limits.conf")
        core_fix+="echo '* hard core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
        core_fix+="echo '* soft core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
    fi

    if [[ -f /etc/systemd/coredump.conf ]]; then
        local storage_val
        storage_val=$(grep -E '^\s*Storage\s*=' /etc/systemd/coredump.conf 2>/dev/null \
                      | awk -F= '{print $2}' | tr -d ' ' || true)
        if [[ "$storage_val" != "none" ]]; then
            core_issues+=("systemd-coredump Storage=${storage_val:-default} - core dumps stored on disk")
            core_fix+="sudo /bin/sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/systemctl daemon-reload"$'\n'
        fi
    fi

    # NEW (Missing #18): kernel.core_pattern check
    local core_pattern
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")
    # Acceptable: systemd coredump handler or /dev/null; anything user-writable is a risk
    if [[ -n "$core_pattern" ]]; then
        local pattern_ok=0
        # Standard systemd handler
        [[ "$core_pattern" == "|/usr/lib/systemd/systemd-coredump"* ]] && pattern_ok=1
        # Disabled
        [[ "$core_pattern" == "/dev/null" ]] && pattern_ok=1
        # Core in root-owned dirs only
        [[ "$core_pattern" =~ ^/var/lib/systemd ]] && pattern_ok=1

        if [[ $pattern_ok -eq 0 ]]; then
            core_issues+=("kernel.core_pattern='${core_pattern}' - may point to user-writable path or unexpected handler")
            core_fix+="# Set core_pattern to systemd handler or disable entirely:"$'\n'
            core_fix+="echo 'kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h' | sudo /usr/bin/tee -a /etc/sysctl.d/99-coredump.conf"$'\n'
            core_fix+="sudo /sbin/sysctl --system"$'\n'
        fi
    fi

    if [[ ${#core_issues[@]} -eq 0 ]]; then
        print_status "OK" "Core dump restrictions are in place"
        append_report "## Core Dump Restrictions\n- 🟢 fs.suid_dumpable=0, hard core limit set, core_pattern safe"
    else
        print_status "WARN" "Core dump issues: ${#core_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${core_issues[@]}")
        append_report "## Core Dump Restrictions\n- 🔴 ${#core_issues[@]} core dump issue(s) found"
        core_fix+="# Verify after applying:
/sbin/sysctl fs.suid_dumpable kernel.core_pattern
/bin/grep -r 'core' /etc/security/limits.conf /etc/security/limits.d/"
        report_issue 6 \
            "Core dump restrictions missing or incomplete" \
            "Core dumps from privileged processes may expose sensitive memory (passwords, keys, tokens)" \
            "$core_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

check_umask() {
    print_status "INFO" "Checking default umask for login shells..."
    local umask_val=""
    umask_val=$(awk '/^\s*UMASK\s/ {print $2}' /etc/login.defs 2>/dev/null | head -1 | tr -d '[:space:]' || true)
    if [[ -z "$umask_val" ]]; then
        umask_val=$(grep -hE '^\s*umask\s' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null \
                    | awk '{print $2}' | head -1 | tr -d '[:space:]' || true)
    fi
    local is_weak=0
    case "${umask_val:-unset}" in
        022|0022|002|0002|"unset") is_weak=1 ;;
    esac
    if [[ $is_weak -eq 1 ]]; then
        print_status "WARN" "Default umask is ${umask_val:-unset} - new files may be group/other-readable"
        append_report "## Default Umask\n- 🟡 umask ${umask_val:-unset}: new files are group/other-readable"
        report_issue 4 \
            "Weak default umask for login shells" \
            "Default umask is ${umask_val:-unset}; CIS recommends 027" \
            "sudo /bin/sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
echo 'umask 027' | sudo /usr/bin/tee /etc/profile.d/umask.sh
sudo /bin/chmod 644 /etc/profile.d/umask.sh
grep UMASK /etc/login.defs && bash -c 'umask'" \
            0
    else
        print_status "OK" "Default umask is ${umask_val} - appropriately restrictive"
        append_report "## Default Umask\n- 🟢 umask ${umask_val} is appropriately restrictive"
    fi
}

check_login_banner() {
    print_status "INFO" "Checking login banners (/etc/issue, /etc/motd, SSH Banner)..."
    local -a banner_issues=()
    [[ ! -s /etc/issue ]] && banner_issues+=("/etc/issue is empty - no pre-login warning banner")
    [[ ! -s /etc/motd  ]] && banner_issues+=("/etc/motd is empty - no post-login message of the day")
    # FIX: use sshd -T (effective runtime config) instead of reading /etc/ssh/sshd_config
    # directly, which misses drop-in files in /etc/ssh/sshd_config.d/
    local ssh_banner
    local _sshd_eff
    _sshd_eff=$(sudo sshd -T 2>/dev/null || true)
    ssh_banner=$(awk '/^banner / {print $2}' <<< "$_sshd_eff" | head -1 || true)
    if [[ -z "$ssh_banner" || "${ssh_banner,,}" == "none" ]]; then
        banner_issues+=("SSH Banner directive not configured in sshd_config")
    fi
    if [[ ${#banner_issues[@]} -gt 0 ]]; then
        local issue_list
        issue_list=$(printf ' - %s\n' "${banner_issues[@]}")
        print_status "WARN" "Login banner issues: ${#banner_issues[@]} found"
        append_report "## Login Banners\n- 🟡 ${#banner_issues[@]} banner issue(s)"
        report_issue 3 \
            "Login banners missing or incomplete" \
            "Warning banners missing - required by CIS/legal best practice" \
            'BANNER="Authorized use only. Unauthorized access is prohibited and monitored."
echo "$BANNER" | sudo /usr/bin/tee /etc/issue /etc/issue.net /etc/motd
sudo /bin/sed -i "s|^#\?Banner.*|Banner /etc/issue.net|" /etc/ssh/sshd_config
sudo /bin/systemctl restart ssh
cat /etc/issue && sudo /usr/sbin/sshd -T | grep -i banner' \
            0 \
            "Issues:\n${issue_list}"
    else
        print_status "OK" "Login banners are configured"
        append_report "## Login Banners\n- 🟢 Banners present on /etc/issue, /etc/motd, and SSH"
    fi
}

# NEW CHECK: PAM password complexity (Missing #10)
check_pam_pwquality() {
    print_status "INFO" "Checking PAM password complexity (pwquality/cracklib)..."
    local pq_ok=0

    if grep -rqE 'pam_pwquality' /etc/pam.d/ 2>/dev/null; then
        local minlen
        minlen=$(grep -rhoE 'minlen=[0-9]+' /etc/pam.d/ /etc/security/pwquality.conf 2>/dev/null \
                 | grep -oE '[0-9]+' | sort -n | head -1 || true)
        # Also check pwquality.conf directly
        [[ -z "$minlen" ]] && minlen=$(awk '/^\s*minlen\s*=/ {print $3}' /etc/security/pwquality.conf 2>/dev/null | head -1 || true)

        if [[ -z "$minlen" || "$minlen" -lt 8 ]]; then
            print_status "WARN" "pam_pwquality present but minlen=${minlen:-unset} (should be ≥ 8)"
            append_report "## PAM Password Complexity\n- 🟡 pam_pwquality present but minlen too low (${minlen:-unset})"
            report_issue 5 \
                "pam_pwquality minlen too low" \
                "Password minimum length is ${minlen:-unset} (CIS requires ≥ 8, recommend 12+)" \
                "# Set policy in /etc/security/pwquality.conf:
sudo /usr/bin/tee /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
# Verify:
/bin/grep -v '^#' /etc/security/pwquality.conf | /bin/grep -v '^\s*$'" \
                0
        else
            print_status "OK" "pam_pwquality configured (minlen=${minlen})"
            append_report "## PAM Password Complexity\n- 🟢 pam_pwquality configured (minlen=${minlen})"
        fi
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 ]] && grep -rqE 'pam_cracklib' /etc/pam.d/ 2>/dev/null; then
        print_status "OK" "pam_cracklib configured"
        append_report "## PAM Password Complexity\n- 🟢 pam_cracklib configured"
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 ]]; then
        print_status "WARN" "No PAM password complexity enforcement found (pwquality/cracklib)"
        append_report "## PAM Password Complexity\n- 🔴 No password complexity enforcement"
        report_issue 7 \
            "No PAM password complexity enforcement" \
            "pam_pwquality and pam_cracklib are not configured - users can set trivially weak passwords" \
            "sudo /usr/bin/apt-get install -y libpam-pwquality
sudo /usr/sbin/pam-auth-update --enable pwquality
sudo /usr/bin/tee /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
/bin/grep -v '^#' /etc/security/pwquality.conf | /bin/grep -v '^\s*\$'" \
            0
    fi
}

# NEW CHECK: Secure Boot (Missing #17)
check_secure_boot() {
    print_status "INFO" "Checking Secure Boot status..."
    # Non-UEFI systems: skip
    if [[ ! -d /sys/firmware/efi ]]; then
        print_status "INFO" "Non-UEFI system - Secure Boot not applicable"
        append_report "## Secure Boot\n- ℹ️ Non-UEFI system - not applicable"
        return
    fi

    local sb_enabled=0
    if command -v mokutil >/dev/null 2>&1; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || true)
        echo "$sb_state" | grep -q "SecureBoot enabled" && sb_enabled=1
    fi
    # Fallback: read EFI variable directly
    if [[ $sb_enabled -eq 0 ]]; then
        local sb_efi="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        if [[ -f "$sb_efi" ]]; then
            local sb_byte
            sb_byte=$(od -An -t u1 "$sb_efi" 2>/dev/null | awk '{print $NF}' || true)
            [[ "$sb_byte" == "1" ]] && sb_enabled=1
        fi
    fi

    if [[ $sb_enabled -eq 1 ]]; then
        print_status "OK" "Secure Boot is enabled"
        append_report "## Secure Boot\n- 🟢 Secure Boot enabled"
    else
        print_status "WARN" "Secure Boot is disabled or not detectable"
        append_report "## Secure Boot\n- 🔴 Secure Boot disabled"
        report_issue 5 \
            "Secure Boot disabled" \
            "Secure Boot is not enabled - unsigned kernel modules and bootloaders can load" \
            "# Enable Secure Boot in UEFI/BIOS firmware settings
# Verify current state:
mokutil --sb-state
# Ensure Ubuntu's signed bootloader is in place:
sudo /usr/bin/apt-get install -y shim-signed grub-efi-amd64-signed linux-signed-generic
sudo /usr/sbin/update-grub" \
            0 \
            "Secure Boot requires UEFI firmware support and a signed kernel/bootloader"
    fi
}

# NEW CHECK: Root PATH safety (Missing #19)
check_root_path() {
    print_status "INFO" "Checking root PATH safety..."
    local root_path
    root_path=$(sudo bash -c 'echo $PATH' 2>/dev/null || true)

    local -a path_issues=()
    local path_fix=""

    # Check for . or empty components
    if echo "$root_path" | tr ':' '\n' | grep -qE '^\.?$'; then
        path_issues+=("Root PATH contains '.' or empty component (current directory execution risk)")
        path_fix+="# Remove '.' from root PATH in /root/.bashrc, /root/.profile, /etc/environment"$'\n'
        path_fix+="sudo /bin/grep -rn 'PATH.*\.' /root/.bashrc /root/.profile /etc/environment 2>/dev/null"$'\n'
    fi

    # Check for world-writable directories in PATH
    while IFS= read -r dir; do
        [[ -z "$dir" || "$dir" == "." ]] && continue
        if [[ -d "$dir" ]]; then
            local dperms downer
            dperms=$(stat -c '%a' "$dir" 2>/dev/null || true)
            downer=$(stat -c '%U' "$dir" 2>/dev/null || true)
            if [[ "$downer" != "root" ]] && (( (8#${dperms:-0} & 8#002) != 0 )); then
                path_issues+=("World-writable non-root directory in root PATH: $dir (${dperms}, owned by ${downer})")
                path_fix+="# Remove from PATH or fix permissions: $dir"$'\n'
            fi
        fi
    done < <(echo "$root_path" | tr ':' '\n')

    if [[ ${#path_issues[@]} -eq 0 ]]; then
        print_status "OK" "Root PATH is safe (no '.' or world-writable directories)"
        append_report "## Root PATH Safety\n- 🟢 Root PATH contains no dangerous entries"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${path_issues[@]}")
        print_status "WARN" "Root PATH safety issues: ${#path_issues[@]} found"
        append_report "## Root PATH Safety\n- 🔴 ${#path_issues[@]} dangerous entry/entries in root PATH"
        path_fix+="# After fixing, verify:
sudo bash -c 'echo \$PATH'"
        report_issue 8 \
            "Dangerous entries in root PATH" \
            "Root's PATH contains '.' or world-writable directories - classic privilege escalation vector" \
            "$path_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: Home directory permissions (from review doc)
check_home_permissions() {
    print_status "INFO" "Checking home directory permissions..."
    local -a home_issues=()
    local home_fix=""

    while IFS= read -r dir; do
        local perms owner
        perms=$(stat -c '%a' "$dir" 2>/dev/null || true)
        owner=$(stat -c '%U' "$dir" 2>/dev/null || true)
        [[ -z "$perms" ]] && continue
        # Others should have no access (last octet)
        if (( (8#$perms & 8#007) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - others have access")
            home_fix+="sudo /bin/chmod 700 $(printf '%q' "$dir")   # ${owner}'s home"$'\n'
        # Group-writable is also a problem
        elif (( (8#$perms & 8#020) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - group-writable")
            home_fix+="sudo /bin/chmod g-w $(printf '%q' "$dir")"$'\n'
        fi
    done < <(find /home /root -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

    if [[ ${#home_issues[@]} -eq 0 ]]; then
        print_status "OK" "Home directory permissions are secure"
        append_report "## Home Directory Permissions\n- 🟢 All home directories are properly restricted"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${home_issues[@]}")
        print_status "WARN" "Home directory permission issues: ${#home_issues[@]} found"
        append_report "## Home Directory Permissions\n- 🔴 ${#home_issues[@]} home dir(s) with insecure permissions"
        home_fix+="# Verify after fixing:
/usr/bin/find /home /root -mindepth 1 -maxdepth 1 -type d -exec /usr/bin/stat -c '%n %a %U' {} \;"
        report_issue 6 \
            "Home directories have insecure permissions" \
            "Home directories accessible by other users - may expose SSH keys, config files, credentials" \
            "$home_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: journald persistence (from review doc)
check_journald() {
    print_status "INFO" "Checking journald log persistence..."
    local storage_val
    storage_val=$(grep -hE '^\s*Storage\s*=' \
                  /etc/systemd/journald.conf \
                  /etc/systemd/journald.conf.d/*.conf 2>/dev/null \
                  | tail -1 | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$storage_val" == "persistent" ]]; then
        print_status "OK" "journald persistence enabled (Storage=persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=persistent"
    elif [[ "$storage_val" == "auto" && -d /var/log/journal ]]; then
        print_status "OK" "journald Storage=auto with /var/log/journal present (persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=auto + /var/log/journal exists"
    elif [[ "$storage_val" == "auto" && ! -d /var/log/journal ]]; then
        print_status "WARN" "journald Storage=auto but /var/log/journal does not exist - logs are volatile"
        append_report "## Journald Persistence\n- 🟡 Storage=auto but /var/log/journal missing"
        report_issue 4 \
            "journald logs may be volatile (Storage=auto, no /var/log/journal)" \
            "System logs are lost on reboot without /var/log/journal directory" \
            "sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
# Verify:
sudo /usr/bin/journalctl --disk-usage" \
            0
    else
        print_status "WARN" "journald Storage=${storage_val:-volatile} - logs not persisted across reboots"
        append_report "## Journald Persistence\n- 🔴 Logs not persistent (Storage=${storage_val:-volatile})"
        report_issue 5 \
            "journald logs not persistent across reboots" \
            "Storage=${storage_val:-unset} - logs lost on reboot, hindering forensics and incident response" \
            "sudo /bin/sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
sudo /usr/bin/journalctl --disk-usage" \
            0
    fi
}

# NEW CHECK: APT repository security (from review doc)
check_apt_repos() {
    print_status "INFO" "Checking APT repository security..."
    local -a repo_issues=()
    local repo_fix=""

    local trusted_sources
    trusted_sources=$(grep -rE '\[trusted=yes\]' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$trusted_sources" ]]; then
        repo_issues+=("APT source(s) with [trusted=yes] found - GPG signature verification bypassed")
        repo_fix+="# Remove [trusted=yes] from these sources (shown below):"$'\n'
        while IFS= read -r src_line; do
            repo_fix+="# $src_line"$'\n'
        done <<< "$trusted_sources"
        repo_fix+="# Edit each file and remove the [trusted=yes] attribute"$'\n'
    fi

    # Check for sources with allow-insecure
    local insecure_sources
    insecure_sources=$(grep -rE 'allow-insecure=yes|allow-weak=yes|allow-downgrade-to-insecure=yes' \
                       /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$insecure_sources" ]]; then
        repo_issues+=("APT source(s) with allow-insecure/allow-weak found")
        repo_fix+="# Remove allow-insecure/allow-weak options from APT sources"$'\n'
    fi

    if [[ ${#repo_issues[@]} -eq 0 ]]; then
        print_status "OK" "APT repository sources appear secure"
        append_report "## APT Repository Security\n- 🟢 No [trusted=yes] or insecure repositories found"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${repo_issues[@]}")
        print_status "WARN" "APT repository security issues: ${#repo_issues[@]} found"
        append_report "## APT Repository Security\n- 🔴 ${#repo_issues[@]} insecure repository configuration(s)"
        repo_fix+="# After changes, verify APT sources:
sudo /usr/bin/apt-get update 2>&1 | /bin/grep -E 'NO_PUBKEY|EXPKEYSIG|not signed|trusted' || echo 'Clean'"
        report_issue 8 \
            "Insecure APT repositories configured" \
            "APT repositories with disabled authentication allow unsigned/malicious packages to install" \
            "$repo_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: Unnecessary/dangerous packages (from review doc)
check_unnecessary_packages() {
    print_status "INFO" "Checking for unnecessary/dangerous packages..."
    local -a dangerous_pkgs=("telnet" "rsh-client" "rsh-server" "nis" "yp-tools"
                              "xinetd" "inetd" "atftpd" "tftpd" "tftp"
                              "talk" "talkd" "ntalk" "finger" "fingerd")
    local -a installed_dangerous=()

    for pkg in "${dangerous_pkgs[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            installed_dangerous+=("$pkg")
        fi
    done

    if [[ ${#installed_dangerous[@]} -eq 0 ]]; then
        print_status "OK" "No unnecessary/dangerous packages installed"
        append_report "## Unnecessary Packages\n- 🟢 No dangerous legacy packages found"
    else
        local pkg_list
        pkg_list=$(printf ' - %s\n' "${installed_dangerous[@]}")
        local purge_list="${installed_dangerous[*]}"
        print_status "WARN" "Dangerous/unnecessary packages found: ${purge_list}"
        append_report "## Unnecessary Packages\n- 🔴 ${#installed_dangerous[@]} dangerous package(s) installed"
        report_issue 8 \
            "Dangerous/unnecessary packages installed" \
            "Legacy/plaintext protocol packages increase attack surface" \
            "sudo /usr/bin/apt-get purge -y ${purge_list}
sudo /usr/bin/apt-get autoremove -y
# Verify removal:
dpkg -l ${purge_list} 2>/dev/null | grep '^ii' || echo 'All removed'" \
            0 \
            "Packages found:\n${pkg_list}\n\nReplace telnet with SSH; replace FTP with SFTP"
    fi
}

# ====================== ENHANCED DEEP MODE ======================
run_deep_checks() {
    print_status "INFO" "=== Starting Deep Analysis ==="

    # 1. SUID binaries
    print_status "INFO" "Scanning SUID/SGID binaries (full filesystem - may take a while on large systems)..."
    local _scan_start _scan_elapsed
    _scan_start=$(date +%s)
    local -a risky_suid=()
    local _suid_checked=0
    while IFS= read -r f; do
        _suid_checked=$(( _suid_checked + 1 ))
        # Progress heartbeat every 500 files
        if (( _suid_checked % 500 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  SUID scan: ${_suid_checked} files checked (${_scan_elapsed}s elapsed)..."
        fi
        local f_resolved
        f_resolved=$(readlink -f "$f" 2>/dev/null || echo "$f")
        local in_whitelist=0
        for wl in "${SUID_WHITELIST[@]}"; do
            local wl_resolved
            wl_resolved=$(readlink -f "$wl" 2>/dev/null || echo "$wl")
            if [[ "$f" == "$wl" || "$f" == "$wl_resolved" || "$f_resolved" == "$wl" || "$f_resolved" == "$wl_resolved" ]]; then
                in_whitelist=1; break
            fi
        done
        [[ $in_whitelist -eq 0 ]] && risky_suid+=("$f")
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  SUID scan complete: ${_suid_checked} files scanned in ${_scan_elapsed}s"
    if [[ ${#risky_suid[@]} -gt 0 ]]; then
        local suid_list
        suid_list=$(printf ' - %s\n' "${risky_suid[@]}")
        local suid_fix_cmds
        suid_fix_cmds="# Review each binary carefully before removing its SUID bit.
# NEVER remove SUID from: /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/mount"$'\n'
        for f in "${risky_suid[@]}"; do
            suid_fix_cmds+="sudo /bin/chmod -s $(printf '%q' "$f")   # removes SUID from ${f}"$'\n'
        done
        suid_fix_cmds+="# Verify no unexpected SUID bits remain:
sudo /usr/bin/find / -xdev -perm -4000 -type f 2>/dev/null"
        report_issue 14 \
            "Non-standard SUID binaries found" \
            "These are privilege-escalation vectors if exploited" \
            "$suid_fix_cmds" \
            1 \
            "Risky SUID files:\n${suid_list}\nNever remove SUID from sudo/su/passwd"
    fi

    # 1b. SGID binaries
    print_status "INFO" "Scanning SGID binaries (full filesystem)..."
    _scan_start=$(date +%s)
    local -a risky_sgid=()
    local _sgid_checked=0
    while IFS= read -r f; do
        _sgid_checked=$(( _sgid_checked + 1 ))
        if (( _sgid_checked % 500 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  SGID scan: ${_sgid_checked} files checked (${_scan_elapsed}s elapsed)..."
        fi
        local f_resolved
        f_resolved=$(readlink -f "$f" 2>/dev/null || echo "$f")
        local in_whitelist=0
        for wl in "${SGID_WHITELIST[@]}"; do
            local wl_resolved
            wl_resolved=$(readlink -f "$wl" 2>/dev/null || echo "$wl")
            if [[ "$f" == "$wl" || "$f" == "$wl_resolved" || "$f_resolved" == "$wl" || "$f_resolved" == "$wl_resolved" ]]; then
                in_whitelist=1; break
            fi
        done
        [[ $in_whitelist -eq 0 ]] && risky_sgid+=("$f")
    done < <(find / -xdev -perm -2000 -type f 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  SGID scan complete: ${_sgid_checked} files scanned in ${_scan_elapsed}s"
    if [[ ${#risky_sgid[@]} -gt 0 ]]; then
        local sgid_list sgid_fix_cmds
        sgid_list=$(printf ' - %s\n' "${risky_sgid[@]}")
        sgid_fix_cmds="# Review each binary carefully before removing its SGID bit."$'\n'
        for f in "${risky_sgid[@]}"; do
            sgid_fix_cmds+="sudo /bin/chmod g-s $(printf '%q' "$f")   # removes SGID from ${f}"$'\n'
        done
        sgid_fix_cmds+="sudo /usr/bin/find / -xdev -perm -2000 -type f 2>/dev/null"
        report_issue 10 \
            "Non-standard SGID binaries found" \
            "SGID binaries run with the owning group's privileges - exploitable for group escalation" \
            "$sgid_fix_cmds" \
            1 \
            "Non-whitelisted SGID files:\n${sgid_list}"
    else
        print_status "OK" "No unexpected SGID binaries found"
        append_report "## Deep: SGID Binaries\n- 🟢 No non-standard SGID binaries detected"
    fi

    # 2. World-writable files
    print_status "INFO" "Scanning world-writable files..."
    local -a world_write=()
    while IFS= read -r f; do
        world_write+=("$f")
    done < <(find /etc /var /home -xdev -perm -002 -type f 2>/dev/null)
    if [[ ${#world_write[@]} -gt 0 ]]; then
        local ww_list ww_fix_cmds
        ww_list=$(printf ' - %s\n' "${world_write[@]}")
        ww_fix_cmds="# Remove world-write bit from each file - verify ownership first:"$'\n'
        for f in "${world_write[@]}"; do
            ww_fix_cmds+="sudo /bin/chmod o-w $(printf '%q' "$f")"$'\n'
        done
        ww_fix_cmds+="sudo /usr/bin/find /etc /var /home -xdev -perm -002 -type f 2>/dev/null"
        report_issue 16 \
            "World-writable files in sensitive dirs" \
            "Anyone on the system can modify these files" \
            "$ww_fix_cmds" \
            1 \
            "World-writable files:\n${ww_list}"
    fi

    # 2b. World-writable directories
    print_status "INFO" "Scanning world-writable directories..."
    local -a world_write_dirs=()
    while IFS= read -r d; do
        world_write_dirs+=("$d")
    done < <(find /etc /var /home -xdev -perm -002 -type d ! -name 'tmp' 2>/dev/null)
    if [[ ${#world_write_dirs[@]} -gt 0 ]]; then
        local wwd_list wwd_fix_cmds
        wwd_list=$(printf ' - %s\n' "${world_write_dirs[@]}")
        wwd_fix_cmds="# Remove world-write bit from each directory:"$'\n'
        for d in "${world_write_dirs[@]}"; do
            wwd_fix_cmds+="sudo /bin/chmod o-w $(printf '%q' "$d")"$'\n'
        done
        wwd_fix_cmds+="sudo /usr/bin/find /etc /var /home -xdev -perm -002 -type d ! -name 'tmp' 2>/dev/null"
        report_issue 12 \
            "World-writable directories in sensitive paths" \
            "Anyone on the system can create or delete files inside these directories" \
            "$wwd_fix_cmds" \
            1 \
            "World-writable directories:\n${wwd_list}"
    fi

    # 2c. Unowned files
    print_status "INFO" "Scanning for unowned files and directories (full filesystem - may take several minutes)..."
    _scan_start=$(date +%s)
    local -a unowned_files=()
    local _unowned_checked=0
    while IFS= read -r f; do
        unowned_files+=("$f")
        _unowned_checked=$(( _unowned_checked + 1 ))
        if (( _unowned_checked % 1000 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  Unowned scan: ${_unowned_checked} hits so far (${_scan_elapsed}s elapsed)..."
        fi
    done < <(find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null)
    local -a unowned_dirs=()
    while IFS= read -r d; do unowned_dirs+=("$d"); done \
        < <(find / -xdev \( -nouser -o -nogroup \) -type d 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  Unowned scan complete in ${_scan_elapsed}s (${#unowned_files[@]} files, ${#unowned_dirs[@]} dirs)"

    local total_unowned=$(( ${#unowned_files[@]} + ${#unowned_dirs[@]} ))
    if [[ $total_unowned -gt 0 ]]; then
        local unowned_list=""
        [[ ${#unowned_files[@]} -gt 0 ]] && unowned_list+="Files:\n$(printf ' - %s\n' "${unowned_files[@]}")\n"
        [[ ${#unowned_dirs[@]}  -gt 0 ]] && unowned_list+="Dirs:\n$(printf '  - %s\n' "${unowned_dirs[@]}")"
        local unowned_fix_cmds
        unowned_fix_cmds="# Assign unowned files to root:root after review:
sudo /usr/bin/find / -xdev -nouser -type f 2>/dev/null | xargs -r sudo /bin/chown root:
sudo /usr/bin/find / -xdev -nogroup -type f 2>/dev/null | xargs -r sudo /bin/chown :root
# Verify none remain:
sudo /usr/bin/find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l"
        print_status "WARN" "Found ${total_unowned} unowned file(s)/dir(s) (no valid UID/GID)"
        append_report "## Deep: Unowned Files & Directories\n- 🔴 ${total_unowned} path(s) with no valid owner or group"
        report_issue 8 \
            "Files or directories with no valid owner/group" \
            "${total_unowned} path(s) have a UID/GID mapping to no existing user/group - can be hijacked if UID/GID reused" \
            "$unowned_fix_cmds" \
            1 \
            "${unowned_list}"
    else
        print_status "OK" "No unowned files or directories found"
        append_report "## Deep: Unowned Files & Directories\n- 🟢 All files and directories have valid owners and groups"
    fi

    # 3. Empty passwords
    print_status "INFO" "Checking for empty passwords..."
    local empty_pw
    empty_pw=$(sudo /usr/bin/awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pw" ]]; then
        local pw_fix_cmds
        pw_fix_cmds="# Lock each account with an empty password immediately:"$'\n'
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            pw_fix_cmds+="sudo /usr/bin/passwd -l $(printf '%q' "$user")"$'\n'
            pw_fix_cmds+="sudo /usr/sbin/usermod -s /usr/sbin/nologin $(printf '%q' "$user")"$'\n'
        done <<< "$empty_pw"
        pw_fix_cmds+="sudo /usr/bin/awk -F: '\$2==\"\" {print \$1}' /etc/shadow"
        report_issue 20 \
            "Accounts with empty passwords found" \
            "These accounts have no password set (critical risk)" \
            "$pw_fix_cmds" \
            1 \
            "Affected users: $(echo "$empty_pw" | tr '\n' ' ')"
    fi

    # 4. Password aging policy
    print_status "INFO" "Checking password policy (login.defs)..."
    local max_days
    max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs 2>/dev/null || true)
    if [[ -z "$max_days" || "$max_days" -gt 90 ]]; then
        report_issue 8 \
            "Weak password aging policy" \
            "PASS_MAX_DAYS not set or too high (${max_days:-unset}) in /etc/login.defs" \
            "sudo /bin/sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
/bin/grep '^PASS_' /etc/login.defs" \
            1
    fi

    # 5. Mount options - /tmp, /dev/shm, /var/tmp + sticky bit
    # NEW (Missing #11, #12): expanded to cover /dev/shm, /var/tmp, and /tmp sticky bit
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
        mount_fix+="echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0' | sudo /usr/bin/tee -a /etc/fstab"$'\n'
        mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev /tmp"$'\n'
    fi

    # /tmp: sticky bit check (NEW Missing #12)
    local tmp_perms
    tmp_perms=$(stat -c '%a' /tmp 2>/dev/null || true)
    if [[ -n "$tmp_perms" ]] && (( (8#$tmp_perms & 8#1000) == 0 )); then
        mount_issues+=("/tmp is missing the sticky bit (perms: ${tmp_perms}) - users can delete each other's files")
        mount_fix+="sudo /bin/chmod +t /tmp   # add sticky bit"$'\n'
        mount_fix+="# Verify: stat -c '%a' /tmp   # should end in 1 (e.g. 1777)"$'\n'
    fi

    # /dev/shm and /var/tmp (NEW Missing #11)
    for mpoint in /dev/shm /var/tmp; do
        [[ ! -d "$mpoint" ]] && continue
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
            mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev ${mpoint}   # immediate"$'\n'
            if [[ "$mpoint" == "/dev/shm" ]]; then
                mount_fix+="# Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"$'\n'
            else
                mount_fix+="# Add to /etc/fstab: /var/tmp /var/tmp bind defaults,noexec,nosuid,nodev,bind 0 0"$'\n'
            fi
        fi
    done

    if [[ ${#mount_issues[@]} -gt 0 ]]; then
        local mnt_issue_list
        mnt_issue_list=$(printf ' - %s\n' "${mount_issues[@]}")
        mount_fix+="# Verify all mounts:
/bin/mount | /bin/grep -E '/tmp|/dev/shm|/var/tmp'"
        report_issue 10 \
            "Insecure mount options on /tmp, /dev/shm, or /var/tmp" \
            "${#mount_issues[@]} mount issue(s) - missing noexec/nosuid/nodev or sticky bit" \
            "$mount_fix" \
            1 \
            "Issues:\n${mnt_issue_list}"
    fi

    # 6. Sudo timeout
    print_status "INFO" "Checking sudo password timeout..."
    local timeout_val
    timeout_val=$(sudo grep -oE 'timestamp_timeout=[0-9]+' \
                      /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
                  | grep -oE '[0-9]+$' | sort -n | tail -1 || true)
    if [[ -z "$timeout_val" || "$timeout_val" -gt 15 ]]; then
        report_issue 5 \
            "Sudo password timeout too long or unset" \
            "Timeout is ${timeout_val:-unset} minutes (should be ≤ 15)" \
            "echo 'Defaults timestamp_timeout=5' | sudo /usr/bin/tee /etc/sudoers.d/timeout
sudo /bin/chmod 440 /etc/sudoers.d/timeout
sudo /usr/sbin/visudo -c -f /etc/sudoers.d/timeout
sudo /usr/bin/grep timestamp_timeout /etc/sudoers /etc/sudoers.d/*" \
            1
    fi

    # 7. debsums
    prompt_install "debsums" "debsums"
    if command -v debsums >/dev/null; then
        print_status "INFO" "Running debsums integrity check..."
        local debsums_log
        debsums_log=$(mktemp "${REPORT_DIR}/debsums-audit-XXXXXX.log")
        sudo /usr/bin/debsums -c > "$debsums_log" 2>&1 || true
        if [[ -s "$debsums_log" ]]; then
            local debsums_pkgs
            debsums_pkgs=$(
                /usr/bin/awk '{print $1}' "$debsums_log" \
                | xargs -I{} /usr/bin/dpkg -S {} 2>/dev/null \
                | /usr/bin/cut -d: -f1 \
                | /usr/bin/sort -u \
                | /bin/grep -E '^[a-z0-9][a-z0-9.+-]+$' \
                || true
            )
            local debsums_fix_cmds
            debsums_fix_cmds="# Reinstall each package with modified files to restore originals:"$'\n'
            if [[ -n "$debsums_pkgs" ]]; then
                # FIX: build validated package list line-by-line, not via unquoted subshell
                local pkg_args=""
                while IFS= read -r pkg; do
                    # Only pass packages matching safe naming pattern
                    [[ "$pkg" =~ ^[a-z0-9][a-z0-9.+-]+$ ]] && pkg_args+=" $pkg"
                done <<< "$debsums_pkgs"
                [[ -n "$pkg_args" ]] && debsums_fix_cmds+="sudo /usr/bin/apt-get install --reinstall${pkg_args}"$'\n'
            else
                debsums_fix_cmds+="# Could not resolve packages automatically - run manually:
sudo /usr/bin/debsums -c
# Then for each failed file:  sudo /usr/bin/dpkg -S <file>  to find its package
# Then:  sudo /usr/bin/apt-get install --reinstall <package>"
            fi
            debsums_fix_cmds+=$'\n'"sudo /usr/bin/debsums -c   # re-verify after reinstall"
            report_issue 12 \
                "Package files modified (integrity violation)" \
                "System files differ from package checksums - possible tampering" \
                "$debsums_fix_cmds" \
                1 \
                "Full output: $debsums_log"
            append_report "##### debsums - Modified/Failed Files\n\`\`\`\n$(< "$debsums_log")\n\`\`\`"
            append_report "**Full log:** $debsums_log"
        fi
    fi

    # 8. rkhunter
    prompt_install "rkhunter" "rkhunter"
    if command -v rkhunter >/dev/null; then
        print_status "INFO" "Running rkhunter rootkit scan..."
        local rk_log
        rk_log=$(mktemp "${REPORT_DIR}/rkhunter-audit-XXXXXX.log")
        sudo /usr/bin/rkhunter --update --quiet 2>/dev/null || true
        sudo /usr/bin/rkhunter --check --skip-keypress --quiet --logfile "$rk_log" 2>&1 || true
        local rk_failures
        rk_failures=$(grep -E "\[ (Warning|FAILED|CRITICAL|INFECTED) \]|^Warning:|Rootkit|Suspect|HIDDEN" \
                      "$rk_log" 2>/dev/null || true)
        if [[ -n "$rk_failures" ]]; then
            report_issue 18 \
                "rkhunter detected warnings / suspicious items" \
                "Possible rootkits, hidden files, or modified binaries detected" \
                "sudo /usr/bin/rkhunter --propupd
sudo /usr/bin/rkhunter --check --skip-keypress
sudo /usr/bin/less ${rk_log}" \
                1 \
                "Full log: $rk_log"
            append_report "##### rkhunter - Failures & Warnings Only\n\`\`\`\n${rk_failures}\n\`\`\`"
            append_report "**Full log (all checks):** $rk_log"
        fi
    fi

    # 9. ClamAV
    prompt_install "clamscan" "clamav"
    if command -v clamscan >/dev/null; then
        print_status "INFO" "Updating ClamAV virus definitions..."
        # Suppress the 'NotifyClamd: Can't find clamd.conf' error with 2>/dev/null
        # Timeout prevents hanging indefinitely if freshclam is slow/blocked
        if timeout 120 sudo /usr/bin/freshclam --quiet 2>/dev/null; then
            print_status "OK" "ClamAV definitions updated"
        else
            print_status "WARN" "freshclam update timed out or failed - scanning with existing definitions (clamd daemon not required for clamscan)"
        fi

        print_status "INFO" "Running targeted ClamAV scan (critical directories only)..."
        local clam_log
        clam_log=$(mktemp "${REPORT_DIR}/clamav-audit-XXXXXX.log")
        # FIX: 30-minute timeout prevents indefinite hang
        timeout 1800 sudo /usr/bin/clamscan -r -i \
            --exclude-dir='^/proc' --exclude-dir='^/sys' --exclude-dir='^/dev' \
            /home /root /tmp /var /etc /usr/bin /usr/sbin /bin /sbin > "$clam_log" 2>&1 || true

        local infected_count
        infected_count=$(grep -oP 'Infected files: \K\d+' "$clam_log" 2>/dev/null || echo 0)

        if [[ "$infected_count" -gt 0 ]]; then
            local infected_lines
            infected_lines=$(grep ' FOUND$' "$clam_log" || true)

            local clam_fix_cmds
            clam_fix_cmds="# Create a private quarantine directory:"$'\n'
            clam_fix_cmds+="QUARANTINE_DIR=\$(sudo /bin/mktemp -d /var/clam-quarantine-XXXXXX)"$'\n'
            clam_fix_cmds+="sudo /bin/chmod 700 \"\$QUARANTINE_DIR\""$'\n'
            clam_fix_cmds+="# Move each infected file to quarantine:"$'\n'
            while IFS= read -r found_line; do
                local fpath
                fpath=$(echo "$found_line" | /usr/bin/cut -d: -f1)
                clam_fix_cmds+="sudo /usr/bin/clamscan --move=\"\$QUARANTINE_DIR\" $(printf '%q' "$fpath")"$'\n'
            done <<< "$infected_lines"
            clam_fix_cmds+="# Review quarantined files before deleting:"$'\n'
            clam_fix_cmds+="sudo /bin/ls -lah \"\$QUARANTINE_DIR\""$'\n'
            clam_fix_cmds+="# Delete each file individually AFTER review (do NOT use rm -rf blindly):"$'\n'
            clam_fix_cmds+="# sudo /bin/rm \"\$QUARANTINE_DIR/<filename>\""$'\n'
            clam_fix_cmds+="# Re-scan to confirm clean:"$'\n'
            clam_fix_cmds+="sudo /usr/bin/clamscan -r -i /home /root /tmp /var /etc /usr/bin /usr/sbin /bin /sbin"

            report_issue 25 \
                "ClamAV detected infected/malware files" \
                "Live malware or viruses found on the system (critical - act immediately)" \
                "$clam_fix_cmds" \
                1 \
                "Full scan log: $clam_log"
            append_report "##### ClamAV - Infected Files Found (${infected_count} total)\n\`\`\`\n${infected_lines}\n\`\`\`"
            append_report "**Full scan log:** $clam_log"
            append_report "**Next step:** Quarantine the files above, then review and delete individually"
        fi
    fi

    prompt_install "auditd" "auditd"
    if command -v auditd >/dev/null; then
        if ! /bin/systemctl is-active --quiet auditd; then
            report_issue 7 \
                "auditd not running" \
                "System auditing is disabled - suspicious activity goes unlogged" \
                "sudo /bin/systemctl enable --now auditd
sudo /bin/systemctl status auditd
sudo /usr/sbin/aureport --summary" \
                1
        else
            # Check that meaningful rules are loaded
            local audit_rules
            audit_rules=$(sudo /sbin/auditctl -l 2>/dev/null || true)
            local rule_count
            rule_count=$(echo "$audit_rules" | grep -cE '^-[aw]' || true)
            if [[ "${rule_count:-0}" -lt 1 ]] || echo "$audit_rules" | grep -qE '^No rules|^LIST_RULES'; then
                print_status "WARN" "auditd is running but no meaningful rules are loaded"
                append_report "## Deep: auditd Rules\n- 🔴 auditd running with empty/default ruleset"
                report_issue 5 \
                    "auditd running with no rules loaded" \
                    "auditd service is active but no rules are defined - suspicious activity is not captured" \
                    "# Install CIS-aligned audit rules:
sudo /usr/bin/apt-get install -y auditd audispd-plugins
sudo /usr/bin/tee /etc/audit/rules.d/99-hardening.rules << 'AUDITEOF'
# Privilege escalation
-a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/sudo -k priv_esc
# Identity file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
# Unauthorized access attempts
-a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauth_access
AUDITEOF
sudo /usr/sbin/augenrules --load
# Verify rules loaded:
sudo /sbin/auditctl -l" \
                    1
            else
                print_status "OK" "auditd is running with ${rule_count} rule(s) loaded"
                append_report "## Deep: auditd Rules\n- 🟢 auditd running with ${rule_count} rule(s)"
            fi
        fi
    fi

    # 11. Lynis
    prompt_install "lynis" "lynis"
    if command -v lynis >/dev/null; then
        print_status "INFO" "Running Lynis system audit..."
        local lynis_log
        lynis_log=$(mktemp "${REPORT_DIR}/lynis-audit-XXXXXX.log")
        sudo /usr/sbin/lynis audit system --quiet > "$lynis_log" 2>&1 || true
        local lynis_any_findings
        lynis_any_findings=$(grep -E "(WARNING|FAILED|vulnerable)" "$lynis_log" || true)
        if [[ -n "$lynis_any_findings" ]]; then
            report_issue 15 \
                "Lynis detected warnings or failures" \
                "System audit found high-priority security issues" \
                "# Re-run Lynis interactively to see remediation hints per finding:
sudo /usr/sbin/lynis audit system
# Or show only warnings from the saved log:
sudo /bin/grep -E '(WARNING|FAILED|vulnerable)' \"${lynis_log}\"
# Full log for all suggestions and details:
sudo /usr/bin/less \"${lynis_log}\"" \
                1 \
                "Full log (includes all suggestions): $lynis_log"
            append_report "##### Lynis - Warnings & Failures Only\n\`\`\`\n${lynis_any_findings}\n\`\`\`"
            append_report "**Full log (all checks + suggestions):** $lynis_log"
        fi
    fi

    # 12. Authorized keys
    print_status "INFO" "Checking authorized_keys files..."
    local auth_keys
    # FIX: wrap -name predicates in \( \) so -type f applies to both, not just authorized_keys2
    auth_keys=$(find /home /root \( -name authorized_keys -o -name authorized_keys2 \) -type f 2>/dev/null | head -10 || true)
    if [[ -n "$auth_keys" ]]; then
        append_report "## Deep: SSH Authorized Keys\n\`\`\`\n$auth_keys\n\`\`\`"
    fi

    # NEW 13. User SSH private key permissions (Missing #16)
    print_status "INFO" "Checking user SSH private key permissions..."
    local user_key_issues=0
    while IFS= read -r keyfile; do
        local kperms kowner
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        # Private keys must not be readable by group or others (any of 077 bits set)
        if [[ -n "$kperms" ]] && (( (8#$kperms & 8#077) != 0 )); then
            print_status "WARN" "Private key too permissive: $keyfile ($kperms, owned by $kowner)"
            append_report "## Deep: SSH User Key Permissions\n- 🔴 $keyfile: $kperms (should be 600)"
            report_issue 10 \
                "User SSH private key has insecure permissions: $(basename "$keyfile")" \
                "Private key $keyfile is ${kperms} - readable by group/others (credential exposure)" \
                "sudo /bin/chmod 600 $(printf '%q' "$keyfile")
# Verify:
/usr/bin/stat -c '%n %a %U' $(printf '%q' "$keyfile")" \
                1
            user_key_issues=$((user_key_issues + 1))
        fi
    done < <(find /home /root -name 'id_*' ! -name '*.pub' -type f 2>/dev/null)
    if [[ $user_key_issues -eq 0 ]]; then
        print_status "OK" "No world/group-readable user SSH private keys found"
        append_report "## Deep: SSH User Key Permissions\n- 🟢 User private SSH keys are properly restricted"
    fi

    # NEW 14. File capabilities scan (from review doc)
    print_status "INFO" "Scanning file capabilities..."
    if command -v getcap >/dev/null 2>&1; then
        local caps_output
        caps_output=$(getcap -r / 2>/dev/null | grep -v ' = $' || true)
        if [[ -n "$caps_output" ]]; then
            local caps_count
            caps_count=$(echo "$caps_output" | wc -l)
            print_status "WARN" "Found $caps_count file(s) with capabilities set - review for necessity"
            append_report "## Deep: File Capabilities\n\`\`\`\n${caps_output}\n\`\`\`"
            report_issue 5 \
                "Files with Linux capabilities set" \
                "$caps_count file(s) have capabilities - unnecessary caps are privilege escalation vectors" \
                "# Review each capability; remove unnecessary ones:
getcap -r / 2>/dev/null | grep -v ' = $'
# Remove a capability from a specific file:
# sudo /usr/sbin/setcap -r <file>
# Example: python with cap_net_raw that doesn't need it:
# sudo /usr/sbin/setcap -r /usr/bin/python3.x
# Verify after removal:
getcap -r / 2>/dev/null" \
                1 \
                "Files with capabilities (first 20):\n$(echo "$caps_output" | head -20)"
        else
            print_status "OK" "No unexpected file capabilities found"
            append_report "## Deep: File Capabilities\n- 🟢 No unnecessary capabilities detected"
        fi
    else
        print_status "INFO" "getcap not available - skipping file capabilities scan"
    fi
}


check_ntp() {
    print_status "INFO" "Checking NTP time synchronization..."
    local ntp_ok=0

    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        local sync_status
        sync_status=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
        if [[ "$sync_status" == "yes" ]]; then
            print_status "OK" "systemd-timesyncd active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 systemd-timesyncd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v chronyc >/dev/null 2>&1; then
        if systemctl is-active --quiet chronyd 2>/dev/null && \
           chronyc tracking 2>/dev/null | grep -q "Leap status.*Normal"; then
            print_status "OK" "chrony is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 chrony synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v ntpq >/dev/null 2>&1; then
        if ntpq -p 2>/dev/null | grep -q '^\*'; then
            print_status "OK" "ntpd is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 ntpd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]]; then
        print_status "WARN" "NTP not synchronized or not running"
        append_report "## NTP Synchronization\n- 🔴 NTP not active or not synchronized"
        report_issue 5 \
            "NTP synchronization not active" \
            "System clock may drift - accurate time is essential for log correlation and audit trails" \
            "sudo /bin/systemctl enable --now systemd-timesyncd
sudo timedatectl set-ntp true
timedatectl status
timedatectl show --property=NTPSynchronized" \
            0
    fi
}

check_grub_password() {
    print_status "INFO" "Checking GRUB bootloader password protection..."
    local grub_pw_set=0
    if grep -rqE '^\s*password_pbkdf2\s' /boot/grub/grub.cfg /etc/grub.d/ 2>/dev/null; then
        grub_pw_set=1
    fi
    if [[ $grub_pw_set -eq 1 ]]; then
        print_status "OK" "GRUB bootloader password is configured"
        append_report "## GRUB Bootloader Password\n- 🟢 GRUB password protection configured"
    else
        print_status "WARN" "GRUB bootloader has no password protection"
        append_report "## GRUB Bootloader Password\n- 🔴 GRUB not password protected"
        report_issue 6 \
            "GRUB bootloader not password protected" \
            "Without a GRUB password, anyone with physical access can boot into recovery mode and gain root" \
            '# 1. Generate a GRUB password hash (run interactively):
grub-mkpasswd-pbkdf2
# 2. Add to /etc/grub.d/40_custom:
sudo /bin/tee -a /etc/grub.d/40_custom <<EOF
set superusers="root"
password_pbkdf2 root <PASTE_HASH_HERE>
EOF
sudo /bin/chmod 700 /etc/grub.d/40_custom
# 3. Rebuild grub.cfg:
sudo /usr/sbin/update-grub
# 4. Verify:
sudo /bin/grep -E "password_pbkdf2|superusers" /boot/grub/grub.cfg' \
            0 \
            "Physical access without a GRUB password bypasses all OS-level controls"
    fi
}

# ====================== MAIN AUDIT RUNNER =======================
print_status "INFO" "Starting Ubuntu Security Audit..."

# Standard checks
check_updates
check_firewall
check_open_ports
check_ssh
check_users
check_permissions
check_unattended
check_apparmor
check_failed_logins
check_kernel
check_reboot
check_cron
check_pam_lockout
check_core_dumps
check_umask
check_login_banner
check_pam_pwquality
check_secure_boot
check_root_path
check_home_permissions
check_journald
check_apt_repos
check_unnecessary_packages
check_ntp
check_grub_password

# Deep checks
if [[ $DEEP -eq 1 ]]; then
    run_deep_checks
fi

# ====================== SCORE & GRADE ======================
[[ $SCORE -lt 0 ]] && SCORE=0
if   [[ $SCORE -ge 90 ]]; then GRADE="A"; COLOR="🟢"
elif [[ $SCORE -ge 80 ]]; then GRADE="B"; COLOR="🟡"
elif [[ $SCORE -ge 70 ]]; then GRADE="C"; COLOR="🟡"
elif [[ $SCORE -ge 60 ]]; then GRADE="D"; COLOR="🔴"
else                            GRADE="F"; COLOR="🔴"
fi

# ====================== FINAL REPORT ======================
append_report "
## Executive Summary (Final)
**Overall Security Score:** $SCORE/100 $COLOR ($GRADE)
**Issues found:** $ISSUE_COUNT total ($DEEP_ISSUE_COUNT in Deep mode)

## Quick Remediation Commands (Copy-Paste Ready)
$(printf '%s\n\n' "${ISSUES[@]}")

## Actionable Recommendations
$( [[ $SCORE -lt 90 ]] && echo "- Run the Quick Remediation section above immediately" || echo "- System is well maintained" )
$( [[ $DEEP -eq 0 ]] && echo "- Re-run with \`--deep\` for full attack-surface coverage (includes ClamAV + Lynis)" || echo "- Deep mode complete - review warnings only" )
- For full antivirus scan run: \`sudo clamscan -r -i /\` manually
- Review report and apply fixes in priority order (🔴 first).

## Appendix
- Generated by ubuntu-security-audit.sh (Deep mode: $([[ $DEEP -eq 1 ]] && echo enabled || echo disabled))
"

# ====================== FIX SCRIPT GENERATION ======================
FIX_SCRIPT="${REPORT_DIR}/fix-audit-$(date +%Y%m%d-%H%M).sh"
cat > "$FIX_SCRIPT" << 'FIX'
#!/usr/bin/env bash
# =========================================================
# Ubuntu Security Audit - Auto-generated Fix Script
# Review EACH block carefully before running.
# Run individual sections; do NOT blindly execute the whole
# script without understanding each command first.
# =========================================================
set -euo pipefail
echo "=== Ubuntu Security Fix Script ==="
echo "Review each block before running!"
echo ""
FIX

for i in "${!REMEDIATIONS[@]}"; do
    fix_title="${TITLES[$i]:-Fix $((i+1))}"
    printf '\n# ======================================================\n' >> "$FIX_SCRIPT"
    printf '# Fix %d: %s\n' "$((i+1))" "$fix_title"              >> "$FIX_SCRIPT"
    printf '# ======================================================\n' >> "$FIX_SCRIPT"
    printf '%s\n'           "${REMEDIATIONS[$i]}"                 >> "$FIX_SCRIPT"
done

chmod 700 "$FIX_SCRIPT"

print_status "OK" "Audit complete! Report saved to $REPORT_FILE"
print_status "INFO" "Quick-fix script created: $FIX_SCRIPT"

# ====================== TERMINAL SUMMARY ======================
echo -e "\n${BOLD}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║               SECURITY AUDIT COMPLETE                      ║${RESET}"
echo -e "${BOLD}╠════════════════════════════════════════════════════════════╣${RESET}"
echo -e "   Score : ${COLOR}$SCORE/100 ($GRADE)${RESET}"
echo -e "   Mode  : $([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")"
echo -e "   Report: $REPORT_FILE"
echo -e "   Fix script: $FIX_SCRIPT"
echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${RESET}"
echo -e "\nNext steps:"
echo "   • less $REPORT_FILE"
echo "   • Review warnings in Deep sections"
echo "   • Run the Quick Remediation blocks"
echo "   • Re-run with --deep for maximum coverage"
