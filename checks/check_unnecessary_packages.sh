# shellcheck shell=bash
# check_unnecessary_packages — standard check (sourced by ubuntu-sec-audit.sh)

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
