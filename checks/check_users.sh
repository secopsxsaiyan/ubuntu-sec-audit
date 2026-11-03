# shellcheck shell=bash
# check_users — standard check (sourced by ubuntu-sec-audit.sh)

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
