# shellcheck shell=bash
# check_users — standard check (sourced by ubuntu-sec-audit.sh)

# _sudoers_nopasswd_all FILE... — "file:line: rule" for each rule that lets
# someone run ALL commands without a password. NOPASSWD: applies to the
# commands after it until a PASSWD: tag; a rule limited to named commands
# (e.g. "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app") is not
# reported. Continued lines (trailing backslash) are joined.
_sudoers_nopasswd_all() {
    [[ $# -gt 0 ]] || return 0
    awk '
        FNR == 1 { cont = "" }
        {
            line = $0
            if (cont != "") { line = cont " " line } else { start = FNR }
            if (line ~ /\\$/) { cont = substr(line, 1, length(line) - 1); next }
            cont = ""
            sub(/^[ \t]+/, "", line)
            # "#" starts a comment unless a digit follows (#1000 is a user ID).
            if (line ~ /^#/ && line !~ /^#[0-9]/) next
            sub(/[ \t]+#([^0-9].*)?$/, "", line)
            if (line ~ /^(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|Cmd_Alias|@include)/) next
            if (index(line, "NOPASSWD:") == 0) next
            s = line
            gsub(/NOPASSWD:/, ",@NOPW@,", s)
            gsub(/PASSWD:/, ",@PW@,", s)
            n = split(s, tok, ",")
            nopw = 0
            for (i = 1; i <= n; i++) {
                t = tok[i]
                gsub(/^[ \t]+|[ \t]+$/, "", t)
                if (t == "@NOPW@") { nopw = 1; continue }
                if (t == "@PW@")   { nopw = 0; continue }
                sub(/^\([^)]*\)[ \t]*/, "", t)        # Runas_Spec
                sub(/^([A-Z_]+:[ \t]*)+/, "", t)      # other tags (SETENV: ...)
                if (nopw && t == "ALL") {
                    print FILENAME ":" start ": " line
                    break
                }
            }
        }' "$@" 2>/dev/null || true
}

check_users() {
    print_status "INFO" "Checking users & sudo..."
    local passwd_file="${AUDIT_ROOT}/etc/passwd"

    local sudoers
    local -a sudoers_files=()
    mapfile -t sudoers_files < <(_sudoers_files)
    sudoers=$(_sudoers_nopasswd_all "${sudoers_files[@]}")
    sudoers="${sudoers//"${AUDIT_ROOT}/etc/"//etc/}"
    if [[ -n "$sudoers" ]]; then
        print_status "WARN" "Users with NOPASSWD sudo found"
        append_report "## Users & Sudo\n- 🟡 Full sudo privileges found"
        # Manual: a person has to decide which rules stay; an unattended
        # visudo would just hang waiting for an editor.
        report_issue 8 \
            "Users with NOPASSWD sudo" \
            "Users can run any command as root without password" \
            "# Edit each file listed in the note with visudo (never directly):
#   sudo visudo -f /etc/sudoers.d/<file>
# Remove NOPASSWD or restrict it to specific commands, e.g.
#   username ALL=(ALL) NOPASSWD: ALL   ->   username ALL=(ALL) ALL
# Make sure the account has a password first (sudo passwd <username>),
# then check the syntax:  sudo visudo -c" \
            0 \
            "Rules found:\n${sudoers}"
    else
        print_status "OK" "No dangerous sudoers"
        append_report "## Users & Sudo\n- 🟢 No dangerous sudo privileges"
    fi

    local plain_pw_users
    plain_pw_users=$(awk -F: '($2 != "x" && $2 != "*" && $2 != "!" && $2 != "") {print $1}' "$passwd_file" 2>/dev/null || true)
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

    # An empty password field means /etc/shadow is never consulted: the
    # account has no password at all and, wherever PAM allows it (nullok),
    # anyone can log in as it. "passwd -l" alone would only lock the shadow
    # entry, so the field is moved to /etc/shadow first (CIS 7.2.1), then
    # locked there. Key-based SSH logins keep working. NIS "+"/"-" lines are
    # not accounts.
    local empty_pw_users
    empty_pw_users=$(awk -F: 'NF > 1 && $2 == "" && $1 !~ /^[+-]/ {print $1}' "$passwd_file" 2>/dev/null || true)
    if [[ -n "$empty_pw_users" ]]; then
        local empty_fix name
        empty_fix="# Move the password field to /etc/shadow, then lock it there:"$'\n'
        empty_fix+="sudo /usr/sbin/pwconv"$'\n'
        while IFS= read -r name; do
            empty_fix+="sudo /usr/bin/passwd -l $(printf '%q' "$name")"$'\n'
        done <<< "$empty_pw_users"
        empty_fix+="# Verify (no output expected):
/usr/bin/awk -F: '\$2 == \"\" {print \$1}' /etc/passwd"
        print_status "ERR" "Accounts with an empty password field in /etc/passwd"
        append_report "## Users & Sudo\n- 🔴 Accounts with an empty password field in /etc/passwd"
        report_issue 15 \
            "Accounts with an empty password field in /etc/passwd" \
            "These accounts have no password and /etc/shadow is not consulted for them - anyone can log in as them wherever empty passwords are allowed (nullok)" \
            "$empty_fix" \
            0 \
            "Affected accounts: $(echo "$empty_pw_users" | tr '\n' ' ')"
    fi

    # System accounts (UID below UID_MIN, except root) should not have an
    # interactive shell (CIS 5.4.2.7). Regular users - including key-only
    # admins with a locked password, like the cloud-image "ubuntu" user -
    # are left alone: changing their shell would lock them out.
    local uid_min sys_with_shell
    uid_min=$(_uid_min)
    sys_with_shell=$(awk -F: -v min="$uid_min" '
        $3 != 0 && $3 < min && $7 ~ /\/(bash|sh|dash|zsh|ksh|fish|csh|tcsh|rbash)$/ {print $1 " (" $7 ")"}
    ' "$passwd_file" 2>/dev/null || true)
    if [[ -n "$sys_with_shell" ]]; then
        local shell_fix="" name
        while IFS= read -r name; do
            name="${name%% *}"
            shell_fix+="sudo /usr/sbin/usermod -s /usr/sbin/nologin $(printf '%q' "$name")"$'\n'
        done <<< "$sys_with_shell"
        shell_fix+="# Verify (no output expected):
/usr/bin/awk -F: -v min=${uid_min} '\$3 != 0 && \$3 < min && \$7 ~ /sh\$/ {print \$1, \$7}' /etc/passwd"
        print_status "WARN" "System accounts with interactive login shells detected"
        append_report "## Users & Sudo\n- 🟡 System accounts have interactive shells"
        report_issue 5 \
            "System accounts with interactive login shells" \
            "Accounts below UID ${uid_min} (other than root) have a login shell; they should use nologin" \
            "$shell_fix" \
            0 \
            "Affected accounts: $(echo "$sys_with_shell" | tr '\n' ' ')"
    fi

    local uid0_count
    uid0_count=$(awk -F: '$3==0 {n++} END {print n+0}' "$passwd_file" 2>/dev/null || echo 0)
    if [[ $uid0_count -gt 1 ]]; then
        print_status "ERR" "Multiple root (UID 0) accounts found"
        append_report "## Users & Sudo\n- 🔴 Multiple UID 0 accounts"
        report_issue 12 \
            "Multiple UID 0 accounts" \
            "More than one account with root privileges (privilege escalation risk)" \
            "# List them, then lock every one that is not root:
#   awk -F: '\$3==0 {print \$1}' /etc/passwd
#   sudo usermod -L <username> && sudo usermod -s /usr/sbin/nologin <username>" \
            0 \
            "UID 0 accounts: $(awk -F: '$3==0 {printf "%s ", $1}' "$passwd_file" 2>/dev/null)"
    fi
}
