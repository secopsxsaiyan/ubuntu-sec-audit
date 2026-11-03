# shellcheck shell=bash
# check_deep_empty_passwords / _password_aging / _sudo_timeout — deep checks

check_deep_empty_passwords() {
    print_status "INFO" "Checking for empty passwords..."
    local empty_pw user fix
    empty_pw=$(awk -F: '$2=="" {print $1}' "${AUDIT_ROOT}/etc/shadow" 2>/dev/null || true)
    if [[ -z "$empty_pw" ]]; then
        print_status "OK" "No accounts with empty passwords"
        append_report "## Deep: Empty Passwords\n- 🟢 None"
        return 0
    fi
    fix="# Lock each account with an empty password immediately:"$'\n'
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        fix+="sudo /usr/bin/passwd -l $(printf '%q' "$user")"$'\n'
        fix+="sudo /usr/sbin/usermod -s /usr/sbin/nologin $(printf '%q' "$user")"$'\n'
    done <<< "$empty_pw"
    fix+="sudo /usr/bin/awk -F: '\$2==\"\" {print \$1}' /etc/shadow"
    report_issue 20 \
        "Accounts with empty passwords found" \
        "These accounts have no password set (critical risk)" \
        "$fix" \
        1 \
        "Affected users: $(tr '\n' ' ' <<< "$empty_pw")"
}

check_deep_password_aging() {
    print_status "INFO" "Checking password policy (login.defs)..."
    local max_days
    max_days=$(awk '$1 == "PASS_MAX_DAYS" {print $2; exit}' "${AUDIT_ROOT}/etc/login.defs" 2>/dev/null || true)
    if [[ "$max_days" =~ ^[0-9]+$ ]] && [[ "$max_days" -le 90 ]]; then
        print_status "OK" "PASS_MAX_DAYS is ${max_days}"
        append_report "## Deep: Password Aging\n- 🟢 PASS_MAX_DAYS=${max_days}"
        return 0
    fi
    report_issue 8 \
        "Weak password aging policy" \
        "PASS_MAX_DAYS not set or too high (${max_days:-unset}) in /etc/login.defs" \
        "sudo /bin/sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
/bin/grep '^PASS_' /etc/login.defs
# login.defs only applies to new accounts; for existing ones use, per user:
#   sudo chage --maxdays 90 --mindays 1 --warndays 14 <user>" \
        1
}

check_deep_sudo_timeout() {
    print_status "INFO" "Checking sudo password timeout..."
    # Unset means sudo's built-in default of 15 minutes, which complies.
    # A negative value means credentials never expire.
    local timeout_val
    timeout_val=$(grep -ohE 'timestamp_timeout=-?[0-9]+' \
                      "${AUDIT_ROOT}/etc/sudoers" "${AUDIT_ROOT}/etc/sudoers.d/"* 2>/dev/null \
                  | cut -d= -f2 | sort -n | tail -n 1 || true)
    if [[ -z "$timeout_val" ]] || [[ "$timeout_val" -ge 0 && "$timeout_val" -le 15 ]]; then
        print_status "OK" "sudo timeout is ${timeout_val:-the default (15)} minutes"
        append_report "## Deep: Sudo Timeout\n- 🟢 ${timeout_val:-15} minutes"
        return 0
    fi
    report_issue 5 \
        "Sudo password timeout too long" \
        "Timeout is ${timeout_val} minutes (should be 0-15)" \
        "echo 'Defaults timestamp_timeout=5' | sudo /usr/bin/tee /etc/sudoers.d/timeout
sudo /bin/chmod 440 /etc/sudoers.d/timeout
sudo /usr/sbin/visudo -c -f /etc/sudoers.d/timeout
# Also remove or lower the larger timestamp_timeout found in:
#   sudo grep -rn timestamp_timeout /etc/sudoers /etc/sudoers.d/" \
        1
}
