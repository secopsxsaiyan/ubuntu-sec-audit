# shellcheck shell=bash
# check_failed_logins — standard check (sourced by ubuntu-sec-audit.sh)

check_failed_logins() {
    print_status "INFO" "Analyzing failed logins..."
    local fails
    # A missing journal (containers) counts as no failures, not as an error.
    fails=$( { journalctl -u ssh --since "1 day ago" 2>/dev/null || true; } \
            | awk '/Failed password/{c++} END{print c+0}')
    if [[ "$fails" -le $FAILED_LOGIN_THRESHOLD ]]; then
        print_status "OK" "No unusual failed logins"
        append_report "## Failed Logins\n- 🟢 Normal"
        return 0
    fi

    # An internet-facing host always sees password guesses, and fail2ban
    # bans an address only after maxretry failures, so the count alone can
    # never clear. With an active sshd jail the guessing is being dealt with.
    if command -v fail2ban-client >/dev/null 2>&1 \
       && timeout 10 fail2ban-client status sshd >/dev/null 2>&1; then
        print_status "INFO" "${fails} failed SSH password attempts in 24h; the fail2ban sshd jail bans repeat offenders"
        append_report "## Failed Logins\n- 🟢 ${fails} failed attempts (last 24h), mitigated by the fail2ban sshd jail"
        return 0
    fi

    print_status "WARN" "Many failed login attempts"
    append_report "## Failed Logins\n- 🟡 $fails failed attempts (last 24h)"
    # Nothing to run here: the fixes belong to other checks (check_fail2ban
    # installs and configures the jail; check_ssh covers password logins).
    report_issue 6 \
        "High failed login count" \
        "Possible brute-force attack on SSH ($fails failures in 24h) and no fail2ban sshd jail is banning the sources" \
        "# Failed logins cannot be fixed directly; make them harmless:
# 1. Ban repeat offenders: apply the fix for check_fail2ban (\"Fail2Ban not
#    installed\", \"not running\" or \"without SSH jail\"), which sets up the
#    sshd jail. This finding clears once 'fail2ban-client status sshd' works.
# 2. Better, accept no SSH passwords at all: once every admin has a working
#    key, set 'PasswordAuthentication no' (see check_ssh).
# Review the recent failures:
#   sudo journalctl -u ssh --since '1 day ago' | grep 'Failed password' | tail -20" \
        0 \
        "Review /var/log/auth.log and consider key-only SSH authentication"
}
