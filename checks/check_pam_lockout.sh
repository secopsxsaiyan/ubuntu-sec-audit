# shellcheck shell=bash
# check_pam_lockout — standard check (sourced by ubuntu-sec-audit.sh)

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
                "sudo /usr/bin/tee /etc/security/faillock.conf > /dev/null << 'FAILLOCKEOF'
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root = yes
audit = yes
FAILLOCKEOF
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
            "sudo /usr/bin/tee /etc/security/faillock.conf > /dev/null << 'FAILLOCKEOF'
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root = yes
audit = yes
FAILLOCKEOF
sudo /usr/sbin/pam-auth-update --enable faillock
/bin/grep -r pam_faillock /etc/pam.d/" \
            0 \
            "Also consider Fail2Ban as a complementary layer"
    fi
}
