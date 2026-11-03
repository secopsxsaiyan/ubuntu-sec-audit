# shellcheck shell=bash
# check_pam_lockout — standard check (sourced by ubuntu-sec-audit.sh)

# Settings are replaced in place so other faillock.conf options survive.
_FAILLOCK_CONF_FIX="sudo /bin/sed -i -E '/^[[:space:]]*(deny|unlock_time|fail_interval|even_deny_root|audit)([[:space:]]|=|\$)/d' /etc/security/faillock.conf
sudo /usr/bin/tee -a /etc/security/faillock.conf > /dev/null << 'FAILLOCKEOF'
deny = 5
unlock_time = 900
fail_interval = 900
even_deny_root
audit
FAILLOCKEOF"

check_pam_lockout() {
    print_status "INFO" "Checking PAM brute-force lockout (faillock/tally2)..."

    local pam_ok=0 conf="${AUDIT_ROOT}/etc/security/faillock.conf"

    if [[ -n "$(_pam_lines pam_faillock)" ]]; then
        # Effective values: PAM arguments and faillock.conf, defaults when
        # unset (deny=3, unlock_time=600). CIS: deny ≤ 5, unlock_time 0 or ≥ 900.
        local faillock_deny unlock_time
        faillock_deny=$( { _pam_arg pam_faillock deny; _conf_get deny "$conf"; } \
                         | grep -E '^[0-9]+$' | sort -n | tail -n 1 || true)
        unlock_time=$( { _conf_get unlock_time "$conf"; _pam_arg pam_faillock unlock_time; } \
                       | grep -E '^[0-9]+$' | tail -n 1 || true)
        faillock_deny="${faillock_deny:-3}"
        unlock_time="${unlock_time:-600}"
        if [[ "$faillock_deny" -eq 0 || "$faillock_deny" -gt 5 ]] \
           || [[ "$unlock_time" -ne 0 && "$unlock_time" -lt 900 ]]; then
            print_status "WARN" "pam_faillock present but thresholds not strict enough (deny=${faillock_deny}, unlock_time=${unlock_time})"
            append_report "## PAM Brute-Force Lockout\n- 🟡 pam_faillock present but not strict enough"
            report_issue 5 \
                "pam_faillock configured but lockout thresholds too permissive" \
                "deny is ${faillock_deny} (should be 1-5) and/or unlock_time is ${unlock_time} (should be 0 or ≥ 900)" \
                "${_FAILLOCK_CONF_FIX}
/bin/grep -vE '^[[:space:]]*(#|\$)' /etc/security/faillock.conf" \
                0
        else
            print_status "OK" "pam_faillock is configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
            append_report "## PAM Brute-Force Lockout\n- 🟢 pam_faillock configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
        fi
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 && -n "$(_pam_lines pam_tally2)" ]]; then
        print_status "OK" "pam_tally2 is configured in PAM"
        append_report "## PAM Brute-Force Lockout\n- 🟢 pam_tally2 configured"
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 ]]; then
        print_status "WARN" "No PAM brute-force lockout configured"
        append_report "## PAM Brute-Force Lockout\n- 🔴 No pam_faillock or pam_tally2 found"
        # faillock.conf is safe to write (it only matters once pam_faillock is
        # in the stack). Editing the PAM stack is left to a person: a mistake
        # there can block every login, and Ubuntu ships no faillock profile,
        # so 'pam-auth-update --enable faillock' alone does nothing.
        report_issue 8 \
            "No PAM brute-force lockout configured" \
            "pam_faillock is not active - accounts are not locked after repeated failed logins" \
            "# 1. Lockout thresholds (used once pam_faillock is enabled):
${_FAILLOCK_CONF_FIX}
# 2. Enable pam_faillock BY HAND. Keep a root shell open while testing.
#    Create the CIS benchmark's two pam-auth-update profiles:
#    /usr/share/pam-configs/faillock
#      Name: Enable pam_faillock to deny access
#      Default: yes
#      Priority: 0
#      Auth-Type: Primary
#      Auth:
#          [default=die] pam_faillock.so authfail
#    /usr/share/pam-configs/faillock_notify
#      Name: Notify of failed login attempts and reset count upon success
#      Default: yes
#      Priority: 1024
#      Auth-Type: Primary
#      Auth:
#          requisite pam_faillock.so preauth
#      Account-Type: Primary
#      Account:
#          required pam_faillock.so
#    then:  sudo pam-auth-update --enable faillock --enable faillock_notify
#    and confirm a login works from a second terminal before logging out." \
            0 \
            "Also consider Fail2Ban as a complementary layer"
    fi
}
