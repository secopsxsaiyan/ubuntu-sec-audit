# shellcheck shell=bash
# check_pam_pwquality — standard check (sourced by ubuntu-sec-audit.sh)

_PWQUALITY_FIX="sudo /bin/sed -i -E '/^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit)[[:space:]]*=/d' /etc/security/pwquality.conf
sudo /usr/bin/tee -a /etc/security/pwquality.conf > /dev/null << 'PWQEOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
PWQEOF
# Verify:
/bin/grep -vE '^[[:space:]]*(#|$)' /etc/security/pwquality.conf"

check_pam_pwquality() {
    print_status "INFO" "Checking PAM password complexity (pwquality/cracklib)..."
    local pq_ok=0

    if [[ -n "$(_pam_lines pam_pwquality)" ]]; then
        # Smallest minlen wins (a PAM argument overrides the config files);
        # libpwquality's built-in default is 8.
        local minlen
        minlen=$( { _pam_arg pam_pwquality minlen
                    _conf_get minlen "${AUDIT_ROOT}/etc/security/pwquality.conf" \
                                     "${AUDIT_ROOT}/etc/security/pwquality.conf.d/"*.conf; } \
                  | grep -E '^[0-9]+$' | sort -n | head -n 1 || true)
        minlen="${minlen:-8}"

        if [[ "$minlen" -lt 14 ]]; then
            print_status "WARN" "pam_pwquality present but minlen=${minlen} (should be ≥ 14)"
            append_report "## PAM Password Complexity\n- 🟡 pam_pwquality present but minlen too low (${minlen})"
            report_issue 5 \
                "pam_pwquality minlen too low" \
                "Password minimum length is ${minlen} (CIS requires ≥ 14)" \
                "$_PWQUALITY_FIX" \
                0
        else
            print_status "OK" "pam_pwquality configured (minlen=${minlen})"
            append_report "## PAM Password Complexity\n- 🟢 pam_pwquality configured (minlen=${minlen})"
        fi
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 && -n "$(_pam_lines pam_cracklib)" ]]; then
        print_status "OK" "pam_cracklib configured"
        append_report "## PAM Password Complexity\n- 🟢 pam_cracklib configured"
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 ]]; then
        print_status "WARN" "No PAM password complexity enforcement found (pwquality/cracklib)"
        append_report "## PAM Password Complexity\n- 🔴 No password complexity enforcement"
        # Installing libpam-pwquality adds it to the PAM stack through its own
        # pam-auth-update profile.
        report_issue 7 \
            "No PAM password complexity enforcement" \
            "pam_pwquality and pam_cracklib are not configured - users can set trivially weak passwords" \
            "sudo /usr/bin/apt-get install -y libpam-pwquality
${_PWQUALITY_FIX}" \
            0
    fi
}
