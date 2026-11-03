# shellcheck shell=bash
# check_pam_pwquality — standard check (sourced by ubuntu-sec-audit.sh)

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
