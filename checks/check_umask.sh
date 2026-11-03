# shellcheck shell=bash
# check_umask — standard check (sourced by ubuntu-sec-audit.sh)

check_umask() {
    print_status "INFO" "Checking default umask for login shells..."
    local umask_val=""
    # Field comparison, not \s: Ubuntu's default awk (mawk) has no \s.
    umask_val=$(awk '$1 == "UMASK" {print $2; exit}' "${AUDIT_ROOT}/etc/login.defs" 2>/dev/null || true)
    if [[ -z "$umask_val" ]]; then
        umask_val=$(grep -hE '^[[:space:]]*umask[[:space:]]' "${AUDIT_ROOT}/etc/profile" \
                    "${AUDIT_ROOT}/etc/bash.bashrc" "${AUDIT_ROOT}"/etc/profile.d/*.sh 2>/dev/null \
                    | awk '{print $2; exit}' || true)
    fi
    # Weak unless group-write and all "other" bits are masked (027 or stricter).
    local is_weak=1
    if [[ "$umask_val" =~ ^0?[0-7]{3}$ ]] && (( (8#$umask_val & 8#027) == 8#027 )); then
        is_weak=0
    fi
    if [[ $is_weak -eq 1 ]]; then
        print_status "WARN" "Default umask is ${umask_val:-unset} - new files may be group/other-readable"
        append_report "## Default Umask\n- 🟡 umask ${umask_val:-unset}: new files are group/other-readable"
        report_issue 4 \
            "Weak default umask for login shells" \
            "Default umask is ${umask_val:-unset}; CIS recommends 027" \
            "if grep -q '^UMASK' /etc/login.defs; then
    sudo /bin/sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
else
    echo 'UMASK           027' | sudo /usr/bin/tee -a /etc/login.defs > /dev/null
fi
echo 'umask 027' | sudo /usr/bin/tee /etc/profile.d/umask.sh > /dev/null
sudo /bin/chmod 644 /etc/profile.d/umask.sh
grep UMASK /etc/login.defs && bash -lc 'umask'" \
            0
    else
        print_status "OK" "Default umask is ${umask_val} - appropriately restrictive"
        append_report "## Default Umask\n- 🟢 umask ${umask_val} is appropriately restrictive"
    fi
}
