# shellcheck shell=bash
# check_umask — standard check (sourced by ubuntu-sec-audit.sh)

check_umask() {
    print_status "INFO" "Checking default umask for login shells..."
    local umask_val=""
    umask_val=$(awk '/^\s*UMASK\s/ {print $2}' /etc/login.defs 2>/dev/null | head -1 | tr -d '[:space:]' || true)
    if [[ -z "$umask_val" ]]; then
        umask_val=$(grep -hE '^\s*umask\s' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null \
                    | awk '{print $2}' | head -1 | tr -d '[:space:]' || true)
    fi
    local is_weak=0
    case "${umask_val:-unset}" in
        022|0022|002|0002|"unset") is_weak=1 ;;
    esac
    if [[ $is_weak -eq 1 ]]; then
        print_status "WARN" "Default umask is ${umask_val:-unset} - new files may be group/other-readable"
        append_report "## Default Umask\n- 🟡 umask ${umask_val:-unset}: new files are group/other-readable"
        report_issue 4 \
            "Weak default umask for login shells" \
            "Default umask is ${umask_val:-unset}; CIS recommends 027" \
            "sudo /bin/sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
echo 'umask 027' | sudo /usr/bin/tee /etc/profile.d/umask.sh
sudo /bin/chmod 644 /etc/profile.d/umask.sh
grep UMASK /etc/login.defs && bash -c 'umask'" \
            0
    else
        print_status "OK" "Default umask is ${umask_val} - appropriately restrictive"
        append_report "## Default Umask\n- 🟢 umask ${umask_val} is appropriately restrictive"
    fi
}
