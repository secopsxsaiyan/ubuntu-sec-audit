# shellcheck shell=bash
# run_deep_checks — deep mode (sourced by ubuntu-sec-audit.sh)
#
# Optional tools are offered up front (only on a terminal), then every deep
# check runs through _run_check, so each has its own check id, honours
# --check/--skip/--verify, and is isolated from the others.

declare -ga DEEP_CHECKS=(
    check_deep_suid
    check_deep_sgid
    check_deep_world_writable_files
    check_deep_world_writable_dirs
    check_deep_unowned
    check_deep_empty_passwords
    check_deep_password_aging
    check_deep_sudo_timeout
    check_deep_debsums
    check_deep_rkhunter
    check_deep_clamav
    check_deep_auditd_rules
    check_deep_lynis
    check_deep_authorized_keys
    check_deep_user_ssh_keys
    check_deep_capabilities
)

run_deep_checks() {
    print_status "INFO" "=== Starting Deep Analysis ==="
    print_status "INFO" "Optional tools provide deeper analysis. Answer prompts now - scan will then run unattended."
    echo ""
    prompt_install "debsums"  "debsums"
    prompt_install "rkhunter" "rkhunter"
    prompt_install "clamscan" "clamav"
    prompt_install "auditctl" "auditd"
    prompt_install "lynis"    "lynis"
    echo ""

    local t
    for t in debsums rkhunter clamscan auditctl lynis; do
        if command -v "$t" >/dev/null 2>&1; then
            print_status "INFO" "  ${t}: yes"
        else
            print_status "INFO" "  ${t}: skipped"
        fi
    done
    echo ""
    print_status "INFO" "--- Beginning deep scans ---"

    local fn
    for fn in "${DEEP_CHECKS[@]}"; do
        _run_check "$fn"
    done
}
