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

# Optional tools: "COMMAND PACKAGE CHECK" — the deep check that needs each.
declare -ga DEEP_TOOLS=(
    "debsums debsums check_deep_debsums"
    "rkhunter rkhunter check_deep_rkhunter"
    "clamscan clamav check_deep_clamav"
    "auditctl auditd check_deep_auditd_rules"
    "lynis lynis check_deep_lynis"
)

run_deep_checks() {
    print_status "INFO" "=== Starting Deep Analysis ==="

    # Offer a tool (and so apt-get) only when its check will run: --check,
    # --skip, --verify and an OSCAL profile can each leave a check out.
    local entry tool pkg fn
    local -a needed=()
    for entry in "${DEEP_TOOLS[@]}"; do
        read -r tool pkg fn <<< "$entry"
        if _selected_by_flags "$fn" && _check_in_profile "$fn"; then
            needed+=("$entry")
        fi
    done

    if [[ ${#needed[@]} -gt 0 ]]; then
        print_status "INFO" "Optional tools provide deeper analysis. Answer prompts now - scan will then run unattended."
        echo ""
        for entry in "${needed[@]}"; do
            read -r tool pkg fn <<< "$entry"
            prompt_install "$tool" "$pkg"
        done
        echo ""
        for entry in "${needed[@]}"; do
            read -r tool pkg fn <<< "$entry"
            if command -v "$tool" >/dev/null 2>&1; then
                print_status "INFO" "  ${tool}: yes"
            else
                print_status "INFO" "  ${tool}: skipped"
            fi
        done
        echo ""
    fi
    print_status "INFO" "--- Beginning deep scans ---"

    for fn in "${DEEP_CHECKS[@]}"; do
        _run_check "$fn"
    done
}
