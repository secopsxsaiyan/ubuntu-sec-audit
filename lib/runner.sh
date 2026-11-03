# shellcheck shell=bash
# Check runner, delta report, and the ordered list of standard checks.

_print_delta_report() {
    local current="$1" prev="$2"
    [[ -z "$prev" || ! -f "$prev" ]] && return
    command -v python3 >/dev/null 2>&1 || return
    python3 -c "
import json, sys
def load(p):
    d = {}
    with open(p) as f:
        for line in f:
            try:
                o = json.loads(line)
                d[o['check_id']] = o['status']
            except Exception:
                pass
    return d
cur  = load(sys.argv[1])
prev = load(sys.argv[2])
fixed     = sorted(k for k in prev if prev[k]=='not-satisfied' and cur.get(k)=='satisfied')
regressed = sorted(k for k in prev if prev[k]=='satisfied'    and cur.get(k)=='not-satisfied')
new_fail  = sorted(k for k in cur  if cur[k]=='not-satisfied'  and k not in prev)
if fixed:     print('fixed='     + ','.join(fixed))
if regressed: print('regressed=' + ','.join(regressed))
if new_fail:  print('new_fail='  + ','.join(new_fail))
if not fixed and not regressed and not new_fail:
    print('unchanged=true')
" "$current" "$prev" 2>/dev/null | while IFS='=' read -r key val; do
        case "$key" in
            fixed)     echo -e "  ${GREEN}✔ Fixed${RESET}       : ${val//,/ }" ;;
            regressed) echo -e "  ${RED}↘ Regressed${RESET}  : ${val//,/ }" ;;
            new_fail)  echo -e "  ${YELLOW}⚠ New failures${RESET}: ${val//,/ }" ;;
            unchanged) echo -e "  ${BLUE}≡ No changes${RESET} since last run" ;;
        esac
    done
}

# _run_check: wrapper for every check_* call.
# Handles: OSCAL profile filter, --check/--skip filters, verify mode,
#          env-awareness skips, progress indicator, satisfied OSCAL recording.
_run_check() {
    local fn="$1"

    # Progress counter (written to stderr so it doesn't pollute report)
    _CHECK_NUM=$((_CHECK_NUM + 1))
    printf '\r  [%2d/%-2d] %-40s' "$_CHECK_NUM" "$_CHECK_TOTAL" "${fn}..." >&2

    # OSCAL profile filter
    if ! _check_in_profile "$fn"; then
        printf '\r%-60s\r' '' >&2
        print_status "INFO" "Skipping ${fn} (not in OSCAL profile)"
        return 0
    fi

    # --check (run-only list)
    if [[ ${#RUN_ONLY[@]} -gt 0 ]]; then
        local _found=0
        for _c in "${RUN_ONLY[@]}"; do [[ "$_c" == "$fn" ]] && _found=1 && break; done
        if [[ $_found -eq 0 ]]; then printf '\r%-60s\r' '' >&2; return 0; fi
    fi

    # --skip list
    for _c in "${SKIP_CHECKS[@]}"; do
        if [[ "$_c" == "$fn" ]]; then
            printf '\r%-60s\r' '' >&2
            print_status "INFO" "Skipping ${fn} (--skip)"
            return 0
        fi
    done

    # --verify filter
    if [[ $VERIFY_MODE -eq 1 && ${#VERIFY_CHECKS[@]} -gt 0 ]]; then
        local _vfound=0
        for _vc in "${VERIFY_CHECKS[@]}"; do [[ "$_vc" == "$fn" ]] && _vfound=1 && break; done
        if [[ $_vfound -eq 0 ]]; then printf '\r%-60s\r' '' >&2; return 0; fi
    fi

    # Environment-awareness: skip checks irrelevant in containers/VMs
    case "$fn" in
        check_secure_boot|check_kernel_lockdown)
            if [[ "$ENV_TYPE" == "docker" || "$ENV_TYPE" == "lxc" || "$ENV_TYPE" == "vm" ]]; then
                printf '\r%-60s\r' '' >&2
                print_status "INFO" "Skipping ${fn} (not applicable in ${ENV_TYPE})"
                return 0
            fi ;;
        check_grub_password)
            if [[ "$ENV_TYPE" == "docker" || "$ENV_TYPE" == "lxc" ]]; then
                printf '\r%-60s\r' '' >&2
                print_status "INFO" "Skipping ${fn} (not applicable in ${ENV_TYPE})"
                return 0
            fi ;;
        check_apparmor)
            if [[ "$ENV_TYPE" == "docker" ]]; then
                printf '\r%-60s\r' '' >&2
                print_status "INFO" "Skipping ${fn} (AppArmor namespace not writable in Docker)"
                return 0
            fi ;;
    esac

    printf '\r%-60s\r' '' >&2
    "$fn"

    if [[ -n "${FINDINGS_FILE:-}" ]]; then
        if ! grep -qF "\"check_id\":\"${fn}\"" "$FINDINGS_FILE" 2>/dev/null; then
            record_finding "$fn" \
                "${fn}: all sub-checks passed" \
                "satisfied" \
                "No issues detected during ${fn}" \
                "" "0"
        fi
    fi
}

# Run every standard check (and deep checks when enabled).
run_all_checks() {
print_status "INFO" "Starting Ubuntu Security Audit..."
print_status "INFO" "Environment: ${ENV_TYPE}"

# Count total _run_check calls for progress indicator
_CHECK_TOTAL=$(grep -c '^_run_check ' "${OSCAL_SCRIPT_DIR}/lib/runner.sh" 2>/dev/null || echo "37")

# Load OSCAL profile if supplied (Phase 3: populates PROFILE_CONTROLS)
if [[ -n "$OSCAL_PROFILE_FILE" ]]; then
    _load_oscal_profile "$OSCAL_PROFILE_FILE"
fi

# Standard checks — wrapped in _run_check for OSCAL evidence collection and profile filtering
_run_check check_updates
_run_check check_firewall
_run_check check_open_ports
_run_check check_ssh
_run_check check_users
_run_check check_permissions
_run_check check_unattended
_run_check check_apparmor
_run_check check_failed_logins
_run_check check_fail2ban
_run_check check_kernel
_run_check check_reboot
_run_check check_cron
_run_check check_pam_lockout
_run_check check_core_dumps
_run_check check_umask
_run_check check_login_banner
_run_check check_pam_pwquality
_run_check check_secure_boot
_run_check check_root_path
_run_check check_home_permissions
_run_check check_journald
_run_check check_rsyslog
_run_check check_apt_repos
_run_check check_unnecessary_packages
_run_check check_docker_hardening
_run_check check_mount_options
_run_check check_ntp
_run_check check_ipv6_exposure
_run_check check_disk_encryption
_run_check check_idle_timeout
_run_check check_grub_password
_run_check check_aide
_run_check check_auditd
_run_check check_kernel_lockdown
_run_check check_debsecan
_run_check check_dns_security
_run_check check_systemd_service_hardening
_run_check check_secrets

# Deep checks
if [[ $DEEP -eq 1 ]]; then
    run_deep_checks
fi
}
