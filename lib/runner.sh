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
                # A check with any failing record is failing.
                if o['status'] == 'not-satisfied' or o['check_id'] not in d:
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

    # --check / --skip / --verify (same rule as the progress total)
    if ! _selected_by_flags "$fn"; then
        local _c
        for _c in "${SKIP_CHECKS[@]}"; do
            if [[ "$_c" == "$fn" ]]; then
                print_status "INFO" "Skipping ${fn} (--skip)"
                break
            fi
        done
        return 0
    fi

    # Progress counter (written to stderr so it doesn't pollute report)
    _CHECK_NUM=$((_CHECK_NUM + 1))
    printf '\r  [%2d/%-2d] %-40s' "$_CHECK_NUM" "$_CHECK_TOTAL" "${fn}..." >&2

    # OSCAL profile filter
    if ! _check_in_profile "$fn"; then
        printf '\r%-60s\r' '' >&2
        print_status "INFO" "Skipping ${fn} (not in OSCAL profile)"
        return 0
    fi

    # Environment-awareness: checks that cannot apply in containers/VMs are
    # recorded as not-applicable (not dropped, so reports show them).
    local _na_reason
    _na_reason=$(_env_not_applicable "$fn")
    if [[ -n "$_na_reason" ]]; then
        printf '\r%-60s\r' '' >&2
        print_status "INFO" "Skipping ${fn} (${_na_reason})"
        CHECK_STATUS["$fn"]="not-applicable"
        record_finding "$fn" "${fn}: not applicable" "not-applicable" "$_na_reason" "" "0"
        return 0
    fi

    printf '\r%-60s\r' '' >&2
    CURRENT_CHECK="$fn"
    _run_isolated "$fn"
    CURRENT_CHECK=""

    # Pass/fail comes from in-memory state, not from re-reading the JSONL.
    local _errors="${CHECK_ERRORS[$fn]:-0}"
    if [[ -n "${CHECK_FAILED[$fn]:-}" ]]; then
        CHECK_STATUS["$fn"]="not-satisfied"
    elif [[ -n "${CHECK_NA[$fn]:-}" && "$_errors" -eq 0 ]]; then
        CHECK_STATUS["$fn"]="not-applicable"
        record_finding "$fn" "${fn}: not applicable" "not-applicable" "${CHECK_NA[$fn]}" "" "0"
    elif [[ -n "${CHECK_SKIPPED[$fn]:-}" && "$_errors" -eq 0 ]]; then
        # Could not be performed (tool missing): neither passed nor failed.
        CHECK_STATUS["$fn"]="skipped"
        record_finding "$fn" "${fn}: not checked" "skipped" "${CHECK_SKIPPED[$fn]}" "" "0"
    elif [[ "$_errors" -gt 0 ]]; then
        # A check that crashed must never be reported as passing.
        CHECK_STATUS["$fn"]="error"
        append_report "## ${fn}\n- ⚠️ Check did not complete (${_errors} unexpected error(s)) - result unknown"
        record_finding "$fn" \
            "${fn}: check did not complete" \
            "error" \
            "${_errors} unexpected error(s) while running ${fn}; see the audit output" \
            "" "0"
    else
        CHECK_STATUS["$fn"]="satisfied"
        record_finding "$fn" \
            "${fn}: all sub-checks passed" \
            "satisfied" \
            "No issues detected during ${fn}" \
            "" "0"
    fi
}

# _env_not_applicable FN — why FN cannot apply in this environment (empty
# when it can).
_env_not_applicable() {
    case "$1|$ENV_TYPE" in
        check_secure_boot\|docker|check_secure_boot\|lxc|check_secure_boot\|vm|\
        check_kernel_lockdown\|docker|check_kernel_lockdown\|lxc|check_kernel_lockdown\|vm|\
        check_grub_password\|docker|check_grub_password\|lxc)
            printf 'not applicable in %s' "$ENV_TYPE" ;;
        check_apparmor\|docker)
            printf 'AppArmor namespace not writable in docker' ;;
    esac
}

# _run_isolated FN — run a check so that an unexpected failure inside it is
# logged and counted (CHECK_ERRORS) instead of ending the whole audit.
# errexit is suspended for the check and an ERR trap (inherited by functions
# via errtrace) does the bookkeeping; the caller's options and trap return
# afterwards.
_run_isolated() {
    local fn="$1" had_e=0 had_E=0 saved_trap
    # Read flags from $- here: $(set +o) runs in a subshell, which never has
    # errexit, so it cannot be used to save it.
    [[ $- == *e* ]] && had_e=1
    [[ $- == *E* ]] && had_E=1
    saved_trap=$(trap -p ERR)
    _ISOLATION_SUBSHELL=$BASH_SUBSHELL
    set +e -E
    trap '_on_check_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
    "$fn"
    trap - ERR
    [[ $had_E -eq 1 ]] || set +E
    [[ $had_e -eq 1 ]] && set -e
    if [[ -n "$saved_trap" ]]; then eval "$saved_trap"; fi
    return 0
}

_on_check_error() {
    local rc="$1" line="$2" cmd="$3"
    # Count only in the shell running the check. A failure inside $(...) also
    # fails the enclosing assignment here, so it is still counted once.
    [[ "$BASH_SUBSHELL" -eq "${_ISOLATION_SUBSHELL:-0}" ]] || return 0
    local id="${CURRENT_CHECK:-unknown}"
    CHECK_ERRORS["$id"]=$(( ${CHECK_ERRORS[$id]:-0} + 1 ))
    print_status "WARN" "${id}: unexpected error (exit ${rc}) at ${BASH_SOURCE[1]##*/}:${line}: ${cmd}"
}

# _verify_counts — "FIXED STILL_FAILING" for the checks re-run by --verify.
_verify_counts() {
    local fixed=0 still=0 vc
    for vc in "${VERIFY_CHECKS[@]}"; do
        if [[ "${CHECK_STATUS[$vc]:-}" == "satisfied" ]]; then
            fixed=$((fixed + 1))
        else
            still=$((still + 1))
        fi
    done
    echo "$fixed $still"
}

# Standard checks, in run order.
declare -ga STANDARD_CHECKS=(
    check_updates
    check_firewall
    check_open_ports
    check_ssh
    check_users
    check_permissions
    check_unattended
    check_apparmor
    check_failed_logins
    check_fail2ban
    check_kernel
    check_reboot
    check_cron
    check_pam_lockout
    check_core_dumps
    check_umask
    check_login_banner
    check_pam_pwquality
    check_secure_boot
    check_root_path
    check_home_permissions
    check_journald
    check_rsyslog
    check_apt_repos
    check_unnecessary_packages
    check_docker_hardening
    check_mount_options
    check_ntp
    check_ipv6_exposure
    check_disk_encryption
    check_idle_timeout
    check_grub_password
    check_aide
    check_auditd
    check_kernel_lockdown
    check_security_updates
    check_dns_security
    check_systemd_service_hardening
    check_secrets
)

# _planned_check_count — how many checks will run after --check/--skip/
# --verify filtering (for the [N/TOTAL] progress counter).
_planned_check_count() {
    local fn n=0
    local -a all=("${STANDARD_CHECKS[@]}")
    [[ "${DEEP:-0}" -eq 1 ]] && all+=("${DEEP_CHECKS[@]}")
    for fn in "${all[@]}"; do
        _selected_by_flags "$fn" && n=$((n + 1))
    done
    echo "$n"
}

# _selected_by_flags FN — true unless --check, --skip or --verify exclude FN.
_selected_by_flags() {
    local fn="$1" c
    if [[ ${#RUN_ONLY[@]} -gt 0 ]]; then
        local found=0
        for c in "${RUN_ONLY[@]}"; do [[ "$c" == "$fn" ]] && found=1 && break; done
        [[ $found -eq 1 ]] || return 1
    fi
    for c in "${SKIP_CHECKS[@]}"; do
        [[ "$c" == "$fn" ]] && return 1
    done
    if [[ ${VERIFY_MODE:-0} -eq 1 && ${#VERIFY_CHECKS[@]} -gt 0 ]]; then
        local vfound=0
        for c in "${VERIFY_CHECKS[@]}"; do [[ "$c" == "$fn" ]] && vfound=1 && break; done
        [[ $vfound -eq 1 ]] || return 1
    fi
    return 0
}

# Run every standard check (and deep checks when enabled).
run_all_checks() {
    print_status "INFO" "Starting Ubuntu Security Audit..."
    print_status "INFO" "Environment: ${ENV_TYPE}"

    _CHECK_TOTAL=$(_planned_check_count)
    _CHECK_NUM=0

    # Load OSCAL profile if supplied (populates PROFILE_CONTROLS)
    if [[ -n "$OSCAL_PROFILE_FILE" ]]; then
        _load_oscal_profile "$OSCAL_PROFILE_FILE"
    fi

    local fn
    for fn in "${STANDARD_CHECKS[@]}"; do
        _run_check "$fn"
    done

    if [[ $DEEP -eq 1 ]]; then
        run_deep_checks
    fi
}
