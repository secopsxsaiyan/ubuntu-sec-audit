# shellcheck shell=bash
# Check runner, delta report, and the ordered list of standard checks.

# _last_known_statuses FILE... — "check_id<TAB>status" for every check in the
# findings FILEs (newest first): the status from the newest file that has the
# check, where any failing record makes the check failing in that run. A
# --check subset run therefore does not hide older results. Pure bash/awk:
# record_finding escapes every quote inside values, so the key/value text
# matched here cannot occur inside a string.
_last_known_statuses() {
    [[ $# -gt 0 ]] || return 0
    awk '
        FNR == 1 { fileno++ }
        {
            if (!match($0, /^\{"check_id": "[a-z0-9_]+"/)) next
            id = substr($0, 15, RLENGTH - 15)
            if (!match($0, /"status": "[a-z-]+"/)) next
            st = substr($0, RSTART + 11, RLENGTH - 12)
            r = (st == "not-satisfied") ? 3 : (st == "error") ? 2 : 1
            key = fileno SUBSEP id
            if (!(key in rank) || r > rank[key]) { rank[key] = r; stat[key] = st }
            if (!(id in newest)) newest[id] = fileno
        }
        END { for (id in newest) print id "\t" stat[newest[id] SUBSEP id] }
    ' "$@" 2>/dev/null | sort
}

# _print_delta_report CURRENT PREVIOUS... — what changed since earlier runs
# (PREVIOUS newest first), comparing each check with its last known status.
_print_delta_report() {
    local current="$1" id st p
    shift
    [[ $# -gt 0 && -f "$current" ]] || return 0
    local -A prev=() cur=()
    while IFS=$'\t' read -r id st; do prev["$id"]="$st"; done < <(_last_known_statuses "$@")
    while IFS=$'\t' read -r id st; do cur["$id"]="$st"; done < <(_last_known_statuses "$current")
    local -a fixed_ids=() regressed_ids=() new_ids=()
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        st="${cur[$id]}"
        p="${prev[$id]:-}"
        if [[ "$p" == "not-satisfied" && ( "$st" == "satisfied" || "$st" == "not-applicable" ) ]]; then
            fixed_ids+=("$id")
        elif [[ "$p" == "satisfied" && "$st" == "not-satisfied" ]]; then
            regressed_ids+=("$id")
        elif [[ "$st" == "not-satisfied" && "$p" != "not-satisfied" && "$p" != "satisfied" ]]; then
            new_ids+=("$id")
        fi
    done < <(printf '%s\n' "${!cur[@]}" | sort)
    [[ ${#fixed_ids[@]} -gt 0 ]]     && echo -e "  ${GREEN}✔ Fixed${RESET}       : ${fixed_ids[*]}"
    [[ ${#regressed_ids[@]} -gt 0 ]] && echo -e "  ${RED}↘ Regressed${RESET}  : ${regressed_ids[*]}"
    [[ ${#new_ids[@]} -gt 0 ]]  && echo -e "  ${YELLOW}⚠ New failures${RESET}: ${new_ids[*]}"
    if [[ ${#fixed_ids[@]} -eq 0 && ${#regressed_ids[@]} -eq 0 && ${#new_ids[@]} -eq 0 ]]; then
        echo -e "  ${BLUE}≡ No changes${RESET} since last run"
    fi
    return 0
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
        CHECK_NA["$fn"]="$_na_reason"
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
    case "$1" in
        check_secure_boot|check_kernel_lockdown|check_grub_password)
            # The host boots the kernel. VMs boot their own (and UEFI VMs
            # have Secure Boot), so these still run there.
            _in_container && printf 'not applicable in a %s container: the host boots the kernel' "$ENV_TYPE" ;;
        check_ntp)
            _in_container && printf 'not applicable in a %s container: the host keeps the time' "$ENV_TYPE" ;;
        check_apparmor)
            [[ "$ENV_TYPE" == "docker" || "$ENV_TYPE" == "container" ]] \
                && printf 'AppArmor namespace not writable in a %s container' "$ENV_TYPE" ;;
    esac
    return 0
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
        if [[ "${CHECK_STATUS[$vc]:-}" == "satisfied" || "${CHECK_STATUS[$vc]:-}" == "not-applicable" ]]; then
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

# Weight of each check in the score: the most its findings can deduct in
# one run (1 for report-only checks that never deduct). The
# score is the weighted share of assessed checks that passed (a check keeps
# weight minus what it lost, never below 0), so it reflects progress instead
# of reaching 0 once findings add up to 100 points.
declare -gA CHECK_WEIGHTS=(
    [check_updates]=6 [check_firewall]=25 [check_open_ports]=15 [check_ssh]=21
    [check_users]=55 [check_permissions]=15 [check_unattended]=8 [check_apparmor]=7
    [check_failed_logins]=6 [check_fail2ban]=6 [check_kernel]=15 [check_reboot]=5
    [check_cron]=8 [check_pam_lockout]=8 [check_core_dumps]=6 [check_umask]=4
    [check_login_banner]=3 [check_pam_pwquality]=7 [check_secure_boot]=5
    [check_root_path]=8 [check_home_permissions]=6 [check_journald]=5 [check_rsyslog]=4
    [check_apt_repos]=8 [check_unnecessary_packages]=8 [check_docker_hardening]=6
    [check_mount_options]=10 [check_ntp]=5 [check_ipv6_exposure]=1
    [check_disk_encryption]=8 [check_idle_timeout]=6 [check_grub_password]=6
    [check_aide]=8 [check_auditd]=7 [check_kernel_lockdown]=7
    [check_security_updates]=10 [check_dns_security]=5
    [check_systemd_service_hardening]=4 [check_secrets]=12
    [check_deep_suid]=39 [check_deep_sgid]=30 [check_deep_world_writable_files]=16
    [check_deep_world_writable_dirs]=12 [check_deep_unowned]=8
    [check_deep_empty_passwords]=20 [check_deep_password_aging]=8
    [check_deep_sudo_timeout]=5 [check_deep_debsums]=12 [check_deep_rkhunter]=18
    [check_deep_clamav]=25 [check_deep_auditd_rules]=5 [check_deep_lynis]=15
    [check_deep_authorized_keys]=1 [check_deep_user_ssh_keys]=10
    [check_deep_capabilities]=5
)

# _partial_run — true when --check, --skip, --verify or an OSCAL profile
# limited which checks ran: the score then covers only those checks.
_partial_run() {
    [[ ${#RUN_ONLY[@]} -gt 0 || ${#SKIP_CHECKS[@]} -gt 0 || ${#PROFILE_CONTROLS[@]} -gt 0 \
       || "${VERIFY_MODE:-0}" -eq 1 ]]
}

# _compute_score — set SCORE (0-100) from the checks that were assessed.
# Skipped and not-applicable checks do not count; a check that did not
# complete counts as failed.
_compute_score() {
    local c st w d total=0 lost=0
    for c in "${!CHECK_STATUS[@]}"; do
        st="${CHECK_STATUS[$c]}"
        case "$st" in satisfied|not-satisfied|error) ;; *) continue ;; esac
        w="${CHECK_WEIGHTS[$c]:-10}"
        d="${CHECK_POINTS[$c]:-0}"
        [[ "$st" == "error" ]] && d=$w
        (( d > w )) && d=$w
        total=$((total + w))
        lost=$((lost + d))
    done
    if (( total == 0 )); then
        SCORE=100
    else
        SCORE=$(( (100 * (total - lost) + total / 2) / total ))
    fi
}

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
