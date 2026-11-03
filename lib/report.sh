# shellcheck shell=bash
# Run initialisation, final Markdown report, and all secondary outputs.

# _os_release_field KEY — value of KEY in /etc/os-release, quotes removed.
_os_release_field() {
    awk -F= -v k="$1" '$1 == k {v = $2; gsub(/^"|"$/, "", v); print v; exit}' \
        "${AUDIT_ROOT}/etc/os-release" 2>/dev/null || true
}

# _version_lt A B — true if version A sorts before B.
_version_lt() {
    [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$1" ]]
}

# _check_os_version — exit unless this is Ubuntu (or a derivative that
# declares ID_LIKE=ubuntu) at MIN_UBUNTU_VERSION or later. Sets ubuntu_ver.
_check_os_version() {
    print_status "INFO" "Checking Ubuntu version compatibility..."
    local id id_like
    id=$(_os_release_field ID)
    id_like=$(_os_release_field ID_LIKE)
    ubuntu_ver=$(_os_release_field VERSION_ID)
    if [[ "$id" != "ubuntu" && " ${id_like} " != *" ubuntu "* ]]; then
        print_status "ERR" "This audit targets Ubuntu; /etc/os-release says ID=${id:-unknown}"
        exit 1
    fi
    if [[ -z "$ubuntu_ver" ]] || _version_lt "$ubuntu_ver" "$MIN_UBUNTU_VERSION"; then
        print_status "ERR" "Ubuntu ${MIN_UBUNTU_VERSION}+ required. Detected: ${ubuntu_ver:-unknown}"
        exit 1
    fi
    print_status "OK" "Ubuntu ${ubuntu_ver} - compatible"
}

# _default_report_dir — home of the user who ran sudo, else $HOME.
_default_report_dir() {
    local home=""
    if [[ -n "${SUDO_USER:-}" ]]; then
        home=$(awk -F: -v u="$SUDO_USER" '$1 == u {print $6; exit}' "${AUDIT_ROOT}/etc/passwd" 2>/dev/null || true)
    fi
    printf '%s' "${home:-$HOME}"
}

# _resolve_report_dir — set REPORT_DIR from --output-dir, AUDIT_REPORT_DIR or
# the default. A directory that cannot be written is replaced by a fresh
# private directory under /tmp (never /tmp itself: predictable file names in
# a shared directory invite symlink tricks).
_resolve_report_dir() {
    local dir label=""
    if [[ -n "$OUTPUT_DIR" ]]; then
        dir="$OUTPUT_DIR"; label="--output-dir"
    elif [[ -n "${AUDIT_REPORT_DIR:-}" ]]; then
        dir="$AUDIT_REPORT_DIR"; label="AUDIT_REPORT_DIR"
    else
        dir=$(_default_report_dir)
    fi
    if [[ -n "$label" ]]; then
        [[ "$dir" == /* ]] || { echo "${label} must be an absolute path"; exit 1; }
        mkdir -p "$dir" || { echo "Cannot create output dir: $dir"; exit 1; }
    fi
    if [[ ! -d "$dir" || ! -w "$dir" ]]; then
        local fallback
        fallback=$(mktemp -d "${TMPDIR:-/tmp}/ubuntu-sec-audit-XXXXXX")
        print_status "WARN" "${dir} is not writable - saving output to ${fallback}"
        dir="$fallback"
    fi
    REPORT_DIR="$dir"
}

# _new_run_id — one timestamp shared by every output file of this run;
# a suffix keeps two runs in the same second apart.
_new_run_id() {
    local id
    id=$(date +%Y%m%d-%H%M%S)
    if compgen -G "${REPORT_DIR}/*-${id}.*" >/dev/null; then
        id="${id}-$$"
    fi
    printf '%s' "$id"
}

# _previous_findings_files — findings files in REPORT_DIR other than this
# run's, newest first, one per line.
_previous_findings_files() {
    local _ts path
    while IFS=$'\t' read -r _ts path; do
        [[ "$path" == "${FINDINGS_FILE:-}" ]] && continue
        printf '%s\n' "$path"
    done < <(find "$REPORT_DIR" -maxdepth 1 -type f -name 'sec-audit-findings-*.jsonl' \
                -printf '%T@\t%p\n' 2>/dev/null | sort -rn)
}

# _previous_findings_file — the newest of them (empty when there is none).
_previous_findings_file() {
    _previous_findings_files | head -n 1
}

# _failed_checks_in FILE... — check ids whose last known status in the
# findings FILEs (newest first) is not-satisfied or error. No python3.
_failed_checks_in() {
    _last_known_statuses "$@" | awk -F'\t' '$2 == "not-satisfied" || $2 == "error" {print $1}'
}

# Marker between the report header and the per-check sections.
readonly _REPORT_SECTIONS_MARKER='<!-- check-results -->'

# _write_report_header — the report's first lines; check sections follow
# the marker and the summary is put in front of them at the end of the run.
_write_report_header() {
    cat << EOF
# Ubuntu Security Audit Report
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool version:** ${SCRIPT_VERSION}
**Hostname:** $(hostname)
**Ubuntu Release:** $(_os_release_field PRETTY_NAME)
**Mode:** $([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")
${_REPORT_SECTIONS_MARKER}
EOF
}

# Version guard, output paths, verify setup, report header.
init_run() {
    _check_os_version
    if [[ -n "$AUDIT_ROOT" ]]; then
        print_status "WARN" "AUDIT_ROOT=${AUDIT_ROOT}: file-based checks read from there, not from /"
    fi

    _resolve_report_dir
    RUN_ID=$(_new_run_id)
    REPORT_FILE="${REPORT_DIR}/sec-audit-report-${RUN_ID}.md"

    # Findings are always written; JSON is encoded in bash.
    FINDINGS_FILE="${REPORT_DIR}/sec-audit-findings-${RUN_ID}.jsonl"
    : > "$FINDINGS_FILE"
    if [[ $OSCAL_MODE -eq 1 ]]; then
        print_status "INFO" "OSCAL mode enabled — catalog: ${OSCAL_CATALOG}"
    fi

    if [[ $VERIFY_MODE -eq 1 ]]; then
        local -a _prev=()
        mapfile -t _prev < <(_previous_findings_files)
        if [[ ${#_prev[@]} -gt 0 ]]; then
            # The last known result of every check, so an earlier --check
            # subset run does not hide what failed before it.
            mapfile -t VERIFY_CHECKS < <(_failed_checks_in "${_prev[@]}")
            print_status "INFO" "Verify mode: re-running ${#VERIFY_CHECKS[@]} check(s) that failed in earlier runs"
            if [[ ${#VERIFY_CHECKS[@]} -eq 0 ]]; then
                print_status "INFO" "Nothing failed in earlier runs - running all checks"
                VERIFY_MODE=0
            fi
        else
            print_status "WARN" "--verify: no previous findings file found in ${REPORT_DIR} — running all checks"
            VERIFY_MODE=0
        fi
    fi

    # Only mention an exit that was not a normal completion.
    trap '_rc=$?; if [[ $_rc -ne 0 && "${_INTERRUPTED:-0}" -eq 0 ]]; then echo -e "\n${YELLOW}[⚠] Audit exited unexpectedly (status ${_rc}).${RESET}" >&2; fi' EXIT

    _write_report_header > "$REPORT_FILE"
}

# _severity_rank SEVERITY — 4 (CRITICAL) to 1 (LOW), 0 for anything else.
_severity_rank() {
    case "$1" in
        CRITICAL) echo 4 ;; HIGH) echo 3 ;; MEDIUM) echo 2 ;; LOW) echo 1 ;; *) echo 0 ;;
    esac
}

# _fail_on_triggered — true when --fail-on is set and a finding is at or
# above that severity.
_fail_on_triggered() {
    [[ -n "${FAIL_ON:-}" ]] || return 1
    local min s
    min=$(_severity_rank "$FAIL_ON")
    for s in "${SEVERITIES[@]}"; do
        (( $(_severity_rank "$s") >= min )) && return 0
    done
    return 1
}

# _count_status STATUS — how many checks ended with STATUS.
_count_status() {
    local c n=0
    for c in "${!CHECK_STATUS[@]}"; do
        [[ "${CHECK_STATUS[$c]}" == "$1" ]] && n=$((n + 1))
    done
    echo "$n"
}

# Score, grade and the final report: header, summary, findings (most severe
# first), checks not assessed, then the per-check results.
write_final_report() {
    _compute_score
    if   [[ $SCORE -ge 90 ]]; then GRADE="A"; COLOR="🟢"
    elif [[ $SCORE -ge 80 ]]; then GRADE="B"; COLOR="🟡"
    elif [[ $SCORE -ge 70 ]]; then GRADE="C"; COLOR="🟡"
    elif [[ $SCORE -ge 60 ]]; then GRADE="D"; COLOR="🔴"
    else                            GRADE="F"; COLOR="🔴"
    fi

    local -A sev_n=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)
    local s i c tier
    for s in "${SEVERITIES[@]}"; do
        [[ -n "${sev_n[$s]+x}" ]] && sev_n[$s]=$(( sev_n[$s] + 1 ))
    done

    local head="" body=""
    if grep -qxF "$_REPORT_SECTIONS_MARKER" "$REPORT_FILE" 2>/dev/null; then
        head=$(sed "/^${_REPORT_SECTIONS_MARKER}\$/,\$d" "$REPORT_FILE")
        body=$(sed "1,/^${_REPORT_SECTIONS_MARKER}\$/d" "$REPORT_FILE")
    else
        body=$(cat "$REPORT_FILE" 2>/dev/null || true)
    fi

    local tmp
    tmp=$(mktemp "${REPORT_DIR}/.sec-audit-report-XXXXXX")
    {
        [[ -n "$head" ]] && printf '%s\n' "$head"
        printf '\n## Executive Summary\n'
        printf '**Overall Security Score:** %s/100 %s (%s)\n' "$SCORE" "$COLOR" "$GRADE"
        printf '**Issues found:** %d (%d critical, %d high, %d medium, %d low)' \
            "$ISSUE_COUNT" "${sev_n[CRITICAL]}" "${sev_n[HIGH]}" "${sev_n[MEDIUM]}" "${sev_n[LOW]}"
        [[ $DEEP -eq 1 ]] && printf '; %d from Deep mode' "$DEEP_ISSUE_COUNT"
        printf '\n**Checks:** %d passed, %d failed, %d did not complete, %d not checked, %d not applicable\n' \
            "$(_count_status satisfied)" "$(_count_status not-satisfied)" "$(_count_status error)" \
            "$(_count_status skipped)" "$(_count_status not-applicable)"
        printf '\nThe score is the weighted share of assessed checks that passed; checks that were not checked or do not apply are left out.\n'

        printf '\n## Findings (most severe first)\n'
        if [[ ${#ISSUES[@]} -gt 0 ]]; then
            for tier in CRITICAL HIGH MEDIUM LOW; do
                for i in "${!ISSUES[@]}"; do
                    [[ "${SEVERITIES[$i]:-LOW}" == "$tier" ]] && printf '%s\n\n' "${ISSUES[$i]}"
                done
            done
        else
            printf '_No issues found._\n\n'
        fi

        local -a not_assessed=()
        for c in $(printf '%s\n' "${!CHECK_STATUS[@]}" | sort); do
            case "${CHECK_STATUS[$c]}" in
                not-applicable) not_assessed+=("- ${c} — not applicable: ${CHECK_NA[$c]:-}") ;;
                skipped)        not_assessed+=("- ${c} — not checked: ${CHECK_SKIPPED[$c]:-}") ;;
                error)          not_assessed+=("- ${c} — did not complete (${CHECK_ERRORS[$c]:-?} unexpected error(s)); result unknown") ;;
            esac
        done
        if [[ ${#not_assessed[@]} -gt 0 ]]; then
            printf '## Checks Not Assessed\n'
            printf '%s\n' "${not_assessed[@]}"
            printf '\n'
        fi

        printf '## Check Results\n'
        [[ -n "$body" ]] && printf '%s\n' "$body"

        printf '\n## Recommendations\n'
        if [[ ${#ISSUES[@]} -gt 0 ]]; then
            printf -- '- Review the generated fix-audit-%s.sh, list its fixes with `--dry-run`, then apply them with `--interactive`\n' "${RUN_ID:-}"
            printf -- '- Fix CRITICAL and HIGH findings first; MANUAL steps are never run automatically\n'
        else
            printf -- '- No findings: keep the scheduled audits running to catch regressions\n'
        fi
        [[ $DEEP -eq 0 ]] && printf -- '- Run with `--deep` for SUID/SGID, file integrity, rootkit and malware scans (ClamAV, rkhunter, Lynis)\n'
        printf '\n## Appendix\n'
        printf -- '- Generated by ubuntu-sec-audit.sh %s (Deep mode: %s)\n' "$SCRIPT_VERSION" \
            "$([[ $DEEP -eq 1 ]] && echo enabled || echo disabled)"
    } > "$tmp"
    mv -f "$tmp" "$REPORT_FILE"
}

# Optional Ansible playbook.
generate_ansible() {
# ====================== ANSIBLE PLAYBOOK GENERATION ======================
ANSIBLE_FILE=""
if [[ $ANSIBLE_MODE -eq 1 && ${#REMEDIATIONS[@]} -gt 0 ]]; then
    ANSIBLE_FILE="${REPORT_DIR}/remediate-${RUN_ID}.yml"
    cat > "$ANSIBLE_FILE" << ANSIBLEHDR
---
# Ubuntu Security Audit — Ansible Remediation Playbook
# Framework(s) : ${_fw_label_str:-}
# Generated    : $(date '+%Y-%m-%d %H:%M')
# Host         : $(hostname 2>/dev/null || echo unknown)
# Score        : ${SCORE:-?}/100 (${GRADE:-?})
#
# Run locally : ansible-playbook $(basename "$ANSIBLE_FILE") -i "localhost," -c local --become
# Run remote  : ansible-playbook $(basename "$ANSIBLE_FILE") -i inventory --become -e target_hosts=all
#
# These tasks come from the findings on $(hostname 2>/dev/null || echo "this host"); other hosts may
# differ. Review each task before executing in production.
# Every fix is attempted even if an earlier one fails; the last task then
# fails the play and lists the fixes that failed.
# SSH tasks run only with -e apply_ssh_changes=true: Ansible has no
# confirm-or-rollback guard, so test them on one host first.
# MANUAL items are listed as comments and are never run.

- name: Ubuntu Security Audit Remediation
  hosts: "{{ target_hosts | default('localhost') }}"
  become: true

  tasks:
ANSIBLEHDR

    _ansible_task_num=0
    for _sev_tier in CRITICAL HIGH MEDIUM LOW; do
        _printed_sev_hdr=0
        for i in "${_sorted_indices[@]}"; do
            [[ "${SEVERITIES[$i]:-LOW}" != "$_sev_tier" ]] && continue
            if [[ $_printed_sev_hdr -eq 0 ]]; then
                printf '\n  # ── %s ─────────────────────────────────────────────\n\n' \
                    "$_sev_tier" >> "$ANSIBLE_FILE"
                _printed_sev_hdr=1
            fi
            # Per-framework control comment
            for _fw in "${FRAMEWORKS[@]}"; do
                _ids=""
                for _part in ${CTRL_IDS_ALL[$i]//|/ }; do
                    [[ "${_part%%:*}" == "$_fw" ]] && { _ids="${_part#*:}"; break; }
                done
                [[ -n "$_ids" ]] && printf '  # %s: %s\n' "${_fw^^}" "$_ids" >> "$ANSIBLE_FILE"
            done
            _a_title=$(_fix_safe_title "${TITLES[$i]}")
            if _is_manual_remediation "${REMEDIATIONS[$i]}"; then
                {
                    printf '  # MANUAL: %s\n' "$_a_title"
                    printf '  #   %s\n' "See the fix script for the steps; never run automatically."
                    printf '\n'
                } >> "$ANSIBLE_FILE"
                continue
            fi
            _ansible_task_num=$((_ansible_task_num + 1))
            # JSON strings are valid YAML, so quotes and colons in titles are safe.
            _json_escape_into _a_name "Fix: ${_a_title}"
            {
                printf '  - name: %s\n' "$_a_name"
                printf '    ansible.builtin.shell:\n'
                # Remediations are bash, as in the fix script.
                printf '      executable: /bin/bash\n'
                printf '      cmd: |\n'
                while IFS= read -r _rline; do
                    printf '        %s\n' "$_rline"
                done <<< "${REMEDIATIONS[$i]}"
                printf '    register: fix_%d_result\n' "$_ansible_task_num"
                if [[ "$(_fix_kind "$i")" == "ssh" ]]; then
                    printf '    when: apply_ssh_changes | default(false) | bool\n'
                fi
                printf '    ignore_errors: true\n\n'
            } >> "$ANSIBLE_FILE"
        done
    done
    if [[ $_ansible_task_num -gt 0 ]]; then
        local _n _checks=""
        for (( _n = 1; _n <= _ansible_task_num; _n++ )); do
            _checks+="${_checks:+, }('${_n}' if fix_${_n}_result is failed else '')"
        done
        {
            printf '  - name: Fail if any fix failed (each fix above was attempted)\n'
            printf '    ansible.builtin.fail:\n'
            printf '      msg: "Fix task(s) that failed, by number: {{ failed_fixes | join(%s) }}. See their output above."\n' "', '"
            printf '    vars:\n'
            printf '      failed_fixes: "{{ [%s] | select | list }}"\n' "$_checks"
            printf '    when: failed_fixes | length > 0\n'
        } >> "$ANSIBLE_FILE"
    fi
    chmod 600 "$ANSIBLE_FILE"
    print_status "OK" "Ansible playbook saved: ${ANSIBLE_FILE}"
fi

print_status "OK" "Audit complete! Report saved to $REPORT_FILE"
print_status "INFO" "Fix script created (changes nothing without --apply or confirmation): $FIX_SCRIPT"
}

# Optional OSCAL Assessment Results.
generate_oscal() {
# ====================== OSCAL GENERATION ======================
OSCAL_AR_FILE=""
if [[ $OSCAL_MODE -eq 1 && -n "${FINDINGS_FILE:-}" ]]; then
    local _oscal_out="${REPORT_DIR}/oscal-ar-${RUN_ID}.json"
    _oscal_generator="${OSCAL_SCRIPT_DIR}/oscal/oscal_generate.py"
    _oscal_mapping="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"

    if [[ ! -f "$_oscal_generator" ]]; then
        print_status "WARN" "OSCAL generator not found: ${_oscal_generator} — skipping OSCAL output"
    elif ! command -v python3 >/dev/null 2>&1; then
        print_status "WARN" "python3 not available — skipping OSCAL output"
    else
        _audit_start_iso=$(date -u -d "@${_AUDIT_START}" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                           || date -u +'%Y-%m-%dT%H:%M:%SZ')
        _audit_end_iso=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

        print_status "INFO" "Generating OSCAL Assessment Results (catalog: ${OSCAL_CATALOG})..."
        if python3 "$_oscal_generator" \
            --findings    "$FINDINGS_FILE" \
            --mapping     "$_oscal_mapping" \
            --catalog     "$OSCAL_CATALOG" \
            --hostname    "$(hostname)" \
            --ubuntu-version "${ubuntu_ver:-unknown}" \
            --tool-version "$SCRIPT_VERSION" \
            --frameworks  "$(IFS=','; echo "${FRAMEWORKS[*]}")" \
            --audit-start "$_audit_start_iso" \
            --audit-end   "$_audit_end_iso" \
            --output      "$_oscal_out" \
            ${OSCAL_PROFILE_FILE:+--profile "$OSCAL_PROFILE_FILE"} \
            && [[ -s "$_oscal_out" ]]; then
            OSCAL_AR_FILE="$_oscal_out"
            print_status "OK" "OSCAL AR saved: ${OSCAL_AR_FILE}"
        else
            print_status "WARN" "OSCAL generation failed — no Assessment Results written (findings: ${FINDINGS_FILE})"
        fi
    fi
fi
}

# HTML report.
generate_html() {
# ====================== HTML REPORT GENERATION ======================
HTML_REPORT_FILE=""
if [[ -n "${FINDINGS_FILE:-}" ]] && command -v python3 >/dev/null 2>&1; then
    _html_generator="${OSCAL_SCRIPT_DIR}/oscal/html_report.py"
    if [[ -f "$_html_generator" ]]; then
        HTML_REPORT_FILE="${REPORT_DIR}/sec-audit-report-${RUN_ID}.html"
        _fw_str=$(IFS=','; echo "${FRAMEWORKS[*]}")
        _AUDIT_ELAPSED_TMP=$(( $(date +%s) - _AUDIT_START ))
        python3 "$_html_generator" \
            --findings   "$FINDINGS_FILE" \
            --score      "$SCORE" \
            --grade      "$GRADE" \
            --hostname   "$(hostname)" \
            --frameworks "$_fw_str" \
            --duration   "${_AUDIT_ELAPSED_TMP}s" \
            --output     "$HTML_REPORT_FILE" \
            && { chmod 600 "$HTML_REPORT_FILE"; print_status "OK" "HTML report saved: ${HTML_REPORT_FILE}"; } \
            || { print_status "WARN" "HTML generation failed"; HTML_REPORT_FILE=""; }
    fi
fi
}

# _webhook_payload — the findings summary as JSON, built in bash. "text"
# makes it readable as a Slack/Mattermost/Teams-style incoming webhook.
_webhook_payload() {
    local -A n=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)
    local s fw fws="" host mode text
    local j_fw j_host j_grade j_mode j_report j_ts j_text
    for s in "${SEVERITIES[@]}"; do
        [[ -n "${n[$s]+x}" ]] && n[$s]=$(( n[$s] + 1 ))
    done
    for fw in "${FRAMEWORKS[@]}"; do
        _json_escape_into j_fw "$fw"
        fws+="${fws:+, }${j_fw}"
    done
    host=$(hostname 2>/dev/null || echo unknown)
    mode=$([[ $DEEP -eq 1 ]] && echo deep || echo standard)
    text="Security audit of ${host}: score ${SCORE}/100 (${GRADE}), ${ISSUE_COUNT} issue(s) - critical ${n[CRITICAL]}, high ${n[HIGH]}, medium ${n[MEDIUM]}, low ${n[LOW]}"
    _json_escape_into j_text "$text"
    _json_escape_into j_host "$host"
    _json_escape_into j_grade "${GRADE:-?}"
    _json_escape_into j_mode "$mode"
    _json_escape_into j_report "${REPORT_FILE:-}"
    _json_escape_into j_ts "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    printf '{"text": %s, "hostname": %s, "score": %d, "grade": %s, "issues": %d, "severity": {"critical": %d, "high": %d, "medium": %d, "low": %d}, "mode": %s, "frameworks": [%s], "report": %s, "timestamp": %s}\n' \
        "$j_text" "$j_host" "${SCORE:-0}" "$j_grade" "${ISSUE_COUNT:-0}" \
        "${n[CRITICAL]}" "${n[HIGH]}" "${n[MEDIUM]}" "${n[LOW]}" \
        "$j_mode" "$fws" "$j_report" "$j_ts"
}

# Optional webhook delivery. The URL (which often holds the secret) goes to
# curl through a config file descriptor and the payload through stdin, so
# neither appears in the process list.
send_webhook() {
# ====================== WEBHOOK DELIVERY ======================
if [[ -n "${WEBHOOK_URL:-}" ]]; then
    if ! command -v curl >/dev/null 2>&1; then
        print_status "WARN" "--webhook requires curl"
        return 0
    fi
    if _webhook_payload | curl -sf --max-time 10 --proto '=http,https' \
            -H "Content-Type: application/json" --data-binary @- \
            -K <(printf 'url = "%s"\n' "$WEBHOOK_URL") >/dev/null 2>&1; then
        print_status "OK" "Webhook delivered: $(_redact_url "$WEBHOOK_URL")"
    else
        print_status "WARN" "Webhook delivery failed: $(_redact_url "$WEBHOOK_URL")"
    fi
fi
return 0
}

# Terminal summary, delta and next steps.
print_summary() {
# ====================== TERMINAL SUMMARY ======================
_AUDIT_ELAPSED=$(( $(date +%s) - _AUDIT_START ))

# Count per-severity
_cnt_critical=0; _cnt_high=0; _cnt_medium=0; _cnt_low=0
for _s in "${SEVERITIES[@]}"; do
    case "$_s" in
        CRITICAL) _cnt_critical=$((_cnt_critical+1)) ;;
        HIGH)     _cnt_high=$((_cnt_high+1)) ;;
        MEDIUM)   _cnt_medium=$((_cnt_medium+1)) ;;
        LOW)      _cnt_low=$((_cnt_low+1)) ;;
    esac
done

# Verify summary
_verify_fixed=0; _verify_still=0
if [[ $VERIFY_MODE -eq 1 && ${#VERIFY_CHECKS[@]} -gt 0 ]]; then
    read -r _verify_fixed _verify_still < <(_verify_counts)
fi

echo -e "\n${BOLD}╔════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║               SECURITY AUDIT COMPLETE                      ║${RESET}"
echo -e "${BOLD}╠════════════════════════════════════════════════════════════╣${RESET}"
echo -e "   Version  : ${SCRIPT_VERSION}"
echo -e "   Score    : ${COLOR}$SCORE/100 ($GRADE)${RESET}"
echo -e "   Severity : ${RED}CRITICAL:${_cnt_critical}${RESET}  ${YELLOW}HIGH:${_cnt_high}${RESET}  MEDIUM:${_cnt_medium}  LOW:${_cnt_low}"
echo -e "   Mode     : $([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")  |  Env: ${ENV_TYPE}"
echo -e "   Duration : ${_AUDIT_ELAPSED}s"
echo -e "   Report   : $REPORT_FILE"
[[ -n "$HTML_REPORT_FILE"  ]] && echo -e "   HTML     : $HTML_REPORT_FILE"
echo -e "   Fix      : $FIX_SCRIPT"
[[ -n "${ANSIBLE_FILE:-}"  ]] && echo -e "   Ansible  : $ANSIBLE_FILE"
[[ -n "${OSCAL_AR_FILE:-}" ]] && echo -e "   OSCAL AR : $OSCAL_AR_FILE"
[[ $VERIFY_MODE -eq 1      ]] && echo -e "   Verify   : ${GREEN}${_verify_fixed} fixed${RESET} / ${RED}${_verify_still} still failing${RESET}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${RESET}"

# Delta report: each check against its last known result in earlier runs.
if [[ -n "${FINDINGS_FILE:-}" ]]; then
    local -a _prev_runs=()
    mapfile -t _prev_runs < <(_previous_findings_files)
    if [[ ${#_prev_runs[@]} -gt 0 ]]; then
        echo -e "\n${BOLD}Changes since last run:${RESET}"
        _print_delta_report "$FINDINGS_FILE" "${_prev_runs[@]}"
    fi
fi

echo -e "\nNext steps:"
echo "   • less $REPORT_FILE"
[[ -n "$HTML_REPORT_FILE" ]] && echo "   • open $HTML_REPORT_FILE"
if [[ ${#ISSUES[@]} -gt 0 ]]; then
    echo "   • Review the fix script: sudo bash $FIX_SCRIPT --dry-run"
    echo "   • Apply fixes one by one: sudo bash $FIX_SCRIPT --interactive"
fi
[[ $DEEP -eq 0 ]] && echo "   • Re-run with --deep for maximum coverage"
if [[ $_cnt_critical -gt 0 ]]; then
    echo -e "   • ${RED}Address CRITICAL findings immediately${RESET}"
fi
return 0
}
