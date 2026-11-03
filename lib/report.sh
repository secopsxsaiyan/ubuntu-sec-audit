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

# _previous_findings_file — newest findings file in REPORT_DIR other than
# this run's (empty when there is none).
_previous_findings_file() {
    local _ts path
    while IFS=$'\t' read -r _ts path; do
        [[ "$path" == "${FINDINGS_FILE:-}" ]] && continue
        printf '%s' "$path"
        return 0
    done < <(find "$REPORT_DIR" -maxdepth 1 -type f -name 'sec-audit-findings-*.jsonl' \
                -printf '%T@\t%p\n' 2>/dev/null | sort -rn)
}

# _failed_checks_in FILE — check ids with a not-satisfied record. The file is
# written by record_finding, where quotes inside values are always escaped,
# so the key/value text below cannot occur inside a string. No python3.
_failed_checks_in() {
    sed -nE 's/^\{"check_id": "([a-z0-9_]+)",.*"status": "not-satisfied".*/\1/p' "$1" 2>/dev/null | sort -u
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
        local _prev_findings
        _prev_findings=$(_previous_findings_file)
        if [[ -n "$_prev_findings" ]]; then
            mapfile -t VERIFY_CHECKS < <(_failed_checks_in "$_prev_findings")
            print_status "INFO" "Verify mode: re-running ${#VERIFY_CHECKS[@]} previously-failed check(s) from $(basename "$_prev_findings")"
        else
            print_status "WARN" "--verify: no previous findings file found in ${REPORT_DIR} — running all checks"
            VERIFY_MODE=0
        fi
    fi

    # Only mention an exit that was not a normal completion.
    trap '_rc=$?; if [[ $_rc -ne 0 && "${_INTERRUPTED:-0}" -eq 0 ]]; then echo -e "\n\033[0;33m[⚠] Audit exited unexpectedly (status ${_rc}).\033[0m" >&2; fi' EXIT

    cat > "$REPORT_FILE" << EOF
# Ubuntu Security Audit Report
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool version:** ${SCRIPT_VERSION}
**Hostname:** $(hostname)
**Ubuntu Release:** $(_os_release_field PRETTY_NAME)
**Mode:** $([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")

## Executive Summary
EOF
}

# Score, grade and the findings section of the report.
write_final_report() {
# ====================== SCORE & GRADE ======================
[[ $SCORE -lt 0 ]] && SCORE=0
if   [[ $SCORE -ge 90 ]]; then GRADE="A"; COLOR="🟢"
elif [[ $SCORE -ge 80 ]]; then GRADE="B"; COLOR="🟡"
elif [[ $SCORE -ge 70 ]]; then GRADE="C"; COLOR="🟡"
elif [[ $SCORE -ge 60 ]]; then GRADE="D"; COLOR="🔴"
else                            GRADE="F"; COLOR="🔴"
fi

# ====================== FINAL REPORT ======================
# All issue detail blocks are emitted here once, in sorted order, so the report
# has one authoritative findings section rather than inline-scattered blocks.
{
cat << EXECEOF

## Executive Summary (Final)
**Overall Security Score:** $SCORE/100 $COLOR ($GRADE)
**Issues found:** $ISSUE_COUNT total ($DEEP_ISSUE_COUNT in Deep mode)

## All Findings (Remediation Details)
EXECEOF
if [[ ${#ISSUES[@]} -gt 0 ]]; then
    printf '%s\n\n' "${ISSUES[@]}"
else
    printf '_No issues found — system is fully compliant._\n\n'
fi
cat << RECEOF

## Actionable Recommendations
$( [[ $SCORE -lt 90 ]] && echo "- Run the generated fix script or apply Quick Remediation blocks above" || echo "- System is well maintained" )
$( [[ $DEEP -eq 0 ]] && echo "- Re-run with \`--deep\` for full attack-surface coverage (includes ClamAV + Lynis)" || echo "- Deep mode complete - review warnings only" )
- For full antivirus scan run: \`sudo clamscan -r -i /\` manually
- Review report and apply fixes in priority order (🔴 first).

## Appendix
- Generated by ubuntu-sec-audit.sh ${SCRIPT_VERSION} (Deep mode: $([[ $DEEP -eq 1 ]] && echo enabled || echo disabled))
RECEOF
} >> "$REPORT_FILE"
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
                printf '    ansible.builtin.shell: |\n'
                while IFS= read -r _rline; do
                    printf '      %s\n' "$_rline"
                done <<< "${REMEDIATIONS[$i]}"
                printf '    register: fix_%d_result\n' "$_ansible_task_num"
                if [[ "$(_fix_kind "$i")" == "ssh" ]]; then
                    printf '    when: apply_ssh_changes | default(false) | bool\n'
                fi
                printf '    ignore_errors: true\n'
                printf '    changed_when: false\n\n'
            } >> "$ANSIBLE_FILE"
        done
    done
    chmod 600 "$ANSIBLE_FILE"
    print_status "OK" "Ansible playbook saved: ${ANSIBLE_FILE}"
fi

print_status "OK" "Audit complete! Report saved to $REPORT_FILE"
print_status "INFO" "Quick-fix script created: $FIX_SCRIPT"
}

# Optional OSCAL Assessment Results.
generate_oscal() {
# ====================== OSCAL GENERATION ======================
OSCAL_AR_FILE=""
if [[ $OSCAL_MODE -eq 1 && -n "${FINDINGS_FILE:-}" ]]; then
    OSCAL_AR_FILE="${REPORT_DIR}/oscal-ar-${RUN_ID}.json"
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
        python3 "$_oscal_generator" \
            --findings    "$FINDINGS_FILE" \
            --mapping     "$_oscal_mapping" \
            --catalog     "$OSCAL_CATALOG" \
            --hostname    "$(hostname)" \
            --ubuntu-version "${ubuntu_ver:-unknown}" \
            --tool-version "$SCRIPT_VERSION" \
            --frameworks  "$(IFS=','; echo "${FRAMEWORKS[*]}")" \
            --audit-start "$_audit_start_iso" \
            --audit-end   "$_audit_end_iso" \
            --output      "$OSCAL_AR_FILE" \
            ${OSCAL_PROFILE_FILE:+--profile "$OSCAL_PROFILE_FILE"} \
            && print_status "OK" "OSCAL AR saved: ${OSCAL_AR_FILE}" \
            || { print_status "WARN" "OSCAL generation encountered errors — check ${FINDINGS_FILE}"; true; }
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

# Optional webhook delivery.
send_webhook() {
# ====================== WEBHOOK DELIVERY ======================
if [[ -n "${WEBHOOK_URL:-}" ]]; then
    if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
        _wh_payload=$(python3 -c "
import json, sys
print(json.dumps({
    'hostname':   sys.argv[1],
    'score':      int(sys.argv[2]),
    'grade':      sys.argv[3],
    'issues':     int(sys.argv[4]),
    'mode':       sys.argv[5],
    'frameworks': sys.argv[6].split(','),
    'report':     sys.argv[7],
    'timestamp':  sys.argv[8],
}))" \
"$(hostname)" "$SCORE" "$GRADE" "$ISSUE_COUNT" \
"$([[ $DEEP -eq 1 ]] && echo deep || echo standard)" \
"$(IFS=','; echo "${FRAMEWORKS[*]}")" \
"$REPORT_FILE" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" 2>/dev/null || echo '{}')
        curl -sf --max-time 10 \
             -H "Content-Type: application/json" \
             -d "$_wh_payload" \
             "$WEBHOOK_URL" >/dev/null 2>&1 \
            && print_status "OK" "Webhook delivered: $(_redact_url "$WEBHOOK_URL")" \
            || { print_status "WARN" "Webhook delivery failed: $(_redact_url "$WEBHOOK_URL")"; true; }
    else
        print_status "WARN" "--webhook requires curl and python3"
    fi
fi
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

# Delta report (changes since last run)
if [[ -n "${FINDINGS_FILE:-}" ]]; then
    _prev_run_findings=$(_previous_findings_file)
    if [[ -n "$_prev_run_findings" ]]; then
        echo -e "\n${BOLD}Changes since last run:${RESET}"
        _print_delta_report "$FINDINGS_FILE" "$_prev_run_findings"
    fi
fi

echo -e "\nNext steps:"
echo "   • less $REPORT_FILE"
[[ -n "$HTML_REPORT_FILE" ]] && echo "   • open $HTML_REPORT_FILE"
echo "   • Review warnings in Deep sections"
echo "   • Run the Quick Remediation blocks"
echo "   • Re-run with --deep for maximum coverage"
if [[ $_cnt_critical -gt 0 ]]; then
    echo "   • ${RED}Address CRITICAL findings immediately${RESET}"
fi
return 0
}
