# shellcheck shell=bash
# Run initialisation, final Markdown report, and all secondary outputs.

# Version guard, output paths, verify setup, report header.
init_run() {
# ====================== UBUNTU VERSION GUARD ======================
print_status "INFO" "Checking Ubuntu version compatibility..."
ubuntu_ver=$(lsb_release -rs 2>/dev/null || echo "")
# FIX: use dpkg --compare-versions instead of fragile awk lexical string compare
# (awk < on "9.04" vs "20.04" fails lexically; dpkg uses proper version semantics)
if dpkg --compare-versions "${ubuntu_ver:-0}" lt "$MIN_UBUNTU_VERSION" 2>/dev/null; then
    print_status "ERR" "Ubuntu ${MIN_UBUNTU_VERSION}+ required. Detected: ${ubuntu_ver:-unknown}"
    exit 1
fi
print_status "OK" "Ubuntu ${ubuntu_ver} - compatible"

# ====================== REPORT FILE SETUP ======================
if [[ -n "$OUTPUT_DIR" ]]; then
    REPORT_DIR="$OUTPUT_DIR"
    [[ "$REPORT_DIR" =~ ^/ ]] || { echo "--output-dir must be an absolute path"; exit 1; }
    [[ -d "$REPORT_DIR" ]] || mkdir -p "$REPORT_DIR" || { echo "Cannot create output dir: $REPORT_DIR"; exit 1; }
elif [[ -n "${AUDIT_REPORT_DIR:-}" ]]; then
    REPORT_DIR="$AUDIT_REPORT_DIR"
    [[ "$REPORT_DIR" =~ ^/ ]] || { echo "AUDIT_REPORT_DIR must be an absolute path"; exit 1; }
elif [[ -n "${SUDO_USER:-}" ]]; then
    REPORT_DIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    REPORT_DIR="$HOME"
fi
if [[ ! -w "$REPORT_DIR" ]]; then
    REPORT_DIR="/tmp"
    print_status "WARN" "Home directory not writable - saving report to /tmp"
fi
REPORT_FILE="${REPORT_DIR}/sec-audit-report-$(date +%Y%m%d-%H%M).md"

# ====================== FINDINGS FILE (always-on when python3 available) ======================
if command -v python3 >/dev/null 2>&1; then
    FINDINGS_FILE="${REPORT_DIR}/sec-audit-findings-$(date +%Y%m%d-%H%M).jsonl"
    (umask 177; : > "$FINDINGS_FILE")
fi
if [[ $OSCAL_MODE -eq 1 ]]; then
    print_status "INFO" "OSCAL mode enabled — catalog: ${OSCAL_CATALOG}"
fi

# ====================== VERIFY MODE SETUP ======================
if [[ $VERIFY_MODE -eq 1 ]]; then
    _prev_findings=$(find "${REPORT_DIR}" -maxdepth 1 -name 'sec-audit-findings-*.jsonl' -printf '%T@ %p\n' 2>/dev/null | sort -rn | awk 'NR==2{print $2}' || true)
    if [[ -n "$_prev_findings" ]] && command -v python3 >/dev/null 2>&1; then
        mapfile -t VERIFY_CHECKS < <(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    for line in f:
        try:
            obj = json.loads(line)
            if obj.get('status') == 'not-satisfied':
                print(obj['check_id'])
        except Exception:
            pass
" "$_prev_findings" 2>/dev/null || true)
        print_status "INFO" "Verify mode: re-running ${#VERIFY_CHECKS[@]} previously-failed check(s) from $(basename "$_prev_findings")"
    else
        print_status "WARN" "--verify: no previous findings file found in ${REPORT_DIR} — running all checks"
        VERIFY_MODE=0
    fi
fi

# ====================== SUDO & KEEP-ALIVE ======================
# Keep-alive only needed when sudo was used to elevate (not when already root)
SUDO_PID=""
if [[ -n "${SUDO_USER:-}" ]]; then
    ( while true; do
        if ! sudo -n true 2>/dev/null; then
            echo -e "\n${YELLOW}[⚠]${RESET} sudo keep-alive: credentials may have expired - some later checks may fail" >&2
        fi
        sleep 55
      done ) &
    SUDO_PID=$!
fi
trap '[[ -n "${SUDO_PID:-}" ]] && kill "$SUDO_PID" 2>/dev/null; [[ "${_INTERRUPTED:-0}" -eq 0 ]] && echo -e "\n\033[0;33m[⚠] Audit complete or unexpectedly exited.\033[0m"' EXIT

# ====================== REPORT HEADER ======================
(umask 177; : > "$REPORT_FILE")
cat > "$REPORT_FILE" << EOF
# Ubuntu Security Audit Report
**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Tool version:** ${SCRIPT_VERSION}
**Hostname:** $(hostname)
**Ubuntu Release:** $(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
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
- Generated by ubuntu-security-audit.sh (Deep mode: $([[ $DEEP -eq 1 ]] && echo enabled || echo disabled))
RECEOF
} >> "$REPORT_FILE"
}

# Optional Ansible playbook.
generate_ansible() {
# ====================== ANSIBLE PLAYBOOK GENERATION ======================
ANSIBLE_FILE=""
if [[ $ANSIBLE_MODE -eq 1 && ${#REMEDIATIONS[@]} -gt 0 ]]; then
    ANSIBLE_FILE="${REPORT_DIR}/remediate-$(date +%Y%m%d-%H%M).yml"
    cat > "$ANSIBLE_FILE" << ANSIBLEHDR
---
# Ubuntu Security Audit — Ansible Remediation Playbook
# Framework(s) : ${_fw_label_str}
# Generated    : $(date '+%Y-%m-%d %H:%M')
# Host         : $(hostname)
# Score        : ${SCORE}/100 (${GRADE})
#
# Run locally : ansible-playbook $(basename "$ANSIBLE_FILE") -i "localhost," -c local --become
# Run remote  : ansible-playbook $(basename "$ANSIBLE_FILE") -i inventory --become
# Review each task before executing in production.

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
            _ansible_task_num=$((_ansible_task_num + 1))
            printf '  - name: "Fix: %s"\n' "${TITLES[$i]}"        >> "$ANSIBLE_FILE"
            printf '    ansible.builtin.shell: |\n'                >> "$ANSIBLE_FILE"
            while IFS= read -r _rline; do
                printf '      %s\n' "$_rline"                      >> "$ANSIBLE_FILE"
            done <<< "${REMEDIATIONS[$i]}"
            printf '    register: fix_%d_result\n'   "$_ansible_task_num" >> "$ANSIBLE_FILE"
            printf '    ignore_errors: true\n'                     >> "$ANSIBLE_FILE"
            printf '    changed_when: false\n\n'                   >> "$ANSIBLE_FILE"
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
    OSCAL_AR_FILE="${REPORT_DIR}/oscal-ar-$(date +%Y%m%d-%H%M).json"
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
        HTML_REPORT_FILE="${REPORT_DIR}/sec-audit-report-$(date +%Y%m%d-%H%M).html"
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
            && print_status "OK" "Webhook delivered: ${WEBHOOK_URL}" \
            || { print_status "WARN" "Webhook delivery failed: ${WEBHOOK_URL}"; true; }
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
if [[ $VERIFY_MODE -eq 1 && ${#VERIFY_CHECKS[@]} -gt 0 && -n "${FINDINGS_FILE:-}" ]]; then
    for _vc in "${VERIFY_CHECKS[@]}"; do
        if grep -q "\"check_id\":\"${_vc}\".*\"status\":\"satisfied\"" "$FINDINGS_FILE" 2>/dev/null; then
            _verify_fixed=$((_verify_fixed+1))
        else
            _verify_still=$((_verify_still+1))
        fi
    done
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
    _prev_run_findings=$(ls -1t "${REPORT_DIR}"/sec-audit-findings-*.jsonl 2>/dev/null | sed -n '2p' || true)
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
[[ $_cnt_critical -gt 0 ]] && echo "   • ${RED}Address CRITICAL findings immediately${RESET}"
}
