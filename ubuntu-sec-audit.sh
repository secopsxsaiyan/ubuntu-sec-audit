#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# ubuntu-sec-audit.sh - Ubuntu LTS Security Audit (Standard + Deep mode)
# CIS/Lynis aligned - WITH EXACT REMEDIATION COMMANDS
# Deep mode includes FULL ClamAV antivirus scan + Lynis + rkhunter + debsums
# Zero dependencies in Standard mode.
# Requires: Ubuntu 20.04+, run as root/sudo
# =============================================================================
readonly SCRIPT_VERSION="2.1.0"

set -euo pipefail

# Must run as root (directly or via sudo)
if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root. Try: sudo $0 $*" >&2
    exit 1
fi

# ERR trap fires on any unexpected non-zero exit; INT/TERM for user interrupts
_INTERRUPTED=0
trap 'echo -e "\n\033[0;31m[✗] Unexpected error on line ${LINENO} (exit code: $?). Aborting.\033[0m"; exit 1' ERR
trap '_INTERRUPTED=1; echo -e "\n\033[0;33m[⚠] Audit interrupted. Report saved if possible.\033[0m"; exit 1' INT TERM

# ====================== NAMED CONSTANTS ======================
readonly FAILED_LOGIN_THRESHOLD=5
readonly MIN_UBUNTU_VERSION="20.04"

# ====================== CONFIG & GLOBALS ======================
SCORE=100
DEEP=0
VERBOSE=0
SKIP_APT_UPDATE=0
ISSUE_COUNT=0
DEEP_ISSUE_COUNT=0
SUDO_PID=""
OUTPUT_DIR=""
_AUDIT_START=$(date +%s)
# OSCAL mode globals
OSCAL_MODE=0
OSCAL_CATALOG="nist"
OSCAL_PROFILE_FILE=""
FINDINGS_FILE=""
OSCAL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -a PROFILE_CONTROLS=()

# Arrays to collect issues, remediations, and titles separately
declare -a ISSUES=()
declare -a REMEDIATIONS=()
declare -a TITLES=()

# Multi-framework support
declare -a FRAMEWORKS=("nist")  # first element = primary (drives sort order)
INTERACTIVE_MODE=0
_FLAGS_SET=0   # set to 1 by any intent flag; suppresses wizard auto-trigger
declare -a CHECK_IDS=()         # parallel to TITLES[]: which check_* filed the issue
declare -a CTRL_IDS_ALL=()      # parallel to TITLES[]: "fw:ids|fw:ids" for all selected frameworks

# Severity tiers (auto-derived from points in report_issue)
declare -a SEVERITIES=()

# Progress indicator
_CHECK_TOTAL=0
_CHECK_NUM=0

# Environment awareness
ENV_TYPE="bare-metal"

# Targeted check execution
declare -a RUN_ONLY=()
declare -a SKIP_CHECKS=()

# Verify mode
VERIFY_MODE=0
declare -a VERIFY_CHECKS=()

# Webhook + Ansible
WEBHOOK_URL=""
ANSIBLE_MODE=0

# Colors & emojis (tput fallback to ANSI)
if command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
    BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
    BOLD='\033[1m'; RESET='\033[0m'
fi

# SUID whitelist - paths resolved by readlink -f at runtime to handle /bin -> /usr/bin symlinks
SUID_WHITELIST=(
    "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/gpasswd" "/usr/bin/chsh"
    "/usr/bin/chfn" "/usr/bin/chage" "/usr/bin/mount" "/usr/bin/umount" "/usr/bin/newgrp"
    "/usr/bin/pkexec" "/usr/lib/openssh/ssh-keysign" "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/bin/fusermount3"
)

# SGID whitelist
SGID_WHITELIST=(
    "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent" "/usr/bin/bsd-write"
    "/usr/bin/crontab" "/usr/bin/expiry" "/usr/sbin/unix_chkpwd"
    "/usr/lib/openssh/ssh-keysign" "/usr/bin/chage" "/usr/bin/dotlockfile"
    "/usr/bin/lockfile" "/usr/sbin/pam_extrausers_chkpwd"
)

# ====================== CONTROL MAPPING CACHE ======================
# Load control-mapping.json once into memory; queried by report_issue() per finding.
# Avoids spawning a python3 subprocess for every finding (was 37+ forks per run).
_CTRL_MAP_JSON=""
_ctrl_map_file="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"
if [[ -f "$_ctrl_map_file" ]] && command -v python3 >/dev/null 2>&1; then
    _CTRL_MAP_JSON=$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))))" \
        "$_ctrl_map_file" 2>/dev/null || true)
fi

# ====================== ENVIRONMENT DETECTION ======================
_detect_env() {
    if [[ -f /.dockerenv ]] || grep -qE 'docker|containerd' /proc/1/cgroup 2>/dev/null; then
        echo "docker"
    elif grep -q 'lxc' /proc/1/cgroup 2>/dev/null; then
        echo "lxc"
    elif command -v systemd-detect-virt >/dev/null 2>&1 \
         && systemd-detect-virt -q 2>/dev/null; then
        echo "vm"
    else
        echo "bare-metal"
    fi
}
ENV_TYPE=$(_detect_env)

# ====================== HELPER FUNCTIONS ======================
print_status() {
    local type="$1" msg="$2"
    case "$type" in
        OK)   echo -e "${GREEN}[✓]${RESET} $msg" ;;
        WARN) echo -e "${YELLOW}[⚠]${RESET} $msg" ;;
        ERR)  echo -e "${RED}[✗]${RESET} $msg" ;;
        INFO) echo -e "${BLUE}[i]${RESET} $msg" ;;
    esac
}

append_report() {
    printf '%b\n' "$1" >> "$REPORT_FILE"
}

report_issue() {
    local points="$1"
    local title="$2"
    local description="$3"
    local remediation="$4"
    local is_deep="${5:-0}"
    local note="${6:-}"

    SCORE=$((SCORE - points))
    [[ $SCORE -lt 0 ]] && SCORE=0

    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    [[ "$is_deep" -eq 1 ]] && DEEP_ISSUE_COUNT=$((DEEP_ISSUE_COUNT + 1))

    local sev
    sev=$(_severity_from_points "$points")
    SEVERITIES+=("$sev")

    local entry="### 🔴 [${sev}] ${title} (${points} pts)
**Issue**: ${description}
**Remediation**:
\`\`\`bash
${remediation}
\`\`\`
${note:+**Note**: ${note}}"

    ISSUES+=("$entry")
    TITLES+=("$title")
    REMEDIATIONS+=("$remediation")
    CHECK_IDS+=("${BASH_FUNCNAME[1]:-unknown}")
    local _ctrl_all=""
    if [[ -n "$_CTRL_MAP_JSON" ]]; then
        _ctrl_all=$(python3 -c "
import json, sys
m = json.loads(sys.argv[1])
entry = m.get(sys.argv[2], {})
parts = [fw + ':' + ','.join(entry[fw]) for fw in sys.argv[3].split(',') if entry.get(fw)]
print('|'.join(parts))
" "$_CTRL_MAP_JSON" "${BASH_FUNCNAME[1]:-unknown}" \
  "$(IFS=','; echo "${FRAMEWORKS[*]}")" 2>/dev/null || true)
    fi
    CTRL_IDS_ALL+=("${_ctrl_all:-}")
    append_report "$entry"
    record_finding "${BASH_FUNCNAME[1]:-unknown}" "$title" "not-satisfied" "$description" "$remediation" "$points"

    if [[ "$VERBOSE" -eq 1 ]]; then
        print_status "WARN" "${title}"
    fi
    return 0
}

prompt_install() {
    local tool="$1" pkg="${2:-$1}"
    if ! command -v "$tool" >/dev/null 2>&1; then
        print_status "WARN" "$tool not found."
        read -r -p "   Install now? (y/N) " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            # FIX: honour --skip-apt-update flag; don't unconditionally run apt-get update
            if [[ "$SKIP_APT_UPDATE" -eq 0 ]]; then
                sudo apt-get update -qq
            fi
            sudo apt-get install -y "$pkg" && print_status "OK" "$tool installed."
        else
            print_status "INFO" "Skipping $tool (install manually later)."
        fi
    fi
}

# ====================== OSCAL HELPERS ======================

_severity_from_points() {
    local p=$1
    if   [[ $p -ge 20 ]]; then echo "CRITICAL"
    elif [[ $p -ge 10 ]]; then echo "HIGH"
    elif [[ $p -ge  5 ]]; then echo "MEDIUM"
    else                        echo "LOW"
    fi
}

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

# record_finding: appends one JSON line to FINDINGS_FILE.
# Uses python3 for safe JSON encoding (handles quotes, newlines, special chars).
# Args: check_id  title  status(satisfied|not-satisfied)  evidence  remediation  points
record_finding() {
    [[ -z "${FINDINGS_FILE:-}" ]] && return 0
    local check_id="$1" title="$2" status="$3" evidence="$4" remediation="${5:-}" points="${6:-0}"
    local ts
    ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    python3 -c "
import json, sys
print(json.dumps({
    'check_id':    sys.argv[1],
    'title':       sys.argv[2],
    'status':      sys.argv[3],
    'evidence':    sys.argv[4],
    'remediation': sys.argv[5],
    'points':      int(sys.argv[6]) if sys.argv[6].isdigit() else 0,
    'timestamp':   sys.argv[7],
}, ensure_ascii=False))
" "$check_id" "$title" "$status" "$evidence" "$remediation" "$points" "$ts" \
    >> "$FINDINGS_FILE" 2>/dev/null || true
}

# _load_oscal_profile: parse an OSCAL Profile JSON and populate PROFILE_CONTROLS.
# If python3 is unavailable or profile has no include-controls, all checks run.
_load_oscal_profile() {
    local profile_file="$1"
    if ! command -v python3 >/dev/null 2>&1; then
        print_status "WARN" "--profile requires python3; running all checks"
        return
    fi
    mapfile -t PROFILE_CONTROLS < <(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        doc = json.load(f)
    for imp in doc.get('profile',{}).get('imports',[]):
        for sel in imp.get('include-controls',[]):
            for cid in sel.get('with-ids',[]):
                print(cid.lower())
except Exception as e:
    import sys as _s; print(f'profile-load-error: {e}', file=_s.stderr)
" "$profile_file" 2>/dev/null || true)
    local n=${#PROFILE_CONTROLS[@]}
    if [[ $n -gt 0 ]]; then
        print_status "INFO" "OSCAL profile loaded: ${n} control(s) selected — non-matching checks skipped"
    else
        print_status "WARN" "OSCAL profile produced no control IDs — running all checks"
    fi
}

# _check_in_profile: returns 0 (run) or 1 (skip) for a given check function.
# Requires PROFILE_CONTROLS populated and mapping file present.
_check_in_profile() {
    local fn="$1"
    [[ ${#PROFILE_CONTROLS[@]} -eq 0 ]] && return 0   # no filter → always run
    local mapping_file="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"
    [[ ! -f "$mapping_file" ]] && return 0              # no mapping → always run
    command -v python3 >/dev/null 2>&1 || return 0      # no python3 → always run
    local result
    result=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    m = json.load(f)
check_ctrls = set(c.lower() for c in m.get(sys.argv[2],{}).get(sys.argv[3],[]))
profile_set = set(c.lower() for c in sys.argv[4:])
print('yes' if (not check_ctrls) or (check_ctrls & profile_set) else 'no')
" "$mapping_file" "$fn" "$OSCAL_CATALOG" "${PROFILE_CONTROLS[@]}" 2>/dev/null || echo "yes")
    [[ "$result" == "yes" ]]
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

# ====================== INTERACTIVE WIZARD ======================

_interactive_wizard() {
    echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║           Ubuntu Security Audit — Setup Wizard               ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    # Step 1: Compliance Frameworks
    echo ""
    echo "Step 1/5  Compliance Frameworks"
    echo "  Select one or more (space-separated numbers, or \"all\"):"
    echo "    [1] NIST SP 800-53 Rev 5    federal / enterprise baseline"
    echo "    [2] CIS Ubuntu 24.04 LTS    prescriptive benchmark"
    echo "    [3] ISO/IEC 27001:2022       international standard (Annex A)"
    echo "    [4] SOC 2 TSC 2017           service organization controls"
    echo "  First selection is primary (drives fix ordering)."
    while true; do
        read -r -p "  Selection [1]: " _fw_input
        _fw_input="${_fw_input:-1}"
        if [[ "$_fw_input" == "all" ]]; then
            FRAMEWORKS=("nist" "cis" "iso27001" "soc2")
            break
        fi
        _fw_valid=1
        _fw_new=()
        for _num in $_fw_input; do
            case "$_num" in
                1) _fw_new+=("nist") ;;
                2) _fw_new+=("cis") ;;
                3) _fw_new+=("iso27001") ;;
                4) _fw_new+=("soc2") ;;
                *) echo "  Invalid selection '$_num'. Enter numbers 1-4 or 'all'."; _fw_valid=0; break ;;
            esac
        done
        if [[ "$_fw_valid" -eq 1 && ${#_fw_new[@]} -gt 0 ]]; then
            FRAMEWORKS=("${_fw_new[@]}")
            break
        fi
    done

    # Step 2: Audit Depth
    echo ""
    echo "Step 2/5  Audit Depth"
    echo "    [1] Standard   fast, zero extra dependencies        (~2-5 min)"
    echo "    [2] Deep       ClamAV + rkhunter + Lynis + SUID scan (~15-60 min)"
    read -r -p "  Select [1]: " _depth_input
    _depth_input="${_depth_input:-1}"
    [[ "$_depth_input" == "2" ]] && DEEP=1 || DEEP=0

    # Step 3: OSCAL Output
    echo ""
    echo "Step 3/5  OSCAL Output"
    echo "  Generate machine-readable OSCAL 1.1.2 Assessment Results JSON?"
    echo "  (Available for NIST/CIS; ISO 27001 & SOC 2 IDs written as props)"
    read -r -p "  [y/N]: " _oscal_input
    _oscal_input="${_oscal_input:-N}"
    [[ "${_oscal_input,,}" == "y" ]] && OSCAL_MODE=1 || OSCAL_MODE=0

    # Step 4: Output Directory
    echo ""
    echo "Step 4/5  Output Directory"
    _default_dir="${HOME}"
    read -r -p "  Where to save report, fix script, and OSCAL AR? [${_default_dir}]: " _outdir_input
    _outdir_input="${_outdir_input:-${_default_dir}}"
    OUTPUT_DIR="$_outdir_input"

    # Step 5: Skip apt update
    echo ""
    echo "Step 5/5  Skip apt update?"
    read -r -p "  Skip 'apt-get update' (use cached package index)? [y/N]: " _skip_apt_input
    _skip_apt_input="${_skip_apt_input:-N}"
    [[ "${_skip_apt_input,,}" == "y" ]] && SKIP_APT_UPDATE=1 || SKIP_APT_UPDATE=0

    # Sync OSCAL_CATALOG from wizard-selected primary framework
    case "${FRAMEWORKS[0]}" in
        nist|cis) OSCAL_CATALOG="${FRAMEWORKS[0]}" ;;
        *)        OSCAL_CATALOG="nist" ;;
    esac

    # Build display labels
    _wiz_fw_labels=()
    for _fw in "${FRAMEWORKS[@]}"; do
        case "$_fw" in
            nist)     _wiz_fw_labels+=("NIST SP 800-53 Rev 5") ;;
            cis)      _wiz_fw_labels+=("CIS Ubuntu 24.04 LTS") ;;
            iso27001) _wiz_fw_labels+=("ISO/IEC 27001:2022") ;;
            soc2)     _wiz_fw_labels+=("SOC 2 TSC 2017") ;;
        esac
    done
    _wiz_fw_str=$(IFS=', '; echo "${_wiz_fw_labels[*]}")
    _wiz_primary_label="${_wiz_fw_labels[0]:-NIST SP 800-53 Rev 5}"

    echo ""
    echo "──────────────────────────────────────────────────────────────"
    printf "  Frameworks : %s\n"  "$_wiz_fw_str"
    printf "  Primary    : %s (fix ordering and grouping)\n" "$_wiz_primary_label"
    printf "  Mode       : %s\n"  "$([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")"
    printf "  OSCAL      : %s\n"  "$([[ $OSCAL_MODE -eq 1 ]] && echo "Yes  →  catalog: ${OSCAL_CATALOG}" || echo "No")"
    printf "  Output     : %s\n"  "$OUTPUT_DIR"
    echo "──────────────────────────────────────────────────────────────"

    read -r -p "Proceed? [Y/n]: " _proceed_input
    _proceed_input="${_proceed_input:-Y}"
    if [[ "${_proceed_input,,}" == "n" ]]; then
        echo "Audit cancelled."
        exit 0
    fi
    echo ""
}

# ====================== FRAMEWORK HELPER FUNCTIONS ======================

_extract_family() {
    local ctrl="$1" fw="$2"
    case "$fw" in
        nist)
            echo "${ctrl%%-*}" | tr '[:lower:]' '[:upper:]'
            ;;
        cis)
            echo "${ctrl%%.*}"
            ;;
        iso27001)
            # A.8.5 → "A.8"; A.5.15 → "A.5"
            local _part
            _part=$(echo "$ctrl" | sed 's/^\(A\.[0-9]*\)\..*/\1/')
            echo "$_part"
            ;;
        soc2)
            # CC6.1 → "CC6"; A1.1 → "A1"
            echo "$ctrl" | sed 's/\.[0-9]*$//'
            ;;
    esac
}

_write_section_divider() {
    local family="$1" fw="$2"
    local family_label=""
    case "$fw" in
        nist)
            case "$family" in
                AC) family_label="NIST Family: AC — Access Control" ;;
                AU) family_label="NIST Family: AU — Audit and Accountability" ;;
                CM) family_label="NIST Family: CM — Configuration Management" ;;
                IA) family_label="NIST Family: IA — Identification and Authentication" ;;
                RA) family_label="NIST Family: RA — Risk Assessment" ;;
                SC) family_label="NIST Family: SC — System and Communications Protection" ;;
                SI) family_label="NIST Family: SI — System and Information Integrity" ;;
                *)  family_label="NIST Family: ${family}" ;;
            esac
            ;;
        cis)
            case "$family" in
                1) family_label="CIS Section 1 — Initial Setup" ;;
                2) family_label="CIS Section 2 — Services" ;;
                3) family_label="CIS Section 3 — Network Configuration" ;;
                4) family_label="CIS Section 4 — Logging and Auditing" ;;
                5) family_label="CIS Section 5 — Access / Authentication / Authorization" ;;
                6) family_label="CIS Section 6 — System Maintenance" ;;
                *) family_label="CIS Section ${family}" ;;
            esac
            ;;
        iso27001)
            case "$family" in
                "A.5") family_label="ISO 27001 Annex A.5 — Organizational Controls" ;;
                "A.6") family_label="ISO 27001 Annex A.6 — People Controls" ;;
                "A.7") family_label="ISO 27001 Annex A.7 — Physical Controls" ;;
                "A.8") family_label="ISO 27001 Annex A.8 — Technological Controls" ;;
                *)     family_label="ISO 27001 Annex ${family}" ;;
            esac
            ;;
        soc2)
            case "$family" in
                CC1) family_label="SOC 2 TSC — CC1: Control Environment" ;;
                CC4) family_label="SOC 2 TSC — CC4: Monitoring Activities" ;;
                CC6) family_label="SOC 2 TSC — CC6: Logical and Physical Access Controls" ;;
                CC7) family_label="SOC 2 TSC — CC7: System Operations" ;;
                CC8) family_label="SOC 2 TSC — CC8: Change Management" ;;
                *)   family_label="SOC 2 TSC — ${family}" ;;
            esac
            ;;
    esac
    [[ -z "$family_label" ]] && return
    {
        printf '\n# ╔══════════════════════════════════════════════════════════╗\n'
        printf '# ║  %-56s║\n' "$family_label"
        printf '# ╚══════════════════════════════════════════════════════════╝\n'
    } >> "$FIX_SCRIPT"
}

# ====================== LOCAL SERVICE VERSION DETECTION ======================
get_service_version() {
    local prog="$1"
    local pid="${2:-}"

    local bin
    bin=$(basename "$prog" 2>/dev/null || echo "$prog")

    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        if [[ -n "$exe" ]]; then
            local pkg
            pkg=$(dpkg -S "$exe" 2>/dev/null | head -n1 | cut -d: -f1 || true)
            if [[ -n "$pkg" ]]; then
                dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null && return
            fi
        fi
    fi

    case "$bin" in
        sshd)
            local sshd_ver ssh_ver
            sshd_ver=$(timeout 2 sshd -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            ssh_ver=$(timeout 2 ssh -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            if [[ "$sshd_ver" != "N/A" ]]; then
                echo "sshd:${sshd_ver} client:${ssh_ver}"
            else
                echo "client:${ssh_ver}"
            fi
            ;;
        nginx)
            timeout 2 nginx -v 2>&1 | head -n1 | sed 's/.*nginx version: nginx\///' || echo "N/A"
            ;;
        apache2|httpd)
            timeout 2 apache2 -v 2>&1 | grep -o 'Apache/[0-9.]*' || echo "N/A"
            ;;
        mysqld|mariadbd)
            timeout 2 mysqld --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        postgres|postmaster)
            timeout 2 postgres --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        *)
            local pkg
            pkg=$(dpkg -l "*${bin}*" 2>/dev/null | grep '^ii' | head -n1 | awk '{print $2}' || true)
            [[ -n "$pkg" ]] && dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "N/A"
            ;;
    esac
}

# ====================== CLI PARSING ======================
usage() {
    cat << EOF
ubuntu-sec-audit ${SCRIPT_VERSION}
Usage: sudo $0 [OPTIONS]
Options:
  --deep              Enable Deep mode (extra checks + optional tools)
  --verbose           Show detailed output for every check
  --quick             Force Standard mode (default)
  --skip-apt-update   Skip apt-get update (use cached package index)
  --output-dir <dir>  Directory for report and fix script (default: home dir)
  --oscal             Generate OSCAL 1.1.2 Assessment Results JSON alongside Markdown report
  --catalog <name>    Control catalog for OSCAL: nist (SP 800-53 r5, default) or cis (Ubuntu benchmark)
  --profile <file>    OSCAL Profile JSON: only run checks whose controls are included in the profile
  --framework <list>  Comma-separated compliance frameworks: nist, cis, iso27001, soc2
                      First entry is primary (drives fix-script ordering). Default: nist
                      Example: --framework nist,iso27001,soc2
  --interactive       Force the setup wizard (auto-triggered in TTY when no flags are set)
  --check <list>      Run only these checks (comma-separated check_* ids)
  --skip  <list>      Skip these checks (comma-separated check_* ids)
  --verify            Re-run only checks that failed in the most recent previous run
  --webhook <url>     POST findings summary JSON to this URL at end of run
  --ansible           Generate an Ansible remediation playbook alongside the fix script
  --help              Show this help

OSCAL examples:
  sudo $0 --oscal
  sudo $0 --oscal --catalog cis
  sudo $0 --oscal --profile oscal/profiles/sshd-only.json
  sudo $0 --deep --oscal --output-dir /var/log/audits

Framework examples:
  sudo $0 --framework nist,iso27001,soc2
  sudo $0 --framework cis --output-dir /tmp/cis-audit

Targeted execution examples:
  sudo $0 --check check_ssh,check_firewall --skip-apt-update
  sudo $0 --skip check_docker_hardening,check_debsecan
  sudo $0 --verify --output-dir /var/log/audits
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep)             DEEP=1;            _FLAGS_SET=1 ;;
        --verbose)          VERBOSE=1 ;;
        --quick)            DEEP=0 ;;
        --skip-apt-update)  SKIP_APT_UPDATE=1 ;;
        --output-dir)
            shift
            [[ -z "${1:-}" ]] && { echo "--output-dir requires a path argument"; usage; exit 1; }
            OUTPUT_DIR="$1";   _FLAGS_SET=1
            ;;
        --oscal)            OSCAL_MODE=1;      _FLAGS_SET=1 ;;
        --catalog)
            shift
            [[ -z "${1:-}" ]] && { echo "--catalog requires nist or cis"; usage; exit 1; }
            case "$1" in
                nist|cis) OSCAL_CATALOG="$1"; FRAMEWORKS=("$1") ;;
                *) echo "Unknown catalog '$1': use nist or cis"; usage; exit 1 ;;
            esac
            _FLAGS_SET=1
            ;;
        --profile)
            shift
            [[ -z "${1:-}" ]] && { echo "--profile requires a file path"; usage; exit 1; }
            [[ ! -f "$1" ]] && { echo "--profile: file not found: $1"; exit 1; }
            OSCAL_PROFILE_FILE="$1"; _FLAGS_SET=1
            ;;
        --framework)
            shift
            [[ -z "${1:-}" ]] && { echo "--framework requires a value"; usage; exit 1; }
            IFS=',' read -ra FRAMEWORKS <<< "$1"
            for _fw in "${FRAMEWORKS[@]}"; do
                case "$_fw" in
                    nist|cis|iso27001|soc2) ;;
                    *) echo "Unknown framework '$_fw': use nist, cis, iso27001, soc2"; exit 1 ;;
                esac
            done
            _FLAGS_SET=1
            ;;
        --interactive)      INTERACTIVE_MODE=1 ;;
        --check)
            shift
            [[ -z "${1:-}" ]] && { echo "--check requires a value"; usage; exit 1; }
            IFS=',' read -ra RUN_ONLY <<< "$1"; _FLAGS_SET=1
            ;;
        --skip)
            shift
            [[ -z "${1:-}" ]] && { echo "--skip requires a value"; usage; exit 1; }
            IFS=',' read -ra SKIP_CHECKS <<< "$1"; _FLAGS_SET=1
            ;;
        --verify)           VERIFY_MODE=1;     _FLAGS_SET=1 ;;
        --webhook)
            shift
            [[ -z "${1:-}" ]] && { echo "--webhook requires a URL"; usage; exit 1; }
            [[ "$1" =~ ^https?:// ]] || { echo "--webhook URL must start with http:// or https://"; exit 1; }
            WEBHOOK_URL="$1";  _FLAGS_SET=1
            ;;
        --ansible)          ANSIBLE_MODE=1;    _FLAGS_SET=1 ;;
        --help)             usage; exit 0 ;;
        *)                  echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# Sync OSCAL_CATALOG from primary framework (iso27001/soc2 fall back to nist catalog)
case "${FRAMEWORKS[0]}" in
    nist|cis) OSCAL_CATALOG="${FRAMEWORKS[0]}" ;;
    *)        OSCAL_CATALOG="nist" ;;
esac

# Auto-trigger wizard: TTY + no intent flags passed
# --interactive forces it; any intent flag suppresses it
if [[ $INTERACTIVE_MODE -eq 1 ]] || \
   { [[ -t 0 ]] && [[ $_FLAGS_SET -eq 0 ]]; }; then
    _interactive_wizard
fi

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
    _prev_findings=$(ls -1t "${REPORT_DIR}"/sec-audit-findings-*.jsonl 2>/dev/null | sed -n '2p' || true)
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

# ====================== CHECK FUNCTIONS ======================

check_updates() {
    print_status "INFO" "Checking package updates..."
    if [[ $SKIP_APT_UPDATE -eq 0 ]]; then
        sudo apt-get update -qq
    else
        print_status "INFO" "Skipping apt-get update (--skip-apt-update set)"
    fi
    if apt list --upgradable 2>/dev/null | grep -q upgradable; then
        print_status "WARN" "Updates available"
        append_report "## Package Updates\n- 🟡 Updates available"
        report_issue 12 \
            "System not fully patched" \
            "Outdated packages increase attack surface (CVEs)" \
            "sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y" \
            0 \
            "Reboot if kernel or libc was upgraded"
    else
        print_status "OK" "System up-to-date"
        append_report "## Package Updates\n- 🟢 Up-to-date"
    fi
}

check_firewall() {
    print_status "INFO" "Checking firewall (IPv4 + IPv6)..."

    local ipv4_ok=0
    local ufw_active=0

    if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "Status: active"; then
        print_status "OK" "UFW active (IPv4)"
        append_report "## Firewall\n- 🟢 UFW active (IPv4)"
        ipv4_ok=1
        ufw_active=1
    elif command -v nft >/dev/null 2>&1 && sudo nft list ruleset | grep -q "chain"; then
        print_status "OK" "nftables active"
        append_report "## Firewall\n- 🟢 nftables active"
        ipv4_ok=1
    elif sudo iptables -nL | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
        print_status "OK" "iptables rules present"
        append_report "## Firewall\n- 🟢 iptables rules present"
        ipv4_ok=1
    fi

    if [[ $ipv4_ok -eq 0 ]]; then
        print_status "WARN" "No IPv4 firewall detected"
        append_report "## Firewall\n- 🔴 No active IPv4 firewall"

        local ssh_port
        ssh_port=$(sudo sshd -T 2>/dev/null | awk '/^port / {print $2}' | head -1 || echo "22")
        [[ -z "$ssh_port" ]] && ssh_port="22"

        report_issue 15 \
            "No Active Firewall (IPv4)" \
            "Neither UFW, nftables, nor iptables rules are active" \
            "sudo /usr/bin/apt-get install -y ufw
sudo /usr/sbin/ufw default deny incoming
sudo /usr/sbin/ufw default allow outgoing
# SSH port auto-detected as ${ssh_port} - verify before applying:
sudo /usr/sbin/ufw allow ${ssh_port}/tcp
sudo /usr/sbin/ufw --force enable
sudo /usr/sbin/ufw status verbose" \
            0 \
            "⚠️ SSH port detected as ${ssh_port}. If wrong, update the allow rule BEFORE enabling UFW to avoid lockout."
    fi

    # --- IPv6 firewall check ---
    local ipv6_ok=0

    if [[ $ufw_active -eq 1 ]]; then
        if grep -qE '^\s*IPV6\s*=\s*yes' /etc/default/ufw 2>/dev/null; then
            print_status "OK" "UFW IPv6 enabled (/etc/default/ufw IPV6=yes)"
            append_report "## Firewall IPv6\n- 🟢 UFW managing IPv6"
            ipv6_ok=1
        else
            print_status "WARN" "UFW is active but IPV6=yes not set - IPv6 traffic unfiltered"
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]] && command -v ip6tables >/dev/null 2>&1; then
        if sudo ip6tables -nL 2>/dev/null | grep -qE "Chain INPUT.*(DROP|REJECT)"; then
            print_status "OK" "ip6tables rules present (IPv6)"
            append_report "## Firewall IPv6\n- 🟢 ip6tables rules present"
            ipv6_ok=1
        fi
    fi

    if [[ $ipv6_ok -eq 0 ]]; then
        print_status "WARN" "No IPv6 firewall rules detected"
        append_report "## Firewall IPv6\n- 🔴 No active IPv6 firewall"
        report_issue 10 \
            "No Active Firewall (IPv6)" \
            "IPv6 traffic is unfiltered - UFW IPV6=yes not set and no ip6tables DROP/REJECT rules found" \
            "# Enable IPv6 in UFW (recommended):
sudo /bin/sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
sudo /usr/sbin/ufw disable && sudo /usr/sbin/ufw --force enable
# Verify:
sudo /usr/sbin/ufw status verbose
sudo /usr/sbin/ip6tables -L INPUT --line-numbers" \
            0 \
            "IPv6 is enabled on most Ubuntu systems by default; unfiltered IPv6 bypasses IPv4-only rules"
    fi

    # --- UFW logging check ---
    if [[ $ufw_active -eq 1 ]]; then
        local ufw_log_level
        ufw_log_level=$(sudo ufw status verbose 2>/dev/null | awk '/^Logging:/ {print $2}' || true)
        if [[ -z "$ufw_log_level" || "$ufw_log_level" == "off" ]]; then
            print_status "WARN" "UFW logging is disabled - firewall events are not recorded"
            append_report "## Firewall Logging\n- 🔴 UFW logging is off"
            report_issue 5 \
                "UFW firewall logging disabled" \
                "UFW is active but logging is off - blocked/allowed connections are not recorded" \
                "sudo /usr/sbin/ufw logging low
# Verify:
sudo /usr/sbin/ufw status verbose | grep -i logging
sudo /usr/bin/tail -20 /var/log/ufw.log" \
                0 \
                "Recommended minimum is 'low'; use 'medium' on internet-facing systems"
        else
            print_status "OK" "UFW logging is enabled (level: ${ufw_log_level})"
            append_report "## Firewall Logging\n- 🟢 UFW logging enabled (level: ${ufw_log_level})"
        fi
    fi
}

check_open_ports() {
    print_status "INFO" "Checking open ports and service versions..."
    local raw_ports port_tool="ss"
    if command -v ss >/dev/null 2>&1; then
        raw_ports=$(sudo ss -tulpn 2>/dev/null | tail -n +2)
    elif command -v netstat >/dev/null 2>&1; then
        raw_ports=$(sudo netstat -tulpn 2>/dev/null | tail -n +2)
        port_tool="netstat"
    else
        print_status "WARN" "No tool to list ports (ss/netstat missing)"
        append_report "## Open Ports & Services\n- ⚠️ Cannot list listening ports"
        return
    fi

    if [[ -z "$raw_ports" ]]; then
        print_status "OK" "No listening services"
        append_report "## Open Ports & Services\n- 🟢 No listening services"
        return
    fi

    print_status "INFO" "Listening services detected (service + version shown below)"

    local section="## Open Ports & Running Services\n\n"
    section+="| Proto | Listen Address:Port         | PID   | Process Name     | Version                  |\n"
    section+="|-------|-----------------------------|-------|------------------|-------------------------|\n"

    local count=0
    local -a deprecated_services=()

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        count=$((count + 1))
        local proto listen pid_raw process_raw
        if [[ "$port_tool" == "ss" ]]; then
            proto=$(awk '{print $1}' <<< "$line")
            listen=$(awk '{print $5}' <<< "$line")
            pid_raw=$(grep -oE 'pid=[0-9]+' <<< "$line" | head -1 | cut -d= -f2 || echo "-")
            # FIX: more robust process name extraction: handle spaces or special chars in name
            # ss format: users:(("name",pid=N,fd=N)) — extract first quoted name field
            process_raw=$(grep -oP 'users:\(\("([^"]+)"' <<< "$line" | head -1 | grep -oP '"([^"]+)"$' | tr -d '"' || echo "unknown")
            [[ -z "$pid_raw" ]] && pid_raw="-"
            [[ -z "$process_raw" ]] && process_raw="unknown"
        else
            read -r proto listen pid_raw process_raw < <(
                awk '{
                    proto=$1; addr=$4
                    pid="-"; proc="unknown"
                    n=split($NF,a,"/")
                    if (n>=2) { pid=a[1]; proc=a[2] }
                    print proto, addr, pid, proc
                }' <<< "$line"
            )
        fi
        local version="N/A"
        [[ "$pid_raw" != "-" ]] && version=$(get_service_version "$process_raw" "$pid_raw" || echo "N/A")
        [[ ${#version} -gt 28 ]] && version="${version:0:25}..."
        section+="| $proto | $listen | $pid_raw | $process_raw | $version |\n"

        if echo "$listen" | grep -qE '^(\[?::\]?|0\.0\.0\.0|\*):'; then
            print_status "WARN" "Service '$process_raw' is bound to ALL interfaces on $listen - consider restricting to 127.0.0.1 if not intentional"
        fi

        # FIX: robust port extraction supporting all address formats:
        #   IPv4  0.0.0.0:22   127.0.0.1:22
        #   IPv6  [::]:22      [::1]:22      *:22
        local port_num
        port_num=$(echo "$listen" | grep -oE ':([0-9]+)$' | tr -d ':' || true)
        case "$port_num" in
            21)  deprecated_services+=("FTP (plaintext file transfer) on port 21 - process: $process_raw") ;;
            23)  deprecated_services+=("Telnet (plaintext shell) on port 23 - process: $process_raw") ;;
            69)  deprecated_services+=("TFTP (unauthenticated file transfer) on port 69 - process: $process_raw") ;;
            513) deprecated_services+=("rsh/exec (no auth, plaintext) on port 513 - process: $process_raw") ;;
            514) deprecated_services+=("rlogin (no auth, plaintext) on port 514 - process: $process_raw") ;;
        esac
    done <<< "$raw_ports"

    append_report "$section"
    if [[ $count -gt 0 ]]; then
        print_status "INFO" "Found $count listening service(s) - full table in report"
    fi

    # Report deprecated services as a single issue
    if [[ ${#deprecated_services[@]} -gt 0 ]]; then
        local dep_list
        dep_list=$(printf ' - %s\n' "${deprecated_services[@]}")
        print_status "WARN" "Deprecated/plaintext protocol services detected: ${#deprecated_services[@]}"
        append_report "## Deprecated Network Services\n- 🔴 ${#deprecated_services[@]} plaintext/deprecated protocol(s) listening"
        report_issue 15 \
            "Deprecated or plaintext network services listening" \
            "${#deprecated_services[@]} deprecated service(s) detected - these transmit credentials in cleartext and/or lack authentication" \
            "# Stop and disable deprecated services:
sudo /bin/systemctl disable --now inetd xinetd telnet.socket 2>/dev/null || true
sudo /usr/bin/apt-get purge -y telnetd telnet nis rsh-server rsh-client atftpd tftpd tftp xinetd inetd 2>/dev/null || true
sudo /usr/bin/apt-get autoremove -y
# Block at firewall level even if already purged:
sudo /usr/sbin/ufw deny 21/tcp
sudo /usr/sbin/ufw deny 23/tcp
sudo /usr/sbin/ufw deny 69/udp
sudo /usr/sbin/ufw deny 513/tcp
sudo /usr/sbin/ufw deny 514/tcp
# Verify no longer listening:
sudo ss -tulpn | grep -E ':21|:23|:69|:513|:514'" \
            0 \
            "Services detected:\n${dep_list}\n\nReplace with: SFTP/SCP (not FTP), SSH (not Telnet/rsh/rlogin)"
    fi
}

check_ssh() {
    print_status "INFO" "Checking SSH hardening (extended)..."
    if ! command -v sshd >/dev/null 2>&1; then
        print_status "OK" "SSH not installed"
        return
    fi

    local sshd_conf
    sshd_conf=$(sudo sshd -T 2>/dev/null)

    local ssh_issues=()
    local ssh_fixes=""

    # Check 1: PermitRootLogin
    if ! grep -qE 'permitrootlogin (no|prohibit-password)' <<< "$sshd_conf"; then
        ssh_issues+=("PermitRootLogin is not set to 'no' or 'prohibit-password'")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 2: PasswordAuthentication
    # Warn about disabling password auth without verifying keys
    if ! grep -qE 'passwordauthentication no' <<< "$sshd_conf"; then
        ssh_issues+=("PasswordAuthentication is enabled")
        ssh_fixes+="# ⚠️  BEFORE APPLYING: verify SSH keys are installed for all admin accounts"$'\n'
        ssh_fixes+="#    Run from another terminal: ssh -o PasswordAuthentication=no user@host"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 3: MaxAuthTries (CIS: ≤ 4)
    local max_auth_tries
    max_auth_tries=$(awk '/^maxauthtries / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$max_auth_tries" || "$max_auth_tries" -gt 4 ]]; then
        ssh_issues+=("MaxAuthTries is ${max_auth_tries:-unset} (should be ≤ 4)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 4: LoginGraceTime (CIS: ≤ 60 seconds)
    local grace_time
    grace_time=$(awk '/^logingracetime / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$grace_time" || "$grace_time" -eq 0 || "$grace_time" -gt 60 ]]; then
        ssh_issues+=("LoginGraceTime is ${grace_time:-unset} (should be 1–60 seconds)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 5: X11Forwarding
    if grep -qE 'x11forwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("X11Forwarding is enabled (unnecessary attack surface)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 6: AllowTcpForwarding
    if grep -qE 'allowtcpforwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("AllowTcpForwarding is enabled (can tunnel unauthorised traffic)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 7: ClientAlive settings (idle timeout)
    local client_interval
    client_interval=$(awk '/^clientaliveinterval / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$client_interval" || "$client_interval" -eq 0 ]]; then
        ssh_issues+=("ClientAliveInterval is 0 (no idle session timeout)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="sudo /bin/sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 8: SSHv1 disabled
    if grep -qE '^protocol\s+.*\b1\b' <<< "$sshd_conf"; then
        ssh_issues+=("SSHv1 is enabled - it is deprecated and cryptographically broken")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?Protocol.*/Protocol 2/' /etc/ssh/sshd_config"$'\n'
    fi

    # Check 9: SSH host private key file permissions (must be 600, root-owned)
    while IFS= read -r keyfile; do
        local kperms kowner
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        if [[ "$kperms" != "600" || "$kowner" != "root" ]]; then
            ssh_issues+=("Host private key ${keyfile}: perms=${kperms:-?}, owner=${kowner:-?} (should be 600 root)")
            ssh_fixes+="sudo /bin/chmod 600 $(printf '%q' "$keyfile")"$'\n'
            ssh_fixes+="sudo /bin/chown root:root $(printf '%q' "$keyfile")"$'\n'
        fi
    done < <(find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' ! -name '*.pub' 2>/dev/null)

    # Check 10: Weak ciphers, MACs, and KEX algorithms
    local weak_ciphers=("3des-cbc" "blowfish-cbc" "cast128-cbc" "arcfour" "arcfour128" "arcfour256"
                        "aes128-cbc" "aes192-cbc" "aes256-cbc" "rijndael-cbc@lysator.liu.se")
    local weak_macs=("hmac-md5" "hmac-md5-96" "hmac-sha1-96"
                     "umac-64@openssh.com" "hmac-md5-etm@openssh.com" "hmac-md5-96-etm@openssh.com"
                     "umac-64-etm@openssh.com" "hmac-sha1-96-etm@openssh.com")
    local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group14-sha1"
                    "diffie-hellman-group-exchange-sha1" "gss-gex-sha1-" "gss-group1-sha1-"
                    "gss-group14-sha1-")

    local active_ciphers active_macs active_kex
    active_ciphers=$(awk '/^ciphers / {print $2}' <<< "$sshd_conf" | tr ',' '\n' || true)
    active_macs=$(awk '/^macs / {print $2}'    <<< "$sshd_conf" | tr ',' '\n' || true)
    active_kex=$(awk '/^kexalgorithms / {print $2}' <<< "$sshd_conf" | tr ',' '\n' || true)

    local -a crypto_issues=() bad_ciphers=() bad_macs=() bad_kex=()

    for c in "${weak_ciphers[@]}"; do
        if grep -qxF "$c" <<< "$active_ciphers"; then
            bad_ciphers+=("$c"); crypto_issues+=("Weak cipher active: ${c}")
        fi
    done
    for m in "${weak_macs[@]}"; do
        if grep -qxF "$m" <<< "$active_macs"; then
            bad_macs+=("$m"); crypto_issues+=("Weak MAC active: ${m}")
        fi
    done
    for k in "${weak_kex[@]}"; do
        if echo "$active_kex" | grep -q "^${k}"; then
            bad_kex+=("$k"); crypto_issues+=("Weak KEX active: ${k}")
        fi
    done

    if [[ ${#crypto_issues[@]} -gt 0 ]]; then
        ssh_issues+=("Weak crypto algorithms in use (${#crypto_issues[@]} issue(s)) - see note")
        # FIX: write to a drop-in file instead of tee -a /etc/ssh/sshd_config.
        # tee -a can create duplicate/conflicting Ciphers/MACs/KexAlgorithms directives
        # if partial entries already exist, causing sshd to refuse to start.
        # Ubuntu 20.04+ natively supports /etc/ssh/sshd_config.d/ include fragments.
        # The drop-in takes precedence over the main config and is idempotent on re-run.
        ssh_fixes+='# Write crypto hardening to a drop-in file (safe, idempotent, Ubuntu 20.04+):'$'\n'
        ssh_fixes+='sudo /bin/mkdir -p /etc/ssh/sshd_config.d'$'\n'
        ssh_fixes+='sudo /usr/bin/tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null << '"'"'SSHEOF'"'"$'\n'
        ssh_fixes+='Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'$'\n'
        ssh_fixes+='MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com'$'\n'
        ssh_fixes+='KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'$'\n'
        ssh_fixes+='SSHEOF'$'\n'
        ssh_fixes+='sudo /bin/chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf'$'\n'
        ssh_fixes+='sudo /bin/chown root:root /etc/ssh/sshd_config.d/99-hardening.conf'$'\n'
        # Ensure main sshd_config has an Include directive (Ubuntu 22.04+ includes it by default)
        ssh_fixes+='# Ensure the main sshd_config includes the drop-in directory (Ubuntu 22.04+ does this by default):'$'\n'
        ssh_fixes+='grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \'$'\n'
        ssh_fixes+='  sudo /bin/sed -i '"'"'1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|'"'"' /etc/ssh/sshd_config'$'\n'
    fi

    # NEW Check 11: PermitEmptyPasswords (must be no)
    if ! grep -qE 'permitemptypasswords no' <<< "$sshd_conf"; then
        ssh_issues+=("PermitEmptyPasswords is not explicitly set to 'no'")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 12: HostbasedAuthentication (must be no)
    if grep -qE 'hostbasedauthentication yes' <<< "$sshd_conf"; then
        ssh_issues+=("HostbasedAuthentication is enabled (allows host-trust logins)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 13: IgnoreRhosts (must be yes)
    if grep -qE 'ignorerhosts no' <<< "$sshd_conf"; then
        ssh_issues+=("IgnoreRhosts is disabled - .rhosts files are honoured (legacy trust risk)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 14: MaxStartups (CIS: 10:30:60)
    local max_startups max_startups_max
    max_startups=$(awk '/^maxstartups / {print $2}' <<< "$sshd_conf" | head -1)
    max_startups_max=$(echo "${max_startups:-}" | cut -d: -f3)
    if [[ -z "$max_startups" || -z "$max_startups_max" || "$max_startups_max" -gt 60 ]]; then
        ssh_issues+=("MaxStartups is ${max_startups:-unset} (third component should be ≤ 60; default 10:30:100 allows connection floods)")
        ssh_fixes+="sudo /bin/sed -i 's/^#\?MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config"$'\n'
    fi

    # NEW Check 15: AllowUsers / AllowGroups restriction
    if ! grep -qE '^(allowusers|allowgroups)\s' <<< "$sshd_conf"; then
        ssh_issues+=("No AllowUsers or AllowGroups directive - any valid system user can attempt SSH login")
        ssh_fixes+="# Restrict SSH to specific users or group (choose one approach):"$'\n'
        ssh_fixes+="# echo 'AllowGroups sshusers' | sudo /usr/bin/tee -a /etc/ssh/sshd_config"$'\n'
        ssh_fixes+="# sudo /usr/sbin/groupadd sshusers && sudo /usr/sbin/usermod -aG sshusers <yourusername>"$'\n'
    fi

    if [[ ${#ssh_issues[@]} -eq 0 ]]; then
        print_status "OK" "SSH fully hardened (all extended checks passed)"
        append_report "## SSH Hardening\n- 🟢 All SSH hardening checks passed"
    else
        print_status "WARN" "SSH hardening issues: ${#ssh_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${ssh_issues[@]}")
        append_report "## SSH Hardening\n- 🔴 Weak SSH config (${#ssh_issues[@]} issue(s))"

        ssh_fixes+="# Validate config before restarting (explicit guard so sshd is never restarted with invalid config):
if sudo /usr/sbin/sshd -t 2>&1; then
    sudo /bin/systemctl restart ssh
    echo '[OK] sshd restarted with hardened config'
else
    echo '[ERROR] sshd -t validation failed - sshd NOT restarted. Review /etc/ssh/sshd_config manually.'
fi
# Verify:
sudo /usr/sbin/sshd -T 2>/dev/null | grep -E 'permitroot|passwordauth|maxauth|logingrace|x11|tcpforward|clientalive|permitempty|hostbased|ignorerhosts|maxstartups|allowusers|allowgroups' || true"

        local combined_note="Issues:\n${issue_list}\n\nAlso consider Fail2Ban or key-only auth"
        combined_note+=$'\n\n⚠️ BEFORE disabling PasswordAuthentication: verify working SSH keys from another terminal'
        [[ ${#crypto_issues[@]} -gt 0 ]] && combined_note+=$'\n\nWeak crypto details:\n'"$(printf ' - %s\n' "${crypto_issues[@]}")"
        report_issue 10 \
            "SSH configuration weaknesses found" \
            "SSH daemon is not fully hardened: ${#ssh_issues[@]} setting(s) out of compliance" \
            "$ssh_fixes" \
            0 \
            "$combined_note"
    fi
}

check_users() {
    print_status "INFO" "Checking users & sudo..."
    local sudoers
    sudoers=$(sudo grep -E '^\s*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true)
    if [[ -n "$sudoers" ]]; then
        print_status "WARN" "Users with NOPASSWD sudo found"
        append_report "## Users & Sudo\n- 🟡 Full sudo privileges found"
        report_issue 8 \
            "Users with NOPASSWD sudo" \
            "Users can run any command as root without password" \
            "# Open sudoers safely with visudo - do NOT edit /etc/sudoers directly
sudo /usr/sbin/visudo
# Find and remove or restrict lines matching NOPASSWD, e.g.:
#   username ALL=(ALL) NOPASSWD: ALL   <-- remove or change to:
#   username ALL=(ALL) ALL" \
            0
    else
        print_status "OK" "No dangerous sudoers"
        append_report "## Users & Sudo\n- 🟢 No dangerous sudo privileges"
    fi

    local plain_pw_users
    plain_pw_users=$(awk -F: '($2 != "x" && $2 != "*" && $2 != "!" && $2 != "") {print $1}' /etc/passwd || true)
    if [[ -n "$plain_pw_users" ]]; then
        print_status "ERR" "Accounts with plaintext passwords in /etc/passwd"
        append_report "## Users & Sudo\n- 🔴 Accounts with plaintext passwords in /etc/passwd"
        report_issue 15 \
            "Plaintext passwords in /etc/passwd" \
            "These accounts have passwords stored directly in /etc/passwd (pre-shadow format - critical risk)" \
            "/usr/sbin/pwconv
# Verify no plaintext passwords remain:
/usr/bin/awk -F: '(\$2 != \"x\" && \$2 != \"*\" && \$2 != \"!\" && \$2 != \"\") {print \$1}' /etc/passwd" \
            0 \
            "Affected accounts: $(echo "$plain_pw_users" | tr '\n' ' ')"
    fi

    local locked_with_shell
    locked_with_shell=$(
        while IFS=: read -r user pw _rest; do
            [[ "$pw" == '!'* ]] || continue
            shell=$(awk -F: -v u="$user" '$1==u {print $7}' /etc/passwd 2>/dev/null || true)
            [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/dash" ]] \
                && echo "$user ($shell)"
        done < /etc/shadow 2>/dev/null || true
    )
    if [[ -n "$locked_with_shell" ]]; then
        print_status "WARN" "Locked accounts with interactive login shells detected"
        append_report "## Users & Sudo\n- 🟡 Locked accounts retain interactive shells"
        report_issue 5 \
            "Locked accounts with interactive login shells" \
            "Accounts are locked in shadow but still have /bin/bash or similar" \
            "$(echo "$locked_with_shell" | awk '{print "sudo /usr/sbin/usermod -s /usr/sbin/nologin " $1}')
# Verify:
/usr/bin/awk -F: '(\$7 ~ /bash|sh|dash/) {print \$1, \$7}' /etc/passwd" \
            0 \
            "Affected accounts: $(echo "$locked_with_shell" | tr '\n' ' ')"
    fi

    local uid0_count
    uid0_count=$(awk -F: '$3==0 {print}' /etc/passwd | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        print_status "ERR" "Multiple root (UID 0) accounts found"
        append_report "## Users & Sudo\n- 🔴 Multiple UID 0 accounts"
        report_issue 12 \
            "Multiple UID 0 accounts" \
            "More than one account with root privileges (privilege escalation risk)" \
            "/usr/bin/awk -F: '\$3==0 {print \$1}' /etc/passwd
# For each unexpected UID 0 account (NOT root), lock it:
sudo /usr/sbin/usermod -L <username>
sudo /usr/sbin/usermod -s /usr/sbin/nologin <username>" \
            0
    fi
}

check_permissions() {
    print_status "INFO" "Checking critical permissions..."
    if [[ "$(stat -c %a /etc/shadow)" != "640" ]] || [[ "$(stat -c %a /etc/passwd)" != "644" ]]; then
        print_status "ERR" "Weak critical file permissions"
        append_report "## Critical Permissions\n- 🔴 /etc/shadow or /etc/passwd permissions incorrect"
        report_issue 10 \
            "Weak critical file permissions" \
            "/etc/shadow or /etc/passwd have incorrect permissions" \
            "sudo /bin/chmod 640 /etc/shadow
sudo /bin/chmod 644 /etc/passwd
sudo /bin/chown root:shadow /etc/shadow
sudo /bin/chown root:root /etc/passwd
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/shadow /etc/passwd" \
            0
    else
        print_status "OK" "Critical files properly permissioned"
        append_report "## Critical Permissions\n- 🟢 Correct permissions on /etc/shadow and /etc/passwd"
    fi

    if [[ -f /etc/ssh/sshd_config ]]; then
        local sshd_cfg_perms sshd_cfg_owner sshd_cfg_group
        sshd_cfg_perms=$(stat -c '%a' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_owner=$(stat -c '%U' /etc/ssh/sshd_config  2>/dev/null || true)
        sshd_cfg_group=$(stat -c '%G' /etc/ssh/sshd_config  2>/dev/null || true)
        if [[ "$sshd_cfg_perms" != "600" || "$sshd_cfg_owner" != "root" || "$sshd_cfg_group" != "root" ]]; then
            print_status "WARN" "sshd_config permissions incorrect: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} (should be 600 root:root)"
            append_report "## Critical Permissions\n- 🔴 /etc/ssh/sshd_config: ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group}"
            report_issue 8 \
                "sshd_config has insecure permissions" \
                "/etc/ssh/sshd_config is ${sshd_cfg_perms} ${sshd_cfg_owner}:${sshd_cfg_group} - should be 600 root:root (CIS 5.2.1)" \
                "sudo /bin/chmod 600 /etc/ssh/sshd_config
sudo /bin/chown root:root /etc/ssh/sshd_config
# Verify:
/usr/bin/stat -c '%n %a %U:%G' /etc/ssh/sshd_config" \
                0
        else
            print_status "OK" "/etc/ssh/sshd_config permissions are correct (600 root:root)"
            append_report "## Critical Permissions\n- 🟢 /etc/ssh/sshd_config is 600 root:root"
        fi
    fi
}

check_unattended() {
    print_status "INFO" "Checking unattended-upgrades..."
    if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Unattended-upgrades missing"
        append_report "## Automatic Updates\n- 🔴 Not installed"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades package is not installed" \
            "sudo /usr/bin/apt-get install -y unattended-upgrades
sudo /usr/sbin/dpkg-reconfigure -pmedium unattended-upgrades
/usr/bin/systemctl is-enabled unattended-upgrades" \
            0
        return
    fi

    if grep -qE '"${distro_id}:${distro_codename}-security"' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
        print_status "OK" "Unattended-upgrades installed and enabled for security"
        append_report "## Automatic Updates\n- 🟢 Enabled"
    else
        print_status "WARN" "Unattended-upgrades not configured for security updates"
        append_report "## Automatic Updates\n- 🔴 Security updates not enabled"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades installed but security updates not enabled" \
            "sudo /usr/sbin/dpkg-reconfigure -pmedium unattended-upgrades
# Or manually ensure this line is uncommented in /etc/apt/apt.conf.d/50unattended-upgrades:
#   \"\${distro_id}:\${distro_codename}-security\";
sudo /bin/grep -n 'security' /etc/apt/apt.conf.d/50unattended-upgrades" \
            0
    fi
}

check_apparmor() {
    print_status "INFO" "Checking AppArmor..."
    local enforced_count
    enforced_count=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}' || echo 0)
    if [[ "$enforced_count" -gt 0 ]]; then
        print_status "OK" "AppArmor enforced ($enforced_count profile(s) in enforce mode)"
        append_report "## AppArmor\n- 🟢 Enforced ($enforced_count profile(s))"
    else
        print_status "WARN" "AppArmor not enforcing"
        append_report "## AppArmor\n- 🔴 Not enforcing"
        report_issue 7 \
            "AppArmor disabled" \
            "AppArmor is not enforcing profiles" \
            "sudo /usr/bin/apt-get install -y apparmor apparmor-profiles apparmor-utils
sudo /bin/systemctl enable --now apparmor
sudo /usr/sbin/aa-enforce /etc/apparmor.d/*
sudo /usr/sbin/aa-status" \
            0
    fi
}

check_failed_logins() {
    print_status "INFO" "Analyzing failed logins..."
    local fails
    fails=$(sudo journalctl -u ssh --since "1 day ago" 2>/dev/null \
            | awk '/Failed password/{c++} END{print c+0}')
    if [[ "$fails" -gt $FAILED_LOGIN_THRESHOLD ]]; then
        print_status "WARN" "Many failed login attempts"
        append_report "## Failed Logins\n- 🟡 $fails failed attempts (last 24h)"
        report_issue 6 \
            "High failed login count" \
            "Possible brute-force attack on SSH ($fails failures in 24h)" \
            "sudo /usr/bin/apt-get install -y fail2ban
sudo /bin/systemctl enable --now fail2ban
sudo /usr/bin/fail2ban-client status sshd
sudo /usr/bin/journalctl -u ssh --since '1 day ago' | /bin/grep 'Failed password' | /usr/bin/tail -20" \
            0 \
            "Review /var/log/auth.log and consider key-only SSH authentication"
    else
        print_status "OK" "No unusual failed logins"
        append_report "## Failed Logins\n- 🟢 Normal"
    fi
}

check_fail2ban() {
    print_status "INFO" "Checking Fail2Ban installation and configuration..."

    if ! dpkg -l fail2ban 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Fail2Ban is not installed"
        append_report "## Fail2Ban\n- 🔴 fail2ban not installed"
        report_issue 6 \
            "Fail2Ban not installed" \
            "No automated IP banning on repeated authentication failures - brute-force attacks go unchecked at the OS level" \
            "sudo /usr/bin/apt-get install -y fail2ban
sudo /bin/systemctl enable --now fail2ban
# Create a hardened SSH jail override:
sudo /usr/bin/tee /etc/fail2ban/jail.d/sshd-hardened.conf << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
bantime  = 1d
findtime = 10m
EOF
sudo /bin/systemctl restart fail2ban
sudo /usr/bin/fail2ban-client status sshd" \
            0 \
            "Also consider CrowdSec as a community-driven alternative with shared blocklists"
        return
    fi

    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_status "WARN" "Fail2Ban installed but not running"
        append_report "## Fail2Ban\n- 🔴 fail2ban installed but inactive"
        report_issue 5 \
            "Fail2Ban installed but not running" \
            "fail2ban service is not active - no IP banning is occurring despite the package being present" \
            "sudo /bin/systemctl enable --now fail2ban
sudo /bin/systemctl status fail2ban
sudo /usr/bin/fail2ban-client status" \
            0
        return
    fi

    local ssh_jail_status
    ssh_jail_status=$(sudo /usr/bin/fail2ban-client status sshd 2>/dev/null || true)
    if [[ -z "$ssh_jail_status" ]]; then
        print_status "WARN" "Fail2Ban active but sshd jail is not configured"
        append_report "## Fail2Ban\n- 🟡 fail2ban running but no sshd jail enabled"
        report_issue 4 \
            "Fail2Ban running without SSH jail" \
            "fail2ban is active but no sshd jail is enabled - SSH brute-force attempts are not being blocked" \
            "sudo /usr/bin/tee /etc/fail2ban/jail.d/sshd-hardened.conf << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 5
bantime  = 1d
findtime = 10m
EOF
sudo /bin/systemctl restart fail2ban
sudo /usr/bin/fail2ban-client status sshd" \
            0
    else
        local banned_count
        banned_count=$(echo "$ssh_jail_status" | grep -oE 'Currently banned:[[:space:]]+[0-9]+' | grep -oE '[0-9]+' || echo "0")
        print_status "OK" "Fail2Ban active with sshd jail configured (currently banned: ${banned_count:-0} IPs)"
        append_report "## Fail2Ban\n- 🟢 fail2ban active, sshd jail enabled (banned: ${banned_count:-0})"
    fi
}

check_kernel() {
    print_status "INFO" "Checking kernel/sysctl hardening (extended)..."

    declare -A SYSCTL_CHECKS=(
        ["kernel.randomize_va_space"]="2"
        ["fs.protected_hardlinks"]="1"
        ["fs.protected_symlinks"]="1"
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="2"
        ["kernel.yama.ptrace_scope"]="1"
        ["fs.protected_fifos"]="2"
        ["fs.protected_regular"]="2"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="1"
        ["net.ipv4.conf.default.secure_redirects"]="1"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv6.conf.all.forwarding"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
        ["net.ipv6.conf.all.accept_source_route"]="0"
        ["net.ipv6.conf.default.accept_source_route"]="0"
        ["kernel.unprivileged_bpf_disabled"]="1"
        ["net.core.bpf_jit_harden"]="2"
        ["kernel.kexec_load_disabled"]="1"
        ["kernel.perf_event_paranoid"]="3"
        ["kernel.sysrq"]="0"
        ["net.ipv4.tcp_timestamps"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.tcp_rfc1337"]="1"
    )

    # Docker requires ip_forward; skip those keys to avoid false positives and broken fixes
    if command -v docker >/dev/null 2>&1 || dpkg -l docker-ce 2>/dev/null | grep -q '^ii'; then
        unset 'SYSCTL_CHECKS[net.ipv4.ip_forward]'
        unset 'SYSCTL_CHECKS[net.ipv6.conf.all.forwarding]'
        print_status "INFO" "Docker detected - skipping net.ipv4.ip_forward / net.ipv6.conf.all.forwarding checks"
    fi

    local -a sysctl_failures=()
    local sysctl_fix_lines=""

    for key in "${!SYSCTL_CHECKS[@]}"; do
        local expected="${SYSCTL_CHECKS[$key]}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "")
        if [[ "$actual" != "$expected" ]]; then
            sysctl_failures+=("${key} = ${actual:-unset} (expected ${expected})")
            sysctl_fix_lines+="${key} = ${expected}"$'\n'
        fi
    done

    if [[ ${#sysctl_failures[@]} -eq 0 ]]; then
        print_status "OK" "All kernel sysctl hardening checks passed"
        append_report "## Kernel Hardening\n- 🟢 ASLR, hardlinks, symlinks, dmesg, kptr, ptrace_scope, redirects, source_route, log_martians, syncookies, rp_filter all hardened"
    else
        print_status "WARN" "Kernel sysctl issues: ${#sysctl_failures[@]} found"
        local fail_list
        fail_list=$(printf ' - %s\n' "${sysctl_failures[@]}")
        append_report "## Kernel Hardening\n- 🔴 ${#sysctl_failures[@]} sysctl(s) not hardened"

        local sysctl_fix_content
        sysctl_fix_content="printf '%s' '${sysctl_fix_lines}' | sudo /usr/bin/tee /etc/sysctl.d/99-hardening.conf
sudo /sbin/sysctl --system 2>&1 | grep -v 'No such file' || true
$(printf 'sudo /sbin/sysctl %s 2>/dev/null || true\n' "${!SYSCTL_CHECKS[@]}")"

        report_issue 9 \
            "Kernel sysctl hardening incomplete" \
            "${#sysctl_failures[@]} sysctl parameter(s) are not set to secure values" \
            "$sysctl_fix_content" \
            0 \
            "Non-compliant values:\n${fail_list}"
    fi

    # Kernel module blacklist check (CIS-aligned)
    local -a required_blacklisted=("usb-storage" "cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "dccp" "sctp" "rds" "tipc")
    local -a not_blacklisted=()
    # squashfs is required by snapd; skip the blacklist check if snaps are present
    local snaps_active=false
    if command -v snap &>/dev/null && snap list &>/dev/null 2>&1 && [[ $(snap list 2>/dev/null | wc -l) -gt 1 ]]; then
        snaps_active=true
    fi
    for mod in "${required_blacklisted[@]}"; do
        if [[ "$mod" == "squashfs" && "$snaps_active" == true ]]; then
            continue
        fi
        if ! grep -rqE "^\s*blacklist\s+${mod}\b" /etc/modprobe.d/ 2>/dev/null; then
            not_blacklisted+=("$mod")
        fi
    done
    if [[ ${#not_blacklisted[@]} -gt 0 ]]; then
        local mod_list mod_fix
        mod_list=$(printf ' - %s\n' "${not_blacklisted[@]}")
        mod_fix="# Blacklist dangerous/unnecessary kernel modules:"$'\n'
        for mod in "${not_blacklisted[@]}"; do
            mod_fix+="grep -qxF 'blacklist ${mod}' /etc/modprobe.d/99-hardening-blacklist.conf 2>/dev/null || echo 'blacklist ${mod}' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
            mod_fix+="grep -qxF 'install ${mod} /bin/false' /etc/modprobe.d/99-hardening-blacklist.conf 2>/dev/null || echo 'install ${mod} /bin/false' | sudo /usr/bin/tee -a /etc/modprobe.d/99-hardening-blacklist.conf"$'\n'
        done
        mod_fix+="sudo /usr/bin/update-initramfs -u
/sbin/modprobe --showconfig | /bin/grep -E 'blacklist|install.*false'"
        print_status "WARN" "Kernel module blacklist incomplete: ${#not_blacklisted[@]} module(s) not blacklisted"
        append_report "## Kernel Module Blacklist\n- 🔴 ${#not_blacklisted[@]} dangerous module(s) not blacklisted"
        report_issue 6 \
            "Dangerous kernel modules not blacklisted" \
            "${#not_blacklisted[@]} module(s) can be loaded on demand (attack surface / CIS requirement)" \
            "$mod_fix" \
            0 \
            "Modules not blacklisted:\n${mod_list}"
    else
        print_status "OK" "All recommended kernel modules are blacklisted"
        append_report "## Kernel Module Blacklist\n- 🟢 Dangerous modules blacklisted"
    fi
}

check_reboot() {
    print_status "INFO" "Checking if reboot is required..."
    if [[ -f /var/run/reboot-required ]]; then
        print_status "WARN" "Reboot required after updates"
        append_report "## Reboot Required\n- 🔴 System requires reboot"
        report_issue 5 \
            "Reboot required" \
            "Kernel or critical library updates applied - reboot needed" \
            "sudo reboot" \
            0
    else
        print_status "OK" "No reboot required"
        append_report "## Reboot Required\n- 🟢 System up to date"
    fi
}

check_cron() {
    print_status "INFO" "Checking cron job security..."

    local -a cron_issues=()
    local cron_fix=""

    local -a cron_dirs=(
        /etc/crontab
        /etc/cron.d
        /etc/cron.daily
        /etc/cron.weekly
        /etc/cron.monthly
        /etc/cron.hourly
    )

    for path in "${cron_dirs[@]}"; do
        [[ ! -e "$path" ]] && continue
        local owner perms
        owner=$(stat -c '%U' "$path" 2>/dev/null || true)
        perms=$(stat -c '%a' "$path"  2>/dev/null || true)
        if [[ "$owner" != "root" ]]; then
            cron_issues+=("${path} is owned by '${owner}' (should be root)")
            cron_fix+="sudo /bin/chown root:root '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#002) != 0 )); then
            cron_issues+=("${path} is world-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod o-w '${path}'"$'\n'
        fi
        if [[ -n "$perms" ]] && (( (8#$perms & 8#020) != 0 )); then
            cron_issues+=("${path} is group-writable (perms: ${perms})")
            cron_fix+="sudo /bin/chmod g-w '${path}'"$'\n'
        fi
    done

    local ww_cron_scripts
    ww_cron_scripts=$(find /etc/cron.d /etc/cron.daily /etc/cron.weekly \
                           /etc/cron.monthly /etc/cron.hourly \
                      -type f -perm -002 2>/dev/null || true)
    if [[ -n "$ww_cron_scripts" ]]; then
        while IFS= read -r s; do
            cron_issues+=("cron script is world-writable: ${s}")
            cron_fix+="sudo /bin/chmod o-w $(printf '%q' "$s")"$'\n'
        done <<< "$ww_cron_scripts"
    fi

    if [[ ${#cron_issues[@]} -eq 0 ]]; then
        print_status "OK" "Cron directories and files are properly secured"
        append_report "## Cron Security\n- 🟢 Cron paths are root-owned and not world/group-writable"
    else
        print_status "WARN" "Cron security issues: ${#cron_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${cron_issues[@]}")
        append_report "## Cron Security\n- 🔴 ${#cron_issues[@]} cron issue(s) found"
        cron_fix+="# Verify permissions after fixing:
/usr/bin/stat -c '%n %a %U:%G' /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly"
        report_issue 8 \
            "Insecure cron directory or script permissions" \
            "Cron paths are not root-owned or are world/group-writable - enables privilege escalation via cron" \
            "$cron_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

check_pam_lockout() {
    print_status "INFO" "Checking PAM brute-force lockout (faillock/tally2)..."

    local pam_ok=0

    if grep -rqE 'pam_faillock' /etc/pam.d/ 2>/dev/null; then
        local faillock_deny unlock_time
        faillock_deny=$(grep -rhoE 'deny=[0-9]+' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null \
                        | grep -oE '[0-9]+' | sort -n | tail -1 || true)
        unlock_time=$(grep -rhoE 'unlock_time=[0-9]+' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null \
                      | grep -oE '[0-9]+' | head -1 || true)
        if [[ -z "$faillock_deny" || "$faillock_deny" -gt 5 || -z "$unlock_time" ]]; then
            print_status "WARN" "pam_faillock present but thresholds not strict enough (deny=${faillock_deny:-unset}, unlock_time=${unlock_time:-unset})"
            append_report "## PAM Brute-Force Lockout\n- 🟡 pam_faillock present but not strict enough"
            report_issue 5 \
                "pam_faillock configured but lockout thresholds too permissive" \
                "deny= is ${faillock_deny:-unset} (should be ≤ 5) and/or unlock_time= is ${unlock_time:-unset}" \
                "echo -e 'deny = 5\nunlock_time = 900' | sudo /usr/bin/tee /etc/security/faillock.conf
sudo /usr/sbin/faillock --user root
/bin/grep -r pam_faillock /etc/pam.d/" \
                0
        else
            print_status "OK" "pam_faillock is configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
            append_report "## PAM Brute-Force Lockout\n- 🟢 pam_faillock configured (deny=${faillock_deny}, unlock_time=${unlock_time})"
        fi
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 ]] && grep -rqE 'pam_tally2' /etc/pam.d/ 2>/dev/null; then
        print_status "OK" "pam_tally2 is configured in PAM"
        append_report "## PAM Brute-Force Lockout\n- 🟢 pam_tally2 configured"
        pam_ok=1
    fi

    if [[ $pam_ok -eq 0 ]]; then
        print_status "WARN" "No PAM brute-force lockout configured"
        append_report "## PAM Brute-Force Lockout\n- 🔴 No pam_faillock or pam_tally2 found"
        report_issue 8 \
            "No PAM brute-force lockout configured" \
            "pam_faillock is not active - accounts are not locked after repeated failed logins" \
            "sudo /usr/bin/apt-get install -y libpam-faillock
sudo /usr/sbin/pam-auth-update --enable faillock
echo -e 'deny = 5\nunlock_time = 900' | sudo /usr/bin/tee /etc/security/faillock.conf
sudo /usr/sbin/faillock --user root
/bin/grep -r pam_faillock /etc/pam.d/" \
            0 \
            "Also consider Fail2Ban as a complementary layer"
    fi
}

check_core_dumps() {
    print_status "INFO" "Checking core dump restrictions..."

    local -a core_issues=()
    local core_fix=""

    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")
    if [[ "$suid_dumpable" != "0" ]]; then
        core_issues+=("fs.suid_dumpable = ${suid_dumpable:-unset} (should be 0)")
        core_fix+="echo 'fs.suid_dumpable = 0' | sudo /usr/bin/tee /etc/sysctl.d/99-coredump.conf"$'\n'
        core_fix+="sudo /sbin/sysctl --system"$'\n'
    fi

    local limits_core
    limits_core=$(grep -rE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf \
                  /etc/security/limits.d/ 2>/dev/null || true)
    if [[ -z "$limits_core" ]]; then
        core_issues+=("No 'hard core 0' limit in /etc/security/limits.conf")
        core_fix+="echo '* hard core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
        core_fix+="echo '* soft core 0' | sudo /usr/bin/tee -a /etc/security/limits.d/99-no-coredump.conf"$'\n'
    fi

    if [[ -f /etc/systemd/coredump.conf ]]; then
        local storage_val
        storage_val=$(grep -E '^\s*Storage\s*=' /etc/systemd/coredump.conf 2>/dev/null \
                      | awk -F= '{print $2}' | tr -d ' ' || true)
        if [[ "$storage_val" != "none" ]]; then
            core_issues+=("systemd-coredump Storage=${storage_val:-default} - core dumps stored on disk")
            core_fix+="sudo /bin/sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf"$'\n'
            core_fix+="sudo /bin/systemctl daemon-reload"$'\n'
        fi
    fi

    # NEW (Missing #18): kernel.core_pattern check
    local core_pattern
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")
    # Acceptable: systemd coredump handler or /dev/null; anything user-writable is a risk
    if [[ -n "$core_pattern" ]]; then
        local pattern_ok=0
        # Standard systemd handler
        [[ "$core_pattern" == "|/usr/lib/systemd/systemd-coredump"* ]] && pattern_ok=1
        # Disabled
        [[ "$core_pattern" == "/dev/null" ]] && pattern_ok=1
        # Core in root-owned dirs only
        [[ "$core_pattern" =~ ^/var/lib/systemd ]] && pattern_ok=1

        if [[ $pattern_ok -eq 0 ]]; then
            core_issues+=("kernel.core_pattern='${core_pattern}' - may point to user-writable path or unexpected handler")
            core_fix+="# Set core_pattern to systemd handler or disable entirely:"$'\n'
            core_fix+="echo 'kernel.core_pattern = |/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h' | sudo /usr/bin/tee -a /etc/sysctl.d/99-coredump.conf"$'\n'
            core_fix+="sudo /sbin/sysctl --system"$'\n'
        fi
    fi

    if [[ ${#core_issues[@]} -eq 0 ]]; then
        print_status "OK" "Core dump restrictions are in place"
        append_report "## Core Dump Restrictions\n- 🟢 fs.suid_dumpable=0, hard core limit set, core_pattern safe"
    else
        print_status "WARN" "Core dump issues: ${#core_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${core_issues[@]}")
        append_report "## Core Dump Restrictions\n- 🔴 ${#core_issues[@]} core dump issue(s) found"
        core_fix+="# Verify after applying:
/sbin/sysctl fs.suid_dumpable kernel.core_pattern
/bin/grep -r 'core' /etc/security/limits.conf /etc/security/limits.d/"
        report_issue 6 \
            "Core dump restrictions missing or incomplete" \
            "Core dumps from privileged processes may expose sensitive memory (passwords, keys, tokens)" \
            "$core_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

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

check_login_banner() {
    print_status "INFO" "Checking login banners (/etc/issue, /etc/motd, SSH Banner)..."
    local -a banner_issues=()
    [[ ! -s /etc/issue ]] && banner_issues+=("/etc/issue is empty - no pre-login warning banner")
    [[ ! -s /etc/motd  ]] && banner_issues+=("/etc/motd is empty - no post-login message of the day")
    # FIX: use sshd -T (effective runtime config) instead of reading /etc/ssh/sshd_config
    # directly, which misses drop-in files in /etc/ssh/sshd_config.d/
    local ssh_banner
    local _sshd_eff
    _sshd_eff=$(sudo sshd -T 2>/dev/null || true)
    ssh_banner=$(awk '/^banner / {print $2}' <<< "$_sshd_eff" | head -1 || true)
    if [[ -z "$ssh_banner" || "${ssh_banner,,}" == "none" ]]; then
        banner_issues+=("SSH Banner directive not configured in sshd_config")
    fi
    if [[ ${#banner_issues[@]} -gt 0 ]]; then
        local issue_list
        issue_list=$(printf ' - %s\n' "${banner_issues[@]}")
        print_status "WARN" "Login banner issues: ${#banner_issues[@]} found"
        append_report "## Login Banners\n- 🟡 ${#banner_issues[@]} banner issue(s)"
        report_issue 3 \
            "Login banners missing or incomplete" \
            "Warning banners missing - required by CIS/legal best practice" \
            'BANNER="Authorized use only. Unauthorized access is prohibited and monitored."
echo "$BANNER" | sudo /usr/bin/tee /etc/issue /etc/issue.net /etc/motd
sudo /bin/sed -i "s|^#\?Banner.*|Banner /etc/issue.net|" /etc/ssh/sshd_config
sudo /bin/systemctl restart ssh
cat /etc/issue && sudo /usr/sbin/sshd -T | grep -i banner' \
            0 \
            "Issues:\n${issue_list}"
    else
        print_status "OK" "Login banners are configured"
        append_report "## Login Banners\n- 🟢 Banners present on /etc/issue, /etc/motd, and SSH"
    fi
}

# NEW CHECK: PAM password complexity (Missing #10)
check_pam_pwquality() {
    print_status "INFO" "Checking PAM password complexity (pwquality/cracklib)..."
    local pq_ok=0

    if grep -rqE 'pam_pwquality' /etc/pam.d/ 2>/dev/null; then
        local minlen
        minlen=$(grep -rhoE 'minlen=[0-9]+' /etc/pam.d/ /etc/security/pwquality.conf 2>/dev/null \
                 | grep -oE '[0-9]+' | sort -n | head -1 || true)
        # Also check pwquality.conf directly
        [[ -z "$minlen" ]] && minlen=$(awk '/^\s*minlen\s*=/ {print $3}' /etc/security/pwquality.conf 2>/dev/null | head -1 || true)

        if [[ -z "$minlen" || "$minlen" -lt 8 ]]; then
            print_status "WARN" "pam_pwquality present but minlen=${minlen:-unset} (should be ≥ 8)"
            append_report "## PAM Password Complexity\n- 🟡 pam_pwquality present but minlen too low (${minlen:-unset})"
            report_issue 5 \
                "pam_pwquality minlen too low" \
                "Password minimum length is ${minlen:-unset} (CIS requires ≥ 8, recommend 12+)" \
                "# Set policy in /etc/security/pwquality.conf:
sudo /usr/bin/tee /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
# Verify:
/bin/grep -v '^#' /etc/security/pwquality.conf | /bin/grep -v '^\s*$'" \
                0
        else
            print_status "OK" "pam_pwquality configured (minlen=${minlen})"
            append_report "## PAM Password Complexity\n- 🟢 pam_pwquality configured (minlen=${minlen})"
        fi
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 ]] && grep -rqE 'pam_cracklib' /etc/pam.d/ 2>/dev/null; then
        print_status "OK" "pam_cracklib configured"
        append_report "## PAM Password Complexity\n- 🟢 pam_cracklib configured"
        pq_ok=1
    fi

    if [[ $pq_ok -eq 0 ]]; then
        print_status "WARN" "No PAM password complexity enforcement found (pwquality/cracklib)"
        append_report "## PAM Password Complexity\n- 🔴 No password complexity enforcement"
        report_issue 7 \
            "No PAM password complexity enforcement" \
            "pam_pwquality and pam_cracklib are not configured - users can set trivially weak passwords" \
            "sudo /usr/bin/apt-get install -y libpam-pwquality
sudo /usr/sbin/pam-auth-update --enable pwquality
sudo /usr/bin/tee /etc/security/pwquality.conf << 'EOF'
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
/bin/grep -v '^#' /etc/security/pwquality.conf | /bin/grep -v '^\s*\$'" \
            0
    fi
}

# NEW CHECK: Secure Boot (Missing #17)
check_secure_boot() {
    print_status "INFO" "Checking Secure Boot status..."
    # Non-UEFI systems: skip
    if [[ ! -d /sys/firmware/efi ]]; then
        print_status "INFO" "Non-UEFI system - Secure Boot not applicable"
        append_report "## Secure Boot\n- ℹ️ Non-UEFI system - not applicable"
        return
    fi

    local sb_enabled=0
    if command -v mokutil >/dev/null 2>&1; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || true)
        echo "$sb_state" | grep -q "SecureBoot enabled" && sb_enabled=1
    fi
    # Fallback: read EFI variable directly
    if [[ $sb_enabled -eq 0 ]]; then
        local sb_efi="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        if [[ -f "$sb_efi" ]]; then
            local sb_byte
            sb_byte=$(od -An -t u1 "$sb_efi" 2>/dev/null | awk '{print $NF}' || true)
            [[ "$sb_byte" == "1" ]] && sb_enabled=1
        fi
    fi

    if [[ $sb_enabled -eq 1 ]]; then
        print_status "OK" "Secure Boot is enabled"
        append_report "## Secure Boot\n- 🟢 Secure Boot enabled"
    else
        print_status "WARN" "Secure Boot is disabled or not detectable"
        append_report "## Secure Boot\n- 🔴 Secure Boot disabled"
        report_issue 5 \
            "Secure Boot disabled" \
            "Secure Boot is not enabled - unsigned kernel modules and bootloaders can load" \
            "# Enable Secure Boot in UEFI/BIOS firmware settings
# Verify current state:
mokutil --sb-state
# Ensure Ubuntu's signed bootloader is in place:
sudo /usr/bin/apt-get install -y shim-signed grub-efi-amd64-signed linux-signed-generic
sudo /usr/sbin/update-grub" \
            0 \
            "Secure Boot requires UEFI firmware support and a signed kernel/bootloader"
    fi
}

# NEW CHECK: Root PATH safety (Missing #19)
check_root_path() {
    print_status "INFO" "Checking root PATH safety..."
    local root_path
    root_path=$(sudo bash -c 'echo $PATH' 2>/dev/null || true)

    local -a path_issues=()
    local path_fix=""

    # Check for . or empty components
    if echo "$root_path" | tr ':' '\n' | grep -qE '^\.?$'; then
        path_issues+=("Root PATH contains '.' or empty component (current directory execution risk)")
        path_fix+="# Remove '.' from root PATH in /root/.bashrc, /root/.profile, /etc/environment"$'\n'
        path_fix+="sudo /bin/grep -rn 'PATH.*\.' /root/.bashrc /root/.profile /etc/environment 2>/dev/null"$'\n'
    fi

    # Check for world-writable directories in PATH
    while IFS= read -r dir; do
        [[ -z "$dir" || "$dir" == "." ]] && continue
        if [[ -d "$dir" ]]; then
            local dperms downer
            dperms=$(stat -c '%a' "$dir" 2>/dev/null || true)
            downer=$(stat -c '%U' "$dir" 2>/dev/null || true)
            if [[ "$downer" != "root" ]] && (( (8#${dperms:-0} & 8#002) != 0 )); then
                path_issues+=("World-writable non-root directory in root PATH: $dir (${dperms}, owned by ${downer})")
                path_fix+="# Remove from PATH or fix permissions: $dir"$'\n'
            fi
        fi
    done < <(echo "$root_path" | tr ':' '\n')

    if [[ ${#path_issues[@]} -eq 0 ]]; then
        print_status "OK" "Root PATH is safe (no '.' or world-writable directories)"
        append_report "## Root PATH Safety\n- 🟢 Root PATH contains no dangerous entries"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${path_issues[@]}")
        print_status "WARN" "Root PATH safety issues: ${#path_issues[@]} found"
        append_report "## Root PATH Safety\n- 🔴 ${#path_issues[@]} dangerous entry/entries in root PATH"
        path_fix+="# After fixing, verify:
sudo bash -c 'echo \$PATH'"
        report_issue 8 \
            "Dangerous entries in root PATH" \
            "Root's PATH contains '.' or world-writable directories - classic privilege escalation vector" \
            "$path_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: Home directory permissions (from review doc)
check_home_permissions() {
    print_status "INFO" "Checking home directory permissions..."
    local -a home_issues=()
    local home_fix=""

    while IFS= read -r dir; do
        local perms owner
        perms=$(stat -c '%a' "$dir" 2>/dev/null || true)
        owner=$(stat -c '%U' "$dir" 2>/dev/null || true)
        [[ -z "$perms" ]] && continue
        # Others should have no access (last octet)
        if (( (8#$perms & 8#007) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - others have access")
            home_fix+="sudo /bin/chmod 700 $(printf '%q' "$dir")   # ${owner}'s home"$'\n'
        # Group-writable is also a problem
        elif (( (8#$perms & 8#020) != 0 )); then
            home_issues+=("${dir} (${owner}): perms=${perms} - group-writable")
            home_fix+="sudo /bin/chmod g-w $(printf '%q' "$dir")"$'\n'
        fi
    done < <(find /home /root -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

    if [[ ${#home_issues[@]} -eq 0 ]]; then
        print_status "OK" "Home directory permissions are secure"
        append_report "## Home Directory Permissions\n- 🟢 All home directories are properly restricted"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${home_issues[@]}")
        print_status "WARN" "Home directory permission issues: ${#home_issues[@]} found"
        append_report "## Home Directory Permissions\n- 🔴 ${#home_issues[@]} home dir(s) with insecure permissions"
        home_fix+="# Verify after fixing:
/usr/bin/find /home /root -mindepth 1 -maxdepth 1 -type d -exec /usr/bin/stat -c '%n %a %U' {} \;"
        report_issue 6 \
            "Home directories have insecure permissions" \
            "Home directories accessible by other users - may expose SSH keys, config files, credentials" \
            "$home_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: journald persistence (from review doc)
check_journald() {
    print_status "INFO" "Checking journald log persistence..."
    local storage_val
    storage_val=$(grep -hE '^\s*Storage\s*=' \
                  /etc/systemd/journald.conf \
                  /etc/systemd/journald.conf.d/*.conf 2>/dev/null \
                  | tail -1 | awk -F= '{print $2}' | tr -d ' ' || true)

    if [[ "$storage_val" == "persistent" ]]; then
        print_status "OK" "journald persistence enabled (Storage=persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=persistent"
    elif [[ "$storage_val" == "auto" && -d /var/log/journal ]]; then
        print_status "OK" "journald Storage=auto with /var/log/journal present (persistent)"
        append_report "## Journald Persistence\n- 🟢 Storage=auto + /var/log/journal exists"
    elif [[ "$storage_val" == "auto" && ! -d /var/log/journal ]]; then
        print_status "WARN" "journald Storage=auto but /var/log/journal does not exist - logs are volatile"
        append_report "## Journald Persistence\n- 🟡 Storage=auto but /var/log/journal missing"
        report_issue 4 \
            "journald logs may be volatile (Storage=auto, no /var/log/journal)" \
            "System logs are lost on reboot without /var/log/journal directory" \
            "sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
# Verify:
sudo /usr/bin/journalctl --disk-usage" \
            0
    else
        print_status "WARN" "journald Storage=${storage_val:-volatile} - logs not persisted across reboots"
        append_report "## Journald Persistence\n- 🔴 Logs not persistent (Storage=${storage_val:-volatile})"
        report_issue 5 \
            "journald logs not persistent across reboots" \
            "Storage=${storage_val:-unset} - logs lost on reboot, hindering forensics and incident response" \
            "sudo /bin/sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sudo /bin/mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo /bin/systemctl restart systemd-journald
sudo /usr/bin/journalctl --disk-usage" \
            0
    fi
}

check_rsyslog() {
    print_status "INFO" "Checking rsyslog installation and status..."

    if ! dpkg -l rsyslog 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "rsyslog is not installed"
        append_report "## Rsyslog\n- 🔴 rsyslog not installed"
        report_issue 4 \
            "rsyslog not installed" \
            "Traditional syslog daemon absent - SIEM agents, log shippers, and many audit tools depend on /var/log/syslog" \
            "sudo /usr/bin/apt-get install -y rsyslog
sudo /bin/systemctl enable --now rsyslog
sudo /bin/systemctl status rsyslog
# Verify syslog output:
sudo /usr/bin/logger 'rsyslog test'
sudo /usr/bin/tail -5 /var/log/syslog" \
            0
        return
    fi

    if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
        print_status "WARN" "rsyslog installed but not running"
        append_report "## Rsyslog\n- 🔴 rsyslog installed but inactive"
        report_issue 4 \
            "rsyslog installed but not running" \
            "rsyslog service is not active - /var/log/syslog and related files are not being written" \
            "sudo /bin/systemctl enable --now rsyslog
sudo /bin/systemctl status rsyslog" \
            0
        return
    fi

    # Verify /var/log/syslog is current (written within the last 60 minutes)
    local syslog_recent
    syslog_recent=$(find /var/log/syslog -mmin -60 2>/dev/null || true)
    if [[ ! -f /var/log/syslog || -z "$syslog_recent" ]]; then
        print_status "WARN" "rsyslog active but /var/log/syslog is absent or stale (>60 min)"
        append_report "## Rsyslog\n- 🟡 rsyslog running but /var/log/syslog stale or absent"
        report_issue 3 \
            "rsyslog running but syslog output stale" \
            "/var/log/syslog is missing or has not been written in over 60 minutes despite rsyslog being active" \
            "sudo /bin/systemctl restart rsyslog
sudo /usr/bin/logger 'rsyslog test message'
sudo /usr/bin/tail -5 /var/log/syslog" \
            0
    else
        print_status "OK" "rsyslog active and /var/log/syslog is current"
        append_report "## Rsyslog\n- 🟢 rsyslog active, /var/log/syslog current"
    fi
}

# NEW CHECK: APT repository security (from review doc)
check_apt_repos() {
    print_status "INFO" "Checking APT repository security..."
    local -a repo_issues=()
    local repo_fix=""

    # Legacy one-line format: [trusted=yes]
    local trusted_sources
    trusted_sources=$(grep -rE '\[trusted=yes\]' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$trusted_sources" ]]; then
        repo_issues+=("APT source(s) with [trusted=yes] found - GPG signature verification bypassed")
        repo_fix+="# Remove [trusted=yes] from these sources (shown below):"$'\n'
        while IFS= read -r src_line; do
            repo_fix+="# $src_line"$'\n'
        done <<< "$trusted_sources"
        repo_fix+="# Edit each file and remove the [trusted=yes] attribute"$'\n'
    fi

    # DEB822 format (Ubuntu 22.04+): Trusted: yes
    local deb822_trusted
    deb822_trusted=$(grep -rE '^\s*Trusted\s*:\s*yes' /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$deb822_trusted" ]]; then
        repo_issues+=("DEB822 source(s) with 'Trusted: yes' found - GPG verification bypassed (Ubuntu 22.04+ format)")
        repo_fix+="# Remove 'Trusted: yes' lines from .sources files in /etc/apt/sources.list.d/"$'\n'
        while IFS= read -r src_line; do
            repo_fix+="# $src_line"$'\n'
        done <<< "$deb822_trusted"
    fi

    # Check for sources with allow-insecure (both formats)
    local insecure_sources
    insecure_sources=$(grep -rE 'allow-insecure=yes|allow-weak=yes|allow-downgrade-to-insecure=yes' \
                       /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    # DEB822 equivalent: Allow-Insecure: yes
    local deb822_insecure
    deb822_insecure=$(grep -rE '^\s*Allow-Insecure\s*:\s*yes|^\s*Allow-Weak\s*:\s*yes|^\s*Allow-Downgrade-To-Insecure\s*:\s*yes' \
                      /etc/apt/sources.list.d/ 2>/dev/null || true)
    [[ -n "$deb822_insecure" ]] && insecure_sources+=$'\n'"$deb822_insecure"
    if [[ -n "$insecure_sources" ]]; then
        repo_issues+=("APT source(s) with allow-insecure/allow-weak found")
        repo_fix+="# Remove allow-insecure/allow-weak options from APT sources"$'\n'
    fi

    if [[ ${#repo_issues[@]} -eq 0 ]]; then
        print_status "OK" "APT repository sources appear secure"
        append_report "## APT Repository Security\n- 🟢 No [trusted=yes] or insecure repositories found"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${repo_issues[@]}")
        print_status "WARN" "APT repository security issues: ${#repo_issues[@]} found"
        append_report "## APT Repository Security\n- 🔴 ${#repo_issues[@]} insecure repository configuration(s)"
        repo_fix+="# After changes, verify APT sources:
sudo /usr/bin/apt-get update 2>&1 | /bin/grep -E 'NO_PUBKEY|EXPKEYSIG|not signed|trusted' || echo 'Clean'"
        report_issue 8 \
            "Insecure APT repositories configured" \
            "APT repositories with disabled authentication allow unsigned/malicious packages to install" \
            "$repo_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

# NEW CHECK: Unnecessary/dangerous packages (from review doc)
check_unnecessary_packages() {
    print_status "INFO" "Checking for unnecessary/dangerous packages..."
    local -a dangerous_pkgs=("telnet" "rsh-client" "rsh-server" "nis" "yp-tools"
                              "xinetd" "inetd" "atftpd" "tftpd" "tftp"
                              "talk" "talkd" "ntalk" "finger" "fingerd")
    local -a installed_dangerous=()

    for pkg in "${dangerous_pkgs[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            installed_dangerous+=("$pkg")
        fi
    done

    if [[ ${#installed_dangerous[@]} -eq 0 ]]; then
        print_status "OK" "No unnecessary/dangerous packages installed"
        append_report "## Unnecessary Packages\n- 🟢 No dangerous legacy packages found"
    else
        local pkg_list
        pkg_list=$(printf ' - %s\n' "${installed_dangerous[@]}")
        local purge_list="${installed_dangerous[*]}"
        print_status "WARN" "Dangerous/unnecessary packages found: ${purge_list}"
        append_report "## Unnecessary Packages\n- 🔴 ${#installed_dangerous[@]} dangerous package(s) installed"
        report_issue 8 \
            "Dangerous/unnecessary packages installed" \
            "Legacy/plaintext protocol packages increase attack surface" \
            "sudo /usr/bin/apt-get purge -y ${purge_list}
sudo /usr/bin/apt-get autoremove -y
# Verify removal:
dpkg -l ${purge_list} 2>/dev/null | grep '^ii' || echo 'All removed'" \
            0 \
            "Packages found:\n${pkg_list}\n\nReplace telnet with SSH; replace FTP with SFTP"
    fi
}

check_docker_hardening() {
    # Skip silently if Docker is not present
    if ! command -v docker >/dev/null 2>&1 && ! dpkg -l docker-ce 2>/dev/null | grep -q '^ii'; then
        print_status "INFO" "Docker not detected - skipping Docker hardening check"
        return
    fi

    print_status "INFO" "Checking Docker daemon hardening..."
    local -a docker_issues=()
    local daemon_json="/etc/docker/daemon.json"

    if [[ ! -f "$daemon_json" ]]; then
        docker_issues+=("$daemon_json does not exist - no hardening configuration applied")
    else
        # Use python3 (guaranteed on Ubuntu 20.04+) for reliable JSON parsing
        local _ld _ms _lr _up
        _ld=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('log-driver',''))" 2>/dev/null || true)
        _ms=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('log-opts',{}).get('max-size',''))" 2>/dev/null || true)
        _lr=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('live-restore',False))" 2>/dev/null || true)
        _up=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('userland-proxy',True))" 2>/dev/null || true)
        [[ -z "$_ld" ]]        && docker_issues+=("log-driver not set - container log format unspecified")
        [[ -z "$_ms" ]]        && docker_issues+=("log-opts.max-size not set - container logs can grow unbounded and fill /var/lib/docker")
        [[ "$_lr" != "True" ]] && docker_issues+=("live-restore is not true - all containers stop on daemon restart/upgrade")
        [[ "$_up" != "False" ]] && docker_issues+=("userland-proxy is not false - adds unnecessary network attack surface")
    fi

    if [[ ${#docker_issues[@]} -eq 0 ]]; then
        print_status "OK" "Docker daemon.json is hardened (log limits, live-restore, userland-proxy disabled)"
        append_report "## Docker Hardening\n- 🟢 daemon.json configured: log rotation, live-restore=true, userland-proxy=false"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${docker_issues[@]}")
        print_status "WARN" "Docker hardening issues: ${#docker_issues[@]} found"
        append_report "## Docker Hardening\n- 🔴 ${#docker_issues[@]} Docker daemon hardening issue(s)"

        local docker_fix
        docker_fix='# Write hardened Docker daemon config:'$'\n'
        docker_fix+='sudo /usr/bin/tee /etc/docker/daemon.json > /dev/null << '"'"'DOCKEREOF'"'"$'\n'
        docker_fix+='{'$'\n'
        docker_fix+='    "log-driver": "json-file",'$'\n'
        docker_fix+='    "log-opts": {'$'\n'
        docker_fix+='        "max-size": "10m",'$'\n'
        docker_fix+='        "max-file": "5",'$'\n'
        docker_fix+='        "compress": "true"'$'\n'
        docker_fix+='    },'$'\n'
        docker_fix+='    "live-restore": true,'$'\n'
        docker_fix+='    "userland-proxy": false'$'\n'
        docker_fix+='}'$'\n'
        docker_fix+='DOCKEREOF'$'\n'
        docker_fix+='# reload applies config without stopping running containers; restart stops them:'$'\n'
        docker_fix+='sudo /bin/systemctl reload docker || sudo /bin/systemctl restart docker'$'\n'
        docker_fix+='# Verify:'$'\n'
        docker_fix+='sudo /usr/bin/docker info | grep -E '"'"'Logging Driver|Live Restore'"'"''

        report_issue 6 \
            "Docker daemon not hardened" \
            "Docker daemon.json absent or missing security settings - unbounded logs, no live-restore, userland-proxy enabled" \
            "$docker_fix" \
            0 \
            "Issues:\n${issue_list}\n\nNote: 'reload' applies config without stopping running containers; 'restart' stops them"
    fi
}

check_aide() {
    print_status "INFO" "Checking AIDE file integrity monitoring..."
    if ! command -v aide >/dev/null 2>&1; then
        print_status "WARN" "AIDE not installed"
        append_report "## AIDE File Integrity\n- 🔴 AIDE not installed"
        report_issue 8 \
            "AIDE not installed" \
            "No file integrity monitoring in place - unauthorized changes to system files go undetected" \
            "sudo /usr/bin/apt-get install -y aide aide-common
sudo /usr/sbin/aideinit
sudo /bin/cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
# Schedule weekly check:
echo '0 5 * * 0 root /usr/bin/aide --check' | sudo /usr/bin/tee /etc/cron.d/aide-check
# Verify:
sudo /usr/bin/aide --check" \
            0 \
            "AIDE detects unauthorized modifications to binaries, configs, and libraries"
        return
    fi

    local aide_issues=()

    # Check database initialised
    if [[ ! -f /var/lib/aide/aide.db && ! -f /var/lib/aide/aide.db.gz ]]; then
        aide_issues+=("AIDE database not initialised - run 'aideinit' to create baseline")
    fi

    # Check a cron or systemd timer schedules AIDE checks
    local aide_scheduled=0
    grep -rqE 'aide\s+--check|aide\s+-C' /etc/cron* /var/spool/cron 2>/dev/null && aide_scheduled=1
    systemctl list-timers --all 2>/dev/null | grep -qi aide && aide_scheduled=1
    if [[ $aide_scheduled -eq 0 ]]; then
        aide_issues+=("No scheduled AIDE check found - integrity is not checked automatically")
    fi

    if [[ ${#aide_issues[@]} -eq 0 ]]; then
        print_status "OK" "AIDE installed, database present, and check is scheduled"
        append_report "## AIDE File Integrity\n- 🟢 AIDE installed, database initialised, scheduled check present"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${aide_issues[@]}")
        print_status "WARN" "AIDE issues: ${#aide_issues[@]} found"
        append_report "## AIDE File Integrity\n- 🔴 AIDE issues: ${#aide_issues[@]}"
        report_issue 6 \
            "AIDE file integrity monitoring incomplete" \
            "${#aide_issues[@]} AIDE configuration issue(s) found" \
            "sudo /usr/sbin/aideinit
sudo /bin/cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo '0 5 * * 0 root /usr/bin/aide --check' | sudo /usr/bin/tee /etc/cron.d/aide-check" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

check_auditd() {
    print_status "INFO" "Checking auditd audit framework..."
    if ! command -v auditctl >/dev/null 2>&1; then
        print_status "WARN" "auditd not installed"
        append_report "## Auditd\n- 🔴 auditd not installed"
        report_issue 7 \
            "auditd not installed" \
            "No kernel-level audit logging - privileged operations, login events and file accesses are not tracked" \
            "sudo /usr/bin/apt-get install -y auditd audispd-plugins
sudo /bin/systemctl enable --now auditd
# Add CIS-required rules:
sudo /usr/sbin/auditctl -w /etc/passwd -p wa -k identity
sudo /usr/sbin/auditctl -w /etc/shadow -p wa -k identity
sudo /usr/sbin/auditctl -w /etc/sudoers -p wa -k sudoers
sudo /usr/sbin/auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
# Make rules persistent:
sudo /usr/sbin/augenrules --load" \
            0 \
            "auditd is required by CIS Benchmarks and most compliance frameworks (PCI-DSS, HIPAA, SOC 2)"
        return
    fi

    local audit_issues=()

    # Service running
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        audit_issues+=("auditd service is not running")
    fi

    # Enabled at boot
    if ! systemctl is-enabled --quiet auditd 2>/dev/null; then
        audit_issues+=("auditd not enabled at boot")
    fi

    # Check for minimum required rules
    local audit_rules
    audit_rules=$(sudo auditctl -l 2>/dev/null || true)
    for watched in '/etc/passwd' '/etc/shadow' '/etc/sudoers'; do
        if ! grep -q "$watched" <<< "$audit_rules"; then
            audit_issues+=("No audit rule watching ${watched}")
        fi
    done

    # AU-11: audit log retention
    local _auditd_conf="/etc/audit/auditd.conf"
    if [[ -f "$_auditd_conf" ]]; then
        local _max_logs _max_size _action
        _max_logs=$(grep -i '^num_logs' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        _max_size=$(grep -i '^max_log_file[^_]' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        _action=$(grep -i '^max_log_file_action' "$_auditd_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "")
        local _retention_ok=1
        local _ret_issues=()
        [[ "${_max_logs:-0}" -lt 5 ]] && { _retention_ok=0; _ret_issues+=("num_logs=${_max_logs:-unset} (need ≥5)"); }
        [[ "${_max_size:-0}" -lt 8 ]] && { _retention_ok=0; _ret_issues+=("max_log_file=${_max_size:-unset} MB (need ≥8)"); }
        [[ "${_action,,}" != "keep_logs" && "${_action,,}" != "rotate" ]] && \
            { _retention_ok=0; _ret_issues+=("max_log_file_action=${_action:-unset} (need keep_logs or rotate)"); }
        if [[ $_retention_ok -eq 0 ]]; then
            audit_issues+=("Audit log retention insufficient: $(IFS=', '; echo "${_ret_issues[*]}")")
        fi
    fi

    if [[ ${#audit_issues[@]} -eq 0 ]]; then
        print_status "OK" "auditd active, enabled at boot, essential rules present, and log retention configured"
        append_report "## Auditd\n- 🟢 auditd running with essential audit rules and adequate log retention"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${audit_issues[@]}")
        print_status "WARN" "auditd issues: ${#audit_issues[@]} found"
        append_report "## Auditd\n- 🔴 auditd issues: ${#audit_issues[@]}"
        report_issue 7 \
            "auditd configuration incomplete" \
            "${#audit_issues[@]} auditd issue(s) found" \
            "sudo /bin/systemctl enable --now auditd
sudo /usr/sbin/auditctl -w /etc/passwd -p wa -k identity
sudo /usr/sbin/auditctl -w /etc/shadow -p wa -k identity
sudo /usr/sbin/auditctl -w /etc/sudoers -p wa -k sudoers
sudo /usr/sbin/auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
sudo /usr/sbin/augenrules --load
# AU-11: configure log retention (≥5 logs, ≥8 MB each, rotate on full)
sudo /bin/sed -i 's/^num_logs.*/num_logs = 5/'             /etc/audit/auditd.conf
sudo /bin/sed -i 's/^max_log_file .*/max_log_file = 8/'    /etc/audit/auditd.conf
sudo /bin/sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/' /etc/audit/auditd.conf
sudo /bin/systemctl restart auditd
# Verify:
grep -E 'num_logs|max_log_file' /etc/audit/auditd.conf" \
            0 \
            "Issues:\n${issue_list}"
    fi
}

check_kernel_lockdown() {
    print_status "INFO" "Checking kernel lockdown mode..."
    if [[ ! -f /sys/kernel/security/lockdown ]]; then
        print_status "INFO" "Kernel lockdown not available on this kernel (requires 5.4+ with CONFIG_SECURITY_LOCKDOWN_LSM)"
        append_report "## Kernel Lockdown\n- ⚪ Lockdown LSM not available on this kernel"
        return
    fi

    local lockdown_state
    lockdown_state=$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -oP '\[\K[^\]]+' || echo "none")

    if [[ "$lockdown_state" == "integrity" || "$lockdown_state" == "confidentiality" ]]; then
        print_status "OK" "Kernel lockdown enabled: ${lockdown_state}"
        append_report "## Kernel Lockdown\n- 🟢 Kernel lockdown active: ${lockdown_state}"
    else
        print_status "WARN" "Kernel lockdown is off (current: ${lockdown_state})"
        append_report "## Kernel Lockdown\n- 🔴 Kernel lockdown not enabled (current: ${lockdown_state})"
        report_issue 7 \
            "Kernel lockdown mode not enabled" \
            "Kernel lockdown=none: unsigned modules, /dev/mem access, and kexec are unrestricted" \
            "# Add lockdown=integrity to kernel boot parameters:
sudo /bin/sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lockdown=integrity\"/' /etc/default/grub
sudo /usr/sbin/update-grub
# Verify after reboot:
cat /sys/kernel/security/lockdown" \
            0 \
            "Lockdown 'integrity' blocks: loading unsigned modules, /dev/mem writes, kexec with unsigned images. Reboot required after GRUB change."
    fi
}

check_debsecan() {
    print_status "INFO" "Checking for known CVEs in installed packages (debsecan)..."
    if ! command -v debsecan >/dev/null 2>&1; then
        print_status "WARN" "debsecan not installed"
        append_report "## CVE Exposure (debsecan)\n- 🔴 debsecan not installed"
        report_issue 5 \
            "debsecan not installed" \
            "No automated CVE check against installed packages - known vulnerabilities may go undetected" \
            "sudo /usr/bin/apt-get install -y debsecan
# Run CVE scan (fetches current Debian/Ubuntu vuln data):
sudo /usr/bin/debsecan --suite \$(lsb_release -cs) --format detail --only-fixed
# List only packages with available fixes:
sudo /usr/bin/debsecan --suite \$(lsb_release -cs) --only-fixed" \
            0 \
            "debsecan queries the Debian Security Tracker (open-source) to find CVEs affecting installed packages"
        return
    fi

    print_status "INFO" "Running debsecan (may take a moment to fetch CVE data)..."
    local suite
    suite=$(lsb_release -cs 2>/dev/null || echo "")
    if [[ -z "$suite" ]]; then
        print_status "INFO" "Cannot determine Ubuntu codename - skipping debsecan"
        append_report "## CVE Exposure (debsecan)\n- ⚪ Could not determine Ubuntu suite"
        return
    fi

    local fixable_cves
    fixable_cves=$(timeout 60 sudo debsecan --suite "$suite" --only-fixed 2>/dev/null | grep -c '.' || echo "0")

    if [[ "$fixable_cves" -eq 0 ]]; then
        print_status "OK" "debsecan: no CVEs with available fixes found"
        append_report "## CVE Exposure (debsecan)\n- 🟢 No fixable CVEs detected by debsecan"
    else
        print_status "WARN" "debsecan: ${fixable_cves} fixable CVE(s) found in installed packages"
        append_report "## CVE Exposure (debsecan)\n- 🔴 ${fixable_cves} fixable CVE(s) detected - run 'apt upgrade'"
        report_issue 10 \
            "Installed packages have fixable CVEs" \
            "${fixable_cves} CVE(s) with available fixes detected by debsecan" \
            "sudo /usr/bin/apt-get update && sudo /usr/bin/apt-get upgrade -y
# Re-check after upgrading:
sudo /usr/bin/debsecan --suite $(lsb_release -cs) --only-fixed" \
            0 \
            "Run 'debsecan --suite \$(lsb_release -cs) --format detail --only-fixed' to see CVE details"
    fi
}

check_dns_security() {
    print_status "INFO" "Checking DNS security (systemd-resolved DNSSEC/DoT)..."
    if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        print_status "INFO" "systemd-resolved not active - skipping DNS security check"
        append_report "## DNS Security\n- ⚪ systemd-resolved not active"
        return
    fi

    local dns_issues=()
    local _need_dnssec=0 _need_dot=0

    # DNSSEC
    local dnssec_setting
    dnssec_setting=$(resolvectl status 2>/dev/null | awk '/DNSSEC setting:/ {print $NF}' | head -1 || \
                     grep -i '^DNSSEC=' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2 || \
                     echo "no")
    dnssec_setting=${dnssec_setting,,}
    if [[ "$dnssec_setting" != "yes" && "$dnssec_setting" != "allow-downgrade" ]]; then
        dns_issues+=("DNSSEC is '${dnssec_setting:-no}' - DNS responses are not validated (MITM/spoofing risk)")
        _need_dnssec=1
    fi

    # DNS over TLS
    local dot_setting
    dot_setting=$(grep -i '^DNSOverTLS=' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null | tail -1 | cut -d= -f2 || echo "no")
    dot_setting=${dot_setting,,}
    if [[ "$dot_setting" != "yes" && "$dot_setting" != "opportunistic" ]]; then
        dns_issues+=("DNS over TLS is '${dot_setting:-no}' - DNS queries are sent in plaintext")
        _need_dot=1
    fi

    if [[ ${#dns_issues[@]} -eq 0 ]]; then
        print_status "OK" "DNSSEC and DNS over TLS are configured"
        append_report "## DNS Security\n- 🟢 DNSSEC and DNS over TLS enabled in systemd-resolved"
    else
        # Build a single drop-in conf with all needed settings (avoids duplicate [Resolve] headers)
        local dns_fix _conf_body=""
        [[ $_need_dnssec -eq 1 ]] && _conf_body+="DNSSEC=allow-downgrade"$'\n'
        [[ $_need_dot    -eq 1 ]] && _conf_body+="DNSOverTLS=opportunistic"$'\n'
        dns_fix="sudo /bin/mkdir -p /etc/systemd/resolved.conf.d"$'\n'
        dns_fix+="printf '[Resolve]\n${_conf_body}' | sudo /usr/bin/tee /etc/systemd/resolved.conf.d/99-hardening.conf"$'\n'
        dns_fix+="sudo /bin/systemctl restart systemd-resolved"$'\n'
        dns_fix+="# Verify:
resolvectl status | grep -E 'DNSSEC|DNS over TLS'"
        local issue_list
        issue_list=$(printf ' - %s\n' "${dns_issues[@]}")
        print_status "WARN" "DNS security issues: ${#dns_issues[@]} found"
        append_report "## DNS Security\n- 🔴 DNS security issues: ${#dns_issues[@]}"
        report_issue 5 \
            "DNS security not fully configured" \
            "${#dns_issues[@]} DNS security issue(s) in systemd-resolved" \
            "$dns_fix" \
            0 \
            "Issues:\n${issue_list}\n\nDNSSEC validates DNS responses; DNS over TLS encrypts queries from eavesdropping"
    fi
}

check_systemd_service_hardening() {
    print_status "INFO" "Checking systemd service hardening directives..."
    local -a unhardened=()

    local -a services_to_check=("ssh" "sshd" "cron" "rsyslog" "auditd" "fail2ban")
    local -a required_directives=("NoNewPrivileges=yes" "PrivateTmp=yes" "ProtectSystem=")

    for svc in "${services_to_check[@]}"; do
        systemctl cat "$svc.service" >/dev/null 2>&1 || continue  # skip if not installed
        local svc_unit
        svc_unit=$(systemctl cat "$svc.service" 2>/dev/null || true)
        local missing=()
        for directive in "${required_directives[@]}"; do
            if ! grep -qi "$directive" <<< "$svc_unit"; then
                missing+=("$directive")
            fi
        done
        if [[ ${#missing[@]} -gt 0 ]]; then
            unhardened+=("$svc: missing ${missing[*]}")
        fi
    done

    if [[ ${#unhardened[@]} -eq 0 ]]; then
        print_status "OK" "Key systemd services have hardening directives"
        append_report "## Systemd Service Hardening\n- 🟢 NoNewPrivileges/PrivateTmp/ProtectSystem present on checked services"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${unhardened[@]}")
        print_status "WARN" "Systemd service hardening gaps: ${#unhardened[@]} service(s)"
        append_report "## Systemd Service Hardening\n- 🟡 ${#unhardened[@]} service(s) lack hardening directives"
        report_issue 4 \
            "Systemd services missing hardening directives" \
            "${#unhardened[@]} service(s) lack NoNewPrivileges/PrivateTmp/ProtectSystem - increases blast radius of service compromise" \
            "# Example drop-in for sshd (repeat for each service listed in note):
sudo /bin/mkdir -p /etc/systemd/system/ssh.service.d/
sudo /usr/bin/tee /etc/systemd/system/ssh.service.d/hardening.conf > /dev/null << 'EOF'
[Service]
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
EOF
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart ssh" \
            0 \
            "Services without hardening:\n${issue_list}"
    fi
}

# ====================== ENHANCED DEEP MODE ======================
run_deep_checks() {
    print_status "INFO" "=== Starting Deep Analysis ==="

    # ---- Optional tool pre-flight ----
    # All install prompts are presented upfront so the scan runs unattended.
    # If the user declines, that tool's checks are skipped entirely.
    print_status "INFO" "Optional tools provide deeper analysis. Answer prompts now - scan will then run unattended."
    echo ""
    prompt_install "debsums"  "debsums"
    prompt_install "rkhunter" "rkhunter"
    prompt_install "clamscan" "clamav"
    prompt_install "auditd"   "auditd"
    prompt_install "lynis"    "lynis"
    echo ""

    local _have_debsums=0  _have_rkhunter=0  _have_clamscan=0
    local _have_auditd=0   _have_lynis=0
    command -v debsums  >/dev/null 2>&1 && _have_debsums=1  || true
    command -v rkhunter >/dev/null 2>&1 && _have_rkhunter=1 || true
    command -v clamscan >/dev/null 2>&1 && _have_clamscan=1 || true
    command -v auditd   >/dev/null 2>&1 && _have_auditd=1   || true
    command -v lynis    >/dev/null 2>&1 && _have_lynis=1    || true

    local _yn; for _t in "debsums:$_have_debsums" "rkhunter:$_have_rkhunter" \
                          "clamav:$_have_clamscan" "auditd:$_have_auditd" "lynis:$_have_lynis"; do
        _yn="$([[ "${_t#*:}" -eq 1 ]] && echo yes || echo skipped)"
        print_status "INFO" "  ${_t%%:*}: ${_yn}"
    done
    echo ""
    print_status "INFO" "--- Beginning deep scans ---"

    # 1. SUID binaries
    print_status "INFO" "Scanning SUID/SGID binaries (full filesystem - may take a while on large systems)..."
    local _scan_start _scan_elapsed
    _scan_start=$(date +%s)
    local -a risky_suid=()
    local _suid_checked=0
    while IFS= read -r f; do
        _suid_checked=$(( _suid_checked + 1 ))
        # Progress heartbeat every 500 files
        if (( _suid_checked % 500 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  SUID scan: ${_suid_checked} files checked (${_scan_elapsed}s elapsed)..."
        fi
        local f_resolved
        f_resolved=$(readlink -f "$f" 2>/dev/null || echo "$f")
        local in_whitelist=0
        for wl in "${SUID_WHITELIST[@]}"; do
            local wl_resolved
            wl_resolved=$(readlink -f "$wl" 2>/dev/null || echo "$wl")
            if [[ "$f" == "$wl" || "$f" == "$wl_resolved" || "$f_resolved" == "$wl" || "$f_resolved" == "$wl_resolved" ]]; then
                in_whitelist=1; break
            fi
        done
        [[ $in_whitelist -eq 0 ]] && risky_suid+=("$f")
    done < <(find / -xdev -perm -4000 -type f 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  SUID scan complete: ${_suid_checked} files scanned in ${_scan_elapsed}s"
    if [[ ${#risky_suid[@]} -gt 0 ]]; then
        local suid_list
        suid_list=$(printf ' - %s\n' "${risky_suid[@]}")
        local suid_fix_cmds
        suid_fix_cmds="# Review each binary carefully before removing its SUID bit."$'\n'
        suid_fix_cmds+="# NEVER remove SUID from: /usr/bin/sudo /usr/bin/su /usr/bin/passwd /usr/bin/mount"$'\n'
        for f in "${risky_suid[@]}"; do
            suid_fix_cmds+="sudo /bin/chmod -s $(printf '%q' "$f")   # removes SUID from ${f}"$'\n'
        done
        suid_fix_cmds+="# Verify no unexpected SUID bits remain:
sudo /usr/bin/find / -xdev -perm -4000 -type f 2>/dev/null"
        report_issue 14 \
            "Non-standard SUID binaries found" \
            "These are privilege-escalation vectors if exploited" \
            "$suid_fix_cmds" \
            1 \
            "Risky SUID files:\n${suid_list}\nNever remove SUID from sudo/su/passwd"
    else
        print_status "OK" "No unexpected SUID binaries found"
        append_report "## Deep: SUID Binaries\n- 🟢 No non-standard SUID binaries detected"
    fi

    # 1b. SGID binaries
    print_status "INFO" "Scanning SGID binaries (full filesystem)..."
    _scan_start=$(date +%s)
    local -a risky_sgid=()
    local _sgid_checked=0
    while IFS= read -r f; do
        _sgid_checked=$(( _sgid_checked + 1 ))
        if (( _sgid_checked % 500 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  SGID scan: ${_sgid_checked} files checked (${_scan_elapsed}s elapsed)..."
        fi
        local f_resolved
        f_resolved=$(readlink -f "$f" 2>/dev/null || echo "$f")
        local in_whitelist=0
        for wl in "${SGID_WHITELIST[@]}"; do
            local wl_resolved
            wl_resolved=$(readlink -f "$wl" 2>/dev/null || echo "$wl")
            if [[ "$f" == "$wl" || "$f" == "$wl_resolved" || "$f_resolved" == "$wl" || "$f_resolved" == "$wl_resolved" ]]; then
                in_whitelist=1; break
            fi
        done
        [[ $in_whitelist -eq 0 ]] && risky_sgid+=("$f")
    done < <(find / -xdev -perm -2000 -type f 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  SGID scan complete: ${_sgid_checked} files scanned in ${_scan_elapsed}s"
    if [[ ${#risky_sgid[@]} -gt 0 ]]; then
        local sgid_list sgid_fix_cmds
        sgid_list=$(printf ' - %s\n' "${risky_sgid[@]}")
        sgid_fix_cmds="# Review each binary carefully before removing its SGID bit."$'\n'
        for f in "${risky_sgid[@]}"; do
            sgid_fix_cmds+="sudo /bin/chmod g-s $(printf '%q' "$f")   # removes SGID from ${f}"$'\n'
        done
        sgid_fix_cmds+="sudo /usr/bin/find / -xdev -perm -2000 -type f 2>/dev/null"
        report_issue 10 \
            "Non-standard SGID binaries found" \
            "SGID binaries run with the owning group's privileges - exploitable for group escalation" \
            "$sgid_fix_cmds" \
            1 \
            "Non-whitelisted SGID files:\n${sgid_list}"
    else
        print_status "OK" "No unexpected SGID binaries found"
        append_report "## Deep: SGID Binaries\n- 🟢 No non-standard SGID binaries detected"
    fi

    # 2. World-writable files
    print_status "INFO" "Scanning world-writable files..."
    local -a world_write=()
    while IFS= read -r f; do
        world_write+=("$f")
    done < <(find /etc /var /home -xdev -perm -002 -type f 2>/dev/null)
    if [[ ${#world_write[@]} -gt 0 ]]; then
        local ww_list ww_fix_cmds
        ww_list=$(printf ' - %s\n' "${world_write[@]}")
        ww_fix_cmds="# Remove world-write bit from each file - verify ownership first:"$'\n'
        for f in "${world_write[@]}"; do
            ww_fix_cmds+="sudo /bin/chmod o-w $(printf '%q' "$f")"$'\n'
        done
        ww_fix_cmds+="sudo /usr/bin/find /etc /var /home -xdev -perm -002 -type f 2>/dev/null"
        report_issue 16 \
            "World-writable files in sensitive dirs" \
            "Anyone on the system can modify these files" \
            "$ww_fix_cmds" \
            1 \
            "World-writable files:\n${ww_list}"
    fi

    # 2b. World-writable directories
    print_status "INFO" "Scanning world-writable directories..."
    local -a world_write_dirs=()
    while IFS= read -r d; do
        world_write_dirs+=("$d")
    done < <(find /etc /var /home -xdev -perm -002 -type d ! -name 'tmp' 2>/dev/null)
    if [[ ${#world_write_dirs[@]} -gt 0 ]]; then
        local wwd_list wwd_fix_cmds
        wwd_list=$(printf ' - %s\n' "${world_write_dirs[@]}")
        wwd_fix_cmds="# Remove world-write bit from each directory:"$'\n'
        for d in "${world_write_dirs[@]}"; do
            wwd_fix_cmds+="sudo /bin/chmod o-w $(printf '%q' "$d")"$'\n'
        done
        wwd_fix_cmds+="sudo /usr/bin/find /etc /var /home -xdev -perm -002 -type d ! -name 'tmp' 2>/dev/null"
        report_issue 12 \
            "World-writable directories in sensitive paths" \
            "Anyone on the system can create or delete files inside these directories" \
            "$wwd_fix_cmds" \
            1 \
            "World-writable directories:\n${wwd_list}"
    fi

    # 2c. Unowned files
    print_status "INFO" "Scanning for unowned files and directories (full filesystem - may take several minutes)..."
    _scan_start=$(date +%s)
    local -a unowned_files=()
    local _unowned_checked=0
    while IFS= read -r f; do
        unowned_files+=("$f")
        _unowned_checked=$(( _unowned_checked + 1 ))
        if (( _unowned_checked % 1000 == 0 )); then
            _scan_elapsed=$(( $(date +%s) - _scan_start ))
            print_status "INFO" "  Unowned scan: ${_unowned_checked} hits so far (${_scan_elapsed}s elapsed)..."
        fi
    done < <(find / -xdev \( -nouser -o -nogroup \) -type f 2>/dev/null)
    local -a unowned_dirs=()
    while IFS= read -r d; do unowned_dirs+=("$d"); done \
        < <(find / -xdev \( -nouser -o -nogroup \) -type d 2>/dev/null)
    _scan_elapsed=$(( $(date +%s) - _scan_start ))
    print_status "INFO" "  Unowned scan complete in ${_scan_elapsed}s (${#unowned_files[@]} files, ${#unowned_dirs[@]} dirs)"

    local total_unowned=$(( ${#unowned_files[@]} + ${#unowned_dirs[@]} ))
    if [[ $total_unowned -gt 0 ]]; then
        local unowned_list=""
        [[ ${#unowned_files[@]} -gt 0 ]] && unowned_list+="Files:\n$(printf ' - %s\n' "${unowned_files[@]}")\n"
        [[ ${#unowned_dirs[@]}  -gt 0 ]] && unowned_list+="Dirs:\n$(printf '  - %s\n' "${unowned_dirs[@]}")"
        local unowned_fix_cmds
        unowned_fix_cmds="# Assign unowned files to root:root after review:
sudo /usr/bin/find / -xdev -nouser -type f 2>/dev/null | xargs -r sudo /bin/chown root:
sudo /usr/bin/find / -xdev -nogroup -type f 2>/dev/null | xargs -r sudo /bin/chown :root
# Verify none remain:
sudo /usr/bin/find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l"
        print_status "WARN" "Found ${total_unowned} unowned file(s)/dir(s) (no valid UID/GID)"
        append_report "## Deep: Unowned Files & Directories\n- 🔴 ${total_unowned} path(s) with no valid owner or group"
        report_issue 8 \
            "Files or directories with no valid owner/group" \
            "${total_unowned} path(s) have a UID/GID mapping to no existing user/group - can be hijacked if UID/GID reused" \
            "$unowned_fix_cmds" \
            1 \
            "${unowned_list}"
    else
        print_status "OK" "No unowned files or directories found"
        append_report "## Deep: Unowned Files & Directories\n- 🟢 All files and directories have valid owners and groups"
    fi

    # 3. Empty passwords
    print_status "INFO" "Checking for empty passwords..."
    local empty_pw
    empty_pw=$(sudo /usr/bin/awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pw" ]]; then
        local pw_fix_cmds
        pw_fix_cmds="# Lock each account with an empty password immediately:"$'\n'
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            pw_fix_cmds+="sudo /usr/bin/passwd -l $(printf '%q' "$user")"$'\n'
            pw_fix_cmds+="sudo /usr/sbin/usermod -s /usr/sbin/nologin $(printf '%q' "$user")"$'\n'
        done <<< "$empty_pw"
        pw_fix_cmds+="sudo /usr/bin/awk -F: '\$2==\"\" {print \$1}' /etc/shadow"
        report_issue 20 \
            "Accounts with empty passwords found" \
            "These accounts have no password set (critical risk)" \
            "$pw_fix_cmds" \
            1 \
            "Affected users: $(echo "$empty_pw" | tr '\n' ' ')"
    fi

    # 4. Password aging policy
    print_status "INFO" "Checking password policy (login.defs)..."
    local max_days
    max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs 2>/dev/null || true)
    if [[ -z "$max_days" || "$max_days" -gt 90 ]]; then
        report_issue 8 \
            "Weak password aging policy" \
            "PASS_MAX_DAYS not set or too high (${max_days:-unset}) in /etc/login.defs" \
            "sudo /bin/sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
/bin/grep '^PASS_' /etc/login.defs" \
            1
    fi

    # 5. Mount options - now a standard-mode check (check_mount_options); already ran above

    # 6. Sudo timeout
    print_status "INFO" "Checking sudo password timeout..."
    local timeout_val
    timeout_val=$(sudo grep -oE 'timestamp_timeout=[0-9]+' \
                      /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
                  | grep -oE '[0-9]+$' | sort -n | tail -1 || true)
    if [[ -z "$timeout_val" || "$timeout_val" -gt 15 ]]; then
        report_issue 5 \
            "Sudo password timeout too long or unset" \
            "Timeout is ${timeout_val:-unset} minutes (should be ≤ 15)" \
            "echo 'Defaults timestamp_timeout=5' | sudo /usr/bin/tee /etc/sudoers.d/timeout
sudo /bin/chmod 440 /etc/sudoers.d/timeout
sudo /usr/sbin/visudo -c -f /etc/sudoers.d/timeout
sudo /usr/bin/grep timestamp_timeout /etc/sudoers /etc/sudoers.d/*" \
            1
    fi

    # 7. debsums
    if [[ $_have_debsums -eq 1 ]]; then
        print_status "INFO" "Running debsums integrity check..."
        local debsums_log
        debsums_log=$(mktemp "${REPORT_DIR}/debsums-audit-XXXXXX.log")
        sudo /usr/bin/debsums -c 2>&1 | tee "$debsums_log" > /dev/null || true
        if [[ -s "$debsums_log" ]]; then
            local debsums_pkgs
            debsums_pkgs=$(
                /usr/bin/awk '{print $1}' "$debsums_log" \
                | xargs -I{} /usr/bin/dpkg -S {} 2>/dev/null \
                | /usr/bin/cut -d: -f1 \
                | /usr/bin/sort -u \
                | /bin/grep -E '^[a-z0-9][a-z0-9.+-]+$' \
                || true
            )
            local debsums_fix_cmds
            debsums_fix_cmds="# Reinstall each package with modified files to restore originals:"$'\n'
            if [[ -n "$debsums_pkgs" ]]; then
                # FIX: build validated package list line-by-line, not via unquoted subshell
                local pkg_args=""
                while IFS= read -r pkg; do
                    # Only pass packages matching safe naming pattern
                    [[ "$pkg" =~ ^[a-z0-9][a-z0-9.+-]+$ ]] && pkg_args+=" $pkg"
                done <<< "$debsums_pkgs"
                [[ -n "$pkg_args" ]] && debsums_fix_cmds+="sudo /usr/bin/apt-get install --reinstall${pkg_args}"$'\n'
            else
                debsums_fix_cmds+="# Could not resolve packages automatically - run manually:
sudo /usr/bin/debsums -c
# Then for each failed file:  sudo /usr/bin/dpkg -S <file>  to find its package
# Then:  sudo /usr/bin/apt-get install --reinstall <package>"
            fi
            debsums_fix_cmds+=$'\n'"sudo /usr/bin/debsums -c   # re-verify after reinstall"
            report_issue 12 \
                "Package files modified (integrity violation)" \
                "System files differ from package checksums - possible tampering" \
                "$debsums_fix_cmds" \
                1 \
                "Full output: $debsums_log"
            append_report "##### debsums - Modified/Failed Files\n\`\`\`\n$(< "$debsums_log")\n\`\`\`"
            append_report "**Full log:** $debsums_log"
        fi
    else
        print_status "INFO" "debsums not available - skipping package integrity check"
        append_report "## Deep: Package Integrity (debsums)\n- ℹ️ Skipped (not installed)"
    fi

    # 8. rkhunter
    if [[ $_have_rkhunter -eq 1 ]]; then
        print_status "INFO" "Running rkhunter rootkit scan..."
        local rk_log
        rk_log=$(mktemp "${REPORT_DIR}/rkhunter-audit-XXXXXX.log")
        sudo /usr/bin/rkhunter --update --quiet 2>/dev/null || true
        sudo /usr/bin/rkhunter --check --skip-keypress --quiet --logfile "$rk_log" 2>&1 || true
        local rk_failures
        rk_failures=$(grep -E "\[ (Warning|FAILED|CRITICAL|INFECTED) \]|^Warning:|Rootkit|Suspect|HIDDEN" \
                      "$rk_log" 2>/dev/null || true)
        if [[ -n "$rk_failures" ]]; then
            report_issue 18 \
                "rkhunter detected warnings / suspicious items" \
                "Possible rootkits, hidden files, or modified binaries detected" \
                "sudo /usr/bin/rkhunter --propupd
sudo /usr/bin/rkhunter --check --skip-keypress
sudo /usr/bin/less ${rk_log}" \
                1 \
                "Full log: $rk_log"
            append_report "##### rkhunter - Failures & Warnings Only\n\`\`\`\n${rk_failures}\n\`\`\`"
            append_report "**Full log (all checks):** $rk_log"
        fi
    else
        print_status "INFO" "rkhunter not available - skipping rootkit scan"
        append_report "## Deep: Rootkit Scan (rkhunter)\n- ℹ️ Skipped (not installed)"
    fi

    # 9. ClamAV
    if [[ $_have_clamscan -eq 1 ]]; then
        print_status "INFO" "Updating ClamAV virus definitions..."
        local _freshclam_ok=0
        # clamav-freshclam service already holds the lock and handles auto-updates
        if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
            print_status "OK" "clamav-freshclam service is active - definitions auto-updated"
            _freshclam_ok=1
        elif timeout 120 sudo /usr/bin/freshclam --quiet 2>&1 | grep -v "NotifyClamd"; then
            print_status "OK" "ClamAV definitions updated"
            _freshclam_ok=1
        else
            print_status "WARN" "freshclam update timed out or failed - scanning with existing definitions"
            report_issue 3 \
                "ClamAV virus definitions may be outdated" \
                "freshclam could not update - log file locked or network issue; definitions may be stale" \
                "# Enable automatic updates via the service (preferred):
sudo /bin/systemctl enable --now clamav-freshclam
# Or manually update after stopping the service:
sudo /bin/systemctl stop clamav-freshclam 2>/dev/null || true
sudo /usr/bin/freshclam
sudo /bin/systemctl start clamav-freshclam 2>/dev/null || true
# Verify:
sudo /usr/bin/freshclam --version" \
                1
        fi

        print_status "INFO" "Running targeted ClamAV scan (critical directories only)..."
        local clam_log
        clam_log=$(mktemp "${REPORT_DIR}/clamav-audit-XXXXXX.log")
        # FIX: 30-minute timeout prevents indefinite hang
        timeout 1800 sudo /usr/bin/clamscan -r -i \
            --exclude-dir='^/proc' --exclude-dir='^/sys' --exclude-dir='^/dev' \
            /home /root /tmp /var /etc /usr/bin /usr/sbin /bin /sbin > "$clam_log" 2>&1 || true

        local infected_count
        infected_count=$(grep -oP 'Infected files: \K\d+' "$clam_log" 2>/dev/null || echo 0)

        if [[ "$infected_count" -gt 0 ]]; then
            local infected_lines
            infected_lines=$(grep ' FOUND$' "$clam_log" || true)

            local clam_fix_cmds
            clam_fix_cmds="# Create a private quarantine directory:"$'\n'
            clam_fix_cmds+="QUARANTINE_DIR=\$(sudo /bin/mktemp -d /var/clam-quarantine-XXXXXX)"$'\n'
            clam_fix_cmds+="sudo /bin/chmod 700 \"\$QUARANTINE_DIR\""$'\n'
            clam_fix_cmds+="# Move each infected file to quarantine:"$'\n'
            while IFS= read -r found_line; do
                local fpath
                fpath=$(echo "$found_line" | /usr/bin/cut -d: -f1)
                clam_fix_cmds+="sudo /usr/bin/clamscan --move=\"\$QUARANTINE_DIR\" $(printf '%q' "$fpath")"$'\n'
            done <<< "$infected_lines"
            clam_fix_cmds+="# Review quarantined files before deleting:"$'\n'
            clam_fix_cmds+="sudo /bin/ls -lah \"\$QUARANTINE_DIR\""$'\n'
            clam_fix_cmds+="# Delete each file individually AFTER review (do NOT use rm -rf blindly):"$'\n'
            clam_fix_cmds+="# sudo /bin/rm \"\$QUARANTINE_DIR/<filename>\""$'\n'
            clam_fix_cmds+="# Re-scan to confirm clean:"$'\n'
            clam_fix_cmds+="sudo /usr/bin/clamscan -r -i /home /root /tmp /var /etc /usr/bin /usr/sbin /bin /sbin"

            report_issue 25 \
                "ClamAV detected infected/malware files" \
                "Live malware or viruses found on the system (critical - act immediately)" \
                "$clam_fix_cmds" \
                1 \
                "Full scan log: $clam_log"
            append_report "##### ClamAV - Infected Files Found (${infected_count} total)\n\`\`\`\n${infected_lines}\n\`\`\`"
            append_report "**Full scan log:** $clam_log"
            append_report "**Next step:** Quarantine the files above, then review and delete individually"
        fi
    else
        print_status "INFO" "ClamAV not available - skipping antivirus scan"
        append_report "## Deep: Antivirus Scan (ClamAV)\n- ℹ️ Skipped (not installed)"
    fi

    # 10. auditd
    if [[ $_have_auditd -eq 1 ]]; then
        if ! /bin/systemctl is-active --quiet auditd; then
            report_issue 7 \
                "auditd not running" \
                "System auditing is disabled - suspicious activity goes unlogged" \
                "sudo /bin/systemctl enable --now auditd
sudo /bin/systemctl status auditd
sudo /usr/sbin/aureport --summary" \
                1
        else
            # Check that meaningful rules are loaded
            local audit_rules
            audit_rules=$(sudo /sbin/auditctl -l 2>/dev/null || true)
            local rule_count
            rule_count=$(echo "$audit_rules" | grep -cE '^-[aw]' || true)
            if [[ "${rule_count:-0}" -lt 1 ]] || echo "$audit_rules" | grep -qE '^No rules|^LIST_RULES'; then
                print_status "WARN" "auditd is running but no meaningful rules are loaded"
                append_report "## Deep: auditd Rules\n- 🔴 auditd running with empty/default ruleset"
                report_issue 5 \
                    "auditd running with no rules loaded" \
                    "auditd service is active but no rules are defined - suspicious activity is not captured" \
                    "# Install CIS-aligned audit rules:
sudo /usr/bin/apt-get install -y auditd audispd-plugins
sudo /usr/bin/tee /etc/audit/rules.d/99-hardening.rules << 'AUDITEOF'
# Privilege escalation
-a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/sudo -k priv_esc
# Identity file changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# Network configuration changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_config
# Unauthorized access attempts
-a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauth_access
AUDITEOF
sudo /usr/sbin/augenrules --load
# Verify rules loaded:
sudo /sbin/auditctl -l" \
                    1
            else
                print_status "OK" "auditd is running with ${rule_count} rule(s) loaded"
                append_report "## Deep: auditd Rules\n- 🟢 auditd running with ${rule_count} rule(s)"
            fi
        fi
    else
        print_status "INFO" "auditd not available - skipping audit daemon check"
        append_report "## Deep: auditd\n- ℹ️ Skipped (not installed)"
    fi

    # 11. Lynis
    if [[ $_have_lynis -eq 1 ]]; then
        print_status "INFO" "Running Lynis system audit..."
        local lynis_log
        lynis_log=$(mktemp "${REPORT_DIR}/lynis-audit-XXXXXX.log")
        sudo /usr/sbin/lynis audit system --quiet 2>&1 | tee "$lynis_log" > /dev/null || true
        local lynis_any_findings
        lynis_any_findings=$(grep -E "(WARNING|FAILED|vulnerable)" "$lynis_log" || true)
        if [[ -n "$lynis_any_findings" ]]; then
            report_issue 15 \
                "Lynis detected warnings or failures" \
                "System audit found high-priority security issues" \
                "# Re-run Lynis interactively to see remediation hints per finding:
sudo /usr/sbin/lynis audit system
# Or show only warnings from the saved log:
sudo /bin/grep -E '(WARNING|FAILED|vulnerable)' \"${lynis_log}\"
# Full log for all suggestions and details:
sudo /usr/bin/less \"${lynis_log}\"" \
                1 \
                "Full log (includes all suggestions): $lynis_log"
            append_report "##### Lynis - Warnings & Failures Only\n\`\`\`\n${lynis_any_findings}\n\`\`\`"
            append_report "**Full log (all checks + suggestions):** $lynis_log"
        fi
    else
        print_status "INFO" "lynis not available - skipping system audit"
        append_report "## Deep: Lynis System Audit\n- ℹ️ Skipped (not installed)"
    fi

    # 12. Authorized keys
    print_status "INFO" "Checking authorized_keys files..."
    local auth_keys
    # FIX: wrap -name predicates in \( \) so -type f applies to both, not just authorized_keys2
    auth_keys=$(find /home /root \( -name authorized_keys -o -name authorized_keys2 \) -type f 2>/dev/null | head -10 || true)
    if [[ -n "$auth_keys" ]]; then
        append_report "## Deep: SSH Authorized Keys\n\`\`\`\n$auth_keys\n\`\`\`"
    fi

    # NEW 13. User SSH private key permissions (Missing #16)
    print_status "INFO" "Checking user SSH private key permissions..."
    local user_key_issues=0
    while IFS= read -r keyfile; do
        local kperms kowner
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        # Private keys must not be readable by group or others (any of 077 bits set)
        if [[ -n "$kperms" ]] && (( (8#$kperms & 8#077) != 0 )); then
            print_status "WARN" "Private key too permissive: $keyfile ($kperms, owned by $kowner)"
            append_report "## Deep: SSH User Key Permissions\n- 🔴 $keyfile: $kperms (should be 600)"
            report_issue 10 \
                "User SSH private key has insecure permissions: $(basename "$keyfile")" \
                "Private key $keyfile is ${kperms} - readable by group/others (credential exposure)" \
                "sudo /bin/chmod 600 $(printf '%q' "$keyfile")
# Verify:
/usr/bin/stat -c '%n %a %U' $(printf '%q' "$keyfile")" \
                1
            user_key_issues=$((user_key_issues + 1))
        fi
    done < <(find /home /root -name 'id_*' ! -name '*.pub' -type f 2>/dev/null)
    if [[ $user_key_issues -eq 0 ]]; then
        print_status "OK" "No world/group-readable user SSH private keys found"
        append_report "## Deep: SSH User Key Permissions\n- 🟢 User private SSH keys are properly restricted"
    fi

    # NEW 14. File capabilities scan (from review doc)
    print_status "INFO" "Scanning file capabilities..."
    if command -v getcap >/dev/null 2>&1; then
        local caps_output
        caps_output=$(getcap -r / 2>/dev/null | grep -v ' = $' || true)
        if [[ -n "$caps_output" ]]; then
            local caps_count
            caps_count=$(echo "$caps_output" | wc -l)
            print_status "WARN" "Found $caps_count file(s) with capabilities set - review for necessity"
            append_report "## Deep: File Capabilities\n\`\`\`\n${caps_output}\n\`\`\`"
            report_issue 5 \
                "Files with Linux capabilities set" \
                "$caps_count file(s) have capabilities - unnecessary caps are privilege escalation vectors" \
                "# Review each capability; remove unnecessary ones:
getcap -r / 2>/dev/null | grep -v ' = $'
# Remove a capability from a specific file:
# sudo /usr/sbin/setcap -r <file>
# Example: python with cap_net_raw that doesn't need it:
# sudo /usr/sbin/setcap -r /usr/bin/python3.x
# Verify after removal:
getcap -r / 2>/dev/null" \
                1 \
                "Files with capabilities (first 20):\n$(echo "$caps_output" | head -20)"
        else
            print_status "OK" "No unexpected file capabilities found"
            append_report "## Deep: File Capabilities\n- 🟢 No unnecessary capabilities detected"
        fi
    else
        print_status "INFO" "getcap not available - skipping file capabilities scan"
    fi
}


check_mount_options() {
    print_status "INFO" "Checking /tmp, /dev/shm, /var/tmp mount options and sticky bit..."
    local -a mount_issues=()
    local mount_fix=""

    # /tmp: check mount options
    local tmp_mount_line
    tmp_mount_line=$(mount | grep -E ' /tmp ' || true)
    local tmp_flags_missing=()
    if [[ -z "$tmp_mount_line" ]]; then
        tmp_flags_missing+=("noexec" "nosuid" "nodev")
    else
        grep -q 'noexec' <<< "$tmp_mount_line" || tmp_flags_missing+=("noexec")
        grep -q 'nosuid' <<< "$tmp_mount_line" || tmp_flags_missing+=("nosuid")
        grep -q 'nodev'  <<< "$tmp_mount_line" || tmp_flags_missing+=("nodev")
    fi
    if [[ ${#tmp_flags_missing[@]} -gt 0 ]]; then
        mount_issues+=("/tmp missing: ${tmp_flags_missing[*]}")
        mount_fix+="grep -qE '^tmpfs[[:space:]]+/tmp[[:space:]]' /etc/fstab || echo 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=512M 0 0' | sudo /usr/bin/tee -a /etc/fstab"$'\n'
        mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev /tmp"$'\n'
    fi

    # /tmp: sticky bit check
    local tmp_perms
    tmp_perms=$(stat -c '%a' /tmp 2>/dev/null || true)
    if [[ -n "$tmp_perms" ]] && (( (8#$tmp_perms & 8#1000) == 0 )); then
        mount_issues+=("/tmp is missing the sticky bit (perms: ${tmp_perms}) - users can delete each other's files")
        mount_fix+="sudo /bin/chmod +t /tmp"$'\n'
        mount_fix+="# Verify: stat -c '%a' /tmp   # should end in 1 (e.g. 1777)"$'\n'
    fi

    # /dev/shm and /var/tmp
    for mpoint in /dev/shm /var/tmp; do
        [[ ! -d "$mpoint" ]] && continue
        local m_line m_missing=()
        m_line=$(mount | grep -E " ${mpoint} " || true)
        if [[ -z "$m_line" ]]; then
            m_missing+=("noexec" "nosuid" "nodev")
        else
            grep -q 'noexec' <<< "$m_line" || m_missing+=("noexec")
            grep -q 'nosuid' <<< "$m_line" || m_missing+=("nosuid")
            grep -q 'nodev'  <<< "$m_line" || m_missing+=("nodev")
        fi
        if [[ ${#m_missing[@]} -gt 0 ]]; then
            mount_issues+=("${mpoint} missing: ${m_missing[*]} (attackers abuse ${mpoint} for staging)")
            mount_fix+="sudo /bin/mount -o remount,noexec,nosuid,nodev ${mpoint}   # immediate"$'\n'
            if [[ "$mpoint" == "/dev/shm" ]]; then
                mount_fix+="# Add to /etc/fstab: tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0"$'\n'
            else
                mount_fix+="# Add to /etc/fstab: tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0"$'\n'
            fi
        fi
    done

    if [[ ${#mount_issues[@]} -eq 0 ]]; then
        print_status "OK" "/tmp, /dev/shm, /var/tmp mount options and sticky bit are secure"
        append_report "## Mount Options\n- 🟢 /tmp, /dev/shm, /var/tmp: noexec/nosuid/nodev set, /tmp sticky bit present"
    else
        local mnt_issue_list
        mnt_issue_list=$(printf ' - %s\n' "${mount_issues[@]}")
        mount_fix+="# Verify all mounts:
/bin/mount | /bin/grep -E '/tmp|/dev/shm|/var/tmp'"
        print_status "WARN" "Mount option issues: ${#mount_issues[@]} found"
        append_report "## Mount Options\n- 🔴 ${#mount_issues[@]} mount issue(s) found"
        report_issue 10 \
            "Insecure mount options on /tmp, /dev/shm, or /var/tmp" \
            "${#mount_issues[@]} mount issue(s) - missing noexec/nosuid/nodev or sticky bit" \
            "$mount_fix" \
            0 \
            "Issues:\n${mnt_issue_list}"
    fi
}

check_ntp() {
    print_status "INFO" "Checking NTP time synchronization..."
    local ntp_ok=0

    if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        local sync_status
        sync_status=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || true)
        if [[ "$sync_status" == "yes" ]]; then
            print_status "OK" "systemd-timesyncd active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 systemd-timesyncd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v chronyc >/dev/null 2>&1; then
        if systemctl is-active --quiet chronyd 2>/dev/null && \
           chronyc tracking 2>/dev/null | grep -q "Leap status.*Normal"; then
            print_status "OK" "chrony is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 chrony synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]] && command -v ntpq >/dev/null 2>&1; then
        if ntpq -p 2>/dev/null | grep -q '^\*'; then
            print_status "OK" "ntpd is active and synchronized"
            append_report "## NTP Synchronization\n- 🟢 ntpd synchronized"
            ntp_ok=1
        fi
    fi

    if [[ $ntp_ok -eq 0 ]]; then
        print_status "WARN" "NTP not synchronized or not running"
        append_report "## NTP Synchronization\n- 🔴 NTP not active or not synchronized"
        report_issue 5 \
            "NTP synchronization not active" \
            "System clock may drift - accurate time is essential for log correlation and audit trails" \
            "sudo /bin/systemctl enable --now systemd-timesyncd
sudo timedatectl set-ntp true
timedatectl status
timedatectl show --property=NTPSynchronized" \
            0
    fi
}

check_ipv6_exposure() {
    print_status "INFO" "Checking IPv6 status..."

    local _sysctl_off _grub_off
    _sysctl_off=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
    _grub_off=0
    grep -qE 'ipv6\.disable=1' /etc/default/grub 2>/dev/null && _grub_off=1

    if [[ "$_sysctl_off" == "1" && "$_grub_off" == "1" ]]; then
        print_status "OK" "IPv6 fully disabled (sysctl + GRUB kernel parameter)"
        append_report "## IPv6 Status\n- 🟢 IPv6 disabled via sysctl and GRUB (fully hardened)"
        return
    fi

    if [[ "$_sysctl_off" == "1" && "$_grub_off" == "0" ]]; then
        print_status "WARN" "IPv6 disabled via sysctl but GRUB kernel parameter not set - will re-enable after kernel update"
        append_report "## IPv6 Status\n- 🟡 IPv6 disabled via sysctl only (GRUB parameter missing - not persistent across kernel updates)"
        append_report "  Run the fix script with \`--disable-ipv6\` to add the GRUB parameter."
        return
    fi

    # IPv6 is active — inventory addresses and listening services
    local _ipv6_addrs _ipv6_svcs
    _ipv6_addrs=$(ip -6 addr show 2>/dev/null \
        | awk '/inet6/ && !/^[[:space:]]*inet6 ::1/ {print "  " $2 " (" $NF ")"}' || true)
    _ipv6_svcs=$(ss -tulpn 2>/dev/null \
        | awk 'NR>1 && ($5 ~ /^\[/ || $5 ~ /^::/)' | awk '{print "  " $1 " " $5 " " $7}' || true)

    print_status "INFO" "IPv6 is active on this system"
    append_report "## IPv6 Status\n- ℹ️ IPv6 is active (not a scored issue - policy decision)"
    [[ -n "$_ipv6_addrs" ]] && append_report "### IPv6 Addresses\n\`\`\`\n${_ipv6_addrs}\n\`\`\`"
    [[ -n "$_ipv6_svcs"  ]] && append_report "### IPv6 Listening Services\n\`\`\`\n${_ipv6_svcs}\n\`\`\`"
    append_report "  To disable IPv6: run the fix script with \`--disable-ipv6\`"
}

check_disk_encryption() {
    print_status "INFO" "Checking disk encryption at rest (NIST SC-28)..."

    # Detect LUKS-encrypted block devices
    local _luks_devs=()
    while IFS= read -r _dev; do
        [[ -n "$_dev" ]] && _luks_devs+=("$_dev")
    done < <(lsblk -o NAME,TYPE -rn 2>/dev/null | awk '$2=="crypt"{print $1}' || true)

    # Also check blkid for LUKS type
    local _luks_blkid
    _luks_blkid=$(sudo /sbin/blkid 2>/dev/null | grep -c 'TYPE="crypto_LUKS"' || echo "0")

    # Check if root filesystem is on an encrypted volume
    local _root_encrypted=0
    local _root_dev
    _root_dev=$(findmnt -n -o SOURCE / 2>/dev/null || true)
    if [[ -n "$_root_dev" ]]; then
        # Follow device-mapper chain: if root is on dm-*, check if parent is LUKS
        local _dm_name
        _dm_name=$(basename "$_root_dev")
        if sudo /sbin/dmsetup info "$_dm_name" 2>/dev/null | grep -q 'crypt\|LUKS'; then
            _root_encrypted=1
        fi
        # Also check if root device itself is in the luks list
        if sudo /sbin/blkid "$_root_dev" 2>/dev/null | grep -q 'crypto_LUKS'; then
            _root_encrypted=1
        fi
    fi

    if [[ ${#_luks_devs[@]} -gt 0 || "$_luks_blkid" -gt 0 ]]; then
        local _enc_list
        _enc_list=$(sudo /sbin/blkid 2>/dev/null | grep 'crypto_LUKS' | awk -F: '{print $1}' || true)
        if [[ "$_root_encrypted" -eq 1 ]]; then
            print_status "OK" "Root filesystem is on an encrypted (LUKS) volume"
            append_report "## Disk Encryption (SC-28)\n- 🟢 Root filesystem encrypted with LUKS"
        else
            print_status "WARN" "LUKS volumes present but root filesystem may not be encrypted"
            append_report "## Disk Encryption (SC-28)\n- 🟡 LUKS volumes present but root filesystem encryption not confirmed"
            append_report "\`\`\`\n${_enc_list}\n\`\`\`"
            report_issue 5 \
                "Root filesystem encryption not confirmed" \
                "LUKS volumes exist but root (/) may not be encrypted - data at rest may be unprotected" \
                "# Verify which volumes are encrypted:
sudo /sbin/blkid | grep crypto_LUKS
lsblk -o NAME,FSTYPE,MOUNTPOINT
# Full-disk encryption must be configured at install time.
# For existing systems, encrypt non-root volumes (e.g. /home, /var):
# sudo /usr/sbin/cryptsetup luksFormat /dev/sdXN
# Add to /etc/crypttab and /etc/fstab, then update-initramfs -u
# Verify root is encrypted:
findmnt -n -o SOURCE / | xargs sudo /sbin/blkid" \
                0 \
                "Full-disk encryption protects data if physical media is lost or stolen (NIST SC-28)"
        fi
    else
        print_status "WARN" "No LUKS disk encryption detected - data at rest is unprotected"
        append_report "## Disk Encryption (SC-28)\n- 🔴 No LUKS encryption detected on any block device"
        report_issue 8 \
            "No disk encryption detected (NIST SC-28)" \
            "No LUKS-encrypted volumes found - all data at rest is unprotected if media is stolen" \
            "# Disk encryption must be set up at install time for the root filesystem.
# For data partitions on a running system:
# 1. Backup data first
# 2. Encrypt the partition:
#    sudo /usr/sbin/cryptsetup luksFormat /dev/sdXN
#    sudo /usr/sbin/cryptsetup open /dev/sdXN <name>
#    sudo /sbin/mkfs.ext4 /dev/mapper/<name>
# 3. Add entry to /etc/crypttab:
#    echo '<name> /dev/sdXN none luks' | sudo /usr/bin/tee -a /etc/crypttab
# 4. Add entry to /etc/fstab and update-initramfs:
#    sudo /usr/bin/update-initramfs -u
# Verify:
sudo /sbin/blkid | grep crypto_LUKS
lsblk -o NAME,FSTYPE,MOUNTPOINT" \
            0 \
            "NIST SC-28 requires protection of information at rest. Full-disk encryption must be configured at install time."
    fi
}

check_idle_timeout() {
    print_status "INFO" "Checking idle session timeout (NIST AC-11)..."

    local _tmout_val=0
    local _tmout_file=""

    # Check /etc/profile.d/*.sh and /etc/profile for TMOUT
    local _tmout_found
    _tmout_found=$(grep -rh '^[[:space:]]*\(export[[:space:]]\+\)\?TMOUT=' \
        /etc/profile /etc/profile.d/ 2>/dev/null | tail -1 || true)

    if [[ -n "$_tmout_found" ]]; then
        _tmout_val=$(echo "$_tmout_found" | grep -oP 'TMOUT=\K[0-9]+' || echo "0")
        _tmout_file=$(grep -rl 'TMOUT=' /etc/profile /etc/profile.d/ 2>/dev/null | head -1 || true)
    fi

    # Also check if TMOUT is set and readonly (stronger enforcement)
    local _readonly_set=0
    grep -rqh 'readonly TMOUT\|declare -r.*TMOUT' /etc/profile /etc/profile.d/ 2>/dev/null && _readonly_set=1

    if [[ "$_tmout_val" -gt 0 && "$_tmout_val" -le 900 ]]; then
        if [[ $_readonly_set -eq 1 ]]; then
            print_status "OK" "Idle timeout set to ${_tmout_val}s (readonly) in ${_tmout_file}"
            append_report "## Idle Session Timeout (AC-11)\n- 🟢 TMOUT=${_tmout_val}s (readonly) configured in ${_tmout_file}"
        else
            print_status "WARN" "TMOUT=${_tmout_val}s is set but not readonly - users can override it"
            append_report "## Idle Session Timeout (AC-11)\n- 🟡 TMOUT=${_tmout_val}s configured but not readonly (users can unset it)"
            report_issue 3 \
                "Idle session timeout not enforced as readonly" \
                "TMOUT is set to ${_tmout_val}s but is not declared readonly - any user can unset it (NIST AC-11)" \
                "# Make TMOUT readonly so users cannot override it:
sudo /usr/bin/tee /etc/profile.d/99-idle-timeout.sh > /dev/null << 'TMOUTEOF'
# NIST AC-11: automatic session lock/termination after 15 minutes of inactivity
TMOUT=900
readonly TMOUT
export TMOUT
TMOUTEOF
sudo /bin/chmod 644 /etc/profile.d/99-idle-timeout.sh
# Verify (open a new shell):
bash -l -c 'echo TMOUT=\$TMOUT'" \
                0 \
                "readonly TMOUT prevents users from unsetting the timeout to avoid session lock"
        fi
    else
        if [[ "$_tmout_val" -gt 900 ]]; then
            print_status "WARN" "TMOUT=${_tmout_val}s exceeds 900s maximum - NIST AC-11 requires ≤15 minutes"
            append_report "## Idle Session Timeout (AC-11)\n- 🔴 TMOUT=${_tmout_val}s exceeds 900s (15 min) NIST maximum"
        else
            print_status "WARN" "No idle session timeout (TMOUT) configured - sessions never auto-terminate"
            append_report "## Idle Session Timeout (AC-11)\n- 🔴 TMOUT not configured - idle sessions never terminate"
        fi
        report_issue 6 \
            "Idle session timeout not configured (NIST AC-11)" \
            "TMOUT is not set or exceeds 900s - idle terminal sessions are never automatically terminated" \
            "# Configure a 15-minute (900s) readonly idle timeout for all shell sessions:
sudo /usr/bin/tee /etc/profile.d/99-idle-timeout.sh > /dev/null << 'TMOUTEOF'
# NIST AC-11: automatic session termination after 15 minutes of inactivity
TMOUT=900
readonly TMOUT
export TMOUT
TMOUTEOF
sudo /bin/chmod 644 /etc/profile.d/99-idle-timeout.sh
# Verify (open a new shell):
bash -l -c 'echo TMOUT=\$TMOUT'" \
            0 \
            "NIST AC-11 requires automatic session lock or termination after a defined period of inactivity (≤15 min)."
    fi
}

check_grub_password() {
    print_status "INFO" "Checking GRUB bootloader password protection..."
    local grub_pw_set=0
    if grep -rqE '^\s*password_pbkdf2\s' /boot/grub/grub.cfg /etc/grub.d/ 2>/dev/null; then
        grub_pw_set=1
    fi
    if [[ $grub_pw_set -eq 1 ]]; then
        print_status "OK" "GRUB bootloader password is configured"
        append_report "## GRUB Bootloader Password\n- 🟢 GRUB password protection configured"
    else
        print_status "WARN" "GRUB bootloader has no password protection"
        append_report "## GRUB Bootloader Password\n- 🔴 GRUB not password protected"
        report_issue 6 \
            "GRUB bootloader not password protected" \
            "Without a GRUB password, anyone with physical access can boot into recovery mode and gain root" \
            '# 1. Generate a GRUB password hash (run interactively):
grub-mkpasswd-pbkdf2
# 2. Add to /etc/grub.d/40_custom:
sudo /bin/tee -a /etc/grub.d/40_custom <<EOF
set superusers="root"
password_pbkdf2 root <PASTE_HASH_HERE>
EOF
sudo /bin/chmod 700 /etc/grub.d/40_custom
# 3. Rebuild grub.cfg:
sudo /usr/sbin/update-grub
# 4. Verify:
sudo /bin/grep -E "password_pbkdf2|superusers" /boot/grub/grub.cfg' \
            0 \
            "Physical access without a GRUB password bypasses all OS-level controls"
    fi
}

check_secrets() {
    print_status "INFO" "Scanning for exposed credentials and secrets..."
    local _issues=()

    # 1. SSH private keys readable by group or world
    while IFS= read -r _keyfile; do
        local _perms
        _perms=$(stat -c '%a' "$_keyfile" 2>/dev/null || true)
        if [[ -n "$_perms" && ( $(( 0${_perms} & 044 )) -ne 0 ) ]]; then
            _issues+=("SSH private key group/world-readable: ${_keyfile} (${_perms})")
        fi
    done < <(find /home /root -maxdepth 4 \( -name 'id_*' ! -name '*.pub' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | grep -v '\.pub$' || true)

    # 2. .env files containing secret patterns
    while IFS= read -r _envfile; do
        if grep -qiE '(PASSWORD|SECRET|API_KEY|AWS_|TOKEN|PRIVATE_KEY)\s*=' "$_envfile" 2>/dev/null; then
            _issues+=(".env file with secrets: ${_envfile}")
        fi
    done < <(find /home /root /etc /opt /var/www -maxdepth 4 -name '.env' 2>/dev/null || true)

    # 3. AWS credential files readable by group or world
    while IFS= read -r _awsfile; do
        local _aperms
        _aperms=$(stat -c '%a' "$_awsfile" 2>/dev/null || true)
        if [[ -n "$_aperms" && $(( 0${_aperms} & 044 )) -ne 0 ]]; then
            _issues+=("AWS credentials file group/world-readable: ${_awsfile} (${_aperms})")
        fi
    done < <(find /home /root -maxdepth 3 -path '*/.aws/credentials' 2>/dev/null || true)

    # 4. Private key files in /etc/ssl readable by group or world
    # Exclude /etc/ssl/certs/ — public CA certificates there are intentionally world-readable
    while IFS= read -r _sslfile; do
        local _sperms
        _sperms=$(stat -c '%a' "$_sslfile" 2>/dev/null || true)
        if [[ -n "$_sperms" && $(( 0${_sperms} & 044 )) -ne 0 ]]; then
            _issues+=("SSL/TLS private key group/world-readable: ${_sslfile} (${_sperms})")
        fi
    done < <(find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' \( -name '*.key' -o -name '*.pem' \) 2>/dev/null || true)

    if [[ ${#_issues[@]} -gt 0 ]]; then
        local _details
        _details=$(printf '%s\n' "${_issues[@]}")
        print_status "WARN" "Exposed credentials/secrets found (${#_issues[@]} item(s))"
        report_issue 12 \
            "Exposed credentials or secrets detected" \
            "$(printf '%s\n' "${_issues[@]}")" \
            "# Fix SSH key permissions
find /home /root -maxdepth 4 \( -name 'id_*' ! -name '*.pub' -o -name '*.pem' -o -name '*.key' \) -exec chmod 600 {} \;
# Secure AWS credentials
find /home /root -maxdepth 3 -path '*/.aws/credentials' -exec chmod 600 {} \;
# Secure SSL private keys
find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' -name '*.key' -exec chmod 640 {} \;
find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' -name '*.pem' -exec chmod 640 {} \;
# Review and remove .env files with plaintext secrets from version control
# Consider using a secrets manager (Vault, AWS Secrets Manager, etc.)" \
            0
    else
        print_status "OK" "No exposed credentials or secrets detected"
        append_report "## Secrets Exposure\n- 🟢 No world/group-readable credential files or .env secrets found"
    fi
}

# ====================== MAIN AUDIT RUNNER =======================
print_status "INFO" "Starting Ubuntu Security Audit..."
print_status "INFO" "Environment: ${ENV_TYPE}"

# Count total _run_check calls for progress indicator
_CHECK_TOTAL=$(grep -c '^_run_check ' "$0" 2>/dev/null || echo "37")

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

# ====================== SCORE & GRADE ======================
[[ $SCORE -lt 0 ]] && SCORE=0
if   [[ $SCORE -ge 90 ]]; then GRADE="A"; COLOR="🟢"
elif [[ $SCORE -ge 80 ]]; then GRADE="B"; COLOR="🟡"
elif [[ $SCORE -ge 70 ]]; then GRADE="C"; COLOR="🟡"
elif [[ $SCORE -ge 60 ]]; then GRADE="D"; COLOR="🔴"
else                            GRADE="F"; COLOR="🔴"
fi

# ====================== FINAL REPORT ======================
append_report "
## Executive Summary (Final)
**Overall Security Score:** $SCORE/100 $COLOR ($GRADE)
**Issues found:** $ISSUE_COUNT total ($DEEP_ISSUE_COUNT in Deep mode)

## Quick Remediation Commands (Copy-Paste Ready)
$(printf '%s\n\n' "${ISSUES[@]}")

## Actionable Recommendations
$( [[ $SCORE -lt 90 ]] && echo "- Run the Quick Remediation section above immediately" || echo "- System is well maintained" )
$( [[ $DEEP -eq 0 ]] && echo "- Re-run with \`--deep\` for full attack-surface coverage (includes ClamAV + Lynis)" || echo "- Deep mode complete - review warnings only" )
- For full antivirus scan run: \`sudo clamscan -r -i /\` manually
- Review report and apply fixes in priority order (🔴 first).

## Appendix
- Generated by ubuntu-security-audit.sh (Deep mode: $([[ $DEEP -eq 1 ]] && echo enabled || echo disabled))
"

# ====================== FIX SCRIPT GENERATION ======================
FIX_SCRIPT="${REPORT_DIR}/fix-audit-$(date +%Y%m%d-%H%M).sh"

# --- Header + argument parsing ---
# Build human-readable framework label(s) for the header
_fw_labels=()
for _fw in "${FRAMEWORKS[@]}"; do
    case "$_fw" in
        nist)     _fw_labels+=("NIST SP 800-53 Rev 5") ;;
        cis)      _fw_labels+=("CIS Ubuntu Linux 24.04 LTS Benchmark") ;;
        iso27001) _fw_labels+=("ISO/IEC 27001:2022") ;;
        soc2)     _fw_labels+=("SOC 2 TSC 2017") ;;
    esac
done
_fw_label_str=$(IFS=', '; echo "${_fw_labels[*]}")
_primary_fw_label="${_fw_labels[0]:-NIST SP 800-53 Rev 5}"

cat > "$FIX_SCRIPT" << FIX
#!/usr/bin/env bash
# =========================================================
# Ubuntu Security Audit — Auto-generated Fix Script
# Framework(s) : ${_fw_label_str}
# Primary      : ${_primary_fw_label}  (drives ordering)
# Generated    : $(date '+%Y-%m-%d %H:%M')
# Host         : $(hostname)
# Score        : ${SCORE}/100 (${GRADE})
# Issues found : ${ISSUE_COUNT}
#
# Fixes are ORDERED and GROUPED by: ${_primary_fw_label}
# Each block shows control IDs for every selected framework.
# Review EACH block carefully before applying.
#
# --ssh-safe     : Apply SSH fixes with backup + rollback
# --disable-ipv6 : Disable IPv6 via sysctl + GRUB
# =========================================================
set -euo pipefail

SSH_SAFE=0
DISABLE_IPV6=0
for _arg in "\$@"; do
    case "\$_arg" in
        --ssh-safe)      SSH_SAFE=1 ;;
        --disable-ipv6)  DISABLE_IPV6=1 ;;
        --help)
            echo "Usage: \$0 [--ssh-safe] [--disable-ipv6]"
            echo "  --ssh-safe      Apply SSH hardening with backup, sshd -t validation,"
            echo "                  and a 5-minute auto-rollback timer."
            echo "  --disable-ipv6  Disable IPv6 via sysctl (immediate) + GRUB (persistent)."
            exit 0 ;;
        *) echo "Unknown option: \$_arg"; exit 1 ;;
    esac
done

echo "=== Ubuntu Security Fix Script ==="
echo "  Framework(s): ${_fw_label_str}"
[[ "\$SSH_SAFE" -eq 1 ]]     && echo "  Mode: SSH-safe (backup + 5-min rollback timer active)" || true
[[ "\$DISABLE_IPV6" -eq 1 ]] && echo "  Mode: disable-ipv6 (sysctl immediate + GRUB persistent)" || true
echo "Review each block before running!"
echo ""

# Refresh package index once upfront so all apt-get install blocks succeed
if command -v apt-get >/dev/null 2>&1; then
    echo "[INFO] Refreshing apt package index..."
    sudo /usr/bin/apt-get update -qq 2>&1 | grep -v "^$" || true
    echo "[INFO] Package index updated."
    echo ""
fi
FIX

# --- SSH-safe function: open (backup + apply SSH-specific fixes) ---
# NOTE: SSH remediation commands are written unindented so heredoc terminators
# remain at column 0 and are recognised correctly by bash.
cat >> "$FIX_SCRIPT" << 'SSHOPEN'
# ====================== SSH SAFE MODE FUNCTION ======================
_ssh_safe_apply() {
local _BACKUP_DIR
_BACKUP_DIR=$(sudo /bin/mktemp -d /tmp/sshd-backup-XXXXXX)
sudo /bin/chmod 700 "$_BACKUP_DIR"
sudo /bin/cp -a /etc/ssh/sshd_config "$_BACKUP_DIR/"
[[ -d /etc/ssh/sshd_config.d ]] && sudo /bin/cp -a /etc/ssh/sshd_config.d "$_BACKUP_DIR/"
echo "[SSH-SAFE] Config backed up to ${_BACKUP_DIR}"
echo "[SSH-SAFE] Applying SSH hardening changes..."
SSHOPEN

# Embed only true sshd-config remediations (titles containing "ssh config" or "sshd")
# Intentionally excludes titles like "Fail2Ban running without SSH jail" or
# "User SSH private key..." which contain "ssh" but don't touch sshd_config.
_ssh_indices=()
for i in "${!TITLES[@]}"; do
    _t="${TITLES[$i],,}"
    if [[ "$_t" == *"ssh config"* || "$_t" == *"sshd"* ]]; then
        _ssh_indices+=("$i")
        printf '# --- Fix: %s ---\n' "${TITLES[$i]}" >> "$FIX_SCRIPT"
        printf '%s\n\n'               "${REMEDIATIONS[$i]}" >> "$FIX_SCRIPT"
    fi
done

# --- SSH-safe function: close (validate + rollback timer + restart + confirm) ---
cat >> "$FIX_SCRIPT" << 'SSHCLOSE'
echo "[SSH-SAFE] Validating configuration with sshd -t ..."
if ! sudo /usr/sbin/sshd -t; then
    echo "[SSH-SAFE][ERROR] sshd -t failed - rolling back immediately."
    sudo /bin/cp -f "${_BACKUP_DIR}/sshd_config" /etc/ssh/sshd_config
    if [[ -d "${_BACKUP_DIR}/sshd_config.d" ]]; then
        sudo /bin/rm -rf /etc/ssh/sshd_config.d
        sudo /bin/cp -a "${_BACKUP_DIR}/sshd_config.d" /etc/ssh/sshd_config.d
    fi
    sudo /bin/systemctl restart ssh
    echo "[SSH-SAFE] Rollback complete - original config restored."
    return 1
fi
echo "[SSH-SAFE] Config validated OK."

local _ROLLBACK_SECS=300
(
    sleep "$_ROLLBACK_SECS"
    echo -e "\n[SSH-SAFE][TIMEOUT] No confirmation in ${_ROLLBACK_SECS}s - auto-rolling back."
    sudo /bin/cp -f "${_BACKUP_DIR}/sshd_config" /etc/ssh/sshd_config
    if [[ -d "${_BACKUP_DIR}/sshd_config.d" ]]; then
        sudo /bin/rm -rf /etc/ssh/sshd_config.d
        sudo /bin/cp -a "${_BACKUP_DIR}/sshd_config.d" /etc/ssh/sshd_config.d
    fi
    sudo /bin/systemctl restart ssh && echo "[SSH-SAFE] Rollback complete." \
        || echo "[SSH-SAFE][ERROR] sshd restart after rollback failed - restore ${_BACKUP_DIR}/sshd_config manually!"
) &
local _TIMER_PID=$!

echo "[SSH-SAFE] Restarting sshd ..."
sudo /bin/systemctl restart ssh

local _HOST
_HOST=$(hostname -I 2>/dev/null | awk '{print $1}' || hostname)
echo ""
echo "=========================================================="
echo "  SSH hardening applied. You have ${_ROLLBACK_SECS}s to verify."
echo "  1. Open a NEW terminal and test:  ssh user@${_HOST}"
echo "  2. Return here and confirm if the login succeeded."
echo "  Auto-rollback timer PID: ${_TIMER_PID}"
echo "  Manual cancel (if already confirmed OK): kill ${_TIMER_PID}"
echo "=========================================================="

local _confirm=""
if read -r -t "$_ROLLBACK_SECS" -p "Did the new SSH session succeed? (y/N): " _confirm \
   && [[ "${_confirm,,}" == "y" ]]; then
    kill "$_TIMER_PID" 2>/dev/null || true
    wait "$_TIMER_PID" 2>/dev/null || true
    echo "[SSH-SAFE] Confirmed. SSH hardening is live. Backup at: ${_BACKUP_DIR}"
else
    echo "[SSH-SAFE] Not confirmed or timed out. Rolling back..."
    kill "$_TIMER_PID" 2>/dev/null || true
    wait "$_TIMER_PID" 2>/dev/null || true
    sudo /bin/cp -f "${_BACKUP_DIR}/sshd_config" /etc/ssh/sshd_config
    if [[ -d "${_BACKUP_DIR}/sshd_config.d" ]]; then
        sudo /bin/rm -rf /etc/ssh/sshd_config.d
        sudo /bin/cp -a "${_BACKUP_DIR}/sshd_config.d" /etc/ssh/sshd_config.d
    fi
    sudo /bin/systemctl restart ssh && echo "[SSH-SAFE] Rollback complete - original config restored." \
        || echo "[SSH-SAFE][ERROR] sshd restart after rollback failed - restore ${_BACKUP_DIR}/sshd_config manually!"
fi
}
SSHCLOSE

# --- Invocation block: call _ssh_safe_apply when flag is set ---
cat >> "$FIX_SCRIPT" << 'SSHINVOKE'

# ====================== MAIN EXECUTION ======================
if [[ "$SSH_SAFE" -eq 1 ]]; then
    echo "--- SSH-safe mode: applying SSH hardening with rollback protection ---"
    _ssh_safe_apply
    echo "--- SSH-safe mode complete ---"
    echo ""
fi

SSHINVOKE

# --- disable-ipv6 function ---
# NOTE: function body is unindented so the IPV6SYSCTL heredoc terminator
# sits at column 0 and is recognised correctly when the fix script runs.
cat >> "$FIX_SCRIPT" << 'IPV6FUNC'
# ====================== DISABLE IPv6 FUNCTION ======================
_disable_ipv6_apply() {
echo "[DISABLE-IPv6] Starting pre-flight checks..."

# Already fully disabled?
local _sysctl_off _grub_off
_sysctl_off=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
_grub_off=0
grep -qE 'ipv6\.disable=1' /etc/default/grub 2>/dev/null && _grub_off=1

if [[ "$_sysctl_off" == "1" && "$_grub_off" == "1" ]]; then
echo "[DISABLE-IPv6] IPv6 is already fully disabled (sysctl + GRUB). Nothing to do."
return 0
fi

# Warn if the current SSH session is over IPv6
if [[ -n "${SSH_CONNECTION:-}" ]]; then
local _src_ip
_src_ip=$(awk '{print $1}' <<< "$SSH_CONNECTION")
if [[ "$_src_ip" == *:* ]]; then
    echo "[DISABLE-IPv6][WARNING] Your SSH session is via IPv6 address: ${_src_ip}"
    echo "                         Disabling IPv6 WILL drop this connection immediately."
    local _yn=""
    read -r -p "Continue anyway? (y/N): " _yn
    [[ "${_yn,,}" == "y" ]] || { echo "[DISABLE-IPv6] Aborted."; return 1; }
fi
fi

# Warn if any service is listening exclusively on an IPv6 loopback address
local _ipv6_only_svcs
_ipv6_only_svcs=$(ss -tulpn 2>/dev/null \
    | awk '$5 ~ /^\[::1\]:/ || $5 ~ /^::1:/' || true)
if [[ -n "$_ipv6_only_svcs" ]]; then
echo "[DISABLE-IPv6][WARNING] Services bound exclusively to IPv6 loopback (::1):"
echo "$_ipv6_only_svcs"
echo "These will lose their socket once IPv6 is disabled."
local _yn=""
read -r -p "Continue? (y/N): " _yn
[[ "${_yn,,}" == "y" ]] || { echo "[DISABLE-IPv6] Aborted."; return 1; }
fi

# --- Step 1: sysctl (immediate, no reboot required) ---
if [[ "$_sysctl_off" != "1" ]]; then
echo "[DISABLE-IPv6] Writing /etc/sysctl.d/99-disable-ipv6.conf ..."
sudo /usr/bin/tee /etc/sysctl.d/99-disable-ipv6.conf > /dev/null << 'IPV6SYSCTL'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
IPV6SYSCTL
sudo /bin/chmod 644 /etc/sysctl.d/99-disable-ipv6.conf
sudo /sbin/sysctl --system
echo "[DISABLE-IPv6] sysctl applied - IPv6 disabled immediately."
else
echo "[DISABLE-IPv6] sysctl already set - skipping."
fi

# --- Step 2: GRUB kernel parameter (survives kernel updates, requires reboot) ---
if [[ "$_grub_off" != "1" ]]; then
echo "[DISABLE-IPv6] Adding ipv6.disable=1 to GRUB_CMDLINE_LINUX_DEFAULT ..."
if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub 2>/dev/null; then
    sudo /bin/sed -i \
        's/^\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 ipv6.disable=1"/' \
        /etc/default/grub
else
    echo 'GRUB_CMDLINE_LINUX_DEFAULT="ipv6.disable=1"' \
        | sudo /usr/bin/tee -a /etc/default/grub > /dev/null
fi
sudo /usr/sbin/update-grub
echo "[DISABLE-IPv6] GRUB updated - parameter active after next reboot."
else
echo "[DISABLE-IPv6] GRUB already set - skipping."
fi

# --- Verify ---
echo ""
echo "[DISABLE-IPv6] Verification:"
sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6
grep 'GRUB_CMDLINE_LINUX_DEFAULT' /etc/default/grub

echo ""
echo "[DISABLE-IPv6] Done."
echo "  IPv6 is now disabled at the sysctl level (immediate)."
echo "  Reboot to activate the GRUB kernel parameter (belt-and-suspenders)."
echo ""
echo "  To REVERSE: sudo rm /etc/sysctl.d/99-disable-ipv6.conf"
echo "              sudo sysctl --system"
echo "              Then remove 'ipv6.disable=1' from GRUB_CMDLINE_LINUX_DEFAULT"
echo "              in /etc/default/grub and run: sudo update-grub"
}
IPV6FUNC

cat >> "$FIX_SCRIPT" << 'IPV6INVOKE'
if [[ "$DISABLE_IPV6" -eq 1 ]]; then
    echo "--- disable-ipv6 mode: disabling IPv6 (sysctl + GRUB) ---"
    _disable_ipv6_apply
    echo "--- disable-ipv6 complete ---"
    echo ""
fi

IPV6INVOKE

# --- Compute sorted fix-block order (primary framework drives ordering) ---
if [[ ${#REMEDIATIONS[@]} -gt 0 ]] && command -v python3 >/dev/null 2>&1; then
    _sort_py_input_ctrl=$(IFS=$'\t'; echo "${CTRL_IDS_ALL[*]}")
    _sort_py_primary="${FRAMEWORKS[0]}"
    _sort_input=$(python3 -c "
import sys, re
entries = sys.argv[1].split('\t')
primary = sys.argv[2]

def primary_ctrl(entry):
    for part in entry.split('|'):
        fw, _, ids = part.partition(':')
        if fw == primary and ids:
            return ids.split(',')[0].strip()
    return ''

def sort_key(ctrl):
    if not ctrl:
        return ('ZZ', 9999)
    if primary == 'nist':
        p = ctrl.split('-')
        return (p[0].upper(), int(p[1]) if len(p) > 1 and p[1].isdigit() else 0)
    elif primary == 'cis':
        try: return tuple(int(x) for x in ctrl.split('.'))
        except: return (9999,)
    elif primary == 'iso27001':
        parts = ctrl.lstrip('A').lstrip('.').split('.')
        try: return tuple(int(x) for x in parts)
        except: return (9999,)
    else:
        m = re.match(r'CC(\d+)\.(\d+)', ctrl)
        return (int(m.group(1)), int(m.group(2))) if m else (9999,)

indexed = sorted(enumerate(entries), key=lambda x: sort_key(primary_ctrl(x[1])))
print(' '.join(str(i) for i, _ in indexed))
" "$_sort_py_input_ctrl" "$_sort_py_primary" 2>/dev/null \
        || seq 0 $((${#REMEDIATIONS[@]}-1)) | tr '\n' ' ')
    read -ra _sorted_indices <<< "$_sort_input"
else
    mapfile -t _sorted_indices < <(seq 0 $((${#REMEDIATIONS[@]}-1)))
fi

# --- Individual fix blocks; SSH ones skip when --ssh-safe already handled them ---
_prev_family=""
_fix_counter=0
for i in "${_sorted_indices[@]}"; do
    _fix_counter=$((_fix_counter + 1))
    fix_title="${TITLES[$i]:-Fix ${_fix_counter}}"
    ctrl_all="${CTRL_IDS_ALL[$i]:-}"

    # Extract the primary framework's first control ID for section grouping
    _primary_ctrl=""
    for _part in ${ctrl_all//|/ }; do
        _fw_part="${_part%%:*}"; _ids_part="${_part#*:}"
        if [[ "$_fw_part" == "${FRAMEWORKS[0]}" ]]; then
            _primary_ctrl="${_ids_part%%,*}"
            break
        fi
    done
    _cur_family=$(_extract_family "$_primary_ctrl" "${FRAMEWORKS[0]}")

    if [[ -n "$_cur_family" && "$_cur_family" != "$_prev_family" ]]; then
        _write_section_divider "$_cur_family" "${FRAMEWORKS[0]}"
        _prev_family="$_cur_family"
    fi

    _is_ssh=0
    if [[ ${#_ssh_indices[@]} -gt 0 ]]; then
        for _idx in "${_ssh_indices[@]}"; do
            [[ "$_idx" == "$i" ]] && _is_ssh=1 && break
        done
    fi

    printf '\n# ======================================================\n' >> "$FIX_SCRIPT"
    printf '# Fix %d: %s\n' "$_fix_counter" "$fix_title"         >> "$FIX_SCRIPT"
    printf '# Severity      : %s\n' "${SEVERITIES[$i]:-?}"       >> "$FIX_SCRIPT"
    # Per-framework control annotation lines
    for _fw in "${FRAMEWORKS[@]}"; do
        _ids=""
        for _part in ${ctrl_all//|/ }; do
            if [[ "${_part%%:*}" == "$_fw" ]]; then
                _ids="${_part#*:}"
                break
            fi
        done
        case "$_fw" in
            nist)     _fw_col="NIST SP 800-53 " ;;
            cis)      _fw_col="CIS Ubuntu     " ;;
            iso27001) _fw_col="ISO/IEC 27001  " ;;
            soc2)     _fw_col="SOC 2 TSC      " ;;
            *)        _fw_col="$_fw            " ;;
        esac
        printf '# %s: %s\n' "$_fw_col" "${_ids:-N/A}" >> "$FIX_SCRIPT"
    done
    printf '# ======================================================\n' >> "$FIX_SCRIPT"

    if [[ $_is_ssh -eq 1 ]]; then
        printf 'if [[ "$SSH_SAFE" -eq 1 ]]; then\n'              >> "$FIX_SCRIPT"
        printf 'echo "Fix %d (%s): already handled by --ssh-safe mode above - skipping"\n' \
            "$_fix_counter" "$fix_title"                          >> "$FIX_SCRIPT"
        printf 'else\n'                                           >> "$FIX_SCRIPT"
    fi

    printf '(set +e\n'                                             >> "$FIX_SCRIPT"
    printf '%s\n'           "${REMEDIATIONS[$i]}"                 >> "$FIX_SCRIPT"
    printf ') || echo "[WARN] Fix %d (%s) encountered errors - review output above"\n' \
        "$_fix_counter" "$fix_title"                              >> "$FIX_SCRIPT"

    if [[ $_is_ssh -eq 1 ]]; then
        printf 'fi\n'                                             >> "$FIX_SCRIPT"
    fi
done

chmod 700 "$FIX_SCRIPT"

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
            || print_status "WARN" "OSCAL generation encountered errors — check ${FINDINGS_FILE}"
    fi
fi

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
            || print_status "WARN" "Webhook delivery failed: ${WEBHOOK_URL}"
    else
        print_status "WARN" "--webhook requires curl and python3"
    fi
fi

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
