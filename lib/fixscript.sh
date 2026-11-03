# shellcheck shell=bash
# Fix-script generation.

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
            local _tmp="${ctrl#A.}"        # strip leading "A."
            local _major="${_tmp%%.*}"     # first numeric segment
            echo "A.${_major}"
            ;;
        soc2)
            # CC6.1 → "CC6"; A1.1 → "A1"
            echo "${ctrl%.*}"
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
                # CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 sections
                1) family_label="CIS Section 1 — Initial Setup" ;;
                2) family_label="CIS Section 2 — Services" ;;
                3) family_label="CIS Section 3 — Network" ;;
                4) family_label="CIS Section 4 — Host Based Firewall" ;;
                5) family_label="CIS Section 5 — Access Control" ;;
                6) family_label="CIS Section 6 — Logging and Auditing" ;;
                7) family_label="CIS Section 7 — System Maintenance" ;;
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

# ====================== FIX SCRIPT HELPERS ======================

# _fix_safe_title TEXT — TEXT as one printable line. Titles can contain file
# names, and they end up in a script that runs as root.
_fix_safe_title() {
    local t="$1"
    t="${t//$'\n'/ }"
    t="${t//$'\r'/ }"
    t="${t//$'\t'/ }"
    t="${t//[[:cntrl:]]/}"
    printf '%s' "$t"
}

# _is_manual_remediation TEXT — true when TEXT has no executable line, i.e.
# it is instructions for a person. Such blocks are never run.
_is_manual_remediation() {
    ! grep -qvE '^[[:space:]]*(#|$)' <<< "$1"
}

# _fix_kind INDEX — "ssh" when the block changes the SSH daemon configuration
# and must run behind the confirm-or-rollback guard.
_fix_kind() {
    case "${CHECK_IDS[$1]:-}" in
        check_ssh|check_login_banner) echo "ssh" ;;
        *)                            echo "plain" ;;
    esac
}

# _bak_targets TEXT — files TEXT writes with tee (any options) or edits with
# sed -i; one per line, first occurrence only.
_bak_targets() {
    local line tok i n last in_tee
    local -a toks found=()
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        read -ra toks <<< "$line"
        n=${#toks[@]}
        in_tee=0
        for (( i = 0; i < n; i++ )); do
            tok="${toks[$i]}"
            if [[ "$tok" == "tee" || "$tok" == */tee ]]; then
                in_tee=1
                continue
            fi
            if (( in_tee )); then
                case "$tok" in
                    -*) ;;
                    /*) found+=("$tok") ;;
                    *)  in_tee=0 ;;
                esac
            fi
        done
        if [[ "$line" =~ (^|[[:space:]/])sed[[:space:]].*-i ]]; then
            last=""
            for (( i = 0; i < n; i++ )); do
                [[ "${toks[$i]}" == /* ]] && last="${toks[$i]}"
            done
            [[ -n "$last" ]] && found+=("$last")
        fi
    done <<< "$1"
    local f
    local -A seen=()
    for f in "${found[@]+"${found[@]}"}"; do
        [[ "$f" =~ ^/[A-Za-z0-9._/+-]+$ ]] || continue
        [[ "$f" == /dev/* || "$f" == */sed || "$f" == */tee ]] && continue
        [[ -n "${seen[$f]:-}" ]] && continue
        seen["$f"]=1
        printf '%s\n' "$f"
    done
}

# Write the remediation script.
generate_fix_script() {
FIX_SCRIPT="${REPORT_DIR}/fix-audit-$(date +%Y%m%d-%H%M).sh"

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
# Host         : $(hostname 2>/dev/null || echo unknown)
# Score        : ${SCORE:-?}/100 (${GRADE:-?})
# Issues found : ${ISSUE_COUNT:-0}
#
# Nothing is changed unless you ask for it:
#   sudo ./$(basename "$FIX_SCRIPT")              ask before each fix (on a terminal)
#   sudo ./$(basename "$FIX_SCRIPT") --dry-run    list the fixes only (default without a terminal)
#   sudo ./$(basename "$FIX_SCRIPT") --apply      apply every fix without asking
# Options:
#   --interactive      ask before each fix
#   --no-ssh-rollback  apply SSH changes without the confirm-or-rollback
#                      guard (needed for unattended runs: the guard asks you
#                      to confirm a new login on a terminal)
#   --disable-ipv6     also disable IPv6 (sysctl now, GRUB after reboot)
#
# Blocks marked MANUAL are never run; follow their comments by hand.
# Fixes are ordered and grouped by ${_primary_fw_label}.
# =========================================================
FIX

cat >> "$FIX_SCRIPT" << 'FIXLIB'
set -uo pipefail

MODE=""
SSH_ROLLBACK=1
DISABLE_IPV6=0
for _arg in "$@"; do
    case "$_arg" in
        --apply)            MODE="apply" ;;
        --interactive)      MODE="interactive" ;;
        --dry-run|--list)   MODE="dry-run" ;;
        --no-ssh-rollback)  SSH_ROLLBACK=0 ;;
        --ssh-safe)         SSH_ROLLBACK=1 ;;   # the default; accepted for compatibility
        --disable-ipv6)     DISABLE_IPV6=1 ;;
        --help|-h)
            sed -n '/^# Nothing is changed/,/^# Blocks marked MANUAL/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: ${_arg} (see --help)" >&2; exit 1 ;;
    esac
done
if [[ -z "$MODE" ]]; then
    if [[ -t 0 ]]; then MODE="interactive"; else MODE="dry-run"; fi
fi
if [[ "$MODE" != "dry-run" && "$EUID" -ne 0 ]]; then
    echo "Applying fixes needs root: sudo $0 $*" >&2
    exit 1
fi

# Remediations are written with sudo; it is not needed when already root.
if ! command -v sudo >/dev/null 2>&1; then
    sudo() { "$@"; }
fi

echo "=== Ubuntu Security Fix Script (mode: ${MODE}) ==="

# --- Backup helper: cp -p preserves mode/owner; timestamped to avoid collisions ---
_bak() {
    local _f="$1" _dst
    [[ -f "$_f" ]] || return 0
    _dst="${_f}.bak.$(date +%Y%m%d%H%M%S)"
    if cp -p "$_f" "$_dst" 2>/dev/null; then
        echo "[BAK] ${_f} -> ${_dst}"
    else
        echo "[BAK][WARN] Could not back up ${_f}"
    fi
}

_FIX_APPLIED=0
_FIX_SKIPPED=0
_FIX_FAILED=0
_FIX_MANUAL=0
_FIX_LISTED=0
_APT_REFRESHED=0

# _run_fix NUM TITLE FUNCTION [ssh|plain] — list, ask, or apply one fix.
_run_fix() {
    local num="$1" title="$2" fn="$3" kind="${4:-plain}" answer="" rc=0
    case "$MODE" in
        dry-run)
            printf '[DRY-RUN] Fix %s: %s\n' "$num" "$title"
            _FIX_LISTED=$((_FIX_LISTED + 1))
            return 0 ;;
        interactive)
            read -r -p "Apply fix ${num}: ${title}? [y/N] " answer || answer=""
            if [[ "${answer,,}" != "y" ]]; then
                printf '[SKIP] Fix %s: %s\n' "$num" "$title"
                _FIX_SKIPPED=$((_FIX_SKIPPED + 1))
                return 0
            fi ;;
    esac
    if [[ "$_APT_REFRESHED" -eq 0 ]] && declare -f "$fn" | grep -q 'apt-get install'; then
        echo "[INFO] Refreshing apt package index..."
        apt-get update -qq || echo "[WARN] apt-get update failed; package installs may fail"
        _APT_REFRESHED=1
    fi
    printf '[APPLY] Fix %s: %s\n' "$num" "$title"
    if [[ "$kind" == "ssh" && "$SSH_ROLLBACK" -eq 1 ]]; then
        _ssh_guarded "$fn" || rc=$?
    else
        "$fn" || rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
        _FIX_APPLIED=$((_FIX_APPLIED + 1))
    else
        printf '[WARN] Fix %s (%s) did not complete cleanly (exit %s) - review the output above\n' \
            "$num" "$title" "$rc"
        _FIX_FAILED=$((_FIX_FAILED + 1))
    fi
}

# _manual_fix NUM TITLE — announce a manual step; nothing is run.
_manual_fix() {
    printf '[MANUAL] Fix %s: %s - not run; follow the steps in the comments of this script\n' "$1" "$2"
    _FIX_MANUAL=$((_FIX_MANUAL + 1))
}

_ssh_restore() {
    local dir="$1" backup="$2"
    rm -rf "${dir}/sshd_config.d"
    cp -a "${backup}/." "${dir}/"
}

# _ssh_guarded FUNCTION — apply an SSH change, validate it with sshd -t, and
# keep it only if the operator confirms a new login; otherwise roll back.
_ssh_guarded() {
    local fn="$1" dir="${FIX_SSHD_DIR:-/etc/ssh}" secs="${FIX_ROLLBACK_SECS:-300}"
    local backup rc=0 timer answer=""
    backup=$(mktemp -d "${TMPDIR:-/tmp}/sshd-backup-XXXXXX") || return 1
    chmod 700 "$backup"
    cp -a "${dir}/." "${backup}/"
    echo "[SSH] Backed up ${dir} to ${backup}"
    "$fn" || rc=$?
    if ! sshd -t; then
        echo "[SSH][ERROR] sshd -t failed - rolled back to the previous configuration."
        _ssh_restore "$dir" "$backup"
        systemctl restart ssh
        return 1
    fi
    systemctl restart ssh
    if [[ ! -t 0 ]]; then
        echo "[SSH] No terminal to confirm a new login - rolled back. Use --no-ssh-rollback for unattended runs."
        _ssh_restore "$dir" "$backup"
        systemctl restart ssh
        return 1
    fi
    (
        sleep "$secs"
        echo ""
        echo "[SSH][TIMEOUT] No confirmation in ${secs}s - rolled back."
        _ssh_restore "$dir" "$backup"
        systemctl restart ssh
    ) &
    timer=$!
    echo "[SSH] Changes are live. Open a NEW terminal and log in now (${secs}s before rollback)."
    if read -r -t "$secs" -p "Did a new SSH login succeed? (y/N): " answer && [[ "${answer,,}" == "y" ]]; then
        kill "$timer" 2>/dev/null
        wait "$timer" 2>/dev/null
        echo "[SSH] Confirmed. Previous configuration kept at ${backup}"
        return "$rc"
    fi
    kill "$timer" 2>/dev/null
    wait "$timer" 2>/dev/null
    echo "[SSH] Not confirmed - rolled back."
    _ssh_restore "$dir" "$backup"
    systemctl restart ssh
    return 1
}

_fix_summary() {
    echo ""
    if [[ "$MODE" == "dry-run" ]]; then
        echo "Dry run: no changes made. ${_FIX_LISTED} fix(es) listed, ${_FIX_MANUAL} manual."
        echo "Re-run with --interactive to choose fixes, or --apply to apply them all."
    else
        echo "Applied: ${_FIX_APPLIED}  Skipped: ${_FIX_SKIPPED}  Failed: ${_FIX_FAILED}  Manual: ${_FIX_MANUAL}"
    fi
}
FIXLIB

# --- disable-ipv6 function (only runs with --disable-ipv6) ---
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

# --- Compute sorted fix-block order (primary framework drives ordering) ---
# Write explicit "idx<TAB>ctrl_ids" pairs to a temp file so the original index
# is embedded in the data and cannot be lost by any dedup or grouping in Python.
if [[ ${#REMEDIATIONS[@]} -gt 0 ]] && command -v python3 >/dev/null 2>&1; then
    _sort_tmp=$(mktemp)
    for _si in "${!CTRL_IDS_ALL[@]}"; do
        printf '%d\t%s\n' "$_si" "${CTRL_IDS_ALL[$_si]}"
    done > "$_sort_tmp"

    _sort_input=$(python3 - "${FRAMEWORKS[0]}" "$_sort_tmp" 2>/dev/null << 'SORTEOF'
import sys, re

primary = sys.argv[1]
pairs = []
with open(sys.argv[2]) as fh:
    for line in fh:
        line = line.rstrip('\n')
        if not line:
            continue
        idx_str, _, ctrl_all = line.partition('\t')
        pairs.append((int(idx_str), ctrl_all))

def primary_ctrl(ctrl_all):
    for part in ctrl_all.split('|'):
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
        try:
            return tuple(int(x) for x in ctrl.split('.'))
        except ValueError:
            return (9999,)
    elif primary == 'iso27001':
        parts = ctrl.lstrip('A').lstrip('.').split('.')
        try:
            return tuple(int(x) for x in parts)
        except ValueError:
            return (9999,)
    else:
        m = re.match(r'CC(\d+)\.(\d+)', ctrl)
        return (int(m.group(1)), int(m.group(2))) if m else (9999,)

sorted_pairs = sorted(pairs, key=lambda x: sort_key(primary_ctrl(x[1])))
print(' '.join(str(idx) for idx, _ in sorted_pairs))
SORTEOF
)
    [[ -z "$_sort_input" ]] && _sort_input=$(seq 0 $((${#REMEDIATIONS[@]}-1)) | tr '\n' ' ')
    rm -f "$_sort_tmp"
    read -ra _sorted_indices <<< "$_sort_input"
else
    mapfile -t _sorted_indices < <(seq 0 $((${#REMEDIATIONS[@]}-1)))
fi

# --- Individual fix blocks ---
_prev_family=""
_fix_counter=0
for i in "${_sorted_indices[@]}"; do
    _fix_counter=$((_fix_counter + 1))
    fix_title=$(_fix_safe_title "${TITLES[$i]:-Fix ${_fix_counter}}")
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

    # Build per-framework annotation lines
    _fw_annotations=""
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
        _fw_annotations+="# ${_fw_col}: ${_ids:-N/A}"$'\n'
    done

    {
        printf '\n# ======================================================\n'
        if _is_manual_remediation "${REMEDIATIONS[$i]}"; then
            printf '# Fix %d: %s   [MANUAL - never run automatically]\n' "$_fix_counter" "$fix_title"
        else
            printf '# Fix %d: %s\n' "$_fix_counter" "$fix_title"
        fi
        printf '# Severity      : %s\n' "${SEVERITIES[$i]:-?}"
        printf '%s' "$_fw_annotations"
        printf '# ======================================================\n'
        if _is_manual_remediation "${REMEDIATIONS[$i]}"; then
            printf '%s\n' "${REMEDIATIONS[$i]}"
            printf '_manual_fix %d %q\n' "$_fix_counter" "$fix_title"
        else
            printf '_fix_%d() (\n' "$_fix_counter"
            printf 'set +e\n'
            while IFS= read -r _target; do
                [[ -n "$_target" ]] && printf '_bak %s\n' "$_target"
            done < <(_bak_targets "${REMEDIATIONS[$i]}")
            printf '%s\n' "${REMEDIATIONS[$i]}"
            printf ')\n'
            printf '_run_fix %d %q _fix_%d %s\n' "$_fix_counter" "$fix_title" "$_fix_counter" "$(_fix_kind "$i")"
        fi
    } >> "$FIX_SCRIPT"
done

cat >> "$FIX_SCRIPT" << 'FIXEND'

if [[ "$DISABLE_IPV6" -eq 1 ]]; then
    if [[ "$MODE" == "dry-run" ]]; then
        echo "[DRY-RUN] --disable-ipv6: would disable IPv6 (sysctl + GRUB)"
    else
        _disable_ipv6_apply
    fi
fi
_fix_summary
FIXEND

chmod 700 "$FIX_SCRIPT"

# Validate the generated fix script with ShellCheck if available
if command -v shellcheck >/dev/null 2>&1; then
    _sc_out=$(shellcheck -S warning "$FIX_SCRIPT" 2>&1 || true)
    if [[ -n "$_sc_out" ]]; then
        print_status "WARN" "ShellCheck found issues in generated fix script (review before running):"
        echo "$_sc_out"
    else
        print_status "OK" "Generated fix script passed ShellCheck (warning level)"
    fi
fi
}
