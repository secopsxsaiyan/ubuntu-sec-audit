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

# Write the remediation script.
generate_fix_script() {
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

# --- Backup helper: cp -p preserves mode/owner; timestamped to avoid collisions ---
_bak() {
    local _f="\$1"
    [[ -f "\$_f" ]] || return 0
    local _dst="\${_f}.bak.\$(date +%Y%m%d%H%M%S)"
    sudo /bin/cp -p "\$_f" "\$_dst" 2>/dev/null \
        && echo "[BAK] \${_f} → \${_dst}" \
        || echo "[BAK][WARN] Could not back up \${_f}"
}

# --- Idempotency guard: run a command only when grep -q check fails ---
# Usage: _unless <grep-pattern> <file> <command...>
_unless() {
    local _pat="\$1" _file="\$2"; shift 2
    if grep -qF "\$_pat" "\$_file" 2>/dev/null; then
        echo "[SKIP] '\${_pat}' already present in \${_file}"
    else
        "\$@"
    fi
}

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

    # Auto-inject _bak calls for any config file targeted by a tee in this remediation
    _bak_calls=""
    while IFS= read -r _rline; do
        if [[ "$_rline" =~ tee[[:space:]]+'/'([^[:space:]\'\"]+) ]]; then
            _bak_calls+="_bak /${BASH_REMATCH[1]}"$'\n'
        fi
    done <<< "${REMEDIATIONS[$i]}"

    {
        printf '\n# ======================================================\n'
        printf '# Fix %d: %s\n' "$_fix_counter" "$fix_title"
        printf '# Severity      : %s\n' "${SEVERITIES[$i]:-?}"
        printf '%s' "$_fw_annotations"
        printf '# ======================================================\n'
        if [[ $_is_ssh -eq 1 ]]; then
            printf 'if [[ "$SSH_SAFE" -eq 1 ]]; then\n'
            printf 'echo "Fix %d (%s): already handled by --ssh-safe mode above - skipping"\n' \
                "$_fix_counter" "$fix_title"
            printf 'else\n'
        fi
        printf '(set +e\n'
        [[ -n "$_bak_calls" ]] && printf '%s' "$_bak_calls"
        printf '%s\n' "${REMEDIATIONS[$i]}"
        printf ') || echo "[WARN] Fix %d (%s) encountered errors - review output above"\n' \
            "$_fix_counter" "$fix_title"
        if [[ $_is_ssh -eq 1 ]]; then
            printf 'fi\n'
        fi
    } >> "$FIX_SCRIPT"
done

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
