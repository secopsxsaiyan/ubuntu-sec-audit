# shellcheck shell=bash
# check_idle_timeout — standard check (sourced by ubuntu-sec-audit.sh)

check_idle_timeout() {
    print_status "INFO" "Checking idle session timeout (NIST AC-11)..."

    local _tmout_val=0 _tmout_file="" _readonly_set=0
    local -a _files=("${AUDIT_ROOT}/etc/profile" "${AUDIT_ROOT}/etc/bash.bashrc")
    local _f
    for _f in "${AUDIT_ROOT}"/etc/profile.d/*.sh; do
        [[ -f "$_f" ]] && _files+=("$_f")
    done

    # Assignments in any common form: TMOUT=900, export TMOUT=900,
    # readonly TMOUT=900, declare -xr TMOUT=900. The last one read wins.
    local _assign='^[[:space:]]*((export|readonly|declare|typeset)([[:space:]]+-[a-zA-Z]+)*[[:space:]]+)*TMOUT=([0-9]+)'
    local _ro='^[[:space:]]*(readonly([[:space:]]+-[a-zA-Z]+)*|(declare|typeset)[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+TMOUT([=[:space:]]|$)'
    local _line
    for _f in "${_files[@]}"; do
        [[ -f "$_f" ]] || continue
        while IFS= read -r _line; do
            if [[ "$_line" =~ $_assign ]]; then
                _tmout_val="${BASH_REMATCH[4]}"
                _tmout_file="${_f#"${AUDIT_ROOT}"}"
            fi
            [[ "$_line" =~ $_ro ]] && _readonly_set=1
        done < "$_f"
    done
    _tmout_val=$((10#$_tmout_val))

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
