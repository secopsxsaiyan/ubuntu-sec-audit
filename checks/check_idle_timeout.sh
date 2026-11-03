# shellcheck shell=bash
# check_idle_timeout — standard check (sourced by ubuntu-sec-audit.sh)

_TMOUT_DROPIN="/etc/profile.d/99-idle-timeout.sh"

# _tmout_fix FILE... — remediation: write the readonly TMOUT drop-in. A
# readonly TMOUT set anywhere else first would make the drop-in's assignment
# fail ("readonly variable"), so those declarations in FILEs are disabled
# (replaced by ':' so an if/fi around them stays valid; sed -i is backed up).
_tmout_fix() {
    local f out=""
    if [[ $# -gt 0 ]]; then
        out+="# Disable the other readonly TMOUT declarations (they would keep their value):"$'\n'
        for f in "$@"; do
            out+="sudo /bin/sed -i -E 's/^([[:space:]]*)((readonly([[:space:]]+-[a-zA-Z]+)*|(declare|typeset)[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+TMOUT([=[:space:]]|\$))/\\1: # disabled by ubuntu-sec-audit, see 99-idle-timeout.sh: \\2/' $(printf '%q' "$f")"$'\n'
        done
    fi
    out+="# Configure a 15-minute (900s) readonly idle timeout for all shell sessions:
sudo /usr/bin/tee ${_TMOUT_DROPIN} > /dev/null << 'TMOUTEOF'
# NIST AC-11: automatic session termination after 15 minutes of inactivity
TMOUT=900
readonly TMOUT
export TMOUT
TMOUTEOF
sudo /bin/chmod 644 ${_TMOUT_DROPIN}
# Verify (open a new shell):
bash -l -c 'echo TMOUT=\$TMOUT'"
    printf '%s' "$out"
}

check_idle_timeout() {
    print_status "INFO" "Checking idle session timeout (NIST AC-11)..."

    local _tmout_val="" _tmout_file="" _readonly_set=0 _lock_file=""
    local -a _files=("${AUDIT_ROOT}/etc/profile" "${AUDIT_ROOT}/etc/bash.bashrc") _ro_files=()
    local _f _rel
    for _f in "${AUDIT_ROOT}"/etc/profile.d/*.sh; do
        [[ -f "$_f" ]] && _files+=("$_f")
    done

    # Assignments in any common form: TMOUT=900, export TMOUT=900,
    # readonly TMOUT=900, declare -xr TMOUT=900. Files are read in the order
    # a login shell sources them. The last assignment wins - unless TMOUT is
    # made readonly: every later assignment then fails, so the value it had
    # at the first readonly declaration stays (unset if it had none).
    local _assign='^[[:space:]]*((export|readonly|declare|typeset)([[:space:]]+-[a-zA-Z]+)*[[:space:]]+)*TMOUT=([0-9]+)'
    local _ro='^[[:space:]]*(readonly([[:space:]]+-[a-zA-Z]+)*|(declare|typeset)[[:space:]]+-[a-zA-Z]*r[a-zA-Z]*)[[:space:]]+TMOUT([=[:space:]]|$)'
    local _line
    for _f in "${_files[@]}"; do
        [[ -f "$_f" ]] || continue
        _rel="${_f#"${AUDIT_ROOT}"}"
        while IFS= read -r _line; do
            if [[ $_readonly_set -eq 0 && "$_line" =~ $_assign ]]; then
                _tmout_val="${BASH_REMATCH[4]}"
                _tmout_file="$_rel"
            fi
            if [[ "$_line" =~ $_ro ]]; then
                if [[ $_readonly_set -eq 0 ]]; then
                    _readonly_set=1
                    _lock_file="$_rel"
                fi
                if [[ "$_rel" != "$_TMOUT_DROPIN" && " ${_ro_files[*]} " != *" ${_rel} "* ]]; then
                    _ro_files+=("$_rel")
                fi
            fi
        done < "$_f"
    done
    _tmout_val=$((10#${_tmout_val:-0}))

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
$(_tmout_fix)" \
                0 \
                "readonly TMOUT prevents users from unsetting the timeout to avoid session lock"
        fi
    else
        local _state
        if [[ "$_tmout_val" -gt 900 ]]; then
            _state="TMOUT is ${_tmout_val}s (set in ${_tmout_file}), more than 900s"
            print_status "WARN" "TMOUT=${_tmout_val}s exceeds 900s maximum - NIST AC-11 requires ≤15 minutes"
            append_report "## Idle Session Timeout (AC-11)\n- 🔴 TMOUT=${_tmout_val}s exceeds 900s (15 min) NIST maximum"
        else
            _state="TMOUT is not set"
            print_status "WARN" "No idle session timeout (TMOUT) configured - sessions never auto-terminate"
            append_report "## Idle Session Timeout (AC-11)\n- 🔴 TMOUT not configured - idle sessions never terminate"
        fi
        if [[ $_readonly_set -eq 1 ]]; then
            _state+="; it is made readonly in ${_lock_file}, so later assignments cannot change it"
        fi
        report_issue 6 \
            "Idle session timeout not configured (NIST AC-11)" \
            "${_state} - idle terminal sessions are not terminated within 15 minutes" \
            "$(_tmout_fix "${_ro_files[@]}")" \
            0 \
            "NIST AC-11 requires automatic session lock or termination after a defined period of inactivity (≤15 min)."
    fi
}
