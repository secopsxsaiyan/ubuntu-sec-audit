# shellcheck shell=bash
# check_ssh — standard check (sourced by ubuntu-sec-audit.sh)

# _ssh_kex_list — preferred key exchange algorithms that this OpenSSH
# supports, comma-separated. Post-quantum hybrids come first (Ubuntu 24.04's
# default includes sntrup761x25519). Without "ssh -Q kex" the classic list is
# used, which every supported Ubuntu release understands.
_ssh_kex_list() {
    local -a preferred=(
        mlkem768x25519-sha256
        sntrup761x25519-sha512@openssh.com
        curve25519-sha256
        curve25519-sha256@libssh.org
        diffie-hellman-group16-sha512
        diffie-hellman-group18-sha512
    )
    local supported out="" k
    supported=$(ssh -Q kex 2>/dev/null || true)
    for k in "${preferred[@]}"; do
        if [[ -z "$supported" ]]; then
            [[ "$k" == mlkem* || "$k" == sntrup* ]] && continue
        elif ! grep -qxF "$k" <<< "$supported"; then
            continue
        fi
        out+="${out:+,}${k}"
    done
    printf '%s' "${out:-curve25519-sha256,diffie-hellman-group16-sha512}"
}

# _ssh_val KEY — value of KEY in the effective configuration (SSHD_CONF).
_ssh_val() {
    awk -v k="$1" '$1 == k {print $2; exit}' <<< "$SSHD_CONF"
}

# _ssh_weak_match_blocks — Match blocks in sshd_config and its drop-ins that
# turn password, empty-password or root login back on. "sshd -T" without
# -C ignores Match blocks, so they are read from the files.
_ssh_weak_match_blocks() {
    local -a files=()
    local f
    for f in "${AUDIT_ROOT}/etc/ssh/sshd_config" "${AUDIT_ROOT}/etc/ssh/sshd_config.d/"*.conf; do
        [[ -f "$f" ]] && files+=("$f")
    done
    [[ ${#files[@]} -gt 0 ]] || return 0
    awk -v root="$AUDIT_ROOT" '
        FNR == 1 { inm = 0 }
        /^[ \t]*#/ { next }
        tolower($1) == "match" { inm = 1; blk = $0; sub(/^[ \t]+/, "", blk); next }
        inm {
            k = tolower($1); v = tolower($2)
            if (((k == "passwordauthentication" || k == "kbdinteractiveauthentication" \
                  || k == "permitemptypasswords") && v == "yes") \
                || (k == "permitrootlogin" && v == "yes")) {
                fn = FILENAME
                if (root != "" && index(fn, root) == 1) fn = substr(fn, length(root) + 1)
                print fn ": \"" blk "\" sets " $1 " " $2
            }
        }' "${files[@]}" 2>/dev/null || true
}

check_ssh() {
    print_status "INFO" "Checking SSH hardening (extended)..."
    if ! command -v sshd >/dev/null 2>&1; then
        print_status "OK" "SSH server not installed"
        _mark_not_applicable "OpenSSH server is not installed"
        return 0
    fi
    if ! _sshd_effective_config; then
        print_status "WARN" "Cannot read the effective SSH configuration (sshd -T failed)"
        append_report "## SSH Hardening\n- ⚠️ sshd -T failed - SSH configuration not checked"
        _mark_skipped "sshd -T failed, so the effective SSH configuration is unknown: ${SSHD_CONF_ERR:-no output}"
        return 0
    fi

    local -a ssh_issues=() manual_items=()
    local _dropin_lines=""   # directives that fail now, for the tool's drop-in
    local _chmod_fixes=""    # permission fixes that cannot go in a drop-in
    local _allow_users_fix="" severe=0 v

    # Check 1: PermitRootLogin. sshd -T prints prohibit-password under its
    # old name, without-password.
    v=$(_ssh_val permitrootlogin)
    case "$v" in
        no|prohibit-password|without-password|forced-commands-only) ;;
        *)
            ssh_issues+=("PermitRootLogin is ${v:-unset} (should be 'no' or 'prohibit-password')")
            _dropin_lines+="PermitRootLogin prohibit-password"$'\n'
            severe=1 ;;
    esac

    # Check 2: PasswordAuthentication
    if [[ "$(_ssh_val passwordauthentication)" != "no" ]]; then
        ssh_issues+=("PasswordAuthentication is enabled")
        _dropin_lines+="PasswordAuthentication no"$'\n'
        _dropin_lines+="PubkeyAuthentication yes"$'\n'
        severe=1
    fi

    # Check 3: MaxAuthTries (CIS: ≤ 4)
    v=$(_ssh_val maxauthtries)
    if [[ ! "$v" =~ ^[0-9]+$ ]] || (( v > 4 )); then
        ssh_issues+=("MaxAuthTries is ${v:-unset} (should be ≤ 4)")
        _dropin_lines+="MaxAuthTries 4"$'\n'
    fi

    # Check 4: LoginGraceTime (CIS: 1-60 seconds)
    v=$(_ssh_val logingracetime)
    if [[ ! "$v" =~ ^[0-9]+$ ]] || (( v == 0 || v > 60 )); then
        ssh_issues+=("LoginGraceTime is ${v:-unset} (should be 1–60 seconds)")
        _dropin_lines+="LoginGraceTime 60"$'\n'
    fi

    # Check 5: X11Forwarding
    if [[ "$(_ssh_val x11forwarding)" == "yes" ]]; then
        ssh_issues+=("X11Forwarding is enabled (unnecessary attack surface)")
        _dropin_lines+="X11Forwarding no"$'\n'
    fi

    # Check 6: AllowTcpForwarding. Jump hosts, port forwarding and VS Code
    # Remote-SSH need it, so turning it off is a decision for a person.
    if [[ "$(_ssh_val allowtcpforwarding)" == "yes" ]]; then
        manual_items+=("AllowTcpForwarding is enabled (can tunnel traffic past the firewall)")
    fi

    # Check 7: ClientAlive settings
    v=$(_ssh_val clientaliveinterval)
    if [[ ! "$v" =~ ^[0-9]+$ ]] || (( v == 0 )); then
        ssh_issues+=("ClientAliveInterval is ${v:-0} (no idle session timeout)")
        _dropin_lines+="ClientAliveInterval 300"$'\n'
        _dropin_lines+="ClientAliveCountMax 2"$'\n'
    fi

    # Check 8: SSHv1 (only relevant on very old OpenSSH; directive removed in 7.4+)
    if grep -qE '^protocol[[:space:]]+.*1' <<< "$SSHD_CONF" \
       && ! grep -qE '^protocol[[:space:]]+2$' <<< "$SSHD_CONF"; then
        ssh_issues+=("SSHv1 is enabled - cryptographically broken")
        _dropin_lines+="Protocol 2"$'\n'
        severe=1
    fi

    # Check 9: SSH host private key permissions (must be 600 root:root)
    local keyfile kperms kowner
    while IFS= read -r keyfile; do
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        if [[ "$kperms" != "600" || "$kowner" != "root" ]]; then
            ssh_issues+=("Host private key ${keyfile}: perms=${kperms:-?}, owner=${kowner:-?} (should be 600 root)")
            _chmod_fixes+="sudo /bin/chmod 600 $(printf '%q' "$keyfile")"$'\n'
            _chmod_fixes+="sudo /bin/chown root:root $(printf '%q' "$keyfile")"$'\n'
            severe=1
        fi
    done < <(find "${AUDIT_ROOT}/etc/ssh" -maxdepth 1 -name 'ssh_host_*_key' ! -name '*.pub' 2>/dev/null || true)

    # Check 10: Weak ciphers, MACs, and KEX algorithms
    local weak_ciphers=("3des-cbc" "blowfish-cbc" "cast128-cbc" "arcfour" "arcfour128" "arcfour256"
                        "aes128-cbc" "aes192-cbc" "aes256-cbc" "rijndael-cbc@lysator.liu.se")
    local weak_macs=("hmac-md5" "hmac-md5-96" "hmac-sha1-96"
                     "umac-64@openssh.com" "hmac-md5-etm@openssh.com" "hmac-md5-96-etm@openssh.com"
                     "umac-64-etm@openssh.com" "hmac-sha1-96-etm@openssh.com")
    local weak_kex=("diffie-hellman-group1-sha1" "diffie-hellman-group14-sha1"
                    "diffie-hellman-group-exchange-sha1" "gss-gex-sha1-" "gss-group1-sha1-"
                    "gss-group14-sha1-")

    local active_ciphers active_macs active_kex c m k
    active_ciphers=$(_ssh_val ciphers | tr ',' '\n')
    active_macs=$(_ssh_val macs | tr ',' '\n')
    active_kex=$(_ssh_val kexalgorithms | tr ',' '\n')

    local -a crypto_issues=()
    for c in "${weak_ciphers[@]}"; do
        grep -qxF "$c" <<< "$active_ciphers" && crypto_issues+=("Weak cipher active: ${c}")
    done
    for m in "${weak_macs[@]}"; do
        grep -qxF "$m" <<< "$active_macs" && crypto_issues+=("Weak MAC active: ${m}")
    done
    for k in "${weak_kex[@]}"; do
        grep -qF -- "$k" <<< "$active_kex" && crypto_issues+=("Weak KEX active: ${k}")
    done

    if [[ ${#crypto_issues[@]} -gt 0 ]]; then
        ssh_issues+=("Weak crypto algorithms in use (${#crypto_issues[@]} issue(s)) - see note")
        _dropin_lines+="Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"$'\n'
        _dropin_lines+="MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"$'\n'
        _dropin_lines+="KexAlgorithms $(_ssh_kex_list)"$'\n'
    fi

    # Check 11: PermitEmptyPasswords
    if [[ "$(_ssh_val permitemptypasswords)" != "no" ]]; then
        ssh_issues+=("PermitEmptyPasswords is not set to 'no'")
        _dropin_lines+="PermitEmptyPasswords no"$'\n'
        severe=1
    fi

    # Check 12: HostbasedAuthentication
    if [[ "$(_ssh_val hostbasedauthentication)" == "yes" ]]; then
        ssh_issues+=("HostbasedAuthentication is enabled (allows host-trust logins)")
        _dropin_lines+="HostbasedAuthentication no"$'\n'
    fi

    # Check 13: IgnoreRhosts
    if [[ "$(_ssh_val ignorerhosts)" == "no" ]]; then
        ssh_issues+=("IgnoreRhosts is disabled - .rhosts files are honoured (legacy trust risk)")
        _dropin_lines+="IgnoreRhosts yes"$'\n'
    fi

    # Check 14: MaxStartups (CIS: 10:30:60)
    local max_startups max_startups_max
    max_startups=$(_ssh_val maxstartups)
    max_startups_max=$(cut -d: -f3 <<< "${max_startups:-}")
    if [[ ! "$max_startups_max" =~ ^[0-9]+$ ]] || (( max_startups_max > 60 )); then
        ssh_issues+=("MaxStartups is ${max_startups:-unset} (should be 10:30:60)")
        _dropin_lines+="MaxStartups 10:30:60"$'\n'
    fi

    # Check 15: AllowUsers / AllowGroups. Restricting logins to sudo members
    # would lock out deploy, backup and service accounts, so it is manual.
    if ! grep -qE '^(allowusers|allowgroups)[[:space:]]' <<< "$SSHD_CONF"; then
        manual_items+=("No AllowUsers or AllowGroups directive - any valid system user can SSH")
        local _sudo_members
        _sudo_members=$(awk -F: '$1 == "sudo" {gsub(",", " ", $4); print $4}' "${AUDIT_ROOT}/etc/group" 2>/dev/null || true)
        if [[ -n "$_sudo_members" ]]; then
            _allow_users_fix="AllowUsers ${_sudo_members}"
        else
            _allow_users_fix="AllowUsers <add usernames here>"
        fi
    fi

    _report_ssh_settings "$severe" "$_dropin_lines" "$_chmod_fixes" \
        "${ssh_issues[@]+"${ssh_issues[@]}"}" ${crypto_issues[@]+"--crypto"} \
        ${crypto_issues[@]+"${crypto_issues[@]}"}
    _report_ssh_manual "$_allow_users_fix" "${manual_items[@]+"${manual_items[@]}"}"

    local weak_matches
    weak_matches=$(_ssh_weak_match_blocks)
    if [[ -n "$weak_matches" ]]; then
        print_status "WARN" "SSH Match blocks re-enable weak authentication"
        append_report "## SSH Match Blocks\n- 🔴 Match blocks weaken authentication"
        report_issue 8 \
            "SSH Match blocks weaken authentication" \
            "Match blocks turn password, empty-password or root login back on for some connections: $(tr '\n' ';' <<< "$weak_matches")" \
            "# MANUAL: review each Match block below and remove the weakening line
# unless that exception is required, then run: sudo sshd -t && sudo systemctl restart ssh
$(sed 's/^/#   /' <<< "$weak_matches")
# Check what a given connection gets:  sudo sshd -T -C user=<name>,host=<host>,addr=<ip>" \
            0
    fi
    return 0
}

# _report_ssh_settings SEVERE DROPIN_LINES CHMOD_FIXES ISSUE... [--crypto CRYPTO...]
# One finding for the settings the fix can change, written to the tool's
# drop-in. Only failing settings are added, so stricter values set elsewhere
# are never weakened; settings the drop-in already holds from earlier runs
# are kept.
_report_ssh_settings() {
    local severe="$1" dropin_lines="$2" chmod_fixes="$3"
    shift 3
    local -a issues=() crypto=()
    while [[ $# -gt 0 && "$1" != "--crypto" ]]; do issues+=("$1"); shift; done
    [[ "${1:-}" == "--crypto" ]] && { shift; crypto=("$@"); }

    if [[ ${#issues[@]} -eq 0 ]]; then
        print_status "OK" "SSH settings hardened"
        append_report "## SSH Hardening\n- 🟢 All SSH hardening checks passed"
        return 0
    fi
    print_status "WARN" "SSH hardening issues: ${#issues[@]} found"
    append_report "## SSH Hardening\n- 🔴 Weak SSH config (${#issues[@]} issue(s))"

    local dropin="/etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf"
    local kept="" line key
    local -A new_keys=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && new_keys["${line%% *}"]=1
    done <<< "${dropin_lines,,}"
    if [[ -f "${AUDIT_ROOT}${dropin}" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[A-Za-z][A-Za-z0-9]*[[:space:]]+[^[:cntrl:]]+$ ]] || continue
            key="${line%%[[:space:]]*}"
            [[ -n "${new_keys[${key,,}]:-}" || "$line" == SSHEOF* ]] && continue
            kept+="${line}"$'\n'
        done < "${AUDIT_ROOT}${dropin}"
    fi

    local fix="${chmod_fixes}"
    if [[ -n "$dropin_lines" ]]; then
        fix+="sudo /bin/mkdir -p /etc/ssh/sshd_config.d"$'\n'
        fix+="sudo /usr/bin/tee ${dropin} > /dev/null << 'SSHEOF'"$'\n'
        fix+="${kept}${dropin_lines}"
        fix+="SSHEOF"$'\n'
        fix+="sudo /bin/chmod 600 ${dropin}"$'\n'
        fix+="sudo /bin/chown root:root ${dropin}"$'\n'
        fix+="# The drop-in only holds settings that failed, and sorts first so it"$'\n'
        fix+="# wins over later files such as 50-cloud-init.conf. Ensure it is included:"$'\n'
        fix+='grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \'$'\n'
        fix+='  sudo /bin/sed -i '"'"'1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|'"'"' /etc/ssh/sshd_config'$'\n'
    fi
    fix+="# Validate config before restarting:"$'\n'
    fix+="if sudo /usr/sbin/sshd -t 2>&1; then"$'\n'
    fix+="    sudo /bin/systemctl restart ssh"$'\n'
    fix+="    echo '[OK] sshd restarted with hardened config'"$'\n'
    fix+="else"$'\n'
    fix+="    echo '[ERROR] sshd -t failed - NOT restarting. Check ${dropin}'"$'\n'
    fix+="fi"$'\n'
    fix+="# Verify effective config:"$'\n'
    fix+="sudo /usr/sbin/sshd -T 2>/dev/null | grep -E 'permitroot|passwordauth|maxauth|logingrace|x11|clientalive|permitempty|hostbased|ignorerhosts|maxstartups' || true"

    local note
    note="Issues:"$'\n'"$(printf ' - %s\n' "${issues[@]}")"
    note+=$'\n\n'"⚠️ BEFORE disabling PasswordAuthentication: verify working SSH keys from another terminal"
    [[ ${#crypto[@]} -gt 0 ]] && note+=$'\n\n'"Weak crypto:"$'\n'"$(printf ' - %s\n' "${crypto[@]}")"
    # Password, empty-password or root login, SSHv1 and readable host keys
    # are direct paths in; the rest is tuning.
    local points=5
    [[ "$severe" -eq 1 ]] && points=10
    report_issue "$points" \
        "SSH configuration weaknesses found" \
        "SSH daemon is not fully hardened: ${#issues[@]} setting(s) out of compliance" \
        "$fix" \
        0 \
        "$note"
}

# _report_ssh_manual ALLOW_USERS_LINE ITEM... — settings that need a
# person's decision (who may log in, whether forwarding is used).
_report_ssh_manual() {
    local allow_line="$1"
    shift
    [[ $# -gt 0 ]] || return 0
    local fix="# MANUAL: decide who may log in over SSH and whether forwarding is needed.
# Add the lines you choose to /etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf,
# then run: sudo sshd -t && sudo systemctl restart ssh"
    if [[ -n "$allow_line" ]]; then
        fix+="
# Restrict logins. List every account that needs SSH (deploy, backup and
# service users too), not only admins. Suggested from the sudo group:
#   ${allow_line}"
    fi
    if printf '%s\n' "$@" | grep -q AllowTcpForwarding; then
        fix+="
# Unless this host is a jump host or people use port forwarding or VS Code
# Remote-SSH, turn TCP forwarding off:
#   AllowTcpForwarding no"
    fi
    print_status "WARN" "SSH access restrictions need review"
    report_issue 3 \
        "SSH access restrictions need review" \
        "$(printf '%s; ' "$@")" \
        "$fix" \
        0
}
