# shellcheck shell=bash
# check_ssh — standard check (sourced by ubuntu-sec-audit.sh)

check_ssh() {
    print_status "INFO" "Checking SSH hardening (extended)..."
    if ! command -v sshd >/dev/null 2>&1; then
        print_status "OK" "SSH not installed"
        return
    fi

    local sshd_conf
    sshd_conf=$(sudo sshd -T 2>/dev/null)

    local -a ssh_issues=()
    local _dropin_lines=""   # directives written to /etc/ssh/sshd_config.d/99-hardening.conf
    local _chmod_fixes=""    # permission fixes that cannot go in a drop-in
    local _allow_users_fix=""

    # Check 1: PermitRootLogin
    if ! grep -qE 'permitrootlogin (no|prohibit-password)' <<< "$sshd_conf"; then
        ssh_issues+=("PermitRootLogin is not set to 'no' or 'prohibit-password'")
        _dropin_lines+="PermitRootLogin prohibit-password"$'\n'
    fi

    # Check 2: PasswordAuthentication
    if ! grep -qE 'passwordauthentication no' <<< "$sshd_conf"; then
        ssh_issues+=("PasswordAuthentication is enabled")
        _dropin_lines+="PasswordAuthentication no"$'\n'
        _dropin_lines+="PubkeyAuthentication yes"$'\n'
    fi

    # Check 3: MaxAuthTries (CIS: ≤ 4)
    local max_auth_tries
    max_auth_tries=$(awk '/^maxauthtries / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$max_auth_tries" || "$max_auth_tries" -gt 4 ]]; then
        ssh_issues+=("MaxAuthTries is ${max_auth_tries:-unset} (should be ≤ 4)")
        _dropin_lines+="MaxAuthTries 4"$'\n'
    fi

    # Check 4: LoginGraceTime (CIS: ≤ 60 seconds)
    local grace_time
    grace_time=$(awk '/^logingracetime / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$grace_time" || "$grace_time" -eq 0 || "$grace_time" -gt 60 ]]; then
        ssh_issues+=("LoginGraceTime is ${grace_time:-unset} (should be 1–60 seconds)")
        _dropin_lines+="LoginGraceTime 60"$'\n'
    fi

    # Check 5: X11Forwarding
    if grep -qE 'x11forwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("X11Forwarding is enabled (unnecessary attack surface)")
        _dropin_lines+="X11Forwarding no"$'\n'
    fi

    # Check 6: AllowTcpForwarding
    if grep -qE 'allowtcpforwarding yes' <<< "$sshd_conf"; then
        ssh_issues+=("AllowTcpForwarding is enabled (can tunnel unauthorised traffic)")
        _dropin_lines+="AllowTcpForwarding no"$'\n'
    fi

    # Check 7: ClientAlive settings
    local client_interval
    client_interval=$(awk '/^clientaliveinterval / {print $2}' <<< "$sshd_conf" | head -1)
    if [[ -z "$client_interval" || "$client_interval" -eq 0 ]]; then
        ssh_issues+=("ClientAliveInterval is 0 (no idle session timeout)")
        _dropin_lines+="ClientAliveInterval 300"$'\n'
        _dropin_lines+="ClientAliveCountMax 2"$'\n'
    fi

    # Check 8: SSHv1 (only relevant on very old OpenSSH; directive removed in 7.4+)
    if grep -qE '^protocol\s+.*\b1\b' <<< "$sshd_conf"; then
        ssh_issues+=("SSHv1 is enabled - cryptographically broken")
        _dropin_lines+="Protocol 2"$'\n'
    fi

    # Check 9: SSH host private key permissions (must be 600 root:root)
    while IFS= read -r keyfile; do
        local kperms kowner
        kperms=$(stat -c '%a' "$keyfile" 2>/dev/null || true)
        kowner=$(stat -c '%U' "$keyfile" 2>/dev/null || true)
        if [[ "$kperms" != "600" || "$kowner" != "root" ]]; then
            ssh_issues+=("Host private key ${keyfile}: perms=${kperms:-?}, owner=${kowner:-?} (should be 600 root)")
            _chmod_fixes+="sudo /bin/chmod 600 $(printf '%q' "$keyfile")"$'\n'
            _chmod_fixes+="sudo /bin/chown root:root $(printf '%q' "$keyfile")"$'\n'
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

    local -a crypto_issues=()
    for c in "${weak_ciphers[@]}"; do
        grep -qxF "$c" <<< "$active_ciphers" && crypto_issues+=("Weak cipher active: ${c}")
    done
    for m in "${weak_macs[@]}"; do
        grep -qxF "$m" <<< "$active_macs" && crypto_issues+=("Weak MAC active: ${m}")
    done
    for k in "${weak_kex[@]}"; do
        echo "$active_kex" | grep -q "^${k}" && crypto_issues+=("Weak KEX active: ${k}")
    done

    if [[ ${#crypto_issues[@]} -gt 0 ]]; then
        ssh_issues+=("Weak crypto algorithms in use (${#crypto_issues[@]} issue(s)) - see note")
        _dropin_lines+="Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"$'\n'
        _dropin_lines+="MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"$'\n'
        _dropin_lines+="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"$'\n'
    fi

    # Check 11: PermitEmptyPasswords
    if ! grep -qE 'permitemptypasswords no' <<< "$sshd_conf"; then
        ssh_issues+=("PermitEmptyPasswords is not explicitly set to 'no'")
        _dropin_lines+="PermitEmptyPasswords no"$'\n'
    fi

    # Check 12: HostbasedAuthentication
    if grep -qE 'hostbasedauthentication yes' <<< "$sshd_conf"; then
        ssh_issues+=("HostbasedAuthentication is enabled (allows host-trust logins)")
        _dropin_lines+="HostbasedAuthentication no"$'\n'
    fi

    # Check 13: IgnoreRhosts
    if grep -qE 'ignorerhosts no' <<< "$sshd_conf"; then
        ssh_issues+=("IgnoreRhosts is disabled - .rhosts files are honoured (legacy trust risk)")
        _dropin_lines+="IgnoreRhosts yes"$'\n'
    fi

    # Check 14: MaxStartups (CIS: 10:30:60)
    local max_startups max_startups_max
    max_startups=$(awk '/^maxstartups / {print $2}' <<< "$sshd_conf" | head -1)
    max_startups_max=$(echo "${max_startups:-}" | cut -d: -f3)
    if [[ -z "$max_startups" || -z "$max_startups_max" || "$max_startups_max" -gt 60 ]]; then
        ssh_issues+=("MaxStartups is ${max_startups:-unset} (should be 10:30:60)")
        _dropin_lines+="MaxStartups 10:30:60"$'\n'
    fi

    # Check 15: AllowUsers / AllowGroups — detect actual admin users from sudo group
    if ! grep -qE '^(allowusers|allowgroups)\s' <<< "$sshd_conf"; then
        ssh_issues+=("No AllowUsers or AllowGroups directive - any valid system user can SSH")
        local _sudo_members
        _sudo_members=$(getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' ' ' | xargs)
        if [[ -n "$_sudo_members" ]]; then
            _allow_users_fix="AllowUsers ${_sudo_members}"
        else
            _allow_users_fix="# AllowUsers <add usernames here>"
        fi
    fi

    if [[ ${#ssh_issues[@]} -eq 0 ]]; then
        print_status "OK" "SSH fully hardened (all extended checks passed)"
        append_report "## SSH Hardening\n- 🟢 All SSH hardening checks passed"
    else
        print_status "WARN" "SSH hardening issues: ${#ssh_issues[@]} found"
        local issue_list
        issue_list=$(printf ' - %s\n' "${ssh_issues[@]}")
        append_report "## SSH Hardening\n- 🔴 Weak SSH config (${#ssh_issues[@]} issue(s))"

        # Build fix: always write COMPLETE drop-in with ALL hardening directives.
        # Writing only failing-check directives causes regressions on re-run:
        # previously-applied settings would be overwritten and lost.
        local ssh_fixes=""
        [[ -n "$_chmod_fixes" ]] && ssh_fixes+="${_chmod_fixes}"

        ssh_fixes+="sudo /bin/mkdir -p /etc/ssh/sshd_config.d"$'\n'
        ssh_fixes+="sudo /usr/bin/tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null << 'SSHEOF'"$'\n'
        ssh_fixes+="PermitRootLogin prohibit-password"$'\n'
        ssh_fixes+="PasswordAuthentication no"$'\n'
        ssh_fixes+="PubkeyAuthentication yes"$'\n'
        ssh_fixes+="MaxAuthTries 4"$'\n'
        ssh_fixes+="LoginGraceTime 60"$'\n'
        ssh_fixes+="X11Forwarding no"$'\n'
        ssh_fixes+="AllowTcpForwarding no"$'\n'
        ssh_fixes+="ClientAliveInterval 300"$'\n'
        ssh_fixes+="ClientAliveCountMax 2"$'\n'
        ssh_fixes+="PermitEmptyPasswords no"$'\n'
        ssh_fixes+="HostbasedAuthentication no"$'\n'
        ssh_fixes+="IgnoreRhosts yes"$'\n'
        ssh_fixes+="MaxStartups 10:30:60"$'\n'
        ssh_fixes+="Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"$'\n'
        ssh_fixes+="MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"$'\n'
        ssh_fixes+="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"$'\n'
        ssh_fixes+="SSHEOF"$'\n'
        ssh_fixes+="sudo /bin/chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf"$'\n'
        ssh_fixes+="sudo /bin/chown root:root /etc/ssh/sshd_config.d/99-hardening.conf"$'\n'
        ssh_fixes+="# Ensure Include directive exists (Ubuntu 22.04+ has this by default):"$'\n'
        ssh_fixes+='grep -q "^Include /etc/ssh/sshd_config.d" /etc/ssh/sshd_config || \'$'\n'
        ssh_fixes+='  sudo /bin/sed -i '"'"'1s|^|Include /etc/ssh/sshd_config.d/*.conf\n|'"'"' /etc/ssh/sshd_config'$'\n'

        if [[ -n "$_allow_users_fix" ]]; then
            ssh_fixes+="# Restrict SSH access to sudo group members:"$'\n'
            ssh_fixes+="grep -q '^AllowUsers' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || \\"$'\n'
            ssh_fixes+="  echo '${_allow_users_fix}' | sudo /usr/bin/tee -a /etc/ssh/sshd_config.d/99-hardening.conf"$'\n'
        fi

        ssh_fixes+="# Validate config before restarting:"$'\n'
        ssh_fixes+="if sudo /usr/sbin/sshd -t 2>&1; then"$'\n'
        ssh_fixes+="    sudo /bin/systemctl restart ssh"$'\n'
        ssh_fixes+="    echo '[OK] sshd restarted with hardened config'"$'\n'
        ssh_fixes+="else"$'\n'
        ssh_fixes+="    echo '[ERROR] sshd -t failed - NOT restarting. Check /etc/ssh/sshd_config.d/99-hardening.conf'"$'\n'
        ssh_fixes+="fi"$'\n'
        ssh_fixes+="# Verify effective config:"$'\n'
        ssh_fixes+="sudo /usr/sbin/sshd -T 2>/dev/null | grep -E 'permitroot|passwordauth|maxauth|logingrace|x11|tcpforward|clientalive|permitempty|hostbased|ignorerhosts|maxstartups|allowusers|allowgroups' || true"

        local combined_note="Issues:\n${issue_list}\n\nAlso consider Fail2Ban or key-only auth"
        combined_note+=$'\n\n⚠️ BEFORE disabling PasswordAuthentication: verify working SSH keys from another terminal'
        [[ ${#crypto_issues[@]} -gt 0 ]] && combined_note+=$'\n\nWeak crypto:\n'"$(printf ' - %s\n' "${crypto_issues[@]}")"
        report_issue 10 \
            "SSH configuration weaknesses found" \
            "SSH daemon is not fully hardened: ${#ssh_issues[@]} setting(s) out of compliance" \
            "$ssh_fixes" \
            0 \
            "$combined_note"
    fi
}
