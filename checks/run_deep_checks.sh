# shellcheck shell=bash
# run_deep_checks — deep check (sourced by ubuntu-sec-audit.sh)

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
