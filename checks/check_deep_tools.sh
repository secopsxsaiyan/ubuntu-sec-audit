# shellcheck shell=bash
# Deep checks that drive external scanners: debsums, rkhunter, ClamAV,
# auditd rules and Lynis. Each is skipped (not passed) when its tool is
# missing. Logs are kept in the report directory.

check_deep_debsums() {
    if ! command -v debsums >/dev/null 2>&1; then
        _mark_skipped "debsums not installed"
        append_report "## Deep: Package Integrity (debsums)\n- ℹ️ Skipped (not installed)"
        return 0
    fi
    print_status "INFO" "Running debsums integrity check..."
    local log pkgs pkg_args="" pkg
    log=$(mktemp "${REPORT_DIR}/debsums-audit-XXXXXX.log")
    debsums -c > "$log" 2>&1 || true
    if [[ ! -s "$log" ]]; then
        print_status "OK" "debsums: all package files match their checksums"
        append_report "## Deep: Package Integrity (debsums)\n- 🟢 No modified package files"
        return 0
    fi
    pkgs=$(awk '{print $1}' "$log" | xargs -r dpkg -S 2>/dev/null | cut -d: -f1 | tr ',' '\n' \
           | sed 's/^[[:space:]]*//' | sort -u | grep -E '^[a-z0-9][a-z0-9.+-]+$' || true)
    while IFS= read -r pkg; do
        [[ -n "$pkg" ]] && pkg_args+=" $pkg"
    done <<< "$pkgs"
    local fix
    if [[ -n "$pkg_args" ]]; then
        fix="# Reinstall packages with modified files to restore the originals:
sudo /usr/bin/apt-get install --reinstall -y${pkg_args}"
    else
        fix="# Could not resolve packages automatically - run manually:
#   sudo debsums -c
#   dpkg -S <file>   # find each file's package
#   sudo apt-get install --reinstall <package>"
    fi
    fix+=$'\n'"sudo /usr/bin/debsums -c   # re-verify after reinstall"
    report_issue 12 \
        "Package files modified (integrity violation)" \
        "System files differ from package checksums - possible tampering" \
        "$fix" \
        1 \
        "Full output: $log"
    append_report "##### debsums - Modified/Failed Files\n\`\`\`\n$(head -n 100 "$log")\n\`\`\`"
}

check_deep_rkhunter() {
    if ! command -v rkhunter >/dev/null 2>&1; then
        _mark_skipped "rkhunter not installed"
        append_report "## Deep: Rootkit Scan (rkhunter)\n- ℹ️ Skipped (not installed)"
        return 0
    fi
    print_status "INFO" "Running rkhunter rootkit scan..."
    local log warnings count
    log=$(mktemp "${REPORT_DIR}/rkhunter-audit-XXXXXX.log")
    rkhunter --update --quiet >/dev/null 2>&1 || true
    rkhunter --check --skip-keypress --quiet --logfile "$log" >/dev/null 2>&1 || true
    # Only rkhunter's own "Warning:" lines; test names such as "Rootkit
    # checks" or "Suspect files" appear in every log.
    warnings=$(grep -E '^(\[[0-9:]+\][[:space:]]+)?Warning:' "$log" 2>/dev/null || true)
    count=$(grep -c . <<< "$warnings" || true)
    if [[ "$count" -eq 0 ]]; then
        print_status "OK" "rkhunter: no warnings"
        append_report "## Deep: Rootkit Scan (rkhunter)\n- 🟢 No warnings"
        return 0
    fi
    # The fix never runs --propupd: that would accept the current (possibly
    # compromised) state as the new baseline.
    report_issue 18 \
        "rkhunter detected warnings / suspicious items" \
        "${count} rkhunter warning(s): possible rootkits, hidden files, or modified binaries" \
        "# Investigate each warning in the log before changing anything:
#   sudo less ${log}
# Package updates also change file properties: compare with dpkg -V <package>.
# Only once you are sure the system is clean, accept the new state with:
#   sudo rkhunter --propupd" \
        1 \
        "Full log: $log"
    append_report "##### rkhunter - Warnings\n\`\`\`\n${warnings}\n\`\`\`"
}

check_deep_clamav() {
    if ! command -v clamscan >/dev/null 2>&1; then
        _mark_skipped "ClamAV not installed"
        append_report "## Deep: Antivirus Scan (ClamAV)\n- ℹ️ Skipped (not installed)"
        return 0
    fi
    print_status "INFO" "Updating ClamAV virus definitions..."
    if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
        print_status "OK" "clamav-freshclam service is active - definitions auto-updated"
    elif timeout 120 freshclam --quiet >/dev/null 2>&1; then
        print_status "OK" "ClamAV definitions updated"
    else
        print_status "WARN" "freshclam update timed out or failed - scanning with existing definitions"
        report_issue 3 \
            "ClamAV virus definitions may be outdated" \
            "freshclam could not update - log file locked or network issue; definitions may be stale" \
            "# Enable automatic updates via the service (preferred):
sudo /bin/systemctl enable --now clamav-freshclam
# Verify:
sudo /usr/bin/freshclam --version" \
            1
    fi

    print_status "INFO" "Running targeted ClamAV scan (critical directories only)..."
    local log rc=0 r
    local -a targets=()
    log=$(mktemp "${REPORT_DIR}/clamav-audit-XXXXXX.log")
    for r in /home /root /tmp /var /etc /usr/bin /usr/sbin /bin /sbin; do
        [[ -e "${AUDIT_ROOT}${r}" ]] && targets+=("${AUDIT_ROOT}${r}")
    done
    timeout 1800 clamscan -r -i --exclude-dir='^/proc' --exclude-dir='^/sys' --exclude-dir='^/dev' \
        "${targets[@]}" > "$log" 2>&1 || rc=$?

    # No summary means the scan was killed (timeout, out of memory) or never
    # started: that is not a clean result.
    if ! grep -q 'Infected files:' "$log"; then
        report_issue 5 \
            "ClamAV scan did not complete" \
            "clamscan exited with status ${rc} before printing its summary (timeout or out of memory?) - the system was not fully scanned" \
            "# Re-run the scan by hand and watch for errors (needs ~2-3 GiB of RAM):
#   sudo clamscan -r -i /home /root /tmp /var /etc /usr/bin /usr/sbin
# Log of the failed run: ${log}" \
            1
        return 0
    fi

    local infected_count
    infected_count=$(grep -oP 'Infected files: \K\d+' "$log" | head -n 1)
    if [[ "${infected_count:-0}" -eq 0 ]]; then
        print_status "OK" "ClamAV: no infected files"
        append_report "## Deep: Antivirus Scan (ClamAV)\n- 🟢 No infected files"
        return 0
    fi

    local infected_lines fpath clam_fix
    infected_lines=$(grep ' FOUND$' "$log" || true)
    clam_fix="# Create a private quarantine directory:"$'\n'
    clam_fix+="QUARANTINE_DIR=\$(sudo /bin/mktemp -d /var/clam-quarantine-XXXXXX)"$'\n'
    clam_fix+="sudo /bin/chmod 700 \"\$QUARANTINE_DIR\""$'\n'
    clam_fix+="# Move each infected file to quarantine:"$'\n'
    while IFS= read -r found_line; do
        fpath="${found_line%%: *}"
        clam_fix+="sudo /usr/bin/clamscan --move=\"\$QUARANTINE_DIR\" $(printf '%q' "$fpath")"$'\n'
    done <<< "$infected_lines"
    clam_fix+="# Review quarantined files before deleting them one by one:"$'\n'
    clam_fix+="sudo /bin/ls -lah \"\$QUARANTINE_DIR\""
    report_issue 25 \
        "ClamAV detected infected/malware files" \
        "Live malware or viruses found on the system (critical - act immediately)" \
        "$clam_fix" \
        1 \
        "Full scan log: $log"
    append_report "##### ClamAV - Infected Files Found (${infected_count} total)\n\`\`\`\n${infected_lines}\n\`\`\`"
}

check_deep_auditd_rules() {
    if ! command -v auditctl >/dev/null 2>&1; then
        _mark_skipped "auditd not installed"
        append_report "## Deep: auditd\n- ℹ️ Skipped (not installed)"
        return 0
    fi
    local audit_rules rule_count
    audit_rules=$(auditctl -l 2>/dev/null || true)
    rule_count=$(grep -cE '^-[aw]' <<< "$audit_rules" || true)
    if [[ "${rule_count:-0}" -ge 1 ]]; then
        print_status "OK" "auditd has ${rule_count} rule(s) loaded"
        append_report "## Deep: auditd Rules\n- 🟢 ${rule_count} rule(s) loaded"
        return 0
    fi
    print_status "WARN" "auditd has no meaningful rules loaded"
    append_report "## Deep: auditd Rules\n- 🔴 auditd running with empty/default ruleset"
    report_issue 5 \
        "auditd running with no rules loaded" \
        "auditd has no rules defined - suspicious activity is not captured" \
        "sudo /usr/bin/tee /etc/audit/rules.d/99-hardening.rules > /dev/null << 'AUDITEOF'
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
# Failed access to /etc (glibc opens files with openat)
-a always,exit -F arch=b64 -S open -S openat -F dir=/etc -F success=0 -k unauth_access
AUDITEOF
sudo /usr/sbin/augenrules --load
# Verify rules loaded:
sudo /sbin/auditctl -l" \
        1
}

check_deep_lynis() {
    if ! command -v lynis >/dev/null 2>&1; then
        _mark_skipped "lynis not installed"
        append_report "## Deep: Lynis System Audit\n- ℹ️ Skipped (not installed)"
        return 0
    fi
    print_status "INFO" "Running Lynis system audit..."
    local log rep warnings count
    log=$(mktemp "${REPORT_DIR}/lynis-audit-XXXXXX.log")
    rep=$(mktemp "${REPORT_DIR}/lynis-report-XXXXXX.dat")
    lynis audit system --quiet --no-colors --report-file "$rep" --logfile "$log" >/dev/null 2>&1 || true
    # Lynis' warnings are the warning[] entries of its report file; the word
    # WARNING also shows up in normal log and console output.
    warnings=$(grep -E '^warning\[\]=' "$rep" 2>/dev/null | cut -d= -f2- | awk -F'|' '{print $1 ": " $2}' || true)
    count=$(grep -c . <<< "$warnings" || true)
    if [[ "$count" -eq 0 ]]; then
        print_status "OK" "Lynis: no warnings (suggestions are in ${rep})"
        append_report "## Deep: Lynis\n- 🟢 No warnings; suggestions in ${rep}"
        return 0
    fi
    report_issue 15 \
        "Lynis reported ${count} warning(s)" \
        "Lynis warnings:"$'\n'"${warnings}" \
        "# Each warning has a test id; see its explanation with:
#   lynis show details <TEST-ID>
# Report file (all warnings and suggestions): ${rep}
# Full log: ${log}" \
        1 \
        "Report file: ${rep}"
}
