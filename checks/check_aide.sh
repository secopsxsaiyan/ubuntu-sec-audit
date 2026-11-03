# shellcheck shell=bash
# check_aide — standard check (sourced by ubuntu-sec-audit.sh)

# Shared remediation: build the baseline without prompts (-y overwrite,
# -f force) and schedule a check (Ubuntu's timer if present, else cron).
_AIDE_INIT_FIX="# Building the baseline can take 10-30 minutes on large systems.
sudo /usr/sbin/aideinit -y -f
[ -f /var/lib/aide/aide.db.new ] && sudo /bin/cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
if systemctl list-unit-files dailyaidecheck.timer >/dev/null 2>&1; then
    sudo /bin/systemctl enable --now dailyaidecheck.timer
else
    echo '0 5 * * 0 root /usr/bin/aide --config /etc/aide/aide.conf --check' | sudo /usr/bin/tee /etc/cron.d/aide-check
fi"

check_aide() {
    print_status "INFO" "Checking AIDE file integrity monitoring..."
    if ! command -v aide >/dev/null 2>&1; then
        print_status "WARN" "AIDE not installed"
        append_report "## AIDE File Integrity\n- 🔴 AIDE not installed"
        report_issue 8 \
            "AIDE not installed" \
            "No file integrity monitoring in place - unauthorized changes to system files go undetected" \
            "sudo /usr/bin/apt-get install -y aide aide-common
${_AIDE_INIT_FIX}" \
            0 \
            "AIDE detects unauthorized modifications to binaries, configs, and libraries"
        return
    fi

    local aide_issues=()

    # Check database initialised
    if [[ ! -f "${AUDIT_ROOT}/var/lib/aide/aide.db" && ! -f "${AUDIT_ROOT}/var/lib/aide/aide.db.gz" ]]; then
        aide_issues+=("AIDE database not initialised - run 'aideinit' to create baseline")
    fi

    # Check a cron job or systemd timer schedules AIDE checks
    local aide_scheduled=0
    grep -rqE 'aide([[:space:]].*)?[[:space:]](--check|-C)' \
        "${AUDIT_ROOT}"/etc/cron* "${AUDIT_ROOT}/var/spool/cron" 2>/dev/null && aide_scheduled=1
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
            "$_AIDE_INIT_FIX" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
