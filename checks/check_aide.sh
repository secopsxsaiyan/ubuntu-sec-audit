# shellcheck shell=bash
# check_aide — standard check (sourced by ubuntu-sec-audit.sh)

# Build the baseline without prompts (-y overwrite, -f force), but only when
# there is none: rebuilding an existing baseline would silently accept every
# change made since it was taken.
_AIDE_INIT_FIX="# Building the baseline can take 10-30 minutes on large systems.
# It records the current state as trusted: build it on a known-good system.
if [ ! -f /var/lib/aide/aide.db ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
    sudo /usr/sbin/aideinit -y -f
    if [ ! -f /var/lib/aide/aide.db ] && [ -f /var/lib/aide/aide.db.new ]; then
        sudo /bin/cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
else
    echo 'An AIDE baseline already exists - left unchanged'
fi"

# Turn on aide-common's daily check: dailyaidecheck.timer where the unit
# exists (22.04+), else its cron.daily job (20.04); a cron entry only when
# neither is installed. The baseline is never touched.
_AIDE_SCHEDULE_FIX="# Enable aide-common's daily integrity check (the baseline is not changed).
if /bin/systemctl cat dailyaidecheck.timer >/dev/null 2>&1; then
    sudo /bin/systemctl enable --now dailyaidecheck.timer
elif [ -f /etc/cron.daily/dailyaidecheck ]; then
    sudo /bin/chmod 755 /etc/cron.daily/dailyaidecheck
elif [ -f /etc/cron.daily/aide ]; then
    sudo /bin/chmod 755 /etc/cron.daily/aide
else
    echo '0 5 * * * root /usr/bin/aide --config /etc/aide/aide.conf --check' | sudo /usr/bin/tee /etc/cron.d/aide-check > /dev/null
fi"

# _aide_scheduled — true when something runs AIDE checks automatically.
_aide_scheduled() {
    local d f timer_unit=0 cron_hits
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ -f "${AUDIT_ROOT}${d}/dailyaidecheck.timer" ]] && timer_unit=1
    done
    if [[ $timer_unit -eq 1 ]]; then
        # aide-common's cron.daily job exits early on systemd hosts and
        # leaves the work to the timer, so only the timer counts.
        systemctl is-enabled --quiet dailyaidecheck.timer 2>/dev/null && return 0
    else
        for f in "${AUDIT_ROOT}/etc/cron.daily/aide" "${AUDIT_ROOT}/etc/cron.daily/dailyaidecheck"; do
            [[ -f "$f" && -x "$f" ]] && return 0
        done
    fi
    # Any other cron entry or active timer that runs a check.
    cron_hits=$(grep -rlE 'aide([[:space:]].*)?[[:space:]](--check|-C)' \
        "${AUDIT_ROOT}"/etc/cron* "${AUDIT_ROOT}/var/spool/cron" 2>/dev/null \
        | grep -vE '/etc/cron\.daily/(aide|dailyaidecheck)$' || true)
    [[ -n "$cron_hits" ]] && return 0
    systemctl list-timers 2>/dev/null | grep -qi aide && return 0
    return 1
}

check_aide() {
    print_status "INFO" "Checking AIDE file integrity monitoring..."
    if ! command -v aide >/dev/null 2>&1; then
        print_status "WARN" "AIDE not installed"
        append_report "## AIDE File Integrity\n- 🔴 AIDE not installed"
        # --no-install-recommends: aide-common recommends a mailer, which
        # pulls in a mail server (default-mta).
        report_issue 8 \
            "AIDE not installed" \
            "No file integrity monitoring in place - unauthorized changes to system files go undetected" \
            "sudo /usr/bin/apt-get install -y --no-install-recommends aide aide-common
${_AIDE_INIT_FIX}
${_AIDE_SCHEDULE_FIX}" \
            0 \
            "AIDE detects unauthorized modifications to binaries, configs, and libraries"
        return 0
    fi

    local aide_ok=1

    if [[ ! -f "${AUDIT_ROOT}/var/lib/aide/aide.db" && ! -f "${AUDIT_ROOT}/var/lib/aide/aide.db.gz" ]]; then
        aide_ok=0
        print_status "WARN" "AIDE database not initialised"
        append_report "## AIDE File Integrity\n- 🔴 AIDE database not initialised"
        report_issue 5 \
            "AIDE database not initialised" \
            "AIDE is installed but has no baseline database - nothing is compared, so no change is detected" \
            "$_AIDE_INIT_FIX" \
            0 \
            "The baseline records the current state as trusted; build it only on a system you trust"
    fi

    if ! _aide_scheduled; then
        aide_ok=0
        print_status "WARN" "No scheduled AIDE check found"
        append_report "## AIDE File Integrity\n- 🔴 No scheduled AIDE check"
        report_issue 3 \
            "AIDE integrity checks not scheduled" \
            "No scheduled AIDE check found - file integrity is not checked automatically" \
            "$_AIDE_SCHEDULE_FIX" \
            0 \
            "The existing baseline is kept; review the daily check's report for changes"
    fi

    if [[ $aide_ok -eq 1 ]]; then
        print_status "OK" "AIDE installed, database present, and check is scheduled"
        append_report "## AIDE File Integrity\n- 🟢 AIDE installed, database initialised, scheduled check present"
    fi
    return 0
}
