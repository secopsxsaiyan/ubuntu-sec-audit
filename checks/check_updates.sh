# shellcheck shell=bash
# check_updates — standard check (sourced by ubuntu-sec-audit.sh)
#
# Pending updates that are NOT security updates; those are counted (and
# scored) by check_security_updates, so one pending security update is not
# charged twice.

check_updates() {
    print_status "INFO" "Checking package updates..."
    if ! command -v apt-get >/dev/null 2>&1; then
        append_report "## Package Updates\n- ⚪ apt-get not available - not checked"
        _mark_skipped "apt-get not available"
        return 0
    fi
    if [[ $SKIP_APT_UPDATE -eq 0 ]]; then
        apt-get update -qq || print_status "WARN" "apt-get update failed - using the cached package index"
    else
        print_status "INFO" "Skipping apt-get update (--skip-apt-update set)"
    fi

    # apt-get's simulation applies phasing, so phased updates that apt holds
    # back on purpose are not counted ("apt list --upgradable" lists them).
    # Inst lines from a -security pocket belong to check_security_updates.
    local sim pkgs count
    sim=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null || true)
    pkgs=$(awk '/^Inst / && !/-security/ {print $2}' <<< "$sim" | sort -u)
    count=$(grep -c . <<< "$pkgs" || true)

    if [[ "$count" -eq 0 ]]; then
        print_status "OK" "No pending non-security updates"
        append_report "## Package Updates\n- 🟢 Up-to-date (security updates: see Security Updates)"
        return 0
    fi

    print_status "WARN" "${count} package(s) have pending updates"
    append_report "## Package Updates\n- 🟡 ${count} package(s) with pending (non-security) updates"
    # --with-new-pkgs: also install new dependencies (as "apt upgrade" does),
    # so e.g. kernel updates are not held back. Nothing is removed.
    report_issue 6 \
        "System not fully patched" \
        "${count} package(s) have pending updates that are not security updates (those are reported by check_security_updates)" \
        "sudo /usr/bin/apt-get update
sudo /usr/bin/apt-get upgrade -y --with-new-pkgs
# Re-check (non-security updates still pending):
apt-get -s upgrade | grep '^Inst ' | grep -vc -- '-security' || true" \
        0 \
        "Packages: $(head -n 30 <<< "$pkgs" | tr '\n' ' ')- reboot if the kernel or libc was upgraded; 'apt-get autoremove' (not run) removes packages no longer needed"
    return 0
}
