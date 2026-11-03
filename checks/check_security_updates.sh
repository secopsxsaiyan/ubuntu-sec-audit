# shellcheck shell=bash
# check_security_updates — standard check (sourced by ubuntu-sec-audit.sh)
#
# Replaces check_debsecan: debsecan reads Debian's security tracker, which
# has no data for Ubuntu releases. apt's own simulation shows which pending
# upgrades come from the -security pocket, i.e. fix published CVEs.

check_security_updates() {
    print_status "INFO" "Checking for pending security updates..."
    if ! command -v apt-get >/dev/null 2>&1; then
        print_status "INFO" "apt-get not available - skipping security update check"
        append_report "## Security Updates\n- ⚪ apt-get not available"
        return 0
    fi

    local sim pkgs count
    sim=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null || true)
    pkgs=$(awk '/^Inst / && /-security/ {print $2}' <<< "$sim" | sort -u)
    count=$(grep -c . <<< "$pkgs" || true)

    if [[ "$count" -eq 0 ]]; then
        print_status "OK" "No pending security updates"
        append_report "## Security Updates\n- 🟢 No pending security updates"
        return 0
    fi

    local pkg_args="" p
    while IFS= read -r p; do
        [[ "$p" =~ ^[a-z0-9][a-z0-9.+:-]*$ ]] && pkg_args+=" $(printf '%q' "$p")"
    done <<< "$pkgs"

    print_status "WARN" "${count} package(s) have pending security updates"
    append_report "## Security Updates\n- 🔴 ${count} package(s) with pending security updates"
    report_issue 10 \
        "Security updates pending" \
        "${count} package(s) have pending security updates (fixes for published CVEs)" \
        "sudo /usr/bin/apt-get update
if command -v unattended-upgrade >/dev/null 2>&1; then
    # Applies only the origins unattended-upgrades allows (security by default)
    sudo unattended-upgrade -v
else
    sudo /usr/bin/apt-get install --only-upgrade -y${pkg_args}
fi
# Re-check:
apt-get -s dist-upgrade | grep -c '^Inst .*-security' || true" \
        0 \
        "Packages: $(head -n 30 <<< "$pkgs" | tr '\n' ' ')"
}
