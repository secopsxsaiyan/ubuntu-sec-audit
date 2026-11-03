# shellcheck shell=bash
# check_debsecan — standard check (sourced by ubuntu-sec-audit.sh)

check_debsecan() {
    print_status "INFO" "Checking for known CVEs in installed packages (debsecan)..."
    if ! command -v debsecan >/dev/null 2>&1; then
        print_status "WARN" "debsecan not installed"
        append_report "## CVE Exposure (debsecan)\n- 🔴 debsecan not installed"
        report_issue 5 \
            "debsecan not installed" \
            "No automated CVE check against installed packages - known vulnerabilities may go undetected" \
            "sudo /usr/bin/apt-get install -y debsecan
# Run CVE scan (fetches current Debian/Ubuntu vuln data):
sudo /usr/bin/debsecan --suite \$(lsb_release -cs) --format detail --only-fixed
# List only packages with available fixes:
sudo /usr/bin/debsecan --suite \$(lsb_release -cs) --only-fixed" \
            0 \
            "debsecan queries the Debian Security Tracker (open-source) to find CVEs affecting installed packages"
        return
    fi

    print_status "INFO" "Running debsecan (may take a moment to fetch CVE data)..."
    local suite
    suite=$(lsb_release -cs 2>/dev/null || echo "")
    if [[ -z "$suite" ]]; then
        print_status "INFO" "Cannot determine Ubuntu codename - skipping debsecan"
        append_report "## CVE Exposure (debsecan)\n- ⚪ Could not determine Ubuntu suite"
        return
    fi

    local fixable_cves
    fixable_cves=$(timeout 60 sudo debsecan --suite "$suite" --only-fixed 2>/dev/null | grep -c '.' || echo "0")

    if [[ "$fixable_cves" -eq 0 ]]; then
        print_status "OK" "debsecan: no CVEs with available fixes found"
        append_report "## CVE Exposure (debsecan)\n- 🟢 No fixable CVEs detected by debsecan"
    else
        print_status "WARN" "debsecan: ${fixable_cves} fixable CVE(s) found in installed packages"
        append_report "## CVE Exposure (debsecan)\n- 🔴 ${fixable_cves} fixable CVE(s) detected - run 'apt upgrade'"
        report_issue 10 \
            "Installed packages have fixable CVEs" \
            "${fixable_cves} CVE(s) with available fixes detected by debsecan" \
            "sudo /usr/bin/apt-get update && sudo /usr/bin/apt-get upgrade -y
# Re-check after upgrading:
sudo /usr/bin/debsecan --suite $(lsb_release -cs) --only-fixed" \
            0 \
            "Run 'debsecan --suite \$(lsb_release -cs) --format detail --only-fixed' to see CVE details"
    fi
}
