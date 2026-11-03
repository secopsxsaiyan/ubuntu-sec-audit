# shellcheck shell=bash
# check_apt_repos — standard check (sourced by ubuntu-sec-audit.sh)

# NEW CHECK: APT repository security (from review doc)
check_apt_repos() {
    print_status "INFO" "Checking APT repository security..."
    local -a repo_issues=()
    local repo_fix=""

    # Legacy one-line format: [trusted=yes]
    local trusted_sources
    trusted_sources=$(grep -rE '\[trusted=yes\]' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$trusted_sources" ]]; then
        repo_issues+=("APT source(s) with [trusted=yes] found - GPG signature verification bypassed")
        repo_fix+="# Remove [trusted=yes] from these sources (shown below):"$'\n'
        while IFS= read -r src_line; do
            repo_fix+="# $src_line"$'\n'
        done <<< "$trusted_sources"
        repo_fix+="# Edit each file and remove the [trusted=yes] attribute"$'\n'
    fi

    # DEB822 format (Ubuntu 22.04+): Trusted: yes
    local deb822_trusted
    deb822_trusted=$(grep -rE '^\s*Trusted\s*:\s*yes' /etc/apt/sources.list.d/ 2>/dev/null || true)
    if [[ -n "$deb822_trusted" ]]; then
        repo_issues+=("DEB822 source(s) with 'Trusted: yes' found - GPG verification bypassed (Ubuntu 22.04+ format)")
        repo_fix+="# Remove 'Trusted: yes' lines from .sources files in /etc/apt/sources.list.d/"$'\n'
        while IFS= read -r src_line; do
            repo_fix+="# $src_line"$'\n'
        done <<< "$deb822_trusted"
    fi

    # Check for sources with allow-insecure (both formats)
    local insecure_sources
    insecure_sources=$(grep -rE 'allow-insecure=yes|allow-weak=yes|allow-downgrade-to-insecure=yes' \
                       /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    # DEB822 equivalent: Allow-Insecure: yes
    local deb822_insecure
    deb822_insecure=$(grep -rE '^\s*Allow-Insecure\s*:\s*yes|^\s*Allow-Weak\s*:\s*yes|^\s*Allow-Downgrade-To-Insecure\s*:\s*yes' \
                      /etc/apt/sources.list.d/ 2>/dev/null || true)
    [[ -n "$deb822_insecure" ]] && insecure_sources+=$'\n'"$deb822_insecure"
    if [[ -n "$insecure_sources" ]]; then
        repo_issues+=("APT source(s) with allow-insecure/allow-weak found")
        repo_fix+="# Remove allow-insecure/allow-weak options from APT sources"$'\n'
    fi

    if [[ ${#repo_issues[@]} -eq 0 ]]; then
        print_status "OK" "APT repository sources appear secure"
        append_report "## APT Repository Security\n- 🟢 No [trusted=yes] or insecure repositories found"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${repo_issues[@]}")
        print_status "WARN" "APT repository security issues: ${#repo_issues[@]} found"
        append_report "## APT Repository Security\n- 🔴 ${#repo_issues[@]} insecure repository configuration(s)"
        repo_fix+="# After changes, verify APT sources:
sudo /usr/bin/apt-get update 2>&1 | /bin/grep -E 'NO_PUBKEY|EXPKEYSIG|not signed|trusted' || echo 'Clean'"
        report_issue 8 \
            "Insecure APT repositories configured" \
            "APT repositories with disabled authentication allow unsigned/malicious packages to install" \
            "$repo_fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
