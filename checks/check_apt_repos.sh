# shellcheck shell=bash
# check_apt_repos — standard check (sourced by ubuntu-sec-audit.sh)

# _apt_insecure_sources FILE... — entries apt actually uses that turn off
# signature checks, one per line: "trusted|insecure<TAB>file:line<TAB>entry".
# One-line files (.list): active deb/deb-src lines whose [ options ] set
# trusted or allow-insecure/allow-weak/allow-downgrade-to-insecure. deb822
# files (.sources): enabled stanzas with the matching fields. Field names
# and boolean values are case-insensitive, as in apt.
_apt_insecure_sources() {
    [[ $# -gt 0 ]] || return 0
    awk -v root="${AUDIT_ROOT}" '
        function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
        function istrue(v)  { v = tolower(trim(v)); return v == "yes" || v == "true" || v == "with" || v == "on" || v == "enable" || v == "1" }
        function isfalse(v) { v = tolower(trim(v)); return v == "no" || v == "false" || v == "without" || v == "off" || v == "disable" || v == "0" }
        function insecure_key(k) { return k == "allow-insecure" || k == "allow-weak" || k == "allow-downgrade-to-insecure" }
        function shown(f) { if (root != "" && index(f, root) == 1) f = substr(f, length(root) + 1); return f }
        # deb822 findings are held until the end of their stanza, because
        # "Enabled: no" may come after them.
        function flush(   i) {
            for (i = 1; i <= npend; i++)
                if (st_enabled) print pend[i]
            npend = 0; st_enabled = 1
        }
        FNR == 1 { flush(); deb822 = (FILENAME ~ /\.sources$/) }
        deb822 {
            if ($0 ~ /^[ \t\r]*$/) { flush(); next }    # stanza separator
            if ($0 ~ /^#/ || $0 ~ /^[ \t]/) next        # comment, continuation
            colon = index($0, ":")
            if (colon == 0) next
            name = tolower(trim(substr($0, 1, colon - 1)))
            value = substr($0, colon + 1)
            if (name == "enabled" && isfalse(value)) st_enabled = 0
            if (name == "trusted" && istrue(value))
                pend[++npend] = "trusted\t" shown(FILENAME) ":" FNR "\t" trim($0)
            if (insecure_key(name) && istrue(value))
                pend[++npend] = "insecure\t" shown(FILENAME) ":" FNR "\t" trim($0)
            next
        }
        {
            line = $0
            sub(/#.*/, "", line)
            line = trim(line)
            if (line !~ /^deb(-src)?[ \t]+\[/) next
            o = index(line, "["); c = index(line, "]")
            if (c <= o) next
            n = split(substr(line, o + 1, c - o - 1), opts, /[ \t]+/)
            t = 0; ins = 0
            for (i = 1; i <= n; i++) {
                eq = index(opts[i], "=")
                if (eq == 0) continue
                k = tolower(substr(opts[i], 1, eq - 1)); v = substr(opts[i], eq + 1)
                if (k == "trusted" && istrue(v)) t = 1
                if (insecure_key(k) && istrue(v)) ins = 1
            }
            if (t)   print "trusted\t"  shown(FILENAME) ":" FNR "\t" line
            if (ins) print "insecure\t" shown(FILENAME) ":" FNR "\t" line
        }
        END { flush() }
    ' "$@" 2>/dev/null || true
}

check_apt_repos() {
    print_status "INFO" "Checking APT repository security..."

    # Only the files apt reads: sources.list, sources.list.d/*.list and
    # sources.list.d/*.sources (not .save, .distUpgrade, ...).
    local -a src_files=()
    local f
    for f in "${AUDIT_ROOT}/etc/apt/sources.list" \
             "${AUDIT_ROOT}/etc/apt/sources.list.d/"*.list \
             "${AUDIT_ROOT}/etc/apt/sources.list.d/"*.sources; do
        [[ -f "$f" ]] && src_files+=("$f")
    done

    local kind where entry n_trusted=0 n_insecure=0 entry_list=""
    while IFS=$'\t' read -r kind where entry; do
        [[ -n "$kind" ]] || continue
        case "$kind" in
            trusted)  n_trusted=$((n_trusted + 1)) ;;
            insecure) n_insecure=$((n_insecure + 1)) ;;
        esac
        entry_list+="#   ${where}: ${entry}"$'\n'
    done < <(_apt_insecure_sources "${src_files[@]+"${src_files[@]}"}")

    local -a repo_issues=()
    [[ $n_trusted -gt 0 ]] && repo_issues+=("${n_trusted} source entr(y/ies) with trusted=yes / Trusted: yes - GPG signature verification bypassed")
    [[ $n_insecure -gt 0 ]] && repo_issues+=("${n_insecure} source entr(y/ies) with allow-insecure/allow-weak/allow-downgrade-to-insecure")

    if [[ ${#repo_issues[@]} -eq 0 ]]; then
        print_status "OK" "APT repository sources appear secure"
        append_report "## APT Repository Security\n- 🟢 No [trusted=yes] or insecure repositories found"
        return 0
    fi

    local issue_list
    issue_list=$(printf ' - %s\n' "${repo_issues[@]}")
    print_status "WARN" "APT repository security issues: ${#repo_issues[@]} found"
    append_report "## APT Repository Security\n- 🔴 ${#repo_issues[@]} insecure repository configuration(s)"
    # Manual: once the option is gone apt refuses the repository until its
    # signing key is installed, and only a person can obtain the right key.
    report_issue 8 \
        "Insecure APT repositories configured" \
        "APT repositories with disabled authentication allow unsigned/malicious packages to install" \
        "# MANUAL: each repository needs its signing key before the option can go.
# For every entry below:
#  1. Get the repository's signing key from its publisher and store it, e.g.
#     /etc/apt/keyrings/<name>.gpg (dearmored if it is ASCII-armored).
#  2. Reference it - one-line format: [signed-by=/etc/apt/keyrings/<name>.gpg];
#     deb822 (.sources): Signed-By: /etc/apt/keyrings/<name>.gpg
#  3. Remove trusted=yes / Trusted: yes and allow-insecure/allow-weak/
#     allow-downgrade-to-insecure (or disable the repository if it is not needed).
# Entries found (file:line):
${entry_list}# Then check that apt verifies every source:
sudo /usr/bin/apt-get update 2>&1 | /bin/grep -E 'NO_PUBKEY|EXPKEYSIG|not signed|insecure' || echo 'Clean'" \
        0 \
        "Issues:\n${issue_list}"
    return 0
}
