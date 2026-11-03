# shellcheck shell=bash
# check_unattended — standard check (sourced by ubuntu-sec-audit.sh)

# _apt_conf_files — the APT configuration files in the order apt reads them
# (apt.conf(5)): apt.conf.d parts sorted by name, then apt.conf. Parts with
# characters other than [A-Za-z0-9_.-] or an extension other than .conf
# (.dpkg-old, .save, ...) are ignored by apt, so they are skipped here too.
_apt_conf_files() {
    local f base
    local -a parts=()
    for f in "${AUDIT_ROOT}/etc/apt/apt.conf.d/"*; do
        [[ -f "$f" ]] || continue
        base="${f##*/}"
        [[ "$base" =~ ^[A-Za-z0-9_.-]+$ ]] || continue
        [[ "$base" != *.* || "$base" == *.conf ]] || continue
        parts+=("$base")
    done
    if [[ ${#parts[@]} -gt 0 ]]; then
        while IFS= read -r base; do
            printf '%s\n' "${AUDIT_ROOT}/etc/apt/apt.conf.d/${base}"
        done < <(printf '%s\n' "${parts[@]}" | LC_ALL=C sort)
    fi
    if [[ -f "${AUDIT_ROOT}/etc/apt/apt.conf" ]]; then
        printf '%s\n' "${AUDIT_ROOT}/etc/apt/apt.conf"
    fi
    return 0
}

# _apt_conf_unattended FILE... — the effective unattended-upgrades settings
# of the given apt.conf files, read in order. Prints:
#   periodic<TAB>VALUE<TAB>FILE   APT::Periodic::Unattended-Upgrade (last wins)
#   origin<TAB>ITEM               each Unattended-Upgrade::Allowed-Origins item
#   pattern<TAB>ITEM              each Unattended-Upgrade::Origins-Pattern item
# Understands the apt.conf syntax: "//", "#" and "/* */" comments, nested
# scopes (APT { Periodic { ... }; };), list items in scopes or appended with
# "Name:: value;", unquoted values, case-insensitive names, and #clear.
_apt_conf_unattended() {
    [[ $# -gt 0 ]] || return 0
    awk -v root="${AUDIT_ROOT}" '
        function shown(f) { if (root != "" && index(f, root) == 1) f = substr(f, length(root) + 1); return f }
        function key_of(t) { return tolower(depth > 0 ? scope[depth] "::" t : t) }
        function under(full, k) { return full == k || index(full, k "::") == 1 }
        function add_item(k, item) {
            if (k == "unattended-upgrade::allowed-origins") origins[++norig] = item
            else if (k == "unattended-upgrade::origins-pattern") patterns[++npat] = item
        }
        function set_value(k, v) {
            if (k == "apt::periodic::unattended-upgrade") {
                periodic = v; periodic_set = 1; periodic_file = shown(FILENAME)
            }
        }
        function clear_key(k) {
            if (under("apt::periodic::unattended-upgrade", k)) periodic_set = 0
            if (under("unattended-upgrade::allowed-origins", k)) norig = 0
            if (under("unattended-upgrade::origins-pattern", k)) npat = 0
        }
        function end_statement(   k) {
            if (tag != "") {
                k = key_of(tag)
                if (substr(k, length(k) - 1) == "::") {
                    if (hasval) add_item(substr(k, 1, length(k) - 2), val)
                } else if (hasval) {
                    set_value(k, val)
                }
            } else if (hasval && depth > 0) {
                add_item(tolower(scope[depth]), val)
            }
            tag = ""; val = ""; hasval = 0
        }
        function word_done(w) {
            if (clearing) { clear_key(key_of(w)); clearing = 0; return }
            if (tag == "" && !hasval) tag = w
            else if (!hasval) { val = w; hasval = 1 }
        }
        FNR == 1 { depth = 0; tag = ""; val = ""; hasval = 0; incomment = 0; clearing = 0 }
        {
            line = $0; n = length(line); i = 1; word = ""
            while (i <= n) {
                c = substr(line, i, 1)
                if (incomment) {
                    if (substr(line, i, 2) == "*/") { incomment = 0; i += 2 } else i++
                    continue
                }
                two = substr(line, i, 2)
                if (two == "/*" || two == "//" || c == "#" || c == "\"" || c == "{" || c == "}" || c == ";" \
                    || c == " " || c == "\t" || c == "\r") {
                    if (word != "") { word_done(word); word = "" }
                } else {
                    word = word c; i++
                    continue
                }
                if (two == "/*") { incomment = 1; i += 2; continue }
                if (two == "//") break
                if (c == "#") {
                    if (substr(line, i, 6) == "#clear") { clearing = 1; i += 6; continue }
                    break                       # comment (or #include, not followed)
                }
                if (c == "\"") {
                    rest = substr(line, i + 1); j = index(rest, "\"")
                    if (j == 0) { s = rest; i = n + 1 } else { s = substr(rest, 1, j - 1); i += j + 1 }
                    if (!hasval) { val = s; hasval = 1 }
                    continue
                }
                if (c == "{") {
                    scope[depth + 1] = (depth > 0 ? scope[depth] "::" tag : tag)
                    depth++
                    tag = ""; val = ""; hasval = 0
                } else if (c == "}") {
                    end_statement()
                    if (depth > 0) depth--
                } else if (c == ";") {
                    clearing = 0
                    end_statement()
                }
                i++
            }
            if (word != "") word_done(word)
        }
        END {
            if (periodic_set) print "periodic\t" periodic "\t" periodic_file
            for (i = 1; i <= norig; i++) print "origin\t" origins[i]
            for (i = 1; i <= npat; i++) print "pattern\t" patterns[i]
        }
    ' "$@" 2>/dev/null || true
}

# _apt_config_dump_unattended — the same records as _apt_conf_unattended,
# from "apt-config dump" on stdin: apt's effective configuration, with every
# file it reads (#include too).
_apt_config_dump_unattended() {
    awk '{
        k = tolower($1); v = $0
        sub(/^[^ \t]+[ \t]+/, "", v); sub(/;[ \t]*$/, "", v); gsub(/^"|"$/, "", v)
        if (k == "apt::periodic::unattended-upgrade") print "periodic\t" v "\t"
        else if (k == "unattended-upgrade::allowed-origins::") print "origin\t" v
        else if (k == "unattended-upgrade::origins-pattern::") print "pattern\t" v
    }' || true
}

# _uu_is_security_origin KIND ITEM — ITEM (an Allowed-Origins "origin:archive"
# or an Origins-Pattern) allows Ubuntu's main -security pocket. ESM pockets
# (-apps-security, -infra-security) alone do not cover the main archive.
_uu_is_security_origin() {
    local item="${2,,}"
    local origin_re='^(\$\{distro_id\}|ubuntu):(\$\{distro_codename\}|[a-z]+)-security$'
    local pattern_re='(^|,)(a|archive|suite)=(\$\{distro_codename\}|[a-z]+)-security(,|$)'
    case "$1" in
        origin)  [[ "$item" =~ $origin_re ]] ;;
        pattern) [[ "$item" =~ $pattern_re ]] ;;
        *)       return 1 ;;
    esac
}

check_unattended() {
    print_status "INFO" "Checking unattended-upgrades..."
    if ! dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
        print_status "WARN" "Unattended-upgrades missing"
        append_report "## Automatic Updates\n- 🔴 Not installed"
        report_issue 8 \
            "Automatic security updates disabled" \
            "unattended-upgrades package is not installed" \
            "sudo /usr/bin/apt-get install -y unattended-upgrades
sudo /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'AUTOEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"7\";
APT::Periodic::Unattended-Upgrade \"1\";
AUTOEOF
sudo systemctl enable --now unattended-upgrades" \
            0
        return 0
    fi

    # Effective settings: on the live system apt's own view (apt-config
    # dump: every file apt reads, #include too); under AUDIT_ROOT, or without
    # apt-config, apt.conf.d (in apt's order) and apt.conf parsed here.
    local -a conf_files=()
    local settings
    if [[ -z "${AUDIT_ROOT}" ]] && command -v apt-config >/dev/null 2>&1; then
        settings=$(apt-config dump 2>/dev/null | _apt_config_dump_unattended)
    else
        mapfile -t conf_files < <(_apt_conf_files)
        settings=$(_apt_conf_unattended "${conf_files[@]+"${conf_files[@]}"}")
    fi
    local kind value file periodic="" periodic_file="" has_security=0
    while IFS=$'\t' read -r kind value file; do
        case "$kind" in
            periodic) periodic="$value"; periodic_file="$file" ;;
            origin|pattern) _uu_is_security_origin "$kind" "$value" && has_security=1 ;;
        esac
    done <<< "$settings"

    local -a uu_issues=()
    if [[ "$periodic" != "1" ]]; then
        uu_issues+=("APT::Periodic::Unattended-Upgrade is \"${periodic:-unset}\"${periodic_file:+ (last set in ${periodic_file})} - unattended-upgrades does not run daily")
    fi
    if [[ $has_security -eq 0 ]]; then
        uu_issues+=("No -security origin allowed in Unattended-Upgrade::Allowed-Origins or Origins-Pattern - security updates are not installed")
    fi

    if [[ ${#uu_issues[@]} -eq 0 ]]; then
        print_status "OK" "Unattended-upgrades installed and enabled for security"
        append_report "## Automatic Updates\n- 🟢 Enabled"
        return 0
    fi

    # 20auto-upgrades is where Debian/Ubuntu keep the setting; a file apt
    # reads later would still override it.
    local override_note=""
    if [[ "$periodic" != "1" && -n "$periodic_file" \
          && "$periodic_file" != "/etc/apt/apt.conf.d/20auto-upgrades" ]]; then
        local last
        last=$(printf '%s\n' "${periodic_file##*/}" "20auto-upgrades" | LC_ALL=C sort | tail -n 1)
        if [[ "$periodic_file" == "/etc/apt/apt.conf" || "$last" != "20auto-upgrades" ]]; then
            override_note="
# NOTE: ${periodic_file} is read after 20auto-upgrades and sets
# APT::Periodic::Unattended-Upgrade \"${periodic}\"; change it there as well."
        fi
    fi

    local issue_list
    issue_list=$(printf ' - %s\n' "${uu_issues[@]}")
    print_status "WARN" "Unattended-upgrades not configured for security updates"
    append_report "## Automatic Updates\n- 🔴 Security updates not enabled"
    report_issue 8 \
        "Automatic security updates disabled" \
        "unattended-upgrades installed but security updates not enabled" \
        "sudo /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'AUTOEOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"7\";
APT::Periodic::Unattended-Upgrade \"1\";
AUTOEOF
# Append security origin using :: (apt.conf list-append syntax) — avoids editing 50unattended-upgrades
sudo /usr/bin/tee /etc/apt/apt.conf.d/51-security-origins.conf > /dev/null << 'ORIGEOF'
Unattended-Upgrade::Allowed-Origins:: \"\${distro_id}:\${distro_codename}-security\";
Unattended-Upgrade::Allowed-Origins:: \"\${distro_id}ESMApps:\${distro_codename}-apps-security\";
ORIGEOF
sudo systemctl enable --now unattended-upgrades${override_note}
# Verify (prints the effective value):
apt-config dump APT::Periodic::Unattended-Upgrade" \
        0 \
        "Issues:\n${issue_list}"
    return 0
}
