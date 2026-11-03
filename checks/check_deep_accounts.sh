# shellcheck shell=bash
# check_deep_empty_passwords / _password_aging / _sudo_timeout — deep checks

check_deep_empty_passwords() {
    print_status "INFO" "Checking for empty passwords..."
    local empty_pw user fix
    empty_pw=$(awk -F: '$2=="" {print $1}' "${AUDIT_ROOT}/etc/shadow" 2>/dev/null || true)
    if [[ -z "$empty_pw" ]]; then
        print_status "OK" "No accounts with empty passwords"
        append_report "## Deep: Empty Passwords\n- 🟢 None"
        return 0
    fi
    # Every such account gets its password locked. Only system accounts
    # (0 < UID < UID_MIN) also lose their login shell: root and regular
    # users keep theirs, or "sudo -i", "su -", rescue mode and key-only
    # admin logins would stop working.
    local uid_min uid
    local -A uid_of=()
    uid_min=$(_uid_min)
    while IFS=: read -r user _ uid _; do
        [[ -n "$user" ]] && uid_of["$user"]="$uid"
    done < <(cat "${AUDIT_ROOT}/etc/passwd" 2>/dev/null || true)
    fix="# Lock each account with an empty password immediately:"$'\n'
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        fix+="sudo /usr/bin/passwd -l $(printf '%q' "$user")"$'\n'
        uid="${uid_of[$user]:-}"
        if [[ "$uid" =~ ^[0-9]+$ ]] && (( 10#$uid > 0 && 10#$uid < uid_min )); then
            fix+="sudo /usr/sbin/usermod -s /usr/sbin/nologin $(printf '%q' "$user")"$'\n'
        fi
    done <<< "$empty_pw"
    fix+="sudo /usr/bin/awk -F: '\$2==\"\" {print \$1}' /etc/shadow"
    report_issue 20 \
        "Accounts with empty passwords found" \
        "These accounts have no password set (critical risk)" \
        "$fix" \
        1 \
        "Affected users: $(tr '\n' ' ' <<< "$empty_pw")"
}

check_deep_password_aging() {
    print_status "INFO" "Checking password policy (login.defs)..."
    local max_days
    max_days=$(awk '$1 == "PASS_MAX_DAYS" {print $2; exit}' "${AUDIT_ROOT}/etc/login.defs" 2>/dev/null || true)
    if [[ "$max_days" =~ ^[0-9]+$ ]] && [[ "$max_days" -le 90 ]]; then
        print_status "OK" "PASS_MAX_DAYS is ${max_days}"
        append_report "## Deep: Password Aging\n- 🟢 PASS_MAX_DAYS=${max_days}"
        return 0
    fi
    report_issue 8 \
        "Weak password aging policy" \
        "PASS_MAX_DAYS not set or too high (${max_days:-unset}) in /etc/login.defs" \
        "sudo /bin/sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sudo /bin/sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
/bin/grep '^PASS_' /etc/login.defs
# login.defs only applies to new accounts; for existing ones use, per user:
#   sudo chage --maxdays 90 --mindays 1 --warndays 14 <user>" \
        1
}

# The fix's drop-in. sudo reads /etc/sudoers.d files by name, so this one is
# read after the usual NN-name files and its Defaults wins.
_SUDO_TIMEOUT_DROPIN="zz-ubuntu-sec-audit-timeout"

# _sudo_timeout_settings FILE... — every timestamp_timeout a Defaults line
# sets, in parse order: "SCOPE<TAB>MINUTES<TAB>FILE:LINE". SCOPE is
# "Defaults" for the global setting, or the qualified form (Defaults:alice,
# Defaults@host, Defaults>root, Defaults!cmd), which sudo applies after the
# global ones. "!timestamp_timeout" means 0. Comment lines (including the
# #include/#includedir directives, which set nothing) are skipped.
_sudo_timeout_settings() {
    [[ $# -gt 0 ]] || return 0
    awk '
        FNR == 1 { cont = "" }
        {
            line = $0
            if (cont != "") { line = cont " " line } else { start = FNR }
            if (line ~ /\\$/) { cont = substr(line, 1, length(line) - 1); next }
            cont = ""
            sub(/^[ \t]+/, "", line)
            if (line !~ /^Defaults([:@>!][^ \t]*)?[ \t]/) next
            sub(/[ \t]+#([^0-9].*)?$/, "", line)
            match(line, /^Defaults[^ \t]*/)
            scope = substr(line, 1, RLENGTH)
            n = split(substr(line, RLENGTH + 1), opt, ",")
            for (i = 1; i <= n; i++) {
                o = opt[i]
                gsub(/^[ \t]+|[ \t]+$/, "", o)
                if (o ~ /^![ \t]*timestamp_timeout$/) {
                    v = "0"
                } else if (o ~ /^timestamp_timeout[ \t]*=/) {
                    v = o
                    sub(/^timestamp_timeout[ \t]*=[ \t]*/, "", v)
                    gsub(/"/, "", v)
                    if (v !~ /^-?[0-9]+(\.[0-9]+)?$/) continue
                } else {
                    continue
                }
                print scope "\t" v "\t" FILENAME ":" start
            }
        }' "$@" 2>/dev/null || true
}

# _sudo_timeout_ok MINUTES — 0 to 15 (a negative value never expires).
_sudo_timeout_ok() {
    awk -v v="$1" 'BEGIN { exit !(v + 0 >= 0 && v + 0 <= 15) }'
}

check_deep_sudo_timeout() {
    print_status "INFO" "Checking sudo password timeout..."
    # Defaults apply in parse order and the last one wins: /etc/sudoers,
    # then the sudoers.d files sudo reads, by name. Per-user/host/runas/
    # command Defaults apply after the global ones. Unset means sudo's
    # built-in default of 15 minutes, which complies.
    local -a files=() rows=()
    mapfile -t files < <(_sudoers_files)
    mapfile -t rows < <(_sudo_timeout_settings "${files[@]}")

    local row scope val loc global="" global_loc=""
    local -A scoped=() scoped_loc=()
    for row in "${rows[@]}"; do
        IFS=$'\t' read -r scope val loc <<< "$row"
        loc="${loc#"${AUDIT_ROOT}"}"
        if [[ "$scope" == "Defaults" ]]; then
            global="$val"
            global_loc="$loc"
        else
            scoped["$scope"]="$val"
            scoped_loc["$scope"]="$loc"
        fi
    done

    local global_bad=0 bad_scoped="" bad_scoped_fix="" entry
    if [[ -n "$global" ]] && ! _sudo_timeout_ok "$global"; then
        global_bad=1
    fi
    for scope in "${!scoped[@]}"; do
        if ! _sudo_timeout_ok "${scoped[$scope]}"; then
            entry="${scoped_loc[$scope]}: ${scope} timestamp_timeout=${scoped[$scope]}"
            bad_scoped+="${entry} "
            bad_scoped_fix+="#   ${entry}"$'\n'
        fi
    done

    if [[ $global_bad -eq 0 && -z "$bad_scoped" ]]; then
        print_status "OK" "sudo timeout is ${global:-the default (15)} minutes"
        append_report "## Deep: Sudo Timeout\n- 🟢 ${global:-15} minutes"
        return 0
    fi

    local fix="" desc=""
    local dropin="/etc/sudoers.d/${_SUDO_TIMEOUT_DROPIN}"
    if [[ $global_bad -eq 1 ]]; then
        desc="Timeout is ${global} minutes (set in ${global_loc}; should be 0-15)"
        fix="# sudo reads /etc/sudoers, then /etc/sudoers.d by file name, and the last
# Defaults wins: install a drop-in that is read last, after visudo accepts it.
if _t=\$(/bin/mktemp); then
    echo 'Defaults timestamp_timeout=5' > \"\$_t\"
    /bin/chmod 0440 \"\$_t\"
    if sudo /usr/sbin/visudo -cf \"\$_t\"; then
        sudo /usr/bin/install -o root -g root -m 0440 \"\$_t\" ${dropin}
    else
        echo 'visudo rejected the new drop-in; nothing was installed' >&2
    fi
    /bin/rm -f \"\$_t\"
fi
"
        local gfile="${global_loc%:*}" base last
        base="${gfile##*/}"
        if [[ "$gfile" == /etc/sudoers.d/* && "$base" != "$_SUDO_TIMEOUT_DROPIN" ]]; then
            last=$(printf '%s\n' "$base" "$_SUDO_TIMEOUT_DROPIN" | LC_ALL=C sort | tail -n 1)
            if [[ "$last" == "$base" ]]; then
                fix+="# ${gfile} is read after the drop-in: lower or remove its"$'\n'
                fix+="# timestamp_timeout by hand:  sudo visudo -f ${gfile}"$'\n'
            fi
        fi
    else
        fix="# MANUAL: the global timeout is fine; the Defaults below override it."$'\n'
    fi
    if [[ -n "$bad_scoped" ]]; then
        desc+="${desc:+; }these Defaults override it for some users, hosts or commands: ${bad_scoped}"
        fix+="# Per-user/host/command Defaults win over the global one. Lower (0-15) or"$'\n'
        fix+="# remove these by hand with  sudo visudo -f <file>:"$'\n'
        fix+="$bad_scoped_fix"
    fi
    fix+="# Verify:
sudo /usr/sbin/visudo -c"
    report_issue 5 \
        "Sudo password timeout too long" \
        "$desc" \
        "$fix" \
        1
}
