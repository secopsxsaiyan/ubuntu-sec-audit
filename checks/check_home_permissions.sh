# shellcheck shell=bash
# check_home_permissions — standard check (sourced by ubuntu-sec-audit.sh)

# _home_accounts — "user:uid:home" for root and regular users (UID 0, or at
# or above UID_MIN except nobody), in /etc/passwd order.
_home_accounts() {
    local min
    min=$(_uid_min)
    awk -F: -v min="$min" '($3 == 0 || ($3 >= min && $3 != 65534)) && $6 != "" {print $1 ":" $3 ":" $6}' \
        "${AUDIT_ROOT}/etc/passwd" 2>/dev/null || true
}

# _home_private_path HOME UID — true if HOME is where a personal home lives:
# /root for UID 0, or a directory below /home. Anything else (/home itself,
# /tmp, /var/www, /srv/..., /opt/...) may be shared with a service or with
# other users, so its mode is left to a person.
_home_private_path() {
    local home="$1" uid="$2"
    [[ "$home" == *"/.."* ]] && return 1
    if [[ "$uid" == 0 ]]; then
        [[ "$home" == /root || "$home" == /root/ ]]
        return
    fi
    [[ "$home" == /home/?* ]]
}

check_home_permissions() {
    print_status "INFO" "Checking home directory permissions..."
    local -a home_issues=() homes=()
    local -A accts_of=() uid_of=()
    local home_fix="" manual_fix="" uid_min user uid home
    uid_min=$(_uid_min)

    # A home listed for several accounts is checked once, as a shared one.
    while IFS=: read -r user uid home; do
        [[ -z "${accts_of[$home]:-}" ]] && homes+=("$home")
        accts_of["$home"]+="${accts_of[$home]:+, }${user}"
        uid_of["$home"]="$uid"
    done < <(_home_accounts)

    local dir perms owner_uid accts problem why line who
    for home in "${homes[@]}"; do
        [[ "$home" == "/" ]] && continue
        dir="${AUDIT_ROOT}${home}"
        [[ -d "$dir" ]] || continue
        perms=$(stat -L -c '%a' -- "$dir" 2>/dev/null || true)
        owner_uid=$(stat -L -c '%u' -- "$dir" 2>/dev/null || true)
        [[ -z "$perms" ]] && continue
        accts="${accts_of[$home]}"
        uid="${uid_of[$home]}"
        # Others should have no access; group-writable is also a problem.
        if (( (8#$perms & 8#007) != 0 )); then
            problem="others have access"
        elif (( (8#$perms & 8#020) != 0 )); then
            problem="group-writable"
        else
            continue
        fi
        home_issues+=("${home} (${accts}): perms=${perms} - ${problem}")

        # Only a personal home owned by its own account is changed, and then
        # as that account (runuser), never through a symlink. Anything else
        # may be a service's directory (/var/www) or shared (/tmp, /home), so
        # a person decides.
        why=""
        if [[ "$accts" == *", "* ]]; then
            why="the home of several accounts"
        elif [[ -L "$dir" ]]; then
            why="a symlink; check its target"
        elif [[ "$owner_uid" != "$uid" ]]; then
            why="owned by UID ${owner_uid}, not by ${accts} (UID ${uid})"
        elif (( (8#$perms & 8#1000) != 0 )); then
            why="a sticky (shared) directory"
        elif ! _home_private_path "$home" "$uid"; then
            why="not below /home, so a service or other users may need it"
        fi
        line=""
        if [[ -z "$why" ]]; then
            who="$accts"
            [[ "$uid" == 0 ]] && who="root"
            line=$(_safe_chmod_cmd "$who" "g-w,o-rwx" "$home") || line=""
            [[ -z "$line" ]] && why="a directory on its path can be changed by other users"
        fi
        if [[ -n "$line" ]]; then
            home_fix+="${line}"$'\n'
        else
            manual_fix+="#   ${home} (${accts}): ${why}"$'\n'
        fi
    done

    if [[ ${#home_issues[@]} -eq 0 ]]; then
        print_status "OK" "Home directory permissions are secure"
        append_report "## Home Directory Permissions\n- 🟢 All home directories are properly restricted"
    else
        local issue_list fix=""
        issue_list=$(printf ' - %s\n' "${home_issues[@]}")
        print_status "WARN" "Home directory permission issues: ${#home_issues[@]} found"
        append_report "## Home Directory Permissions\n- 🔴 ${#home_issues[@]} home dir(s) with insecure permissions"
        if [[ -z "$home_fix" ]]; then
            fix="# MANUAL: none of these homes is changed automatically."$'\n'
        fi
        fix+="$home_fix"
        if [[ -n "$manual_fix" ]]; then
            fix+="# Not changed automatically - check what uses each directory first:"$'\n'
            fix+="$manual_fix"
            fix+="#   then, if nothing else needs access:  sudo chmod g-w,o-rwx <dir>"$'\n'
        fi
        fix+="# Verify after fixing:
awk -F: '\$3 == 0 || \$3 >= ${uid_min} {print \$6}' /etc/passwd | xargs -r stat -c '%n %a %U' 2>/dev/null || true"
        report_issue 6 \
            "Home directories have insecure permissions" \
            "Home directories accessible by other users - may expose SSH keys, config files, credentials" \
            "$fix" \
            0 \
            "Issues:\n${issue_list}"
    fi
}
