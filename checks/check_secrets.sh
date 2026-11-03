# shellcheck shell=bash
# check_secrets — standard check (sourced by ubuntu-sec-audit.sh)
#
# The helpers below are also used by the deep checks (check_deep_keys.sh,
# check_deep_world_writable.sh).

# Network filesystems are pruned: walking NFS/CIFS/sshfs homes is slow, can
# hang on an unreachable server, and their files belong to another host.
_NETFS_TYPES=(nfs nfs4 cifs smb3 smbfs ncpfs afs ceph
              fuse.sshfs fuse.glusterfs fuse.s3fs fuse.rclone davfs)

# A PEM private key of any kind: PRIVATE KEY, RSA/EC/DSA/OPENSSH PRIVATE KEY,
# ENCRYPTED PRIVATE KEY, ... Certificates and public keys never match.
_PRIVATE_KEY_RE='^[[:space:]]*-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'

# _netfs_prune_args ARRAY_NAME — set ARRAY_NAME to find(1) arguments that
# prune network filesystems: find START "${a[@]}" <tests> -print
_netfs_prune_args() {
    local -n _out="$1"
    local t
    _out=()
    [[ ${#_NETFS_TYPES[@]} -gt 0 ]] || return 0
    _out=('(')
    for t in "${_NETFS_TYPES[@]}"; do _out+=(-fstype "$t" -o); done
    unset '_out[-1]'
    _out+=(')' -prune -o)
}

# _file_head FILE — the start of FILE, read with a size and time limit: the
# file sits in a directory a user controls and may have been swapped for a
# device or a FIFO since find listed it.
_file_head() {
    timeout 5 head -c 262144 -- "$1" 2>/dev/null || true
}

# _has_private_key FILE — FILE holds a PEM private key.
_has_private_key() {
    grep -qE "$_PRIVATE_KEY_RE" < <(_file_head "$1")
}

# _chmod_fix_line MODE PATH — a remediation line that sets MODE on PATH as
# the owner PATH has now, without following a symlink planted before the
# fix runs (_safe_chmod_cmd). When that cannot be done safely, comment lines
# tell the operator what to change instead.
_chmod_fix_line() {
    local mode="$1" path="$2" owner why
    owner=$(stat -c '%U' -- "$path" 2>/dev/null || true)
    if [[ -n "$owner" && "$owner" != "UNKNOWN" ]]; then
        _safe_chmod_cmd "$owner" "$mode" "$path" && return 0
        why="a user other than root can rename a directory on its path"
    else
        why="its owner has no account"
    fi
    printf '# Not changed by this script (%s) - check it, then run by hand:\n#   sudo chmod %s %s\n' \
        "$why" "$mode" "$(printf '%q' "$path")"
}

check_secrets() {
    print_status "INFO" "Scanning for exposed credentials and secrets..."
    local _issues=() _fix="" _env_found=0
    local _homes=("${AUDIT_ROOT}/home" "${AUDIT_ROOT}/root")
    local -a _prune=()
    _netfs_prune_args _prune

    # _flag_readable FILE MASK LABEL MODE — flag FILE if any MASK bit is set
    # and queue a chmod for exactly that file.
    _flag_readable() {
        local f="$1" mask="$2" label="$3" mode="$4" perms
        perms=$(stat -c '%a' -- "$f" 2>/dev/null || true)
        [[ -n "$perms" ]] || return 0
        if (( (8#$perms & mask) != 0 )); then
            _issues+=("${label}: ${f} (${perms})")
            _fix+=$(_chmod_fix_line "$mode" "$f")$'\n'
        fi
        return 0
    }

    # 1. Private keys readable by group or others, recognised by content:
    #    anything in a .ssh directory, and *.pem/*.key files (which are just
    #    as often public certificates and CA bundles).
    local _f
    while IFS= read -r _f; do
        _has_private_key "$_f" || continue
        _flag_readable "$_f" 8#044 "SSH/TLS private key group/world-readable" 600
    done < <(find "${_homes[@]}" -maxdepth 5 "${_prune[@]}" -type f -perm /044 \
                \( \( -path '*/.ssh/*' ! -name '*.pub' \) -o -name '*.pem' -o -name '*.key' \) \
                -print 2>/dev/null || true)

    # 2. .env files with secret patterns that group or others can read
    while IFS= read -r _f; do
        # An active assignment whose variable name contains a secret word
        # (AWS_SECRET_ACCESS_KEY, DB_PASSWORD, GITHUB_TOKEN_RW, ...).
        if grep -qiE '^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(PASSWORD|PASSWD|SECRET|API_?KEY|ACCESS_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)[A-Za-z0-9_]*[[:space:]]*=' < <(_file_head "$_f"); then
            _env_found=1
            _flag_readable "$_f" 8#044 ".env file with secrets group/world-readable" go-rwx
        fi
    done < <(find "${_homes[@]}" "${AUDIT_ROOT}/etc" "${AUDIT_ROOT}/opt" "${AUDIT_ROOT}/var/www" \
                -maxdepth 4 "${_prune[@]}" -type f -name '.env' -perm /044 -print 2>/dev/null || true)

    # 3. AWS credential files readable by group or others
    while IFS= read -r _f; do
        _flag_readable "$_f" 8#044 "AWS credentials file group/world-readable" 600
    done < <(find "${_homes[@]}" -maxdepth 3 "${_prune[@]}" -type f -path '*/.aws/credentials' \
                -print 2>/dev/null || true)

    # 4. Private keys in /etc/ssl readable by everyone, recognised by content.
    #    ssl-cert-snakeoil.key is 640 (ssl-cert group) on purpose, so only
    #    the world-read bit is flagged and removed.
    while IFS= read -r _f; do
        _has_private_key "$_f" || continue
        _flag_readable "$_f" 8#004 "SSL/TLS private key world-readable" o-r
    done < <(find "${AUDIT_ROOT}/etc/ssl" -maxdepth 3 "${_prune[@]}" -type f -perm -004 \
                -print 2>/dev/null || true)
    unset -f _flag_readable

    if [[ ${#_issues[@]} -gt 0 ]]; then
        print_status "WARN" "Exposed credentials/secrets found (${#_issues[@]} item(s))"
        append_report "## Secrets Exposure\n- 🔴 ${#_issues[@]} exposed credential file(s)"
        if [[ $_env_found -eq 1 ]]; then
            _fix+="# Better still, move plaintext secrets in .env files to a secrets manager
# (Vault, AWS Secrets Manager, ...) and keep them out of version control."
        fi
        report_issue 12 \
            "Exposed credentials or secrets detected" \
            "$(printf '%s\n' "${_issues[@]}")" \
            "$_fix" \
            0
    else
        print_status "OK" "No exposed credentials or secrets detected"
        append_report "## Secrets Exposure\n- 🟢 No group/world-readable private keys, credential files or .env secrets found"
    fi
}
