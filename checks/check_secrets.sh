# shellcheck shell=bash
# check_secrets — standard check (sourced by ubuntu-sec-audit.sh)

check_secrets() {
    print_status "INFO" "Scanning for exposed credentials and secrets..."
    local _issues=() _fix=""
    local _homes=("${AUDIT_ROOT}/home" "${AUDIT_ROOT}/root")

    # _flag_readable FILE MASK LABEL MODE — flag FILE if any MASK bit is set
    # and queue a chmod for exactly that file.
    _flag_readable() {
        local f="$1" mask="$2" label="$3" mode="$4" perms
        perms=$(stat -c '%a' "$f" 2>/dev/null || true)
        [[ -n "$perms" ]] || return 0
        if (( (8#$perms & mask) != 0 )); then
            _issues+=("${label}: ${f} (${perms})")
            _fix+="sudo /bin/chmod ${mode} $(printf '%q' "$f")"$'\n'
        fi
    }

    # 1. Private keys readable by group or others: id_* only inside .ssh
    #    directories (elsewhere it is just a file name), *.pem/*.key anywhere.
    local _f
    while IFS= read -r _f; do
        _flag_readable "$_f" 8#044 "SSH/TLS private key group/world-readable" 600
    done < <(find "${_homes[@]}" -maxdepth 5 -type f \
                \( \( -path '*/.ssh/*' -name 'id_*' ! -name '*.pub' \) -o -name '*.pem' -o -name '*.key' \) \
                2>/dev/null || true)

    # 2. .env files containing secret patterns
    while IFS= read -r _f; do
        if grep -qiE '(PASSWORD|SECRET|API_KEY|AWS_|TOKEN|PRIVATE_KEY)[[:space:]]*=' "$_f" 2>/dev/null; then
            _issues+=(".env file with secrets: ${_f}")
        fi
    done < <(find "${_homes[@]}" "${AUDIT_ROOT}/etc" "${AUDIT_ROOT}/opt" "${AUDIT_ROOT}/var/www" \
                -maxdepth 4 -type f -name '.env' 2>/dev/null || true)

    # 3. AWS credential files readable by group or others
    while IFS= read -r _f; do
        _flag_readable "$_f" 8#044 "AWS credentials file group/world-readable" 600
    done < <(find "${_homes[@]}" -maxdepth 3 -type f -path '*/.aws/credentials' 2>/dev/null || true)

    # 4. Private keys in /etc/ssl readable by everyone. /etc/ssl/certs holds
    #    public certificates; ssl-cert-snakeoil.key is 640 (ssl-cert group) on
    #    purpose, so only the world-read bit is flagged and removed.
    while IFS= read -r _f; do
        _flag_readable "$_f" 8#004 "SSL/TLS private key world-readable" o-r
    done < <(find "${AUDIT_ROOT}/etc/ssl" -maxdepth 3 -type f -not -path '*/etc/ssl/certs/*' \
                \( -name '*.key' -o -name '*.pem' \) 2>/dev/null || true)
    unset -f _flag_readable

    if [[ ${#_issues[@]} -gt 0 ]]; then
        print_status "WARN" "Exposed credentials/secrets found (${#_issues[@]} item(s))"
        append_report "## Secrets Exposure\n- 🔴 ${#_issues[@]} exposed credential file(s)"
        _fix+="# Move plaintext secrets in .env files to a secrets manager (Vault,
# AWS Secrets Manager, ...) and keep them out of version control."
        report_issue 12 \
            "Exposed credentials or secrets detected" \
            "$(printf '%s\n' "${_issues[@]}")" \
            "$_fix" \
            0
    else
        print_status "OK" "No exposed credentials or secrets detected"
        append_report "## Secrets Exposure\n- 🟢 No world/group-readable credential files or .env secrets found"
    fi
}
