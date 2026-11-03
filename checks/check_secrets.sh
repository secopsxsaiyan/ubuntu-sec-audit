# shellcheck shell=bash
# check_secrets — standard check (sourced by ubuntu-sec-audit.sh)

check_secrets() {
    print_status "INFO" "Scanning for exposed credentials and secrets..."
    local _issues=()

    # 1. SSH private keys readable by group or world
    while IFS= read -r _keyfile; do
        local _perms
        _perms=$(stat -c '%a' "$_keyfile" 2>/dev/null || true)
        if [[ -n "$_perms" && ( $(( 0${_perms} & 044 )) -ne 0 ) ]]; then
            _issues+=("SSH private key group/world-readable: ${_keyfile} (${_perms})")
        fi
    done < <(find /home /root -maxdepth 4 \( -name 'id_*' ! -name '*.pub' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | grep -v '\.pub$' || true)

    # 2. .env files containing secret patterns
    while IFS= read -r _envfile; do
        if grep -qiE '(PASSWORD|SECRET|API_KEY|AWS_|TOKEN|PRIVATE_KEY)\s*=' "$_envfile" 2>/dev/null; then
            _issues+=(".env file with secrets: ${_envfile}")
        fi
    done < <(find /home /root /etc /opt /var/www -maxdepth 4 -name '.env' 2>/dev/null || true)

    # 3. AWS credential files readable by group or world
    while IFS= read -r _awsfile; do
        local _aperms
        _aperms=$(stat -c '%a' "$_awsfile" 2>/dev/null || true)
        if [[ -n "$_aperms" && $(( 0${_aperms} & 044 )) -ne 0 ]]; then
            _issues+=("AWS credentials file group/world-readable: ${_awsfile} (${_aperms})")
        fi
    done < <(find /home /root -maxdepth 3 -path '*/.aws/credentials' 2>/dev/null || true)

    # 4. Private key files in /etc/ssl readable by world
    # Exclude /etc/ssl/certs/ — public CA certificates there are intentionally world-readable.
    # Files like ssl-cert-snakeoil.key are intentionally mode 640 (ssl-cert group). Only flag world-readable (& 004).
    while IFS= read -r _sslfile; do
        local _sperms
        _sperms=$(stat -c '%a' "$_sslfile" 2>/dev/null || true)
        if [[ -n "$_sperms" && $(( 0${_sperms} & 004 )) -ne 0 ]]; then
            _issues+=("SSL/TLS private key world-readable: ${_sslfile} (${_sperms})")
        fi
    done < <(find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' \( -name '*.key' -o -name '*.pem' \) 2>/dev/null || true)

    if [[ ${#_issues[@]} -gt 0 ]]; then
        local _details
        _details=$(printf '%s\n' "${_issues[@]}")
        print_status "WARN" "Exposed credentials/secrets found (${#_issues[@]} item(s))"
        report_issue 12 \
            "Exposed credentials or secrets detected" \
            "$(printf '%s\n' "${_issues[@]}")" \
            "# Fix SSH key permissions
find /home /root -maxdepth 4 \( -name 'id_*' ! -name '*.pub' -o -name '*.pem' -o -name '*.key' \) -exec chmod 600 {} \;
# Secure AWS credentials
find /home /root -maxdepth 3 -path '*/.aws/credentials' -exec chmod 600 {} \;
# Remove world-read bit from SSL private keys (preserve group read for ssl-cert group)
find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' -name '*.key' -exec chmod o-r {} \;
find /etc/ssl -maxdepth 3 -not -path '/etc/ssl/certs/*' -name '*.pem' -exec chmod o-r {} \;
# Review and remove .env files with plaintext secrets from version control
# Consider using a secrets manager (Vault, AWS Secrets Manager, etc.)" \
            0
    else
        print_status "OK" "No exposed credentials or secrets detected"
        append_report "## Secrets Exposure\n- 🟢 No world/group-readable credential files or .env secrets found"
    fi
}
