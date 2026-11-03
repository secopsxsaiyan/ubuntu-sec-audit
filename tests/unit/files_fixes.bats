#!/usr/bin/env bats
# File-scanning checks: secrets, user SSH keys, world-writable paths,
# SUID/SGID binaries, debsums, and the tools deep mode offers to install.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
    # main() runs the checks with pipefail on; so do these tests.
    set -o pipefail
}

KEY_OPENSSH="-----BEGIN OPENSSH PRIVATE KEY-----"
KEY_RSA="-----BEGIN RSA PRIVATE KEY-----"
CERT=$'-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----'

# run_chmod_lines REMEDIATION — run the remediation's executable chmod lines
# as the fix script would (as root; sudo is a pass-through).
run_chmod_lines() {
    local lines
    lines=$(executable_lines <<< "$1" | grep chmod || true)
    PATH="$ORIG_PATH" bash -c "sudo() { \"\$@\"; }; ${lines}" || true
}

# every_chmod_is_safe REMEDIATION — each executable chmod line comes from
# _safe_chmod_cmd: guarded against a symlink, never a bare "sudo chmod".
every_chmod_is_safe() {
    local line n=0
    while IFS= read -r line; do
        n=$((n + 1))
        [[ "$line" == "[ -L "*" ] || sudo "*"chmod "*" -- "* ]] || { echo "unsafe: $line" >&2; return 1; }
    done < <(executable_lines <<< "$1" | grep chmod || true)
    [ "$n" -gt 0 ]
}

# ---- secrets: private keys are recognised by content ---------------------

@test "secrets: a public CA bundle named *.pem is not a private key" {
    fixture /root/.ccr/system-trust.ca.pem "$CERT"
    fixture /home/alice/certs/chain.pem "$CERT"
    fixture /home/alice/certs/server.key "$CERT"
    chmod 644 "$AUDIT_ROOT/root/.ccr/system-trust.ca.pem" "$AUDIT_ROOT/home/alice/certs/chain.pem" \
        "$AUDIT_ROOT/home/alice/certs/server.key"
    _run_check check_secrets
    refute_issue "Exposed credentials"
    [ "${CHECK_STATUS[check_secrets]}" = "satisfied" ]
}

@test "secrets: private keys are found by their PEM header, whatever their name" {
    fixture /home/alice/tls/server.key "$KEY_RSA"
    fixture /home/alice/tls/bundle.pem "${CERT}"$'\n'"-----BEGIN EC PRIVATE KEY-----"
    fixture /home/alice/tls/pkcs8.pem "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    fixture /home/alice/.ssh/deploy_key "$KEY_OPENSSH"
    fixture /home/alice/.ssh/id_rsa.pub "ssh-rsa AAAAB3NzaC1yc2E alice@host"
    fixture /home/alice/.ssh/id_notes "which key goes where"
    chmod 640 "$AUDIT_ROOT/home/alice/tls/server.key"
    chmod 644 "$AUDIT_ROOT/home/alice/tls/bundle.pem" "$AUDIT_ROOT/home/alice/.ssh/deploy_key" \
        "$AUDIT_ROOT/home/alice/.ssh/id_rsa.pub" "$AUDIT_ROOT/home/alice/.ssh/id_notes"
    chmod 604 "$AUDIT_ROOT/home/alice/tls/pkcs8.pem"
    _run_check check_secrets
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"tls/server.key"* ]]
    [[ "$d" == *"tls/bundle.pem"* ]]
    [[ "$d" == *"tls/pkcs8.pem"* ]]
    [[ "$d" == *".ssh/deploy_key"* ]]
    [[ "$d" != *"id_rsa.pub"* ]]
    [[ "$d" != *"id_notes"* ]]
}

@test "secrets: /etc/ssl private keys are found by content; certificates are not" {
    fixture /etc/ssl/private/site.pem "-----BEGIN PRIVATE KEY-----"
    fixture /etc/ssl/private/ssl-cert-snakeoil.key "-----BEGIN PRIVATE KEY-----"
    fixture /etc/ssl/site-chain.pem "$CERT"
    fixture /etc/ssl/site.key "$CERT"
    chmod 644 "$AUDIT_ROOT/etc/ssl/private/site.pem" "$AUDIT_ROOT/etc/ssl/site-chain.pem" "$AUDIT_ROOT/etc/ssl/site.key"
    chmod 640 "$AUDIT_ROOT/etc/ssl/private/ssl-cert-snakeoil.key"
    _run_check check_secrets
    local d r
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/etc/ssl/private/site.pem"* ]]
    [[ "$d" != *"site-chain.pem"* ]]
    [[ "$d" != *"/etc/ssl/site.key"* ]]
    [[ "$d" != *"snakeoil"* ]]
    r=$(remediation_for "Exposed credentials")
    [[ "$r" == *"chmod o-r -- ${AUDIT_ROOT}/etc/ssl/private/site.pem"* ]]
}

# ---- secrets: .env files -------------------------------------------------

@test "secrets: a .env file with secrets that only its owner can read passes" {
    fixture /home/alice/app/.env "API_KEY=abc123"
    fixture /opt/svc/.env "PASSWORD=hunter2"
    chmod 600 "$AUDIT_ROOT/home/alice/app/.env" "$AUDIT_ROOT/opt/svc/.env"
    _run_check check_secrets
    refute_issue "Exposed credentials"
}

@test "secrets: a readable .env file is fixed with chmod, and then passes" {
    fixture /home/alice/app/.env "DB_PASSWORD=abc123"
    chmod 640 "$AUDIT_ROOT/home/alice/app/.env"
    _run_check check_secrets
    assert_issue "Exposed credentials"
    local r
    r=$(remediation_for "Exposed credentials")
    every_chmod_is_safe "$r"
    run_chmod_lines "$r"
    [ "$(stat -c '%a' "$AUDIT_ROOT/home/alice/app/.env")" = "600" ]
    TITLES=() ISSUES=() REMEDIATIONS=() CHECK_FAILED=()
    _run_check check_secrets
    refute_issue "Exposed credentials"
    [ "${CHECK_STATUS[check_secrets]}" = "satisfied" ]
}

# ---- secrets: symlink-safe chmod as the file's owner -----------------------

@test "secrets: every chmod runs as the file's owner and skips symlinks" {
    fixture /home/alice/.ssh/id_rsa "$KEY_OPENSSH"
    fixture /home/alice/.aws/credentials "aws_secret_access_key = abc"
    fixture /home/alice/app/.env "TOKEN=abc"
    chown nobody "$AUDIT_ROOT/home/alice/.ssh/id_rsa" "$AUDIT_ROOT/home/alice/app/.env"
    chmod 644 "$AUDIT_ROOT/home/alice/.ssh/id_rsa" "$AUDIT_ROOT/home/alice/.aws/credentials" \
        "$AUDIT_ROOT/home/alice/app/.env"
    _run_check check_secrets
    local r
    r=$(remediation_for "Exposed credentials")
    every_chmod_is_safe "$r"
    [[ "$r" == *"runuser -u nobody -- /bin/chmod 600 -- ${AUDIT_ROOT}/home/alice/.ssh/id_rsa"* ]]
    [[ "$r" == *"runuser -u nobody -- /bin/chmod go-rwx -- ${AUDIT_ROOT}/home/alice/app/.env"* ]]
    # root owns the AWS file and only root can write its directories
    [[ "$r" == *"sudo /bin/chmod 600 -- ${AUDIT_ROOT}/home/alice/.aws/credentials"* ]]
}

@test "secrets: a root file others could swap is left to the operator, with a comment" {
    fixture /home/shared/x.pem "$KEY_RSA"
    chmod 644 "$AUDIT_ROOT/home/shared/x.pem"
    chmod 0777 "$AUDIT_ROOT/home/shared"
    _run_check check_secrets
    assert_issue "Exposed credentials"
    local r
    r=$(remediation_for "Exposed credentials")
    run executable_lines <<< "$r"
    [[ "$output" != *"home/shared/x.pem"* ]]
    grep -qE "^#.*chmod 600 ${AUDIT_ROOT}/home/shared/x\.pem" <<< "$r"
}

@test "secrets: a key swapped for a symlink before the fix runs: the target is untouched" {
    fixture /home/alice/a.pem "$KEY_RSA"
    chmod 644 "$AUDIT_ROOT/home/alice/a.pem"
    touch "$T/setuid-target"
    chmod 4755 "$T/setuid-target"
    _run_check check_secrets
    local r
    r=$(remediation_for "Exposed credentials")
    rm "$AUDIT_ROOT/home/alice/a.pem"
    ln -s "$T/setuid-target" "$AUDIT_ROOT/home/alice/a.pem"
    run_chmod_lines "$r"
    [ "$(stat -c '%a' "$T/setuid-target")" = "4755" ]
}

# ---- secrets: network filesystems ----------------------------------------

@test "secrets: network filesystems are pruned from the scan" {
    local t
    for t in nfs nfs4 cifs smb3 fuse.sshfs; do
        [[ " ${_NETFS_TYPES[*]} " == *" ${t} "* ]] || { echo "not pruned: $t"; return 1; }
    done
    fixture /home/bob/.ssh/id_rsa "$KEY_OPENSSH"
    fixture /home/bob/app/.env "PASSWORD=x"
    fixture /home/bob/.aws/credentials "aws_secret_access_key = abc"
    chmod 644 "$AUDIT_ROOT/home/bob/.ssh/id_rsa" "$AUDIT_ROOT/home/bob/app/.env" "$AUDIT_ROOT/home/bob/.aws/credentials"
    # Pretend the filesystem the fixture tree is on is a network one.
    _NETFS_TYPES=("$(find "$AUDIT_ROOT/home" -maxdepth 0 -printf '%F')")
    _run_check check_secrets
    refute_issue "Exposed credentials"
}

# ---- user SSH keys (deep): the homes check_secrets does not cover ----------

PASSWD_SERVICE=$'root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
jenkins:x:115:120:Jenkins:/var/lib/jenkins:/bin/bash
systemd-network:x:998:998::/:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin'

@test "user SSH keys: a key in /home or /root is counted once, by check_secrets" {
    fixture /etc/passwd "$PASSWD_SERVICE"
    fixture /home/alice/.ssh/id_rsa "$KEY_OPENSSH"
    fixture /root/.ssh/id_ed25519 "$KEY_OPENSSH"
    chmod 640 "$AUDIT_ROOT/home/alice/.ssh/id_rsa" "$AUDIT_ROOT/root/.ssh/id_ed25519"
    _run_check check_secrets
    _run_check check_deep_user_ssh_keys
    [ "${#TITLES[@]}" -eq 1 ]
    assert_issue "Exposed credentials"
    [ "${CHECK_STATUS[check_deep_user_ssh_keys]}" = "satisfied" ]
}

@test "user SSH keys: service-account homes from /etc/passwd are checked" {
    fixture /etc/passwd "$PASSWD_SERVICE"
    fixture /var/lib/jenkins/.ssh/id_rsa "$KEY_OPENSSH"
    fixture /var/lib/jenkins/.ssh/id_rsa.pub "ssh-rsa AAAAB3NzaC1yc2E jenkins@ci"
    fixture /var/lib/jenkins/.ssh/known_hosts "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"
    chmod 640 "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_rsa"
    chmod 644 "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_rsa.pub" "$AUDIT_ROOT/var/lib/jenkins/.ssh/known_hosts"
    _run_check check_secrets
    refute_issue "Exposed credentials"
    _run_check check_deep_user_ssh_keys
    assert_issue "User SSH private keys"
    local d
    d=$(printf '%s\n' "${ISSUES[@]}")
    [[ "$d" == *"/var/lib/jenkins/.ssh/id_rsa (640)"* ]]
    [[ "$d" != *"id_rsa.pub"* ]]
    [[ "$d" != *"known_hosts"* ]]
}
