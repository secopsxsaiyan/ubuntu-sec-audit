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

@test "secrets: secret names are found anywhere in the variable name" {
    fixture /home/alice/a/.env "AWS_SECRET_ACCESS_KEY=abc123"
    fixture /home/alice/b/.env "export GITHUB_TOKEN_RW = abc"
    fixture /home/alice/c/.env $'# PASSWORD=commented out\nDEBUG=true\nPORT=8080'
    chmod 644 "$AUDIT_ROOT"/home/alice/{a,b,c}/.env
    _run_check check_secrets
    assert_issue "Exposed credentials"
    run remediation_for "Exposed credentials"
    [[ "$output" == *"/home/alice/a/.env"* ]]
    [[ "$output" == *"/home/alice/b/.env"* ]]
    [[ "$output" != *"/home/alice/c/.env"* ]]
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

# ---- fix-time symlink attacks: chmod never follows a swapped-in link ------

@test "user SSH keys: the chmod runs as the key's owner and skips symlinks" {
    fixture /etc/passwd "$PASSWD_SERVICE"
    fixture /var/lib/jenkins/.ssh/id_ed25519 "$KEY_OPENSSH"
    chown nobody "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_ed25519"
    chmod 644 "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_ed25519"
    _run_check check_deep_user_ssh_keys
    local r
    r=$(remediation_for "User SSH private keys")
    every_chmod_is_safe "$r"
    [[ "$r" == *"runuser -u nobody -- /bin/chmod 600 -- ${AUDIT_ROOT}/var/lib/jenkins/.ssh/id_ed25519"* ]]
}

@test "user SSH keys: a key swapped for a symlink before the fix runs: the target is untouched" {
    fixture /etc/passwd "$PASSWD_SERVICE"
    fixture /var/lib/jenkins/.ssh/id_rsa "$KEY_RSA"
    chmod 644 "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_rsa"
    touch "$T/setuid-target"
    chmod 4755 "$T/setuid-target"
    _run_check check_deep_user_ssh_keys
    local r
    r=$(remediation_for "User SSH private keys")
    rm "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_rsa"
    ln -s "$T/setuid-target" "$AUDIT_ROOT/var/lib/jenkins/.ssh/id_rsa"
    run_chmod_lines "$r"
    [ "$(stat -c '%a' "$T/setuid-target")" = "4755" ]
}

@test "world-writable files: a file swapped for a symlink before the fix runs: the target is untouched" {
    mkdir -p "$AUDIT_ROOT/var/tmp"
    chmod 1777 "$AUDIT_ROOT/var/tmp"
    fixture /var/tmp/x "data"
    chmod 666 "$AUDIT_ROOT/var/tmp/x"
    touch "$T/devnull"
    chmod 666 "$T/devnull"
    _run_check check_deep_world_writable_files
    local r
    r=$(remediation_for "World-writable files")
    rm "$AUDIT_ROOT/var/tmp/x"
    ln -s "$T/devnull" "$AUDIT_ROOT/var/tmp/x"
    run_chmod_lines "$r"
    [ "$(stat -c '%a' "$T/devnull")" = "666" ]
}

@test "world-writable files: each file is changed as its owner, never through a symlink" {
    fixture /etc/app.conf "x"
    fixture /home/alice/notes "x"
    chown nobody "$AUDIT_ROOT/home/alice/notes"
    chmod 666 "$AUDIT_ROOT/etc/app.conf" "$AUDIT_ROOT/home/alice/notes"
    _run_check check_deep_world_writable_files
    local r
    r=$(remediation_for "World-writable files")
    every_chmod_is_safe "$r"
    [[ "$r" == *"runuser -u nobody -- /bin/chmod o-w -- ${AUDIT_ROOT}/home/alice/notes"* ]]
    [[ "$r" == *"[ -L ${AUDIT_ROOT}/etc/app.conf ] || sudo /bin/chmod o-w -- ${AUDIT_ROOT}/etc/app.conf"* ]]
}

@test "world-writable files: the fix still clears the bit, and the check then passes" {
    fixture /etc/app.conf "x"
    chmod 666 "$AUDIT_ROOT/etc/app.conf"
    _run_check check_deep_world_writable_files
    run_chmod_lines "$(remediation_for "World-writable files")"
    [ "$(stat -c '%a' "$AUDIT_ROOT/etc/app.conf")" = "664" ]
    TITLES=() ISSUES=() REMEDIATIONS=() CHECK_FAILED=()
    _run_check check_deep_world_writable_files
    [ "${CHECK_STATUS[check_deep_world_writable_files]}" = "satisfied" ]
}

@test "world-writable dirs: no chmod through a symlink, none on a dir others can swap" {
    mkdir -p "$AUDIT_ROOT/var/bad/sub" "$T/victim"
    chmod 0777 "$AUDIT_ROOT/var/bad" "$AUDIT_ROOT/var/bad/sub" "$T/victim"
    _run_check check_deep_world_writable_dirs
    local r
    r=$(remediation_for "World-writable directories")
    every_chmod_is_safe "$r"
    # /var/bad/sub sits in a world-writable directory: anyone could swap it.
    run executable_lines <<< "$r"
    [[ "$output" != *"/var/bad/sub"* ]]
    grep -qE "^#.*chmod o-w ${AUDIT_ROOT}/var/bad/sub" <<< "$r"
    mv "$AUDIT_ROOT/var/bad" "$AUDIT_ROOT/var/bad.orig"
    ln -s "$T/victim" "$AUDIT_ROOT/var/bad"
    run_chmod_lines "$r"
    [ "$(stat -c '%a' "$T/victim")" = "777" ]
}

# ---- SUID/SGID: shell-escape binaries and every local filesystem ----------

# mock_dpkg_owner PATTERN... — dpkg-query -S reports paths matching any
# PATTERN (shell glob) as owned by a package; others are not found.
mock_dpkg_owner() {
    local pats="$*"
    mock_cmd dpkg-query '
set -f
[ "$1" = "-S" ] || exit 0
shift
rc=1
for p in "$@"; do
    for pat in '"$pats"'; do
        case "$p" in $pat) echo "somepkg: $p"; rc=0 ;; esac
    done
done
exit $rc'
}

# special_files MODE PATH... — create each PATH under AUDIT_ROOT with MODE.
special_files() {
    local mode="$1" p
    shift
    for p in "$@"; do
        mkdir -p "$(dirname "$AUDIT_ROOT$p")"
        touch "$AUDIT_ROOT$p"
        chmod "$mode" "$AUDIT_ROOT$p"
    done
}

# issue_for TITLE — the full text of the first issue whose title contains TITLE.
issue_for() {
    local i
    for i in "${!TITLES[@]}"; do
        [[ "${TITLES[$i]}" == *"$1"* ]] && { printf '%s\n' "${ISSUES[$i]}"; return 0; }
    done
    return 1
}

# points_for TITLE — points recorded for the first finding whose title contains TITLE.
points_for() {
    python3 -c '
import json, sys
for line in open(sys.argv[1]):
    o = json.loads(line)
    if sys.argv[2] in o["title"]:
        print(o["points"])
        break
' "$FINDINGS_FILE" "$1"
}

@test "SUID: package-owned shell-escape binaries are a critical finding with a manual fix" {
    special_files 4755 /usr/bin/find /usr/bin/bash /usr/bin/python3.12 /usr/bin/man \
        /usr/bin/passwd /usr/bin/sudo /usr/lib/snapd/snap-confine
    special_files 0755 /usr/bin/vim.basic
    mock_dpkg_owner '/usr/bin/*' '/usr/lib/snapd/*'
    _run_check check_deep_suid
    assert_issue "shell-escape"
    refute_issue "Non-standard SUID"
    local d
    d=$(issue_for "shell-escape")
    [[ "$d" == *"[CRITICAL]"* ]]
    [[ "$d" == *"/usr/bin/find"* && "$d" == *"/usr/bin/bash"* && "$d" == *"/usr/bin/python3.12"* ]]
    [[ "$d" == *"/usr/bin/man"* ]]
    [[ "$d" != *"passwd"* && "$d" != *"/usr/bin/sudo"* && "$d" != *"snap-confine"* && "$d" != *"vim.basic"* ]]
    [ "$(points_for "shell-escape")" -ge 20 ]
    run executable_lines <<< "$(remediation_for "shell-escape")"
    [ -z "$output" ]
}

@test "SGID: a package-owned shell-escape binary is critical; plocate and crontab are not" {
    special_files 2755 /usr/bin/vim.basic /usr/bin/plocate /usr/bin/crontab
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_sgid
    local d
    d=$(issue_for "shell-escape")
    [[ "$d" == *"[CRITICAL]"* ]]
    [[ "$d" == *"/usr/bin/vim.basic"* ]]
    [[ "$d" != *"plocate"* && "$d" != *"crontab"* ]]
    [ "$(points_for "shell-escape")" -ge 20 ]
    run executable_lines <<< "$(remediation_for "shell-escape")"
    [ -z "$output" ]
}

@test "SUID: unowned files are still reported, and every file is in one finding only" {
    special_files 4755 /usr/local/bin/evil /usr/bin/find /var/tmp/.x/bash
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_suid
    local plain esc
    plain=$(issue_for "Non-standard SUID")
    esc=$(issue_for "shell-escape")
    [[ "$plain" == *"/usr/local/bin/evil"* ]]
    [[ "$plain" != *"/usr/bin/find"* && "$plain" != *"/var/tmp/.x/bash"* ]]
    [[ "$esc" == *"/usr/bin/find"* && "$esc" == *"/var/tmp/.x/bash"* ]]
    [[ "$esc" != *"evil"* ]]
}

@test "SUID: a newline in a path cannot pass a file off as two package-owned ones" {
    special_files 4755 $'/usr/bin/sudo\n/usr/bin/passwd'
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_suid
    assert_issue "Non-standard SUID"
    [[ "$(issue_for "Non-standard SUID")" == *"\$'/usr/bin/sudo\\n/usr/bin/passwd'"* ]]
}

@test "SUID: man-db's optional 'setuid man' /usr/bin/man is not a finding" {
    id man >/dev/null 2>&1 || skip "no man user on this host"
    special_files 4755 /usr/bin/man
    chown man "$AUDIT_ROOT/usr/bin/man"
    chmod 4755 "$AUDIT_ROOT/usr/bin/man"
    mock_dpkg_owner '/usr/bin/*'
    _run_check check_deep_suid
    refute_issue "shell-escape"
    [ "${CHECK_STATUS[check_deep_suid]}" = "satisfied" ]
}

@test "SUID/SGID: every local filesystem is scanned, not only the one / is on" {
    mock_cmd findmnt 'printf "%s\n" /home /var "/srv/data\\x20disk"'
    mock_cmd find 'printf "%s\n" "$@" >> "'"$T"'/find.args"; exit 0'
    AUDIT_ROOT=""
    _run_check check_deep_suid
    local starts
    starts=$(awk '/^-/ { exit } { print }' "$T/find.args" | sort)
    [ "$starts" = "$(printf '%s\n' / /home "/srv/data disk" /var | sort)" ]
    grep -qx -- '-xdev' "$T/find.args"
}

@test "SUID/SGID: with AUDIT_ROOT set, only that tree is scanned" {
    mock_cmd findmnt 'printf "%s\n" /home'
    mock_cmd find 'printf "%s\n" "$@" >> "'"$T"'/find.args"; exit 0'
    _run_check check_deep_sgid
    [ "$(awk '/^-/ { exit } { print }' "$T/find.args")" = "$AUDIT_ROOT" ]
}

# ---- debsums: only changed files count -----------------------------------

@test "debsums: files missing from a minimized image are not an integrity violation" {
    mock_cmd debsums '
echo "debsums: missing file /usr/share/doc/bash/README (from bash package)" >&2
echo "debsums: missing file /usr/share/man/man1/ls.1.gz (from coreutils package)" >&2
exit 2'
    _run_check check_deep_debsums
    refute_issue "integrity"
    [ "${CHECK_STATUS[check_deep_debsums]}" = "satisfied" ]
}

@test "debsums: a changed file is still a finding, and only changed files are listed" {
    mock_cmd debsums '
echo "/usr/bin/ls"
echo "debsums: missing file /usr/share/doc/bash/README (from bash package)" >&2
exit 2'
    mock_cmd dpkg '
[ "$1" = "-S" ] || exit 1
shift
rc=0
for p in "$@"; do
    case "$p" in
        /usr/bin/ls) echo "coreutils: /usr/bin/ls" ;;
        *) echo "dpkg-query: no path found matching pattern $p" >&2; rc=1 ;;
    esac
done
exit $rc'
    _run_check check_deep_debsums
    assert_issue "Package files modified"
    [[ "$(remediation_for "Package files modified")" == *"--reinstall -y coreutils"* ]]
    grep -q '^/usr/bin/ls$' "$REPORT_FILE"
    refute grep -q 'missing file' "$REPORT_FILE"
}

# ---- deep mode: only the tools of checks that will run are offered --------

# record_offers — replace prompt_install with a recorder; apt-get is logged.
record_offers() {
    prompt_install() { echo "$1" >> "$T/offered"; }
    mock_cmd apt-get 'echo "apt-get $*" >> "'"$T"'/apt.log"'
}
offered() { sort "$T/offered" 2>/dev/null || true; }

@test "deep mode: no tool is offered when no selected check needs one" {
    record_offers
    RUN_ONLY=(check_deep_sudo_timeout)
    run_deep_checks </dev/null >/dev/null 2>&1
    [ -z "$(offered)" ]
    [ ! -e "$T/apt.log" ]
}

@test "deep mode: --check offers exactly the tools of the selected checks" {
    record_offers
    RUN_ONLY=(check_deep_lynis check_deep_debsums check_deep_suid)
    run_deep_checks </dev/null >/dev/null 2>&1
    [ "$(offered)" = "$(printf '%s\n' debsums lynis)" ]
}

@test "deep mode: --skip and --verify leave out the tools of excluded checks" {
    record_offers
    SKIP_CHECKS=(check_deep_clamav check_deep_rkhunter)
    run_deep_checks </dev/null >/dev/null 2>&1
    [ "$(offered)" = "$(printf '%s\n' auditctl debsums lynis)" ]
    rm -f "$T/offered"
    SKIP_CHECKS=()
    VERIFY_MODE=1
    VERIFY_CHECKS=(check_deep_auditd_rules)
    run_deep_checks </dev/null >/dev/null 2>&1
    [ "$(offered)" = "auditctl" ]
}

@test "deep mode: a check left out by the OSCAL profile gets no tool offer" {
    record_offers
    OSCAL_CATALOG=nist
    CTRL_MAP["check_deep_lynis|nist"]="CA-7"
    CTRL_MAP["check_deep_debsums|nist"]="SI-7"
    CTRL_MAP["check_deep_rkhunter|nist"]="SI-3"
    CTRL_MAP["check_deep_clamav|nist"]="SI-3"
    CTRL_MAP["check_deep_auditd_rules|nist"]="AU-2"
    PROFILE_CONTROLS=("ca-7")
    run_deep_checks </dev/null >/dev/null 2>&1
    [ "$(offered)" = "lynis" ]
}

@test "SUID: files inside container storage (Docker, containerd, LXD) are not reported" {
    [ "$(id -u)" -eq 0 ] || skip "needs root to set SUID bits"
    local d
    for d in var/lib/docker/overlay2/abc/diff/usr/bin var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/bin \
             var/snap/lxd/common/lxd/storage-pools/default/containers/c1/rootfs/usr/bin \
             var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs/usr/bin \
             var/snap/microk8s/common/var/lib/containerd/snapshots/3/fs/bin \
             var/lib/kubelet/pods/p1/volumes/x/bin \
             home/alice/.local/share/containers/storage/overlay/l1/diff/usr/bin \
             root/.local/share/containers/storage/overlay/l2/diff/usr/bin; do
        mkdir -p "$AUDIT_ROOT/$d"
        printf 'x' > "$AUDIT_ROOT/$d/su"; chmod 4755 "$AUDIT_ROOT/$d/su"
        printf 'x' > "$AUDIT_ROOT/$d/bash"; chmod 4755 "$AUDIT_ROOT/$d/bash"
    done
    mock_cmd dpkg-query 'exit 1'
    _run_check check_deep_suid
    refute_issue "SUID"
}
