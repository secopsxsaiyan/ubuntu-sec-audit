#!/usr/bin/env bats
# The generated fix script: opt-in application, manual steps, SSH rollback,
# backups, and safe handling of titles. Remediations used here are fakes that
# only touch files under BATS_TEST_TMPDIR.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
}

# add_fix TITLE REMEDIATION [CHECK_ID]
add_fix() {
    TITLES+=("$1")
    REMEDIATIONS+=("$2")
    CHECK_IDS+=("${3:-check_fake}")
    CTRL_IDS_ALL+=("")
    SEVERITIES+=("LOW")
}

gen() {
    generate_fix_script >/dev/null
    [ -f "$FIX_SCRIPT" ]
    bash -n "$FIX_SCRIPT"
}

@test "without --apply and without a terminal the fix script changes nothing" {
    add_fix "Make marker" "touch '$T/marker'"
    gen
    run bash "$FIX_SCRIPT" </dev/null
    [ "$status" -eq 0 ]
    [ ! -e "$T/marker" ]
    [[ "$output" == *"Dry run"* ]]
    [[ "$output" == *"Make marker"* ]]
}

@test "--apply applies every block" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix "One" "touch '$T/one'"
    add_fix "Two" "touch '$T/two'"
    gen
    run bash "$FIX_SCRIPT" --apply </dev/null
    [ "$status" -eq 0 ]
    [ -e "$T/one" ] && [ -e "$T/two" ]
}

@test "--interactive applies only the blocks confirmed" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix "One" "touch '$T/one'"
    add_fix "Two" "touch '$T/two'"
    gen
    run bash "$FIX_SCRIPT" --interactive <<< $'n\ny\n'
    [ ! -e "$T/one" ]
    [ -e "$T/two" ]
}

@test "a remediation made only of comments becomes a manual step that never runs" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix "Set a GRUB password" $'# 1. run grub-mkpasswd-pbkdf2\n# 2. touch '"$T"'/marker'
    gen
    grep -q "MANUAL" "$FIX_SCRIPT"
    run bash "$FIX_SCRIPT" --apply </dev/null
    [[ "$output" == *"[MANUAL] Fix 1: Set a GRUB password"* ]]
    [ ! -e "$T/marker" ]
}

@test "a title cannot inject commands into the fix script" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix $'key: id_x\ntouch '"$T"'/pwned1 $(touch '"$T"'/pwned2) `touch '"$T"'/pwned3`' "true"
    gen
    run bash "$FIX_SCRIPT" --apply </dev/null
    [ ! -e "$T/pwned1" ] && [ ! -e "$T/pwned2" ] && [ ! -e "$T/pwned3" ]
    run bash "$FIX_SCRIPT" </dev/null
    [ ! -e "$T/pwned1" ] && [ ! -e "$T/pwned2" ] && [ ! -e "$T/pwned3" ]
}

@test "files written with tee -a or edited with sed -i are backed up first" {
    add_fix "Edit configs" $'echo x | sudo /usr/bin/tee -a /etc/fstab\nsudo /bin/sed -i \'s/a/b c/\' /etc/login.defs\nsudo /usr/bin/tee /etc/issue /etc/issue.net > /dev/null'
    gen
    grep -qx '_bak /etc/fstab' "$FIX_SCRIPT"
    grep -qx '_bak /etc/login.defs' "$FIX_SCRIPT"
    grep -qx '_bak /etc/issue' "$FIX_SCRIPT"
    grep -qx '_bak /etc/issue.net' "$FIX_SCRIPT"
    ! grep -qx '_bak /dev/null' "$FIX_SCRIPT"
}

@test "the fix script works on hosts without sudo" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix "Uses sudo" "sudo touch '$T/marker'"
    gen
    ! command -v sudo
    run bash "$FIX_SCRIPT" --apply </dev/null
    [ -e "$T/marker" ]
}

@test "SSH changes are rolled back when the new login is not confirmed" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    mkdir -p "$T/ssh/sshd_config.d"
    echo original > "$T/ssh/sshd_config"
    mock_cmd sshd 'exit 0'
    mock_cmd systemctl 'echo "systemctl $*" >> "'"$T"'/systemctl.log"'
    add_fix "SSH configuration weaknesses found" \
        "echo changed > '$T/ssh/sshd_config'; echo new > '$T/ssh/sshd_config.d/00-hardening.conf'" check_ssh
    gen
    FIX_SSHD_DIR="$T/ssh" FIX_ROLLBACK_SECS=5 run bash "$FIX_SCRIPT" --apply </dev/null
    [ "$(cat "$T/ssh/sshd_config")" = "original" ]
    [ ! -e "$T/ssh/sshd_config.d/00-hardening.conf" ]
    [[ "$output" == *"rolled back"* ]]
}

@test "--no-ssh-rollback applies SSH changes without the rollback guard" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    mkdir -p "$T/ssh"
    echo original > "$T/ssh/sshd_config"
    mock_cmd sshd 'exit 0'
    mock_cmd systemctl 'exit 0'
    add_fix "SSH configuration weaknesses found" "echo changed > '$T/ssh/sshd_config'" check_ssh
    gen
    FIX_SSHD_DIR="$T/ssh" run bash "$FIX_SCRIPT" --apply --no-ssh-rollback </dev/null
    [ "$(cat "$T/ssh/sshd_config")" = "changed" ]
}

@test "SSH changes that fail sshd -t are rolled back immediately" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    mkdir -p "$T/ssh"
    echo original > "$T/ssh/sshd_config"
    mock_cmd sshd 'exit 1'
    mock_cmd systemctl 'exit 0'
    add_fix "SSH configuration weaknesses found" "echo broken > '$T/ssh/sshd_config'" check_ssh
    gen
    FIX_SSHD_DIR="$T/ssh" run bash "$FIX_SCRIPT" --apply </dev/null
    [ "$(cat "$T/ssh/sshd_config")" = "original" ]
    [[ "$output" == *"sshd -t failed"*"rolled back"* ]]
}

@test "the generated fix script passes ShellCheck" {
    PATH="$ORIG_PATH" command -v shellcheck >/dev/null || skip "shellcheck not installed"
    add_fix "One" "touch '$T/one'"
    add_fix "Manual" "# do it by hand"
    add_fix "SSH configuration weaknesses found" "true" check_ssh
    gen
    PATH="$ORIG_PATH" shellcheck -S warning "$FIX_SCRIPT"
}
