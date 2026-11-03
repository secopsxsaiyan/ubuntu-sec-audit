#!/usr/bin/env bats
# Check outcomes other than pass/fail: a check that could not be performed
# (skipped) or that does not apply to this host (not-applicable) is recorded
# as such, never as satisfied, and never silently dropped.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
    check_fake_na()   { _mark_not_applicable "no widget installed"; return 0; }
    check_fake_skip() { _mark_skipped "widgetctl not installed"; return 0; }
}

# status_of CHECK — the status recorded for CHECK in the findings file.
status_of() { findings_tsv | awk -F'\t' -v c="$1" '$1 == c {print $2}'; }

@test "a check that does not apply is recorded as not-applicable with its reason" {
    _run_check check_fake_na
    [ "$(status_of check_fake_na)" = "not-applicable" ]
    [ "${CHECK_STATUS[check_fake_na]}" = "not-applicable" ]
    grep -q '"evidence": "no widget installed"' "$FINDINGS_FILE"
}

@test "a check that could not run is recorded as skipped with its reason" {
    _run_check check_fake_skip
    [ "$(status_of check_fake_skip)" = "skipped" ]
    [ "${CHECK_STATUS[check_fake_skip]}" = "skipped" ]
    grep -q '"evidence": "widgetctl not installed"' "$FINDINGS_FILE"
}

@test "an issue wins over a not-applicable mark" {
    check_fake_both() { report_issue 3 "Problem" "d" "echo fix"; _mark_not_applicable "x"; }
    _run_check check_fake_both
    [ "$(status_of check_fake_both)" = "not-satisfied" ]
}

@test "a check skipped for its environment is recorded as not-applicable" {
    ENV_TYPE="docker"
    _run_check check_kernel_lockdown
    [ "$(status_of check_kernel_lockdown)" = "not-applicable" ]
    grep -q 'docker' "$FINDINGS_FILE"
}

@test "checks left out by --skip are not recorded at all" {
    SKIP_CHECKS=(check_fake_na)
    _run_check check_fake_na
    [ ! -s "$FINDINGS_FILE" ]
}

# ---- manual remediations -------------------------------------------------

add_fix() {
    TITLES+=("$1"); REMEDIATIONS+=("$2"); CHECK_IDS+=("${3:-check_fake}")
    CTRL_IDS_ALL+=(""); SEVERITIES+=("LOW")
}

@test "a block marked '# MANUAL' never runs, even with commands in it" {
    [ "$(id -u)" -eq 0 ] || skip "applying needs root"
    add_fix "Encrypt the disk" "# MANUAL: encryption is set up at install time
touch $T/marker
# Verify:
lsblk"
    generate_fix_script >/dev/null
    bash -n "$FIX_SCRIPT"
    run bash "$FIX_SCRIPT" --apply </dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == *"[MANUAL] Fix 1: Encrypt the disk"* ]]
    [ ! -e "$T/marker" ]
    # The commands are still shown, as comments, for the operator to follow.
    grep -qE '^#[[:space:]]+touch .*/marker' "$FIX_SCRIPT"
}

@test "_is_manual_remediation: comment-only and '# MANUAL' blocks are manual" {
    _is_manual_remediation $'# step 1\n# step 2'
    _is_manual_remediation $'# MANUAL\nsystemctl restart foo'
    _is_manual_remediation $'\n# MANUAL: reason\nfoo'
    refute _is_manual_remediation $'# note\nsystemctl restart foo'
    refute _is_manual_remediation $'echo hi\n# MANUAL'
}

@test "manual blocks are comments in the Ansible playbook" {
    add_fix "Encrypt the disk" $'# MANUAL\ntouch /tmp/x'
    ANSIBLE_MODE=1
    RUN_ID=test
    generate_fix_script >/dev/null
    generate_ansible >/dev/null
    refute grep -q 'touch /tmp/x' "$ANSIBLE_FILE"
    grep -q 'MANUAL: Encrypt the disk' "$ANSIBLE_FILE"
}

# ---- chmod on paths other users control ----------------------------------

@test "_safe_chmod_cmd: a user's file is changed as that user, never through a symlink" {
    mkdir -p "$T/home/alice"
    run _safe_chmod_cmd alice 600 "$T/home/alice/a key.pem"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ -L "* ]]
    [[ "$output" == *"runuser -u alice -- "*"chmod 600 -- "* ]]
    [[ "$output" == *'a\ key.pem'* ]]
}

@test "_safe_chmod_cmd: a root file in a directory only root can write is changed directly" {
    [ "$(id -u)" -eq 0 ] || skip "needs root-owned directories"
    mkdir -p "$T/etc/ssl/private"
    chmod 700 "$T/etc/ssl/private"
    run _safe_chmod_cmd root o-r "$T/etc/ssl/private/k.key"
    [ "$status" -eq 0 ]
    [[ "$output" == *"[ -L "* ]]
    [[ "$output" != *runuser* ]]
    [[ "$output" == *"chmod o-r -- "* ]]
}

@test "_safe_chmod_cmd: a root file in a directory others can write is left to a person" {
    mkdir -p "$T/shared"
    chmod 0777 "$T/shared"
    run _safe_chmod_cmd root 600 "$T/shared/k.pem"
    [ "$status" -ne 0 ]
}

@test "the emitted chmod line does not follow a symlink swapped in later" {
    [ "$(id -u)" -eq 0 ] || skip "needs root"
    mkdir -p "$T/d"
    chmod 700 "$T/d"
    touch "$T/target"
    chmod 4755 "$T/target"
    local line
    line=$(_safe_chmod_cmd root 600 "$T/d/k.pem")
    ln -s "$T/target" "$T/d/k.pem"
    PATH="$ORIG_PATH" bash -c "sudo() { \"\$@\"; }; $line" || true
    [ "$(stat -c '%a' "$T/target")" = "4755" ]
}
