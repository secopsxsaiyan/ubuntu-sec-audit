#!/usr/bin/env bats
# Engineering rules: no sudo in probes, private outputs, one run id.

load test_helper

@test "no check calls sudo (the script already runs as root)" {
    load_audit
    mock_cmd sudo 'echo "sudo $*" >> "'"$BATS_TEST_TMPDIR"'/sudo.log"; exit 1'
    mock_cmd timeout 'shift; exec "$@"'
    local fn
    for fn in "${STANDARD_CHECKS[@]}" "${DEEP_CHECKS[@]}"; do
        _run_check "$fn" </dev/null >/dev/null 2>&1
    done
    if [ -s "$BATS_TEST_TMPDIR/sudo.log" ]; then
        cat "$BATS_TEST_TMPDIR/sudo.log"
        return 1
    fi
}

@test "there is no sudo keep-alive loop" {
    refute grep -rn 'sudo -n true' "$REPO_ROOT/lib" "$REPO_ROOT/checks" "$REPO_ROOT/ubuntu-sec-audit.sh"
}

@test "the report appendix names the script correctly" {
    refute grep -rn 'ubuntu-security-audit.sh' "$REPO_ROOT/lib" "$REPO_ROOT/checks"
}

e2e_run() {
    [ "$(id -u)" -eq 0 ] || skip "end-to-end tests need root"
    OUT="$BATS_TEST_TMPDIR/out"
    mkdir -p "$OUT"
    run bash "$REPO_ROOT/ubuntu-sec-audit.sh" --check check_umask,check_ssh --skip-apt-update \
        --oscal --ansible --output-dir "$OUT" </dev/null
    [ "$status" -eq 0 ]
}

@test "all outputs of one run share one run id" {
    e2e_run
    local files ids
    files=$(find "$OUT" -maxdepth 1 -type f \( -name 'sec-audit-*' -o -name 'fix-audit-*' \
            -o -name 'oscal-ar-*' -o -name 'remediate-*' \) -printf '%f\n')
    [ "$(grep -c . <<< "$files")" -ge 5 ]
    # Every one of them carries a full date-time run id ...
    refute grep -vE '[0-9]{8}-[0-9]{6}' <<< "$files"
    # ... and it is the same id for all of them.
    ids=$(grep -oE '[0-9]{8}-[0-9]{6}(-[0-9]+)?' <<< "$files" | sort -u)
    [ "$(grep -c . <<< "$ids")" -eq 1 ]
}

@test "all outputs are private to their owner" {
    e2e_run
    local f perms
    while IFS= read -r f; do
        perms=$(stat -c '%a' "$f")
        (( (8#$perms & 8#077) == 0 )) || { echo "$f is $perms"; return 1; }
    done < <(find "$OUT" -type f)
}

@test "a successful run does not say it exited unexpectedly" {
    e2e_run
    [[ "$output" != *"unexpectedly"* ]]
    [[ "$output" != *"Unexpected error"* ]]
}
