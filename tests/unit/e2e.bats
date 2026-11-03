#!/usr/bin/env bats
# End-to-end runs of the real script against the machine running the tests.
# These need root (the script refuses to run otherwise) and are read-only
# apart from the output directory.

load test_helper

setup() {
    [ "$(id -u)" -eq 0 ] || skip "end-to-end tests need root"
    OUT="$BATS_TEST_TMPDIR/out"
    mkdir -p "$OUT"
}

@test "a completed audit exits 0" {
    run bash "$REPO_ROOT/ubuntu-sec-audit.sh" --check check_umask,check_users \
        --skip-apt-update --output-dir "$OUT" </dev/null
    echo "$output" | tail -20
    [ "$status" -eq 0 ]
    [[ "$output" != *"Unexpected error"* ]]
}

@test "the findings file is valid JSONL and covers only the selected checks" {
    run bash "$REPO_ROOT/ubuntu-sec-audit.sh" --check check_umask,check_users \
        --skip-apt-update --output-dir "$OUT" </dev/null
    run python3 -c '
import glob, json, sys
files = glob.glob(sys.argv[1] + "/sec-audit-findings-*.jsonl")
assert len(files) == 1, files
ids = set()
for line in open(files[0]):
    ids.add(json.loads(line)["check_id"])
assert ids == {"check_umask", "check_users"}, ids
print("ok")
' "$OUT"
    echo "$output"
    [ "$output" = "ok" ]
}
