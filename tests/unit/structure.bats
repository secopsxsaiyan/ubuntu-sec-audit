#!/usr/bin/env bats
# Structural tests: the script is sourceable, modules parse, checks are wired.

load test_helper

@test "every shell file parses" {
    local f
    for f in "$REPO_ROOT"/ubuntu-sec-audit.sh "$REPO_ROOT"/lib/*.sh "$REPO_ROOT"/checks/*.sh; do
        bash -n "$f"
    done
}

@test "sourcing the script defines functions without running the audit" {
    run bash -c "cd '$BATS_TEST_TMPDIR' && source '$REPO_ROOT/ubuntu-sec-audit.sh' && type -t main && type -t check_ssh"
    [ "$status" -eq 0 ]
    [ "${lines[0]}" = "function" ]
    [ "${lines[1]}" = "function" ]
    [ "${#lines[@]}" -eq 2 ]
    # Nothing was written to the working directory.
    [ -z "$(ls -A "$BATS_TEST_TMPDIR")" ]
}

@test "every lib/ and checks/ module is sourced by the entrypoint" {
    local f rel
    for f in "$REPO_ROOT"/lib/*.sh "$REPO_ROOT"/checks/*.sh; do
        rel="${f#"$REPO_ROOT"/}"
        grep -qxF "source \"\${OSCAL_SCRIPT_DIR}/${rel}\"" "$REPO_ROOT/ubuntu-sec-audit.sh" \
            || { echo "not sourced: $rel"; return 1; }
    done
}

@test "every check in control-mapping.json has a function" {
    load_audit
    local id
    while IFS= read -r id; do
        [ "$(type -t "$id")" = "function" ] || { echo "missing function: $id"; return 1; }
    done < <(python3 -c '
import json, sys
m = json.load(open(sys.argv[1]))
print("\n".join(k for k, v in m.items() if isinstance(v, dict)))
' "$REPO_ROOT/mappings/control-mapping.json")
}
