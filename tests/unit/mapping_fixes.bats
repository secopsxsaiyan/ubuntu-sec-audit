#!/usr/bin/env bats
# Control mappings claim only what the check actually verifies.

load test_helper

# ids CHECK FRAMEWORK — the mapped ids, one per line.
ids() {
    python3 -c 'import json, sys
m = json.load(open(sys.argv[1]))
print("\n".join(m[sys.argv[2]][sys.argv[3]]))' "$REPO_ROOT/mappings/control-mapping.json" "$1" "$2"
}

@test "auditd: no CIS 6.2.2.2 (keep_logs); the check accepts and the fix sets rotate" {
    refute grep -qx '6.2.2.2' <<< "$(ids check_auditd cis)"
}

@test "fail2ban maps to unsuccessful logon attempts (AC-7), not malicious code (SI-3)" {
    grep -qx 'AC-7' <<< "$(ids check_fail2ban nist)"
    refute grep -qx 'SI-3' <<< "$(ids check_fail2ban nist)"
}

@test "Secure Boot maps to boot verification (SI-7(9)), not data at rest (SC-28)" {
    grep -qx 'SI-7(9)' <<< "$(ids check_secure_boot nist)"
    refute grep -qx 'SC-28' <<< "$(ids check_secure_boot nist)"
}

@test "the report-only authorized_keys inventory claims no controls" {
    local fw
    for fw in nist cis iso27001 soc2; do
        [ -z "$(ids check_deep_authorized_keys "$fw")" ]
    done
}

@test "the NIST catalog reference is the OSCAL catalog, not a web page" {
    python3 -c 'import json, sys
m = json.load(open(sys.argv[1]))
assert m["_nist_catalog"].endswith("NIST_SP-800-53_rev5_catalog.json"), m["_nist_catalog"]' \
        "$REPO_ROOT/mappings/control-mapping.json"
}
