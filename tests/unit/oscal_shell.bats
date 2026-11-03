#!/usr/bin/env bats
# Shell side of the OSCAL and framework support.

load test_helper

setup() {
    load_audit
}

@test "profile filtering matches OSCAL enhancement ids against mapping ids" {
    OSCAL_CATALOG=nist
    CTRL_MAP["check_x|nist"]="SC-28,SC-28(1)"
    CTRL_MAP["check_y|nist"]="AC-2"
    PROFILE_CONTROLS=("sc-28.1")
    _check_in_profile check_x
    refute _check_in_profile check_y
}

@test "profile filtering matches CIS ids written as cis_<number>" {
    OSCAL_CATALOG=cis
    CTRL_MAP["check_x|cis"]="5.1.20"
    PROFILE_CONTROLS=("cis_5.1.20")
    _check_in_profile check_x
}

@test "the OSCAL generator gets the tool version and the selected frameworks" {
    mock_cmd python3 'printf "%s\n" "$@" > "'"$BATS_TEST_TMPDIR"'/args"'
    OSCAL_MODE=1
    FRAMEWORKS=(nist iso27001 soc2)
    REPORT_DIR="$BATS_TEST_TMPDIR/out"
    generate_oscal >/dev/null
    grep -qx -- "--tool-version" "$BATS_TEST_TMPDIR/args"
    grep -qx -- "$SCRIPT_VERSION" "$BATS_TEST_TMPDIR/args"
    grep -qx -- "--frameworks" "$BATS_TEST_TMPDIR/args"
    grep -qx -- "nist,iso27001,soc2" "$BATS_TEST_TMPDIR/args"
}

@test "fix-script CIS section dividers use the 24.04 benchmark sections" {
    FIX_SCRIPT="$BATS_TEST_TMPDIR/fix.sh"
    : > "$FIX_SCRIPT"
    _write_section_divider 4 cis
    _write_section_divider 6 cis
    _write_section_divider 7 cis
    grep -q "CIS Section 4 — Host Based Firewall" "$FIX_SCRIPT"
    grep -q "CIS Section 6 — Logging and Auditing" "$FIX_SCRIPT"
    grep -q "CIS Section 7 — System Maintenance" "$FIX_SCRIPT"
}
