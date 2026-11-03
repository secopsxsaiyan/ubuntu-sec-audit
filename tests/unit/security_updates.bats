#!/usr/bin/env bats
# check_security_updates replaces check_debsecan: debsecan reads Debian's
# security tracker, which has no data for Ubuntu releases.

load test_helper

setup() {
    load_audit
}


@test "pending security updates are counted from apt's simulation" {
    mock_cmd apt-get '[ "$1" = "-s" ] || exit 0
cat <<EOF
NOTE: This is only a simulation!
Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a-0ubuntu0.22.04] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
EOF'
    _run_check check_security_updates
    assert_issue "Security updates pending"
    [[ "$(printf '%s\n' "${ISSUES[@]}")" == *"2 package(s)"* ]]
    [[ "$(printf '%s\n' "${ISSUES[@]}")" == *"libssl3"* ]]
}

@test "no pending security updates passes" {
    mock_cmd apt-get '[ "$1" = "-s" ] && echo "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."; exit 0'
    _run_check check_security_updates
    refute_issue "Security updates pending"
    [ "${CHECK_STATUS[check_security_updates]}" = "satisfied" ]
}

@test "the remediation installs security updates only and passes ShellCheck" {
    mock_cmd apt-get '[ "$1" = "-s" ] && echo "Inst a [1] (2 Ubuntu:24.04/noble-security [amd64])"; exit 0'
    _run_check check_security_updates
    local r
    r=$(remediation_for "Security updates pending")
    [[ "$r" == *"unattended-upgrade"* || "$r" == *"apt-get"* ]]
    PATH="$ORIG_PATH" command -v shellcheck >/dev/null || skip "shellcheck not installed"
    printf '#!/bin/bash\n%s\n' "$r" | PATH="$ORIG_PATH" shellcheck -S warning -
}
