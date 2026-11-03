#!/usr/bin/env bats
# Run-level outputs: delta and verify across runs, the score, --fail-on, the
# webhook, the Markdown report, colours, environment detection, Ansible.

load test_helper

setup() {
    load_audit
    T="$BATS_TEST_TMPDIR"
    check_fake_fail() { report_issue 10 "Fake problem" "broken" "echo fix"; }
    check_fake_pass() { print_status OK "all good"; }
    check_fake_na()   { _mark_not_applicable "not here"; }
    check_fake_skip() { _mark_skipped "tool missing"; }
}

# jsonl FILE CHECK:STATUS... — a findings file in record_finding's format.
jsonl() {
    local f="$1" pair
    shift
    : > "$f"
    for pair in "$@"; do
        printf '{"check_id": "%s", "title": "t", "status": "%s", "evidence": "e", "remediation": "", "points": 0, "timestamp": "x"}\n' \
            "${pair%%:*}" "${pair#*:}" >> "$f"
    done
}

# ---- delta and verify across runs ------------------------------------------

@test "last known status: a check missing from the newest file comes from an older one" {
    jsonl "$T/new.jsonl" check_a:satisfied
    jsonl "$T/old.jsonl" check_a:not-satisfied check_b:not-satisfied
    run _last_known_statuses "$T/new.jsonl" "$T/old.jsonl"
    [ "$output" = "$(printf 'check_a\tsatisfied\ncheck_b\tnot-satisfied')" ]
}

@test "last known status: within one run, any failing record makes the check failing" {
    jsonl "$T/new.jsonl" check_a:satisfied check_a:not-satisfied
    run _last_known_statuses "$T/new.jsonl"
    [ "$output" = "$(printf 'check_a\tnot-satisfied')" ]
}

@test "delta after a --check subset run does not call old failures new" {
    jsonl "$T/full.jsonl"   check_a:not-satisfied check_b:not-satisfied check_c:satisfied
    jsonl "$T/subset.jsonl" check_a:not-satisfied
    jsonl "$T/cur.jsonl"    check_a:not-satisfied check_b:not-satisfied check_c:satisfied
    run _print_delta_report "$T/cur.jsonl" "$T/subset.jsonl" "$T/full.jsonl"
    [[ "$output" != *"New failures"* ]]
    [[ "$output" == *"No changes"* ]]
}

@test "delta: a failing check that no longer applies counts as fixed" {
    jsonl "$T/prev.jsonl" check_a:not-satisfied
    jsonl "$T/cur.jsonl"  check_a:not-applicable
    run _print_delta_report "$T/cur.jsonl" "$T/prev.jsonl"
    [[ "$output" == *"Fixed"*"check_a"* ]]
}

@test "delta works without python3" {
    rm -f "$MOCK_BIN/python3"
    jsonl "$T/prev.jsonl" check_a:not-satisfied check_b:satisfied
    jsonl "$T/cur.jsonl"  check_a:satisfied check_b:not-satisfied check_c:not-satisfied
    run _print_delta_report "$T/cur.jsonl" "$T/prev.jsonl"
    [[ "$output" == *"Fixed"*"check_a"* ]]
    [[ "$output" == *"Regressed"*"check_b"* ]]
    [[ "$output" == *"New failures"*"check_c"* ]]
}

@test "verify after a subset run still re-runs everything that last failed" {
    jsonl "$T/full.jsonl"   check_a:not-satisfied check_b:not-satisfied check_c:satisfied check_d:error
    jsonl "$T/subset.jsonl" check_a:satisfied
    run _failed_checks_in "$T/subset.jsonl" "$T/full.jsonl"
    [ "$output" = "$(printf 'check_b\ncheck_d')" ]
}

@test "previous findings files are listed newest first, without the current one" {
    REPORT_DIR="$T/out"
    FINDINGS_FILE="$REPORT_DIR/sec-audit-findings-3.jsonl"
    : > "$REPORT_DIR/sec-audit-findings-1.jsonl"; touch -d '2026-01-01' "$REPORT_DIR/sec-audit-findings-1.jsonl"
    : > "$REPORT_DIR/sec-audit-findings-2.jsonl"; touch -d '2026-01-02' "$REPORT_DIR/sec-audit-findings-2.jsonl"
    : > "$FINDINGS_FILE"
    run _previous_findings_files
    [ "$output" = "$(printf '%s\n%s' "$REPORT_DIR/sec-audit-findings-2.jsonl" "$REPORT_DIR/sec-audit-findings-1.jsonl")" ]
}

@test "verify summary counts a check that no longer applies as fixed" {
    VERIFY_MODE=1
    VERIFY_CHECKS=(check_fake_na check_fake_fail)
    _run_check check_fake_na
    _run_check check_fake_fail
    [ "$(_verify_counts)" = "1 1" ]
}

# ---- score -------------------------------------------------------------------

@test "score: every check passing is 100" {
    _run_check check_fake_pass
    _compute_score
    [ "$SCORE" -eq 100 ]
}

@test "score: weighted share of the checks that passed, not points below 100" {
    CHECK_WEIGHTS[check_fake_fail]=10
    CHECK_WEIGHTS[check_fake_pass]=30
    _run_check check_fake_fail
    _run_check check_fake_pass
    _compute_score
    [ "$SCORE" -eq 75 ]
}

@test "score: many findings no longer drive the score to 0 while checks still pass" {
    CHECK_WEIGHTS[check_fake_fail]=10
    CHECK_WEIGHTS[check_fake_pass]=10
    check_fake_many() { local i; for i in 1 2 3 4 5 6 7 8 9 10 11 12; do report_issue 10 "P$i" d "echo x"; done; }
    CHECK_WEIGHTS[check_fake_many]=20
    _run_check check_fake_many
    _run_check check_fake_pass
    _compute_score
    # check_fake_many loses at most its own weight: 10 of 30 remain.
    [ "$SCORE" -eq 33 ]
}

@test "score: checks that did not apply or could not run do not count" {
    CHECK_WEIGHTS[check_fake_fail]=10
    CHECK_WEIGHTS[check_fake_pass]=10
    _run_check check_fake_fail
    _run_check check_fake_pass
    _run_check check_fake_na
    _run_check check_fake_skip
    _compute_score
    [ "$SCORE" -eq 50 ]
}

@test "score: a check that crashed counts as failed, never as passed" {
    check_fake_crash() { false; }
    CHECK_WEIGHTS[check_fake_crash]=10
    CHECK_WEIGHTS[check_fake_pass]=10
    _run_check check_fake_crash 2>/dev/null
    _run_check check_fake_pass
    _compute_score
    [ "$SCORE" -eq 50 ]
}

@test "score: every standard and deep check has a weight" {
    local c missing=""
    for c in "${STANDARD_CHECKS[@]}" "${DEEP_CHECKS[@]}"; do
        [[ "${CHECK_WEIGHTS[$c]:-0}" -gt 0 ]] || missing+=" $c"
    done
    [ -z "$missing" ] || { echo "no weight:$missing"; return 1; }
}

@test "points a check reported are kept per check" {
    _run_check check_fake_fail
    [ "${CHECK_POINTS[check_fake_fail]}" -eq 10 ]
}

# ---- --fail-on -------------------------------------------------------------

@test "--fail-on accepts a severity and rejects anything else" {
    parse_args --fail-on high
    [ "$FAIL_ON" = "HIGH" ]
    run parse_args --fail-on severe
    [ "$status" -ne 0 ]
    [[ "$output" == *"--fail-on"* ]]
}

@test "--fail-on triggers at or above the chosen severity only" {
    FAIL_ON=""
    SEVERITIES=(CRITICAL)
    refute _fail_on_triggered
    FAIL_ON=HIGH
    SEVERITIES=(MEDIUM LOW)
    refute _fail_on_triggered
    SEVERITIES=(MEDIUM HIGH)
    _fail_on_triggered
    SEVERITIES=(CRITICAL)
    _fail_on_triggered
}

# e2e_umask_run ARGS... — the real script against a fixture root whose
# login.defs has a weak umask (a LOW finding).
e2e_umask_run() {
    [ "$(id -u)" -eq 0 ] || skip "end-to-end tests need root"
    fixture /etc/os-release $'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"'
    fixture /etc/login.defs "UMASK 022"
    mkdir -p "$T/e2e"
    run env PATH="$ORIG_PATH" AUDIT_ROOT="$AUDIT_ROOT" bash "$REPO_ROOT/ubuntu-sec-audit.sh" \
        --check check_umask --skip-apt-update --output-dir "$T/e2e" "$@" </dev/null
}

@test "--fail-on: the audit exits 2 when a finding reaches the threshold" {
    e2e_umask_run --fail-on low
    [ "$status" -eq 2 ]
    [[ "$output" == *"--fail-on"* ]]
    [[ "$output" != *"unexpectedly"* ]]
    [[ "$output" != *"Unexpected error"* ]]
}

@test "--fail-on: below the threshold the audit exits 0" {
    e2e_umask_run --fail-on critical
    [ "$status" -eq 0 ]
}

# ---- webhook -----------------------------------------------------------------

webhook_mock() {
    mock_cmd curl '
        printf "%s\n" "$*" > "'"$T"'/curl.args"
        cat > "'"$T"'/curl.stdin"
        while [ $# -gt 0 ]; do
            case "$1" in -K|--config) cat "$2" > "'"$T"'/curl.config"; shift ;; esac
            shift
        done
        exit '"${1:-0}"
}

webhook_state() {
    SCORE=72; GRADE=C; ISSUE_COUNT=2; DEEP=0
    SEVERITIES=(HIGH LOW)
    REPORT_FILE="$T/out/report.md"
}

@test "webhook: the URL never appears on curl's command line" {
    webhook_mock
    webhook_state
    WEBHOOK_URL="https://hooks.example.com/services/SECRET123"
    run send_webhook
    [[ "$output" == *"Webhook delivered"* ]]
    refute grep -q SECRET123 "$T/curl.args"
    grep -q 'SECRET123' "$T/curl.config"
}

@test "webhook: the payload is valid JSON with a Slack text and severity counts, without python3" {
    webhook_mock
    webhook_state
    WEBHOOK_URL="https://hooks.example.com/x"
    rm -f "$MOCK_BIN/python3"
    send_webhook >/dev/null
    PATH="$ORIG_PATH" python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["score"] == 72 and d["grade"] == "C" and d["issues"] == 2, d
assert d["severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}, d
assert "72/100" in d["text"], d
' "$T/curl.stdin"
}

@test "webhook: AUDIT_WEBHOOK_URL is used when --webhook is not given" {
    webhook_mock
    webhook_state
    AUDIT_WEBHOOK_URL="https://hooks.example.com/ENVSECRET" parse_args --skip-apt-update
    send_webhook >/dev/null
    grep -q ENVSECRET "$T/curl.config"
}

@test "webhook: a failed delivery is reported as failed" {
    webhook_mock 22
    webhook_state
    WEBHOOK_URL="https://hooks.example.com/x"
    run send_webhook
    [[ "$output" == *"Webhook delivery failed"* ]]
    [[ "$output" != *"delivered:"* ]]
}

@test "webhook: URLs that cannot be passed safely are rejected" {
    run parse_args --webhook 'https://example.com/a"b'
    [ "$status" -ne 0 ]
    run parse_args --webhook 'https://example.com/a b'
    [ "$status" -ne 0 ]
}

# ---- OSCAL output path -------------------------------------------------------

@test "a failed OSCAL generation leaves no OSCAL file in the summary" {
    mock_cmd python3 'exit 1'
    OSCAL_MODE=1; RUN_ID=test; ubuntu_ver=24.04
    generate_oscal >/dev/null
    [ -z "$OSCAL_AR_FILE" ]
}

# ---- Markdown report -----------------------------------------------------

@test "report: score and findings come first, sorted by severity, then check results" {
    RUN_ID=test
    _write_report_header > "$REPORT_FILE"
    append_report "## Firewall\n- 🔴 No active IPv4 firewall"
    check_fake_low()  { report_issue 2  "Low thing"  d "echo a"; }
    check_fake_crit() { report_issue 25 "Critical thing" d "echo b"; }
    _run_check check_fake_low
    _run_check check_fake_crit
    write_final_report
    local score_line crit_line low_line fw_line
    score_line=$(grep -n 'Overall Security Score' "$REPORT_FILE" | cut -d: -f1)
    crit_line=$(grep -n 'Critical thing' "$REPORT_FILE" | head -1 | cut -d: -f1)
    low_line=$(grep -n 'Low thing' "$REPORT_FILE" | head -1 | cut -d: -f1)
    fw_line=$(grep -n '^## Firewall' "$REPORT_FILE" | cut -d: -f1)
    [ "$score_line" -lt "$crit_line" ]
    [ "$crit_line" -lt "$low_line" ]
    [ "$low_line" -lt "$fw_line" ]
    [ "$(grep -c 'Executive Summary' "$REPORT_FILE")" -eq 1 ]
    refute grep -q 'Quick Remediation' "$REPORT_FILE"
}

@test "report: checks that were not assessed are listed with their reason" {
    RUN_ID=test
    _write_report_header > "$REPORT_FILE"
    _run_check check_fake_na
    _run_check check_fake_skip
    write_final_report
    grep -q 'check_fake_na.*not here' "$REPORT_FILE"
    grep -q 'check_fake_skip.*tool missing' "$REPORT_FILE"
}

# ---- colours -----------------------------------------------------------------

@test "no colour codes when output is not a terminal or NO_COLOR is set" {
    PATH="$ORIG_PATH" bash -c 'source "$1"; print_status OK hello' _ "$REPO_ROOT/ubuntu-sec-audit.sh" > "$T/plain.txt"
    refute grep -q $'\033' "$T/plain.txt"
    PATH="$ORIG_PATH" NO_COLOR=1 bash -c 'source "$1"; [ -z "$RED$RESET" ]' _ "$REPO_ROOT/ubuntu-sec-audit.sh"
}

# ---- environment detection ---------------------------------------------------

@test "a podman or Kubernetes container is detected as a container, not a VM" {
    mock_cmd systemd-detect-virt 'case "$1" in --container) echo podman ;; --vm) echo none; exit 1 ;; *) echo podman ;; esac'
    [ "$(_detect_env)" = "container" ]
}

@test "/run/.containerenv (podman) marks a container" {
    mkdir -p "$AUDIT_ROOT/run"
    : > "$AUDIT_ROOT/run/.containerenv"
    [ "$(_detect_env)" = "container" ]
}

@test "a virtual machine is detected as vm" {
    mock_cmd systemd-detect-virt 'case "$1" in --container) echo none; exit 1 ;; --vm) echo kvm ;; *) echo kvm ;; esac'
    [ "$(_detect_env)" = "vm" ]
}

@test "Secure Boot and kernel lockdown are checked in VMs (UEFI VMs support them)" {
    ENV_TYPE=vm
    [ -z "$(_env_not_applicable check_secure_boot)" ]
    [ -z "$(_env_not_applicable check_kernel_lockdown)" ]
    ENV_TYPE=container
    [ -n "$(_env_not_applicable check_secure_boot)" ]
    [ -n "$(_env_not_applicable check_kernel_lockdown)" ]
}

@test "time synchronisation does not apply in containers (the host keeps time)" {
    ENV_TYPE=lxc
    [ -n "$(_env_not_applicable check_ntp)" ]
    ENV_TYPE=docker
    [ -n "$(_env_not_applicable check_ntp)" ]
    ENV_TYPE=vm
    [ -z "$(_env_not_applicable check_ntp)" ]
}

# ---- Ansible -------------------------------------------------------------

@test "Ansible: tasks run in bash and a failed fix fails the play at the end" {
    PATH="$ORIG_PATH" python3 -c 'import yaml' 2>/dev/null || skip "PyYAML not installed"
    ANSIBLE_MODE=1
    TITLES=("One" "Two"); REMEDIATIONS=("echo one" "echo two"); CHECK_IDS=(check_a check_b)
    CTRL_IDS_ALL=("" ""); SEVERITIES=(LOW LOW); _sorted_indices=(0 1)
    generate_ansible >/dev/null
    PATH="$ORIG_PATH" python3 -c '
import sys, yaml
tasks = yaml.safe_load(open(sys.argv[1]))[0]["tasks"]
fixes = [t for t in tasks if t["name"].startswith("Fix: ")]
assert len(fixes) == 2, tasks
for t in fixes:
    assert t["ansible.builtin.shell"]["executable"] == "/bin/bash", t
    assert "changed_when" not in t, t
    assert t["ignore_errors"] is True, t
last = tasks[-1]
assert "ansible.builtin.fail" in last, last
assert "fix_1_result" in str(last) and "fix_2_result" in str(last), last
' "$ANSIBLE_FILE"
}

@test "score: no check's weight is below the largest single finding it can report" {
    local line fn pts bad=""
    # "check_fn points" for every report_issue with a literal point value.
    while read -r fn pts; do
        [[ -n "${CHECK_WEIGHTS[$fn]:-}" ]] || continue
        (( pts <= CHECK_WEIGHTS[$fn] )) || bad+=" $fn($pts>${CHECK_WEIGHTS[$fn]})"
    done < <(awk '
        /^check_[a-z0-9_]+\(\)/ { fn = $1; sub(/\(\).*/, "", fn) }
        /report_issue[ \t]+[0-9]+/ { n = $0; sub(/.*report_issue[ \t]+/, "", n); sub(/[^0-9].*/, "", n); print fn, n }
        /report_issue[ \t]*\\$/ { if ((getline nl) > 0) { sub(/^[ \t]+/, "", nl); if (nl ~ /^[0-9]+/) { sub(/[^0-9].*/, "", nl); print fn, nl } } }
    ' "$REPO_ROOT"/checks/*.sh)
    [ -z "$bad" ] || { echo "weights too low:$bad"; return 1; }
}

@test "a partial run says its score covers only the checks it ran" {
    RUN_ONLY=(check_fake_fail)
    RUN_ID=test
    _write_report_header > "$REPORT_FILE"
    _run_check check_fake_fail
    write_final_report
    grep -qi 'partial run' "$REPORT_FILE"
    webhook_mock
    WEBHOOK_URL="https://hooks.example.com/x"
    send_webhook >/dev/null
    PATH="$ORIG_PATH" python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["partial"] is True, d
assert "partial" in d["text"], d
' "$T/curl.stdin"
}

@test "a full run is not called partial" {
    RUN_ID=test
    _write_report_header > "$REPORT_FILE"
    _run_check check_fake_pass
    write_final_report
    refute grep -qi 'partial run' "$REPORT_FILE"
}

@test "verify without --deep leaves out deep checks it would not run" {
    VERIFY_CHECKS=(check_umask check_deep_password_aging check_ssh)
    DEEP=0
    _drop_unrun_deep_checks >/dev/null
    [ "${VERIFY_CHECKS[*]}" = "check_umask check_ssh" ]
    VERIFY_CHECKS=(check_umask check_deep_password_aging)
    DEEP=1
    _drop_unrun_deep_checks >/dev/null
    [ "${VERIFY_CHECKS[*]}" = "check_umask check_deep_password_aging" ]
}

@test "verify without --deep, when only deep checks failed, says to add --deep" {
    [ "$(id -u)" -eq 0 ] || skip "end-to-end tests need root"
    fixture /etc/os-release $'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"'
    fixture /etc/login.defs "UMASK 027"
    mkdir -p "$T/e2e"
    jsonl "$T/e2e/sec-audit-findings-20260101-000000.jsonl" check_umask:satisfied check_deep_password_aging:not-satisfied
    run env PATH="$ORIG_PATH" AUDIT_ROOT="$AUDIT_ROOT" bash "$REPO_ROOT/ubuntu-sec-audit.sh" \
        --verify --check check_umask --skip-apt-update --output-dir "$T/e2e" </dev/null
    [ "$status" -eq 0 ]
    [[ "$output" == *"--deep"* ]]
    [[ "$output" != *"Nothing failed in earlier runs"* ]]
}

@test "the webhook payload can be built with errexit on, in a full run" {
    webhook_state
    _webhook_payload > "$T/payload.json"
    PATH="$ORIG_PATH" python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["partial"] is False, d' "$T/payload.json"
}

@test "sshd -T runs once per audit run, shared by the checks that need it" {
    : > "$T/sshd.calls"
    mock_cmd sshd 'echo x >> "'"$T"'/sshd.calls"; printf "%s\n" "port 22" "permitrootlogin no" "banner none"'
    mock_cmd ssh 'exit 0'
    _sshd_cache_start
    _run_check check_ssh
    _run_check check_login_banner
    _run_check check_firewall
    [ "$(wc -l < "$T/sshd.calls")" -eq 1 ]
}
