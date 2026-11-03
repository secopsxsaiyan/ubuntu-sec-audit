#!/usr/bin/env bats
# systemd units and the Docker image.

load test_helper

unit() { cat "$REPO_ROOT/systemd/$1"; }

# unit_value FILE KEY — value of KEY= in a unit file (last one).
unit_value() { grep -E "^$2=" "$REPO_ROOT/systemd/$1" | tail -n 1 | cut -d= -f2-; }

@test "timers do not Require their service (that starts an audit at boot)" {
    refute grep -q '^Requires=' "$REPO_ROOT/systemd/ubuntu-sec-audit.timer"
    refute grep -q '^Requires=' "$REPO_ROOT/systemd/ubuntu-sec-audit-deep.timer"
}

@test "the deep timer fires on the first Sunday of the month" {
    local cal
    cal=$(unit_value ubuntu-sec-audit-deep.timer OnCalendar)
    [[ "$cal" == "Sun "* ]]
    if command -v systemd-analyze >/dev/null 2>&1; then
        run systemd-analyze calendar --iterations=3 "$cal"
        [ "$status" -eq 0 ]
        local elapses
        elapses=$(grep -E '(Next elapse|Iteration #[0-9]+):' <<< "$output")
        [ "$(wc -l <<< "$elapses")" -eq 3 ]
        # Every elapse is a Sunday on day 1-7 at 03:00.
        refute grep -vE ': Sun [0-9]{4}-[0-9]{2}-0[1-7] 03:00:00' <<< "$elapses"
    fi
}

@test "the deep service allows enough memory for ClamAV" {
    local mem
    mem=$(unit_value ubuntu-sec-audit-deep.service MemoryMax)
    [[ "$mem" =~ ^([0-9]+)G$ ]]
    [ "${BASH_REMATCH[1]}" -ge 3 ]
}

@test "the standard service runs the script directly and does not hide failures" {
    local exec
    exec=$(unit ubuntu-sec-audit.service | sed -n '/^ExecStart=/,/[^\\]$/p')
    [[ "$exec" == "ExecStart=\${SCRIPT_DIR}/ubuntu-sec-audit.sh"* ]]
    [[ "$exec" != *"bash -c"* ]]
    [[ "$exec" != *"|| true"* ]]
}

@test "both services keep the report directory private" {
    grep -q '^ExecStartPre=/bin/chmod 700 ${REPORT_DIR}' "$REPO_ROOT/systemd/ubuntu-sec-audit.service"
    grep -q '^ExecStartPre=/bin/chmod 700 ${REPORT_DIR}' "$REPO_ROOT/systemd/ubuntu-sec-audit-deep.service"
}

@test "the Docker image installs trestle in a venv and fails the build if it cannot" {
    refute grep -qE 'pip3? install.*\|\| true' "$REPO_ROOT/Dockerfile"
    grep -q 'python3 -m venv' "$REPO_ROOT/Dockerfile"
}

@test "the Docker docs say a container audits itself, not the host" {
    grep -qi 'audits the container' "$REPO_ROOT/Dockerfile"
    grep -qi 'audits the container' "$REPO_ROOT/README.md"
}
