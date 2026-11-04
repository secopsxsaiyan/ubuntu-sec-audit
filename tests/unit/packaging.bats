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
    [[ "$exec" == "ExecStart=/opt/ubuntu-sec-audit/ubuntu-sec-audit.sh"* ]]
    [[ "$exec" != *"bash -c"* ]]
    [[ "$exec" != *"|| true"* ]]
}

@test "the program path of every service is literal (systemd does not expand it)" {
    local f path
    for f in "$REPO_ROOT"/systemd/*.service; do
        path=$(sed -n 's/^ExecStart=\([^ ]*\).*/\1/p' "$f")
        [[ "$path" == /* ]]
        [[ "$path" != *'$'* ]]
    done
}

@test "the entrypoint is executable, so ./ubuntu-sec-audit.sh and the units can run it" {
    [ -x "$REPO_ROOT/ubuntu-sec-audit.sh" ]
    if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
        run git -C "$REPO_ROOT" ls-files -s ubuntu-sec-audit.sh
        [[ "$output" == 100755* ]]
    fi
}

@test "systemd accepts every unit file" {
    command -v systemd-analyze >/dev/null 2>&1 || skip "systemd-analyze not installed"
    local d="$BATS_TEST_TMPDIR/units"
    mkdir -p "$d"
    cp "$REPO_ROOT"/systemd/* "$d/"
    # Point the units at this checkout so the program path exists.
    sed -i "s|/opt/ubuntu-sec-audit/|$REPO_ROOT/|g" "$d"/*.service
    run systemd-analyze verify "$d"/*.service "$d"/*.timer
    echo "$output"
    [ "$status" -eq 0 ]
    refute grep -qiE 'fatal|bad unit|not executable|invalid' <<< "$output"
}

@test "services are started by their timers only, never at boot" {
    refute grep -q '^\[Install\]' "$REPO_ROOT/systemd/ubuntu-sec-audit.service"
    refute grep -q '^\[Install\]' "$REPO_ROOT/systemd/ubuntu-sec-audit-deep.service"
    grep -q '^WantedBy=timers.target' "$REPO_ROOT/systemd/ubuntu-sec-audit.timer"
    grep -q '^WantedBy=timers.target' "$REPO_ROOT/systemd/ubuntu-sec-audit-deep.timer"
}

@test "services wait for the network to be up (webhook after a catch-up run at boot)" {
    local f
    for f in ubuntu-sec-audit.service ubuntu-sec-audit-deep.service; do
        grep -q '^Wants=network-online.target' "$REPO_ROOT/systemd/$f"
        grep -q '^After=network-online.target' "$REPO_ROOT/systemd/$f"
    done
}

@test "the deep service is not killed before it can write its report" {
    local t
    t=$(unit_value ubuntu-sec-audit-deep.service TimeoutStartSec)
    [[ "$t" == "infinity" || "$t" =~ ^([4-9]|[1-9][0-9]+)h$ ]]
}

@test "the README enables both timers" {
    grep -q 'enable --now ubuntu-sec-audit.timer' "$REPO_ROOT/README.md"
    grep -q 'enable --now ubuntu-sec-audit-deep.timer' "$REPO_ROOT/README.md"
}

@test "both services keep the report directory private" {
    grep -q '^ExecStartPre=/bin/chmod 700 ${REPORT_DIR}' "$REPO_ROOT/systemd/ubuntu-sec-audit.service"
    grep -q '^ExecStartPre=/bin/chmod 700 ${REPORT_DIR}' "$REPO_ROOT/systemd/ubuntu-sec-audit-deep.service"
}

@test "the script, the newest CHANGELOG release and the README name the same version" {
    local v line
    v=$(sed -n 's/^readonly SCRIPT_VERSION="\(.*\)"$/\1/p' "$REPO_ROOT/ubuntu-sec-audit.sh")
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
    # The release workflow publishes the section with this heading.
    [ "$(grep -m1 -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$REPO_ROOT/CHANGELOG.md")" = "## [$v]" ]
    grep -qE "^\[${v//./\\.}\]: https://" "$REPO_ROOT/CHANGELOG.md"
    # Every install command clones this release's tag.
    run grep -F 'git clone' "$REPO_ROOT/README.md"
    [ "$status" -eq 0 ]
    while IFS= read -r line; do
        [[ "$line" == *"clone --branch v${v} "* ]] \
            || { echo "not release v${v}: $line"; return 1; }
    done <<< "$output"
}

@test "every GitHub Action is pinned to a full commit SHA, not a movable tag" {
    local line
    run grep -hE '^[[:space:]]*(-[[:space:]]+)?uses:' "$REPO_ROOT"/.github/workflows/*.yml
    [ "$status" -eq 0 ]
    while IFS= read -r line; do
        [[ "$line" =~ uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}([[:space:]]|$) ]] \
            || { echo "not pinned to a commit: $line"; return 1; }
    done <<< "$output"
}

@test "the Docker image installs trestle in a venv and fails the build if it cannot" {
    refute grep -qE 'pip3? install.*\|\| true' "$REPO_ROOT/Dockerfile"
    grep -q 'python3 -m venv' "$REPO_ROOT/Dockerfile"
}

@test "the Docker docs say a container audits itself, not the host" {
    grep -qi 'audits the container' "$REPO_ROOT/Dockerfile"
    grep -qi 'audits the container' "$REPO_ROOT/README.md"
}
