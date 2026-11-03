#!/usr/bin/env bats
# Tests for the test harness itself.

load test_helper

@test "mock_cmd replaces a hermetic symlink without touching its target" {
    load_audit
    local target="$BATS_TEST_TMPDIR/real-tool"
    printf 'original\n' > "$target"
    ln -sf "$target" "$MOCK_BIN/realtool"
    mock_cmd realtool 'echo mocked'
    [ "$(cat "$target")" = "original" ]
    [ ! -L "$MOCK_BIN/realtool" ]
    [ "$(realtool)" = "mocked" ]
}

@test "the hermetic PATH hides real system tools" {
    load_audit
    ! command -v sshd
    ! command -v sudo
    ! command -v systemctl
    command -v grep
}
