#!/usr/bin/env bash
# Ubuntu Security Audit — Integration Test Runner
# Builds a deliberately misconfigured Docker container, runs the audit script
# inside it, then verifies that every expected finding is detected.
#
# Usage: bash tests/run-tests.sh [--no-build]
#   --no-build  Skip image rebuild (use existing ubuntu-sec-audit-test image)
#
# Requirements: docker, bash 4+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="ubuntu-sec-audit-test"
FINDINGS_TMP="$(mktemp)"
AUDIT_LOG="$(mktemp)"
BUILD=1

for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && BUILD=0
done

cleanup() { rm -f "$FINDINGS_TMP" "$AUDIT_LOG"; }
trap cleanup EXIT

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Ubuntu Security Audit — Integration Tests"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Syntax check (fast, no Docker needed)
echo ""
echo "[1/3] Syntax check..."
bash -n "$REPO_DIR/ubuntu-sec-audit.sh" \
    && echo "  PASS: bash -n (no syntax errors)" \
    || { echo "  FAIL: syntax errors in ubuntu-sec-audit.sh"; exit 1; }

# 2. Build test container
if [[ $BUILD -eq 1 ]]; then
    echo ""
    echo "[2/3] Building test container..."
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR" \
        && echo "  Built: $IMAGE_NAME" \
        || { echo "  FAIL: docker build failed"; exit 1; }
else
    echo ""
    echo "[2/3] Skipping build (--no-build)"
fi

# 3. Run audit inside container and collect findings
echo ""
echo "[3/3] Running audit in container..."
docker run --rm \
    --name "sec-audit-test-$$" \
    -v "$REPO_DIR":/opt/ubuntu-sec-audit:ro \
    "$IMAGE_NAME" \
    bash -c "
        mkdir -p /tmp/audit-out
        cd /opt/ubuntu-sec-audit
        # Run as root (sudo not needed inside container)
        # The audit's own output goes to stderr so stdout carries only JSONL.
        bash ubuntu-sec-audit.sh \
            --skip-apt-update \
            --output-dir /tmp/audit-out \
            --framework nist \
            </dev/null 1>&2 || echo \"audit exited with \$?\" >&2
        cat /tmp/audit-out/sec-audit-findings-*.jsonl
    " > "$FINDINGS_TMP" 2> "$AUDIT_LOG" || true

if [[ ! -s "$FINDINGS_TMP" ]]; then
    echo "  FAIL: no findings were produced. Audit output (last 40 lines):"
    tail -40 "$AUDIT_LOG"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Checking expected failures..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# The verdict script fails on any missing check, so an empty or broken run
# can never pass.
python3 "$SCRIPT_DIR/check_expected.py" "$FINDINGS_TMP" "$SCRIPT_DIR/expected-failures.txt"
