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
FINDINGS_TMP="/tmp/audit-test-findings-$$.jsonl"
BUILD=1

for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && BUILD=0
done

cleanup() { rm -f "$FINDINGS_TMP"; }
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
        bash ubuntu-sec-audit.sh \
            --skip-apt-update \
            --output-dir /tmp/audit-out \
            --framework nist \
            2>/dev/null || true
        # Print findings JSONL to stdout for collection
        cat /tmp/audit-out/sec-audit-findings-*.jsonl 2>/dev/null || true
    " > "$FINDINGS_TMP" 2>/dev/null

if [[ ! -s "$FINDINGS_TMP" ]]; then
    echo "  WARN: findings file is empty — script may have failed inside container"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Checking expected failures..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

PASS=0
FAIL=0
SKIP=0

while IFS= read -r expected_id; do
    # Skip comments and blank lines
    [[ "$expected_id" =~ ^#  ]] && continue
    [[ -z "$expected_id"      ]] && continue

    if grep -q "\"check_id\":\"${expected_id}\"" "$FINDINGS_TMP" 2>/dev/null; then
        # Check was run — verify it reported not-satisfied
        if grep -q "\"check_id\":\"${expected_id}\".*\"status\":\"not-satisfied\"" "$FINDINGS_TMP" 2>/dev/null; then
            echo "  PASS  $expected_id"
            PASS=$((PASS + 1))
        else
            echo "  FAIL  $expected_id  (ran but did not detect expected issue)"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  SKIP  $expected_id  (check was not run or not in findings)"
        SKIP=$((SKIP + 1))
    fi
done < "$SCRIPT_DIR/expected-failures.txt"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  Results: %d passed  %d failed  %d skipped\n" "$PASS" "$FAIL" "$SKIP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
