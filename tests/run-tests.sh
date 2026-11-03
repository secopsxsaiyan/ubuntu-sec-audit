#!/usr/bin/env bash
# Ubuntu Security Audit — Integration Test Runner
# Builds a deliberately misconfigured Docker container, runs the audit script
# inside it, then verifies that every expected finding is detected.
#
# Usage: [UBUNTU_VERSION=24.04] bash tests/run-tests.sh [--no-build]
#   --no-build  Skip image rebuild (use existing ubuntu-sec-audit-test image)
#
# Requirements: docker, bash 4+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
# Ubuntu release to test, e.g. UBUNTU_VERSION=20.04 bash tests/run-tests.sh
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"
IMAGE_NAME="ubuntu-sec-audit-test:${UBUNTU_VERSION}"
FINDINGS_TMP="$(mktemp)"
AUDIT_LOG="$(mktemp)"
BUILD=1

for arg in "$@"; do
    [[ "$arg" == "--no-build" ]] && BUILD=0
done

cleanup() { rm -f "$FINDINGS_TMP" "$AUDIT_LOG"; }
trap cleanup EXIT

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Ubuntu Security Audit — Integration Tests (Ubuntu ${UBUNTU_VERSION})"
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
    docker build --build-arg "UBUNTU_VERSION=${UBUNTU_VERSION}" -t "$IMAGE_NAME" "$SCRIPT_DIR" \
        && echo "  Built: $IMAGE_NAME" \
        || { echo "  FAIL: docker build failed"; exit 1; }
else
    echo ""
    echo "[2/3] Skipping build (--no-build)"
fi

# 3. Run audit inside container and collect findings. The audit's own output
# goes to stderr so stdout carries only the findings JSONL; the script also
# reports, on stderr, the audit's exit status and which outputs exist.
echo ""
echo "[3/3] Running audit in container..."
docker run --rm -i \
    --name "sec-audit-test-$$" \
    -v "$REPO_DIR":/opt/ubuntu-sec-audit:ro \
    "$IMAGE_NAME" \
    bash -s > "$FINDINGS_TMP" 2> "$AUDIT_LOG" <<'INNER' || true
out=/tmp/audit-out
mkdir -p "$out"
cd /opt/ubuntu-sec-audit
rc=0
bash ubuntu-sec-audit.sh --skip-apt-update --oscal --output-dir "$out" \
    --framework nist </dev/null 1>&2 || rc=$?
echo "RESULT audit-exit=${rc}" >&2
cat "$out"/sec-audit-findings-*.jsonl
for pat in 'sec-audit-report-*.md' 'sec-audit-report-*.html' 'oscal-ar-*.json' 'fix-audit-*.sh'; do
    if compgen -G "$out/$pat" >/dev/null; then
        echo "RESULT output-ok=${pat}" >&2
    else
        echo "RESULT output-missing=${pat}" >&2
    fi
done
if python3 -c 'import glob, json, sys
d = json.load(open(glob.glob(sys.argv[1] + "/oscal-ar-*.json")[0]))
sys.exit(0 if "assessment-results" in d else 1)' "$out"; then
    echo "RESULT oscal-json=ok" >&2
else
    echo "RESULT oscal-json=bad" >&2
fi
if bash -n "$out"/fix-audit-*.sh; then
    echo "RESULT fix-syntax=ok" >&2
else
    echo "RESULT fix-syntax=bad" >&2
fi
INNER

if [[ ! -s "$FINDINGS_TMP" ]]; then
    echo "  FAIL: no findings were produced. Audit output (last 40 lines):"
    tail -40 "$AUDIT_LOG"
    exit 1
fi

# A crash in the reporting stage (HTML, OSCAL, fix script) must fail the test
# even though findings were written.
_failed=0
grep -q '^RESULT audit-exit=0$' "$AUDIT_LOG" \
    || { echo "  FAIL: the audit did not exit 0: $(grep '^RESULT audit-exit' "$AUDIT_LOG")"; _failed=1; }
if grep -q '^RESULT output-missing=' "$AUDIT_LOG"; then
    echo "  FAIL: outputs missing:"
    grep '^RESULT output-missing=' "$AUDIT_LOG" | sed 's/^RESULT output-missing=/    /'
    _failed=1
fi
grep -q '^RESULT oscal-json=ok$' "$AUDIT_LOG" \
    || { echo "  FAIL: the OSCAL Assessment Results are not valid"; _failed=1; }
grep -q '^RESULT fix-syntax=ok$' "$AUDIT_LOG" \
    || { echo "  FAIL: the generated fix script has syntax errors"; _failed=1; }
if [[ $_failed -ne 0 ]]; then
    echo "  Audit output (last 40 lines):"
    grep -v '^RESULT ' "$AUDIT_LOG" | tail -40
    exit 1
fi
echo "  PASS: audit exited 0; Markdown, HTML, OSCAL and fix script were produced"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Checking expected failures..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# The verdict script fails on any missing check, so an empty or broken run
# can never pass.
python3 "$SCRIPT_DIR/check_expected.py" "$FINDINGS_TMP" "$SCRIPT_DIR/expected-failures.txt"
