#!/usr/bin/env bash
# ShellCheck the whole project.
#
# The entrypoint is checked with -x so variables shared across modules are
# resolved. Modules are then checked one by one; SC2034 (unused) and SC2154
# (unassigned) are disabled there only, because globals live in other files.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SHELLCHECK="${SHELLCHECK:-shellcheck}"

"$SHELLCHECK" -x --shell=bash --severity=warning ubuntu-sec-audit.sh
"$SHELLCHECK" --shell=bash --severity=warning --exclude=SC2034,SC2154 \
    lib/*.sh checks/*.sh
"$SHELLCHECK" --shell=bash --severity=warning --exclude=SC1091 \
    tests/run-tests.sh tests/lint.sh tests/unit/test_helper.bash
echo "ShellCheck: clean"
