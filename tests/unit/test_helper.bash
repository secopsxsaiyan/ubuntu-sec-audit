# shellcheck shell=bash
# Shared helpers for the bats unit tests.
#
# Each test sources ubuntu-sec-audit.sh (main() does not run when sourced),
# points file-based checks at a throwaway root via AUDIT_ROOT, and runs with a
# hermetic PATH that only holds core utilities plus whatever the test mocks.
# Real system tools (sshd, ufw, systemctl, sudo, ...) are therefore never
# called unless a test provides a mock for them.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT

# Core utilities the checks are allowed to use from the real system.
_HERMETIC_TOOLS=(
    bash sh cat cut tr sort uniq head tail wc date mkdir rm cp mv chmod chown
    ls basename dirname readlink realpath env xargs tee mktemp touch od seq
    sleep id grep sed find stat comm paste python3 timeout ln diff tac rev
    expr nl fold
)

load_audit() {
    ORIG_PATH="$PATH"
    export AUDIT_ROOT="$BATS_TEST_TMPDIR/root"
    mkdir -p "$AUDIT_ROOT"

    # shellcheck source=/dev/null
    source "$REPO_ROOT/ubuntu-sec-audit.sh"

    REPORT_DIR="$BATS_TEST_TMPDIR/out"
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="$REPORT_DIR/report.md"
    : > "$REPORT_FILE"
    FINDINGS_FILE="$REPORT_DIR/findings.jsonl"
    : > "$FINDINGS_FILE"

    _make_hermetic_path
}

_make_hermetic_path() {
    MOCK_BIN="$BATS_TEST_TMPDIR/bin"
    mkdir -p "$MOCK_BIN"
    local tool path
    for tool in "${_HERMETIC_TOOLS[@]}"; do
        path=$(PATH="$ORIG_PATH" command -v "$tool" 2>/dev/null) || continue
        [[ "$path" == /* ]] && ln -sf "$path" "$MOCK_BIN/$tool"
    done
    # Ubuntu's default awk is mawk; test against it whenever it exists so
    # gawk-only syntax (\s, \b, ...) is caught.
    path=$(PATH="$ORIG_PATH" command -v mawk 2>/dev/null \
        || PATH="$ORIG_PATH" command -v awk)
    ln -sf "$path" "$MOCK_BIN/awk"
    PATH="$MOCK_BIN"
}

# mock_cmd NAME [BODY]
# Create an executable NAME on the hermetic PATH. BODY is bash; it receives
# the original arguments. Without BODY the mock prints nothing and succeeds.
mock_cmd() {
    local name="$1" body="${2:-exit 0}"
    printf '#!%s\n%s\n' "$(PATH="$ORIG_PATH" command -v bash)" "$body" > "$MOCK_BIN/$name"
    chmod +x "$MOCK_BIN/$name"
}

# fixture PATH CONTENT — write a file under AUDIT_ROOT (PATH is absolute).
fixture() {
    local path="$AUDIT_ROOT$1"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$2" > "$path"
}

# Titles of every issue reported so far, one per line.
issue_titles() {
    printf '%s\n' "${TITLES[@]+"${TITLES[@]}"}"
}

# assert_issue SUBSTRING — some reported issue title contains SUBSTRING.
assert_issue() {
    if ! issue_titles | grep -qF -- "$1"; then
        echo "expected an issue containing: $1" >&2
        echo "issues reported:" >&2
        issue_titles | sed 's/^/  /' >&2
        return 1
    fi
}

# refute_issue SUBSTRING — no reported issue title contains SUBSTRING.
refute_issue() {
    if issue_titles | grep -qF -- "$1"; then
        echo "unexpected issue containing: $1" >&2
        issue_titles | sed 's/^/  /' >&2
        return 1
    fi
}

# Remediation text of the first issue whose title contains SUBSTRING.
remediation_for() {
    local i
    for i in "${!TITLES[@]}"; do
        if [[ "${TITLES[$i]}" == *"$1"* ]]; then
            printf '%s\n' "${REMEDIATIONS[$i]}"
            return 0
        fi
    done
    echo "no issue containing: $1" >&2
    return 1
}

# Non-comment, non-blank lines of some text on stdin.
executable_lines() {
    grep -vE '^[[:space:]]*(#|$)' || true
}

# findings_tsv — "check_id<TAB>status" for every record in FINDINGS_FILE.
findings_tsv() {
    python3 -c '
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if line:
        o = json.loads(line)
        print(o["check_id"] + "\t" + o["status"])
' "$FINDINGS_FILE"
}
