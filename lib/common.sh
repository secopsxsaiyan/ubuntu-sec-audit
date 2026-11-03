# shellcheck shell=bash
# Shared helpers: output, findings, severity, environment detection.

# ====================== ENVIRONMENT DETECTION ======================
_detect_env() {
    if [[ -f /.dockerenv ]] || grep -qE 'docker|containerd' /proc/1/cgroup 2>/dev/null; then
        echo "docker"
    elif grep -q 'lxc' /proc/1/cgroup 2>/dev/null; then
        echo "lxc"
    elif command -v systemd-detect-virt >/dev/null 2>&1 \
         && systemd-detect-virt -q 2>/dev/null; then
        echo "vm"
    else
        echo "bare-metal"
    fi
}

# ====================== HELPER FUNCTIONS ======================
print_status() {
    local type="$1" msg="$2"
    case "$type" in
        OK)   echo -e "${GREEN}[✓]${RESET} $msg" ;;
        WARN) echo -e "${YELLOW}[⚠]${RESET} $msg" ;;
        ERR)  echo -e "${RED}[✗]${RESET} $msg" ;;
        INFO) echo -e "${BLUE}[i]${RESET} $msg" ;;
    esac
}

append_report() {
    printf '%b\n' "$1" >> "$REPORT_FILE"
}

report_issue() {
    local points="$1"
    local title="$2"
    local description="$3"
    local remediation="$4"
    local is_deep="${5:-0}"
    local note="${6:-}"

    SCORE=$((SCORE - points))
    [[ $SCORE -lt 0 ]] && SCORE=0

    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    [[ "$is_deep" -eq 1 ]] && DEEP_ISSUE_COUNT=$((DEEP_ISSUE_COUNT + 1))

    local sev
    sev=$(_severity_from_points "$points")
    SEVERITIES+=("$sev")

    local entry="### 🔴 [${sev}] ${title} (${points} pts)
**Issue**: ${description}
**Remediation**:
\`\`\`bash
${remediation}
\`\`\`
${note:+**Note**: ${note}}"

    ISSUES+=("$entry")
    TITLES+=("$title")
    REMEDIATIONS+=("$remediation")
    # Attribute the finding to the check being run (set by _run_check);
    # fall back to the calling function when report_issue is used directly.
    local check_id="${CURRENT_CHECK:-${FUNCNAME[1]:-unknown}}"
    CHECK_IDS+=("$check_id")
    CTRL_IDS_ALL+=("$(_ctrl_ids_for "$check_id")")
    CHECK_FAILED["$check_id"]=1
    # Issue details are emitted once in the Final Report section (not inline here)
    # so each finding appears exactly once in the output.
    record_finding "$check_id" "$title" "not-satisfied" "$description" "$remediation" "$points"

    if [[ "$VERBOSE" -eq 1 ]]; then
        print_status "WARN" "${title}"
    fi
    return 0
}

prompt_install() {
    local tool="$1" pkg="${2:-$1}"
    if ! command -v "$tool" >/dev/null 2>&1; then
        print_status "WARN" "$tool not found."
        read -r -p "   Install now? (y/N) " yn
        if [[ "$yn" =~ ^[Yy]$ ]]; then
            # FIX: honour --skip-apt-update flag; don't unconditionally run apt-get update
            if [[ "$SKIP_APT_UPDATE" -eq 0 ]]; then
                sudo apt-get update -qq
            fi
            sudo apt-get install -y "$pkg" && print_status "OK" "$tool installed."
        else
            print_status "INFO" "Skipping $tool (install manually later)."
        fi
    fi
}

# ====================== OSCAL HELPERS ======================

_severity_from_points() {
    local p=$1
    if   [[ $p -ge 20 ]]; then echo "CRITICAL"
    elif [[ $p -ge 10 ]]; then echo "HIGH"
    elif [[ $p -ge  5 ]]; then echo "MEDIUM"
    else                        echo "LOW"
    fi
}

# _json_escape_into VAR STRING — set VAR to STRING encoded as a JSON string
# literal (including the surrounding quotes). Pure bash; no python3 needed.
_json_escape_into() {
    local -n _out="$1"
    local s="$2" i c r
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    if [[ "$s" == *[[:cntrl:]]* ]]; then
        for i in {1..31}; do
            printf -v c "\\x$(printf '%02x' "$i")"
            [[ "$s" == *"$c"* ]] || continue
            printf -v r '\\u%04x' "$i"
            s=${s//"$c"/"$r"}
        done
    fi
    _out="\"${s}\""
}

# record_finding: appends one JSON object per line to FINDINGS_FILE.
# Args: check_id  title  status(satisfied|not-satisfied|error)  evidence  remediation  points
record_finding() {
    [[ -z "${FINDINGS_FILE:-}" ]] && return 0
    local check_id="$1" title="$2" status="$3" evidence="$4" remediation="${5:-}" points="${6:-0}"
    [[ "$points" =~ ^[0-9]+$ ]] || points=0
    local ts j_id j_title j_status j_evidence j_rem j_ts
    ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    _json_escape_into j_id "$check_id"
    _json_escape_into j_title "$title"
    _json_escape_into j_status "$status"
    _json_escape_into j_evidence "$evidence"
    _json_escape_into j_rem "$remediation"
    _json_escape_into j_ts "$ts"
    printf '{"check_id": %s, "title": %s, "status": %s, "evidence": %s, "remediation": %s, "points": %d, "timestamp": %s}\n' \
        "$j_id" "$j_title" "$j_status" "$j_evidence" "$j_rem" "$points" "$j_ts" \
        >> "$FINDINGS_FILE"
}

# ====================== LOCAL SERVICE VERSION DETECTION ======================
get_service_version() {
    local prog="$1"
    local pid="${2:-}"

    local bin
    bin=$(basename "$prog" 2>/dev/null || echo "$prog")

    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        local exe
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        if [[ -n "$exe" ]]; then
            local pkg
            pkg=$(dpkg -S "$exe" 2>/dev/null | head -n1 | cut -d: -f1 || true)
            if [[ -n "$pkg" ]]; then
                dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null && return
            fi
        fi
    fi

    case "$bin" in
        sshd)
            local sshd_ver ssh_ver
            sshd_ver=$(timeout 2 sshd -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            ssh_ver=$(timeout 2 ssh -V 2>&1 | head -n1 | sed 's/OpenSSH_//' || echo "N/A")
            if [[ "$sshd_ver" != "N/A" ]]; then
                echo "sshd:${sshd_ver} client:${ssh_ver}"
            else
                echo "client:${ssh_ver}"
            fi
            ;;
        nginx)
            timeout 2 nginx -v 2>&1 | head -n1 | sed 's/.*nginx version: nginx\///' || echo "N/A"
            ;;
        apache2|httpd)
            timeout 2 apache2 -v 2>&1 | grep -o 'Apache/[0-9.]*' || echo "N/A"
            ;;
        mysqld|mariadbd)
            timeout 2 mysqld --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        postgres|postmaster)
            timeout 2 postgres --version 2>&1 | head -n1 | grep -oE '[0-9]+\.[0-9.]+' || echo "N/A"
            ;;
        *)
            local pkg
            pkg=$(dpkg -l "*${bin}*" 2>/dev/null | grep '^ii' | head -n1 | awk '{print $2}' || true)
            [[ -n "$pkg" ]] && dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "N/A"
            ;;
    esac
}
