# shellcheck shell=bash
# Shared helpers: output, findings, severity, environment detection.

# ====================== ENVIRONMENT DETECTION ======================
# _detect_env — docker, lxc, container (any other: podman, Kubernetes,
# systemd-nspawn, ...), vm or bare-metal. Containers are checked first:
# "systemd-detect-virt" without --vm is also true inside containers.
_detect_env() {
    local virt=""
    if [[ -f "${AUDIT_ROOT}/.dockerenv" ]]; then echo "docker"; return 0; fi
    if [[ -f "${AUDIT_ROOT}/run/.containerenv" ]]; then echo "container"; return 0; fi
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        virt=$(systemd-detect-virt --container 2>/dev/null || true)
        case "$virt" in
            ""|none)         ;;
            docker)          echo "docker"; return 0 ;;
            lxc|lxc-libvirt) echo "lxc"; return 0 ;;
            *)               echo "container"; return 0 ;;
        esac
        if systemd-detect-virt --vm -q >/dev/null 2>&1; then echo "vm"; return 0; fi
        echo "bare-metal"
        return 0
    fi
    if grep -q 'lxc' "${AUDIT_ROOT}/proc/1/cgroup" 2>/dev/null; then
        echo "lxc"
    elif grep -qE 'docker|containerd|kubepods|libpod' "${AUDIT_ROOT}/proc/1/cgroup" 2>/dev/null; then
        echo "container"
    else
        echo "bare-metal"
    fi
}

# _in_container — true when ENV_TYPE is any kind of container.
_in_container() {
    case "${ENV_TYPE:-}" in docker|lxc|container) return 0 ;; esac
    return 1
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
    # Notes are display text; many checks write their line breaks as \n.
    note="${note//\\n/$'\n'}"

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
    CHECK_POINTS["$check_id"]=$(( ${CHECK_POINTS[$check_id]:-0} + points ))
    # Issue details are emitted once in the Final Report section (not inline here)
    # so each finding appears exactly once in the output.
    record_finding "$check_id" "$title" "not-satisfied" "$description" "$remediation" "$points"

    if [[ "$VERBOSE" -eq 1 ]]; then
        print_status "WARN" "${title}"
    fi
    return 0
}

prompt_install() {
    local tool="$1" pkg="${2:-$1}" yn=""
    command -v "$tool" >/dev/null 2>&1 && return 0
    # Unattended runs (systemd timer, CI) have no terminal: never prompt, and
    # never let a failed read end the audit.
    if [[ ! -t 0 ]]; then
        print_status "INFO" "$tool not installed - skipping its checks (non-interactive run; install ${pkg} to enable them)"
        return 0
    fi
    print_status "WARN" "$tool not found."
    read -r -p "   Install now? (y/N) " yn || yn=""
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        if [[ "$SKIP_APT_UPDATE" -eq 0 ]]; then
            apt-get update -qq || print_status "WARN" "apt-get update failed"
        fi
        if apt-get install -y "$pkg"; then
            print_status "OK" "$tool installed."
        else
            print_status "WARN" "Could not install ${pkg}; its checks will be skipped."
        fi
    else
        print_status "INFO" "Skipping $tool (install manually later)."
    fi
    return 0
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

# ====================== CONFIG PARSING HELPERS ======================
# All helpers read files under AUDIT_ROOT and use POSIX classes, never \s
# (Ubuntu's default awk is mawk).

# _conf_get KEY FILE... — values of "KEY = VALUE" or "KEY=VALUE" lines, in
# file order, one per line. Comments and surrounding blanks are ignored.
_conf_get() {
    local key="$1"
    shift
    [[ $# -gt 0 ]] || return 0
    awk -v k="$key" '
        { sub(/#.*/, ""); line = $0; sub(/^[ \t]+/, "", line) }
        index(line, k) == 1 {
            rest = substr(line, length(k) + 1)
            if (rest ~ /^[ \t]*=/) {
                sub(/^[ \t]*=[ \t]*/, "", rest)
                sub(/[ \t]+$/, "", rest)
                print rest
            }
        }' "$@" 2>/dev/null || true
}

# _pam_lines MODULE — active (non-comment) lines in /etc/pam.d using MODULE.
_pam_lines() {
    grep -hE "^[[:space:]]*[^#[:space:]].*[[:space:]/]${1}(\.so)?([[:space:]]|$)" \
        "${AUDIT_ROOT}/etc/pam.d/"* 2>/dev/null || true
}

# _pam_arg MODULE ARG — values of ARG=VALUE on active lines using MODULE.
_pam_arg() {
    _pam_lines "$1" | grep -oE "(^|[[:space:]])${2}=[^[:space:]]+" | cut -d= -f2 || true
}

# _systemd_conf_files NAME — NAME.conf and its drop-ins in the order systemd
# applies them (drop-ins sorted by file name; /etc overrides /run, which
# overrides /usr/lib). Later files win.
_systemd_conf_files() {
    local name="$1" d f
    local -A pick=()
    # Only existing files: mawk stops at a missing input file, which would
    # hide every drop-in.
    [[ -f "${AUDIT_ROOT}/etc/systemd/${name}.conf" ]] && printf '%s\n' "${AUDIT_ROOT}/etc/systemd/${name}.conf"
    for d in /usr/lib/systemd /usr/local/lib/systemd /run/systemd /etc/systemd; do
        for f in "${AUDIT_ROOT}${d}/${name}.conf.d/"*.conf; do
            [[ -f "$f" ]] && pick["${f##*/}"]="$f"
        done
    done
    [[ ${#pick[@]} -gt 0 ]] || return 0
    local base
    while IFS= read -r base; do
        printf '%s\n' "${pick[$base]}"
    done < <(printf '%s\n' "${!pick[@]}" | sort)
}

# _systemd_conf_value NAME KEY — effective value of KEY across NAME.conf and
# its drop-ins (last one wins); empty when unset.
_systemd_conf_value() {
    local -a files=()
    mapfile -t files < <(_systemd_conf_files "$1")
    _conf_get "$2" "${files[@]}" | tail -n 1
}

# ====================== SSH DAEMON ======================

# _sshd_effective_config — run "sshd -T" and set SSHD_CONF (its output) and
# SSHD_CONF_ERR (its error text). Returns non-zero when the effective
# configuration could not be read; callers must then not judge it.
# Ubuntu 22.10+ socket-activates ssh, and /run/sshd (which sshd -T insists
# on) only exists once the service has started. In that case sshd -T is run
# again in a private mount namespace with its own /run, so the audit still
# changes nothing on the host.
_sshd_effective_config() {
    local errf rc=0
    if [[ "${_SSHD_CACHE_ON:-0}" -eq 1 && -n "${_SSHD_CACHE_RC:-}" ]]; then
        SSHD_CONF="$_SSHD_CACHE_CONF"
        SSHD_CONF_ERR="$_SSHD_CACHE_ERR"
        return "$_SSHD_CACHE_RC"
    fi
    SSHD_CONF=""
    SSHD_CONF_ERR=""
    errf=$(mktemp) || return 1
    SSHD_CONF=$(sshd -T 2>"$errf") || rc=$?
    if [[ $rc -ne 0 ]] && grep -q 'privilege separation directory' "$errf" \
       && command -v unshare >/dev/null 2>&1; then
        rc=0
        SSHD_CONF=$(unshare -m sh -c \
            'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir -m 0755 /run/sshd && exec sshd -T' \
            2>"$errf") || rc=$?
    fi
    SSHD_CONF_ERR=$(head -c 300 "$errf" | tr '\n' ' ')
    rm -f "$errf"
    local ok=0
    [[ $rc -eq 0 && -n "$SSHD_CONF" ]] || ok=1
    if [[ "${_SSHD_CACHE_ON:-0}" -eq 1 ]]; then
        _SSHD_CACHE_CONF="$SSHD_CONF"
        _SSHD_CACHE_ERR="$SSHD_CONF_ERR"
        _SSHD_CACHE_RC=$ok
    fi
    return "$ok"
}

# _sshd_cache_start — from now on, _sshd_effective_config runs sshd -T once
# and reuses the answer (one audit run; check_ssh, check_login_banner and
# check_firewall all need it).
_sshd_cache_start() {
    _SSHD_CACHE_ON=1
    _SSHD_CACHE_RC=""
}

# ====================== SHARED CHECK HELPERS ======================
# Used by more than one check.

# _uid_min — UID_MIN from login.defs (first UID of regular users), default 1000.
_uid_min() {
    local v
    v=$(awk '$1 == "UID_MIN" {print $2; exit}' "${AUDIT_ROOT}/etc/login.defs" 2>/dev/null || true)
    [[ "$v" =~ ^[0-9]+$ ]] || v=1000
    echo "$v"
}

# _sudoers_files — /etc/sudoers, then the /etc/sudoers.d files sudo reads, in
# the order it reads them (by name, C locale). sudo skips names that contain
# a '.' or end in '~' (package-manager and editor leftovers), and so do we.
_sudoers_files() {
    local f name
    if [[ -f "${AUDIT_ROOT}/etc/sudoers" ]]; then
        printf '%s\n' "${AUDIT_ROOT}/etc/sudoers"
    fi
    for f in "${AUDIT_ROOT}/etc/sudoers.d/"*; do
        name="${f##*/}"
        [[ -f "$f" ]] || continue
        [[ "$name" == *.* || "$name" == *"~" ]] && continue
        printf '%s\n' "$f"
    done | LC_ALL=C sort
}

# Network filesystems are pruned: walking NFS/CIFS/sshfs homes is slow, can
# hang on an unreachable server, and their files belong to another host.
_NETFS_TYPES=(nfs nfs4 cifs smb3 smbfs ncpfs afs ceph
              fuse.sshfs fuse.glusterfs fuse.s3fs fuse.rclone davfs)

# _netfs_prune_args ARRAY_NAME — set ARRAY_NAME to find(1) arguments that
# prune network filesystems: find START "${a[@]}" <tests> -print
_netfs_prune_args() {
    local -n _out="$1"
    local t
    _out=()
    [[ ${#_NETFS_TYPES[@]} -gt 0 ]] || return 0
    _out=('(')
    for t in "${_NETFS_TYPES[@]}"; do _out+=(-fstype "$t" -o); done
    unset '_out[-1]'
    _out+=(')' -prune -o)
}

# _file_head FILE — the start of FILE, read with a size and time limit: the
# file sits in a directory a user controls and may have been swapped for a
# device or a FIFO since find listed it.
_file_head() {
    timeout 5 head -c 262144 -- "$1" 2>/dev/null || true
}

# A PEM private key of any kind: PRIVATE KEY, RSA/EC/DSA/OPENSSH PRIVATE KEY,
# ENCRYPTED PRIVATE KEY, ... Certificates and public keys never match.
_PRIVATE_KEY_RE='^[[:space:]]*-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'

# _has_private_key FILE — FILE holds a PEM private key.
_has_private_key() {
    grep -qE "$_PRIVATE_KEY_RE" < <(_file_head "$1")
}

# _chmod_fix_line MODE PATH — a remediation line that sets MODE on PATH as
# the owner PATH has now, without following a symlink planted before the
# fix runs (_safe_chmod_cmd). When that cannot be done safely, comment lines
# tell the operator what to change instead.
_chmod_fix_line() {
    local mode="$1" path="$2" owner why
    owner=$(stat -c '%U' -- "$path" 2>/dev/null || true)
    if [[ -n "$owner" && "$owner" != "UNKNOWN" ]]; then
        _safe_chmod_cmd "$owner" "$mode" "$path" && return 0
        why="a user other than root can rename a directory on its path"
    else
        why="its owner has no account"
    fi
    printf '# Not changed by this script (%s) - check it, then run by hand:\n#   sudo chmod %s %s\n' \
        "$why" "$mode" "$(printf '%q' "$path")"
}

# _ipv6_off_reason — why the running system has no IPv6, empty while IPv6 is
# up: "boot" when the kernel was booted with ipv6.disable=1 (or has no IPv6
# stack: /proc/sys/net without ipv6), "sysctl" when
# net.ipv6.conf.all.disable_ipv6 = 1. Used by check_firewall,
# check_kernel and check_ipv6_exposure. Never fails.
_ipv6_off_reason() {
    local proc="${AUDIT_ROOT}/proc" val
    if grep -qE '(^|[[:space:]])ipv6\.disable=1([[:space:]]|$)' "${proc}/cmdline" 2>/dev/null \
        || [[ -d "${proc}/sys/net" && ! -d "${proc}/sys/net/ipv6" ]]; then
        echo "boot"
        return 0
    fi
    val=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || true)
    if [[ "$val" == "1" ]]; then
        echo "sysctl"
    fi
    return 0
}

# ====================== PACKAGE OWNERSHIP ======================

# _usrmerge_alias PATH — the other spelling of PATH on merged-/usr systems
# (dpkg may have registered /bin/x while the file is found as /usr/bin/x).
_usrmerge_alias() {
    case "$1" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) printf '%s' "${1#/usr}" ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*)                 printf '%s' "/usr$1" ;;
    esac
}

# _dpkg_unowned PATH... — print the PATHs that no installed package owns.
# Package-owned SUID/SGID binaries and file capabilities are expected;
# anything else deserves a look.
_dpkg_unowned() {
    [[ $# -gt 0 ]] || return 0
    if ! command -v dpkg-query >/dev/null 2>&1; then
        printf '%s\n' "$@"
        return 0
    fi
    local p alias line
    local -a query=()
    local -A owned=()
    for p in "$@"; do
        query+=("$p")
        alias=$(_usrmerge_alias "$p")
        [[ -n "$alias" ]] && query+=("$alias")
    done
    while IFS= read -r line; do
        [[ "$line" == *": /"* ]] && owned["${line#*: }"]=1
    done < <(dpkg-query -S "${query[@]}" 2>/dev/null || true)
    for p in "$@"; do
        alias=$(_usrmerge_alias "$p")
        [[ -n "${owned[$p]:-}" ]] && continue
        [[ -n "$alias" && -n "${owned[$alias]:-}" ]] && continue
        printf '%s\n' "$p"
    done
}

# _mark_skipped REASON — the running check could not be performed (e.g. its
# tool is missing). It is recorded as "skipped", neither passed nor failed.
_mark_skipped() {
    [[ -n "${CURRENT_CHECK:-}" ]] && CHECK_SKIPPED["$CURRENT_CHECK"]="$1"
    print_status "INFO" "${CURRENT_CHECK:-check} skipped: $1"
}

# _mark_not_applicable REASON — the running check does not apply to this host
# (e.g. Docker hardening without Docker). Recorded as "not-applicable".
_mark_not_applicable() {
    [[ -n "${CURRENT_CHECK:-}" ]] && CHECK_NA["$CURRENT_CHECK"]="$1"
    print_status "INFO" "${CURRENT_CHECK:-check} not applicable: $1"
}

# _root_controlled_dir DIR — true if only root can change DIR or any of its
# ancestors (root-owned and not group/world-writable, or sticky), so nobody
# else can swap a path below it for a symlink.
_root_controlled_dir() {
    local d="$1" perm owner
    [[ "$d" == /* ]] || return 1    # dirname of a relative path never reaches /
    while :; do
        perm=$(stat -c '%a' -- "$d" 2>/dev/null) || return 1
        owner=$(stat -c '%u' -- "$d" 2>/dev/null) || return 1
        [[ "$owner" == 0 ]] || return 1
        if (( (8#$perm & 8#022) != 0 && (8#$perm & 8#1000) == 0 )); then
            return 1
        fi
        [[ "$d" == "/" ]] && return 0
        d=$(dirname -- "$d")
    done
}

# _safe_chmod_cmd OWNER MODE PATH — a remediation line that changes PATH's
# mode without following a symlink planted between the audit and the fix.
# A file owned by a user is changed as that user (runuser), so even a swapped
# path can only reach that user's own files. A root-owned file is changed
# directly only when no one else can rename anything on its path; otherwise
# this fails and the caller should leave the change to a person.
_safe_chmod_cmd() {
    local owner="$1" mode="$2" path="$3" q
    q=$(printf '%q' "$path")
    if [[ "$owner" != "root" ]]; then
        printf '[ -L %s ] || sudo /usr/sbin/runuser -u %s -- /bin/chmod %s -- %s\n' \
            "$q" "$(printf '%q' "$owner")" "$mode" "$q"
        return 0
    fi
    _root_controlled_dir "$(dirname -- "$path")" || return 1
    printf '[ -L %s ] || sudo /bin/chmod %s -- %s\n' "$q" "$mode" "$q"
}

# _redact_url URL — scheme://host[:port]/... ; webhook paths and query
# strings often carry the secret, so they are never printed or logged.
_redact_url() {
    local url="$1" scheme rest host
    scheme="${url%%://*}"
    rest="${url#*://}"
    host="${rest%%[/?#]*}"
    host="${host##*@}"
    printf '%s://%s/...' "$scheme" "$host"
}
