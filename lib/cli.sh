# shellcheck shell=bash
# Command-line parsing, usage text and the interactive wizard.

# ====================== INTERACTIVE WIZARD ======================

_interactive_wizard() {
    echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║           Ubuntu Security Audit — Setup Wizard               ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    # Step 1: Compliance Frameworks
    echo ""
    echo "Step 1/5  Compliance Frameworks"
    echo "  Select one or more (space-separated numbers, or \"all\"):"
    echo "    [1] NIST SP 800-53 Rev 5    federal / enterprise baseline"
    echo "    [2] CIS Ubuntu 24.04 LTS    prescriptive benchmark"
    echo "    [3] ISO/IEC 27001:2022       international standard (Annex A)"
    echo "    [4] SOC 2 TSC 2017           service organization controls"
    echo "  First selection is primary (drives fix ordering)."
    # Defaults are the values already chosen (flags or earlier answers).
    local _fw_default="" _fw
    for _fw in "${FRAMEWORKS[@]}"; do
        case "$_fw" in
            nist) _fw_default+="${_fw_default:+ }1" ;; cis) _fw_default+="${_fw_default:+ }2" ;;
            iso27001) _fw_default+="${_fw_default:+ }3" ;; soc2) _fw_default+="${_fw_default:+ }4" ;;
        esac
    done
    _fw_default="${_fw_default:-1}"
    while true; do
        read -r -p "  Selection [${_fw_default}]: " _fw_input || _fw_input=""
        _fw_input="${_fw_input:-${_fw_default}}"
        if [[ "$_fw_input" == "all" ]]; then
            FRAMEWORKS=("nist" "cis" "iso27001" "soc2")
            break
        fi
        _fw_valid=1
        _fw_new=()
        for _num in $_fw_input; do
            case "$_num" in
                1) _fw_new+=("nist") ;;
                2) _fw_new+=("cis") ;;
                3) _fw_new+=("iso27001") ;;
                4) _fw_new+=("soc2") ;;
                *) echo "  Invalid selection '$_num'. Enter numbers 1-4 or 'all'."; _fw_valid=0; break ;;
            esac
        done
        if [[ "$_fw_valid" -eq 1 && ${#_fw_new[@]} -gt 0 ]]; then
            FRAMEWORKS=("${_fw_new[@]}")
            break
        fi
    done

    # Step 2: Audit Depth
    echo ""
    echo "Step 2/5  Audit Depth"
    echo "    [1] Standard   fast, zero extra dependencies        (~2-5 min)"
    echo "    [2] Deep       ClamAV + rkhunter + Lynis + SUID scan (~15-60 min)"
    local _depth_default=1
    [[ "$DEEP" -eq 1 ]] && _depth_default=2
    read -r -p "  Select [${_depth_default}]: " _depth_input || _depth_input=""
    _depth_input="${_depth_input:-${_depth_default}}"
    [[ "$_depth_input" == "2" ]] && DEEP=1 || DEEP=0

    # Step 3: OSCAL Output
    echo ""
    echo "Step 3/5  OSCAL Output"
    echo "  Generate machine-readable OSCAL 1.1.2 Assessment Results JSON?"
    echo "  (Available for NIST/CIS; ISO 27001 & SOC 2 IDs written as props)"
    local _oscal_default=N
    [[ "$OSCAL_MODE" -eq 1 ]] && _oscal_default=y
    read -r -p "  [${_oscal_default}]: " _oscal_input || _oscal_input=""
    _oscal_input="${_oscal_input:-${_oscal_default}}"
    [[ "${_oscal_input,,}" == "y" ]] && OSCAL_MODE=1 || OSCAL_MODE=0

    # Step 4: Output Directory
    echo ""
    echo "Step 4/5  Output Directory"
    # Same default as a run without the wizard (/var/log/ubuntu-sec-audit).
    local _default_dir="${OUTPUT_DIR:-${AUDIT_REPORT_DIR:-$(_default_report_dir)}}"
    read -r -p "  Where to save report, fix script, and OSCAL AR? [${_default_dir}]: " _outdir_input || _outdir_input=""
    _outdir_input="${_outdir_input:-${_default_dir}}"
    OUTPUT_DIR="$_outdir_input"

    # Step 5: Skip apt update
    echo ""
    echo "Step 5/5  Skip apt update?"
    local _skip_default=N
    [[ "$SKIP_APT_UPDATE" -eq 1 ]] && _skip_default=y
    read -r -p "  Skip 'apt-get update' (use cached package index)? [${_skip_default}]: " _skip_apt_input || _skip_apt_input=""
    _skip_apt_input="${_skip_apt_input:-${_skip_default}}"
    [[ "${_skip_apt_input,,}" == "y" ]] && SKIP_APT_UPDATE=1 || SKIP_APT_UPDATE=0

    # OSCAL catalog follows the primary framework unless --catalog was given
    _sync_catalog

    # Build display labels
    _wiz_fw_labels=()
    for _fw in "${FRAMEWORKS[@]}"; do
        case "$_fw" in
            nist)     _wiz_fw_labels+=("NIST SP 800-53 Rev 5") ;;
            cis)      _wiz_fw_labels+=("CIS Ubuntu 24.04 LTS") ;;
            iso27001) _wiz_fw_labels+=("ISO/IEC 27001:2022") ;;
            soc2)     _wiz_fw_labels+=("SOC 2 TSC 2017") ;;
        esac
    done
    _wiz_fw_str=$(IFS=', '; echo "${_wiz_fw_labels[*]}")
    _wiz_primary_label="${_wiz_fw_labels[0]:-NIST SP 800-53 Rev 5}"

    echo ""
    echo "──────────────────────────────────────────────────────────────"
    printf "  Frameworks : %s\n"  "$_wiz_fw_str"
    printf "  Primary    : %s (fix ordering and grouping)\n" "$_wiz_primary_label"
    printf "  Mode       : %s\n"  "$([[ $DEEP -eq 1 ]] && echo "Deep" || echo "Standard")"
    printf "  OSCAL      : %s\n"  "$([[ $OSCAL_MODE -eq 1 ]] && echo "Yes  →  catalog: ${OSCAL_CATALOG}" || echo "No")"
    printf "  Output     : %s\n"  "$OUTPUT_DIR"
    echo "──────────────────────────────────────────────────────────────"

    read -r -p "Proceed? [Y/n]: " _proceed_input || _proceed_input=""
    _proceed_input="${_proceed_input:-Y}"
    if [[ "${_proceed_input,,}" == "n" ]]; then
        echo "Audit cancelled."
        exit 0
    fi
    echo ""
}

# ====================== CLI PARSING ======================
usage() {
    cat << EOF
ubuntu-sec-audit ${SCRIPT_VERSION}
Usage: sudo $0 [OPTIONS]
Options:
  --deep              Enable Deep mode (extra checks + optional tools)
  --verbose           Show detailed output for every check
  --quick             Force Standard mode (default)
  --skip-apt-update   Skip apt-get update (use cached package index)
  --output-dir <dir>  Directory for report and fix script, writable only by
                      root (default: /var/log/ubuntu-sec-audit)
  --oscal             Generate OSCAL 1.1.2 Assessment Results JSON alongside Markdown report
  --catalog <name>    Control catalog for OSCAL: nist (SP 800-53 r5, default) or cis (Ubuntu benchmark)
  --profile <file>    OSCAL Profile JSON: only run checks whose controls are included in the profile
  --framework <list>  Comma-separated compliance frameworks: nist, cis, iso27001, soc2
                      First entry is primary (drives fix-script ordering). Default: nist
                      Example: --framework nist,iso27001,soc2
  --interactive       Force the setup wizard (auto-triggered in TTY when no flags are set)
  --check <list>      Run only these checks (comma-separated check_* ids,
                      including check_deep_* with --deep)
  --skip  <list>      Skip these checks (comma-separated check_* ids)
  --verify            Re-run only checks that failed in the most recent previous run
  --webhook <url>     POST findings summary JSON to this URL at end of run
                      (or set AUDIT_WEBHOOK_URL, which keeps the URL off the
                      command line, e.g. via a systemd EnvironmentFile)
  --fail-on <sev>     Exit with status 2 if any finding is at or above this
                      severity: critical, high, medium or low (for CI)
  --ansible           Generate an Ansible remediation playbook alongside the fix script
  --help              Show this help

The generated fix script changes nothing unless run with --apply or
confirmed fix by fix on a terminal; run it with --help for details.

OSCAL examples:
  sudo $0 --oscal
  sudo $0 --oscal --catalog cis
  sudo $0 --oscal --profile oscal/profiles/ssh-hardening.json
  sudo $0 --deep --oscal --output-dir /var/log/audits

Framework examples:
  sudo $0 --framework nist,iso27001,soc2
  sudo $0 --framework cis --output-dir /var/log/audits/cis

Targeted execution examples:
  sudo $0 --check check_ssh,check_firewall --skip-apt-update
  sudo $0 --skip check_docker_hardening,check_security_updates
  sudo $0 --verify --output-dir /var/log/audits
EOF
}

# _known_checks — every check id accepted by --check / --skip.
_known_checks() {
    printf '%s\n' "${STANDARD_CHECKS[@]}" "${DEEP_CHECKS[@]}"
}

# _parse_check_list FLAG VALUE ARRAY — split a comma list into ARRAY,
# mapping renamed checks and rejecting unknown names.
_parse_check_list() {
    local flag="$1" value="$2" id
    local -n _dest="$3"
    local -a ids=()
    IFS=',' read -ra ids <<< "$value"
    _dest=()
    for id in "${ids[@]}"; do
        [[ -z "$id" ]] && continue
        if [[ "$id" == "check_debsecan" ]]; then
            echo "Note: check_debsecan was replaced by check_security_updates; using that."
            id="check_security_updates"
        fi
        if ! _known_checks | grep -qxF "$id"; then
            echo "Unknown check: ${id} (${flag}). Valid checks:"
            _known_checks | sed 's/^/  /'
            exit 1
        fi
        _dest+=("$id")
    done
}

# _valid_webhook_url URL — http(s) URL without spaces, quotes, backslashes
# or control characters (it is handed to curl in a quoted config line).
_valid_webhook_url() {
    if [[ ! "$1" =~ ^https?://[^[:space:]\"\\]+$ || "$1" == *[[:cntrl:]]* ]]; then
        echo "Webhook URL must start with http:// or https:// and contain no spaces, quotes or backslashes"
        return 1
    fi
    return 0
}

# _sync_catalog — OSCAL catalog follows the primary framework (iso27001 and
# soc2 fall back to nist) unless --catalog chose one explicitly.
_sync_catalog() {
    [[ "${_CATALOG_SET:-0}" -eq 1 ]] && return 0
    case "${FRAMEWORKS[0]}" in
        nist|cis) OSCAL_CATALOG="${FRAMEWORKS[0]}" ;;
        *)        OSCAL_CATALOG="nist" ;;
    esac
}

# Parse command-line flags; may launch the wizard. Any flag counts as intent
# and stops the wizard from starting on its own (--interactive forces it).
parse_args() {
    _CATALOG_SET=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --deep)             DEEP=1 ;;
            --verbose)          VERBOSE=1 ;;
            --quick)            DEEP=0 ;;
            --skip-apt-update)  SKIP_APT_UPDATE=1 ;;
            --output-dir)
                shift
                [[ -z "${1:-}" ]] && { echo "--output-dir requires a path argument"; usage; exit 1; }
                OUTPUT_DIR="$1"
                ;;
            --oscal)            OSCAL_MODE=1 ;;
            --catalog)
                shift
                [[ -z "${1:-}" ]] && { echo "--catalog requires nist or cis"; usage; exit 1; }
                case "$1" in
                    nist|cis) OSCAL_CATALOG="$1"; _CATALOG_SET=1 ;;
                    *) echo "Unknown catalog '$1': use nist or cis"; usage; exit 1 ;;
                esac
                ;;
            --profile)
                shift
                [[ -z "${1:-}" ]] && { echo "--profile requires a file path"; usage; exit 1; }
                [[ ! -f "$1" ]] && { echo "--profile: file not found: $1"; exit 1; }
                OSCAL_PROFILE_FILE="$1"
                ;;
            --framework)
                shift
                [[ -z "${1:-}" ]] && { echo "--framework requires a value"; usage; exit 1; }
                local -a _fws=()
                local _fw
                IFS=',' read -ra _fws <<< "$1"
                for _fw in "${_fws[@]}"; do
                    case "$_fw" in
                        nist|cis|iso27001|soc2) ;;
                        *) echo "Unknown framework '$_fw': use nist, cis, iso27001, soc2"; exit 1 ;;
                    esac
                done
                FRAMEWORKS=("${_fws[@]}")
                ;;
            --interactive)      INTERACTIVE_MODE=1 ;;
            --check)
                shift
                [[ -z "${1:-}" ]] && { echo "--check requires a value"; usage; exit 1; }
                _parse_check_list --check "$1" RUN_ONLY
                ;;
            --skip)
                shift
                [[ -z "${1:-}" ]] && { echo "--skip requires a value"; usage; exit 1; }
                _parse_check_list --skip "$1" SKIP_CHECKS
                ;;
            --verify)           VERIFY_MODE=1 ;;
            --webhook)
                shift
                [[ -z "${1:-}" ]] && { echo "--webhook requires a URL"; usage; exit 1; }
                _valid_webhook_url "$1" || exit 1
                WEBHOOK_URL="$1"
                ;;
            --fail-on)
                shift
                case "${1:-}" in
                    critical|high|medium|low|CRITICAL|HIGH|MEDIUM|LOW) FAIL_ON="${1^^}" ;;
                    *) echo "--fail-on requires critical, high, medium or low"; exit 1 ;;
                esac
                ;;
            --ansible)          ANSIBLE_MODE=1 ;;
            --help)             usage; exit 0 ;;
            *)                  echo "Unknown option: $1"; usage; exit 1 ;;
        esac
        [[ "$1" != "--interactive" ]] && _FLAGS_SET=1
        shift
    done

    # The webhook URL usually holds a secret: AUDIT_WEBHOOK_URL (e.g. from a
    # root-only systemd EnvironmentFile) keeps it off the command line.
    if [[ -z "$WEBHOOK_URL" && -n "${AUDIT_WEBHOOK_URL:-}" ]]; then
        _valid_webhook_url "$AUDIT_WEBHOOK_URL" || exit 1
        WEBHOOK_URL="$AUDIT_WEBHOOK_URL"
    fi

    _sync_catalog

    # Auto-trigger wizard: terminal + no flags; --interactive forces it
    if [[ $INTERACTIVE_MODE -eq 1 ]] || { [[ -t 0 ]] && [[ $_FLAGS_SET -eq 0 ]]; }; then
        _interactive_wizard
    fi
}
