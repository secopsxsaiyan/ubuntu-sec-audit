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
    while true; do
        read -r -p "  Selection [1]: " _fw_input
        _fw_input="${_fw_input:-1}"
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
    read -r -p "  Select [1]: " _depth_input
    _depth_input="${_depth_input:-1}"
    [[ "$_depth_input" == "2" ]] && DEEP=1 || DEEP=0

    # Step 3: OSCAL Output
    echo ""
    echo "Step 3/5  OSCAL Output"
    echo "  Generate machine-readable OSCAL 1.1.2 Assessment Results JSON?"
    echo "  (Available for NIST/CIS; ISO 27001 & SOC 2 IDs written as props)"
    read -r -p "  [y/N]: " _oscal_input
    _oscal_input="${_oscal_input:-N}"
    [[ "${_oscal_input,,}" == "y" ]] && OSCAL_MODE=1 || OSCAL_MODE=0

    # Step 4: Output Directory
    echo ""
    echo "Step 4/5  Output Directory"
    _default_dir="${HOME}"
    read -r -p "  Where to save report, fix script, and OSCAL AR? [${_default_dir}]: " _outdir_input
    _outdir_input="${_outdir_input:-${_default_dir}}"
    OUTPUT_DIR="$_outdir_input"

    # Step 5: Skip apt update
    echo ""
    echo "Step 5/5  Skip apt update?"
    read -r -p "  Skip 'apt-get update' (use cached package index)? [y/N]: " _skip_apt_input
    _skip_apt_input="${_skip_apt_input:-N}"
    [[ "${_skip_apt_input,,}" == "y" ]] && SKIP_APT_UPDATE=1 || SKIP_APT_UPDATE=0

    # Sync OSCAL_CATALOG from wizard-selected primary framework
    case "${FRAMEWORKS[0]}" in
        nist|cis) OSCAL_CATALOG="${FRAMEWORKS[0]}" ;;
        *)        OSCAL_CATALOG="nist" ;;
    esac

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

    read -r -p "Proceed? [Y/n]: " _proceed_input
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
  --output-dir <dir>  Directory for report and fix script (default: home dir)
  --oscal             Generate OSCAL 1.1.2 Assessment Results JSON alongside Markdown report
  --catalog <name>    Control catalog for OSCAL: nist (SP 800-53 r5, default) or cis (Ubuntu benchmark)
  --profile <file>    OSCAL Profile JSON: only run checks whose controls are included in the profile
  --framework <list>  Comma-separated compliance frameworks: nist, cis, iso27001, soc2
                      First entry is primary (drives fix-script ordering). Default: nist
                      Example: --framework nist,iso27001,soc2
  --interactive       Force the setup wizard (auto-triggered in TTY when no flags are set)
  --check <list>      Run only these checks (comma-separated check_* ids)
  --skip  <list>      Skip these checks (comma-separated check_* ids)
  --verify            Re-run only checks that failed in the most recent previous run
  --webhook <url>     POST findings summary JSON to this URL at end of run
  --ansible           Generate an Ansible remediation playbook alongside the fix script
  --help              Show this help

OSCAL examples:
  sudo $0 --oscal
  sudo $0 --oscal --catalog cis
  sudo $0 --oscal --profile oscal/profiles/sshd-only.json
  sudo $0 --deep --oscal --output-dir /var/log/audits

Framework examples:
  sudo $0 --framework nist,iso27001,soc2
  sudo $0 --framework cis --output-dir /tmp/cis-audit

Targeted execution examples:
  sudo $0 --check check_ssh,check_firewall --skip-apt-update
  sudo $0 --skip check_docker_hardening,check_security_updates
  sudo $0 --verify --output-dir /var/log/audits
EOF
}

# Parse command-line flags; may launch the wizard.
parse_args() {
while [[ $# -gt 0 ]]; do
    case "$1" in
        --deep)             DEEP=1;            _FLAGS_SET=1 ;;
        --verbose)          VERBOSE=1 ;;
        --quick)            DEEP=0 ;;
        --skip-apt-update)  SKIP_APT_UPDATE=1 ;;
        --output-dir)
            shift
            [[ -z "${1:-}" ]] && { echo "--output-dir requires a path argument"; usage; exit 1; }
            OUTPUT_DIR="$1";   _FLAGS_SET=1
            ;;
        --oscal)            OSCAL_MODE=1;      _FLAGS_SET=1 ;;
        --catalog)
            shift
            [[ -z "${1:-}" ]] && { echo "--catalog requires nist or cis"; usage; exit 1; }
            case "$1" in
                nist|cis) OSCAL_CATALOG="$1"; FRAMEWORKS=("$1") ;;
                *) echo "Unknown catalog '$1': use nist or cis"; usage; exit 1 ;;
            esac
            _FLAGS_SET=1
            ;;
        --profile)
            shift
            [[ -z "${1:-}" ]] && { echo "--profile requires a file path"; usage; exit 1; }
            [[ ! -f "$1" ]] && { echo "--profile: file not found: $1"; exit 1; }
            OSCAL_PROFILE_FILE="$1"; _FLAGS_SET=1
            ;;
        --framework)
            shift
            [[ -z "${1:-}" ]] && { echo "--framework requires a value"; usage; exit 1; }
            IFS=',' read -ra FRAMEWORKS <<< "$1"
            for _fw in "${FRAMEWORKS[@]}"; do
                case "$_fw" in
                    nist|cis|iso27001|soc2) ;;
                    *) echo "Unknown framework '$_fw': use nist, cis, iso27001, soc2"; exit 1 ;;
                esac
            done
            _FLAGS_SET=1
            ;;
        --interactive)      INTERACTIVE_MODE=1 ;;
        --check)
            shift
            [[ -z "${1:-}" ]] && { echo "--check requires a value"; usage; exit 1; }
            IFS=',' read -ra RUN_ONLY <<< "$1"; _FLAGS_SET=1
            ;;
        --skip)
            shift
            [[ -z "${1:-}" ]] && { echo "--skip requires a value"; usage; exit 1; }
            IFS=',' read -ra SKIP_CHECKS <<< "$1"; _FLAGS_SET=1
            ;;
        --verify)           VERIFY_MODE=1;     _FLAGS_SET=1 ;;
        --webhook)
            shift
            [[ -z "${1:-}" ]] && { echo "--webhook requires a URL"; usage; exit 1; }
            [[ "$1" =~ ^https?:// ]] || { echo "--webhook URL must start with http:// or https://"; exit 1; }
            WEBHOOK_URL="$1";  _FLAGS_SET=1
            ;;
        --ansible)          ANSIBLE_MODE=1;    _FLAGS_SET=1 ;;
        --help)             usage; exit 0 ;;
        *)                  echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# Sync OSCAL_CATALOG from primary framework (iso27001/soc2 fall back to nist catalog)
case "${FRAMEWORKS[0]}" in
    nist|cis) OSCAL_CATALOG="${FRAMEWORKS[0]}" ;;
    *)        OSCAL_CATALOG="nist" ;;
esac

# Auto-trigger wizard: TTY + no intent flags passed
# --interactive forces it; any intent flag suppresses it
if [[ $INTERACTIVE_MODE -eq 1 ]] || \
   { [[ -t 0 ]] && [[ $_FLAGS_SET -eq 0 ]]; }; then
    _interactive_wizard
fi
}
