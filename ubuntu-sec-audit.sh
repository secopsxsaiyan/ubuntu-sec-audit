#!/usr/bin/env bash
# shellcheck shell=bash
# =============================================================================
# ubuntu-sec-audit.sh - Ubuntu LTS Security Audit (Standard + Deep mode)
# CIS/Lynis aligned - WITH EXACT REMEDIATION COMMANDS
# Deep mode includes FULL ClamAV antivirus scan + Lynis + rkhunter + debsums
# Zero dependencies in Standard mode.
# Requires: Ubuntu 20.04+, run as root/sudo
# =============================================================================
readonly SCRIPT_VERSION="2.1.0"

# ====================== NAMED CONSTANTS ======================
readonly FAILED_LOGIN_THRESHOLD=5
readonly MIN_UBUNTU_VERSION="20.04"

# ====================== CONFIG & GLOBALS ======================
SCORE=100
DEEP=0
VERBOSE=0
SKIP_APT_UPDATE=0
ISSUE_COUNT=0
DEEP_ISSUE_COUNT=0
SUDO_PID=""
OUTPUT_DIR=""
_AUDIT_START=$(date +%s)
# OSCAL mode globals
OSCAL_MODE=0
OSCAL_CATALOG="nist"
OSCAL_PROFILE_FILE=""
FINDINGS_FILE=""
OSCAL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -ga PROFILE_CONTROLS=()

# Arrays to collect issues, remediations, and titles separately
declare -ga ISSUES=()
declare -ga REMEDIATIONS=()
declare -ga TITLES=()

# Multi-framework support
declare -ga FRAMEWORKS=("nist")  # first element = primary (drives sort order)
INTERACTIVE_MODE=0
_FLAGS_SET=0   # set to 1 by any intent flag; suppresses wizard auto-trigger
declare -ga CHECK_IDS=()         # parallel to TITLES[]: which check_* filed the issue
declare -ga CTRL_IDS_ALL=()      # parallel to TITLES[]: "fw:ids|fw:ids" for all selected frameworks

# Severity tiers (auto-derived from points in report_issue)
declare -ga SEVERITIES=()

# Per-check state, keyed by check_* id.
declare -gA CHECK_FAILED=()      # set when a check reported at least one issue
declare -gA CHECK_STATUS=()      # satisfied | not-satisfied | error, after the check ran
declare -gA CHECK_ERRORS=()      # unexpected command failures inside a check
CURRENT_CHECK=""                 # check being run by _run_check (attributes findings)

# Control mapping, loaded once: CTRL_MAP["check_id|framework"]="ID1,ID2"
declare -gA CTRL_MAP=()
CONTROL_MAP_FILE="${OSCAL_SCRIPT_DIR}/mappings/control-mapping.json"

# Progress indicator
_CHECK_TOTAL=0
_CHECK_NUM=0

# Environment awareness
ENV_TYPE="bare-metal"

# Targeted check execution
declare -ga RUN_ONLY=()
declare -ga SKIP_CHECKS=()

# Verify mode
VERIFY_MODE=0
declare -ga VERIFY_CHECKS=()

# Webhook + Ansible
WEBHOOK_URL=""
ANSIBLE_MODE=0

# Colors & emojis (tput fallback to ANSI)
if command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); BLUE=$(tput setaf 4)
    BOLD=$(tput bold); RESET=$(tput sgr0)
else
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
    BOLD='\033[1m'; RESET='\033[0m'
fi

# SUID whitelist - paths resolved by readlink -f at runtime to handle /bin -> /usr/bin symlinks
SUID_WHITELIST=(
    "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/gpasswd" "/usr/bin/chsh"
    "/usr/bin/chfn" "/usr/bin/chage" "/usr/bin/mount" "/usr/bin/umount" "/usr/bin/newgrp"
    "/usr/bin/pkexec" "/usr/lib/openssh/ssh-keysign" "/usr/lib/policykit-1/polkit-agent-helper-1"
    "/usr/bin/fusermount3"
)

# SGID whitelist
SGID_WHITELIST=(
    "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent" "/usr/bin/bsd-write"
    "/usr/bin/crontab" "/usr/bin/expiry" "/usr/sbin/unix_chkpwd"
    "/usr/lib/openssh/ssh-keysign" "/usr/bin/chage" "/usr/bin/dotlockfile"
    "/usr/bin/lockfile" "/usr/sbin/pam_extrausers_chkpwd"
)

# ====================== MODULES ======================
# Every module is listed explicitly so `shellcheck -x` can follow them.
# shellcheck source=lib/cli.sh
source "${OSCAL_SCRIPT_DIR}/lib/cli.sh"
# shellcheck source=lib/common.sh
source "${OSCAL_SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/fixscript.sh
source "${OSCAL_SCRIPT_DIR}/lib/fixscript.sh"
# shellcheck source=lib/mapping.sh
source "${OSCAL_SCRIPT_DIR}/lib/mapping.sh"
# shellcheck source=lib/report.sh
source "${OSCAL_SCRIPT_DIR}/lib/report.sh"
# shellcheck source=lib/runner.sh
source "${OSCAL_SCRIPT_DIR}/lib/runner.sh"
# shellcheck source=checks/check_aide.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_aide.sh"
# shellcheck source=checks/check_apparmor.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_apparmor.sh"
# shellcheck source=checks/check_apt_repos.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_apt_repos.sh"
# shellcheck source=checks/check_auditd.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_auditd.sh"
# shellcheck source=checks/check_core_dumps.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_core_dumps.sh"
# shellcheck source=checks/check_cron.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_cron.sh"
# shellcheck source=checks/check_debsecan.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_debsecan.sh"
# shellcheck source=checks/check_disk_encryption.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_disk_encryption.sh"
# shellcheck source=checks/check_dns_security.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_dns_security.sh"
# shellcheck source=checks/check_docker_hardening.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_docker_hardening.sh"
# shellcheck source=checks/check_fail2ban.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_fail2ban.sh"
# shellcheck source=checks/check_failed_logins.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_failed_logins.sh"
# shellcheck source=checks/check_firewall.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_firewall.sh"
# shellcheck source=checks/check_grub_password.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_grub_password.sh"
# shellcheck source=checks/check_home_permissions.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_home_permissions.sh"
# shellcheck source=checks/check_idle_timeout.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_idle_timeout.sh"
# shellcheck source=checks/check_ipv6_exposure.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_ipv6_exposure.sh"
# shellcheck source=checks/check_journald.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_journald.sh"
# shellcheck source=checks/check_kernel.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_kernel.sh"
# shellcheck source=checks/check_kernel_lockdown.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_kernel_lockdown.sh"
# shellcheck source=checks/check_login_banner.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_login_banner.sh"
# shellcheck source=checks/check_mount_options.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_mount_options.sh"
# shellcheck source=checks/check_ntp.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_ntp.sh"
# shellcheck source=checks/check_open_ports.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_open_ports.sh"
# shellcheck source=checks/check_pam_lockout.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_pam_lockout.sh"
# shellcheck source=checks/check_pam_pwquality.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_pam_pwquality.sh"
# shellcheck source=checks/check_permissions.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_permissions.sh"
# shellcheck source=checks/check_reboot.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_reboot.sh"
# shellcheck source=checks/check_root_path.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_root_path.sh"
# shellcheck source=checks/check_rsyslog.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_rsyslog.sh"
# shellcheck source=checks/check_secrets.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_secrets.sh"
# shellcheck source=checks/check_secure_boot.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_secure_boot.sh"
# shellcheck source=checks/check_ssh.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_ssh.sh"
# shellcheck source=checks/check_systemd_service_hardening.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_systemd_service_hardening.sh"
# shellcheck source=checks/check_umask.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_umask.sh"
# shellcheck source=checks/check_unattended.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_unattended.sh"
# shellcheck source=checks/check_unnecessary_packages.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_unnecessary_packages.sh"
# shellcheck source=checks/check_updates.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_updates.sh"
# shellcheck source=checks/check_users.sh
source "${OSCAL_SCRIPT_DIR}/checks/check_users.sh"
# shellcheck source=checks/run_deep_checks.sh
source "${OSCAL_SCRIPT_DIR}/checks/run_deep_checks.sh"

# ====================== MAIN ======================
main() {
set -euo pipefail

# Must run as root (directly or via sudo)
if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root. Try: sudo $0 $*" >&2
    exit 1
fi

# ERR trap fires on any unexpected non-zero exit; INT/TERM for user interrupts
_INTERRUPTED=0
trap 'echo -e "\n\033[0;31m[✗] Unexpected error on line ${LINENO} (exit code: $?). Aborting.\033[0m"; exit 1' ERR
trap '_INTERRUPTED=1; echo -e "\n\033[0;33m[⚠] Audit interrupted. Report saved if possible.\033[0m"; exit 1' INT TERM

load_control_map
ENV_TYPE=$(_detect_env)
parse_args "$@"
init_run
run_all_checks
write_final_report
generate_fix_script
generate_ansible
generate_oscal
generate_html
send_webhook
print_summary
return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
