# Ubuntu Security Audit

**A comprehensive, multi-framework security audit tool for Ubuntu LTS servers.**

Zero dependencies in Standard mode · Exact remediation commands · Auto-generated fix script, HTML report, and Ansible playbook · OSCAL 1.1.2 machine-readable output · Interactive setup wizard

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![Bash](https://img.shields.io/badge/Shell-bash-4EAA25.svg)](https://www.gnu.org/software/bash/)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-brightgreen)](https://github.com/secopsxsaiyan/ubuntu-sec-audit/actions)
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20ISO%2027001%20%7C%20SOC%202-blue)](#compliance-frameworks)
[![Version](https://img.shields.io/badge/version-2.1.0-informational)](#changelog)

---

## Features

- **Interactive wizard** — auto-triggered on first run; guides you through framework selection, audit depth, output options
- **37 standard checks** covering the full CIS Ubuntu 24.04 LTS Benchmark and NIST SP 800-53 Rev 5 surface
- **Multi-framework support** — annotate every finding against NIST SP 800-53 r5, CIS Ubuntu, ISO/IEC 27001:2022, and/or SOC 2 TSC 2017 simultaneously
- **Severity tiers** — every finding is automatically classified CRITICAL / HIGH / MEDIUM / LOW
- **HTML report** — self-contained, browser-ready report with score gauge, severity cards, and inline remediations (generated alongside the Markdown report when python3 is available)
- **Ansible playbook** (`--ansible`) — severity-sorted `remediate-*.yml` alongside the bash fix script, ready for fleet deployment
- **OSCAL 1.1.2 output** (`--oscal`) — machine-readable Assessment Results JSON for NIST and CIS catalogs
- **Delta report** — automatically compares the current run against the previous one and prints what was fixed, regressed, or newly failing
- **Verify mode** (`--verify`) — re-run only the checks that failed last time to confirm fixes worked
- **Webhook delivery** (`--webhook <url>`) — POST a findings summary to any SIEM, Slack, or HTTP endpoint
- **Container/VM awareness** — skips checks that don't apply in Docker, LXC, or VM environments
- **Secrets scan** — detects world-readable SSH keys, `.env` files with credentials, unprotected AWS credential files
- **Targeted execution** — `--check` and `--skip` flags to run specific subsets
- **Fix script** — framework-annotated, sorted by primary framework control family, with SSH-safe rollback and IPv6 disable helpers
- **Deep mode** (`--deep`) — full ClamAV scan + rkhunter + Lynis + SUID/SGID sweep + debsums
- **Zero standard-mode dependencies** — python3 unlocks HTML reports and OSCAL output; everything else is pure bash
- **ShellCheck CI** — all shell scripts gated by ShellCheck on every push

---

## Requirements

- **Ubuntu 20.04 LTS or newer** (tested up to 24.04)
- Run as **root** (`sudo`)
- `python3` — optional, enables HTML reports, OSCAL output, delta reports, webhook, and Ansible playbook

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/secopsxsaiyan/ubuntu-sec-audit.git
cd ubuntu-sec-audit

# Run — the interactive wizard will appear on a TTY
sudo ./ubuntu-sec-audit.sh

# Or non-interactively with explicit flags
sudo ./ubuntu-sec-audit.sh --framework nist --output-dir /var/log/audits --skip-apt-update
```

On the first TTY run with no flags the wizard walks you through five steps:

1. Compliance framework(s) to audit against
2. Standard or Deep mode
3. Whether to generate OSCAL output
4. Output directory
5. Skip apt update?

---

## Options

| Flag | Description |
|------|-------------|
| `--deep` | Deep mode: ClamAV + rkhunter + Lynis + SUID/SGID scan |
| `--verbose` | Print detail for every check, not just failures |
| `--quick` | Force Standard mode |
| `--skip-apt-update` | Use cached package index instead of running `apt-get update` |
| `--output-dir <dir>` | Directory for all output files (default: home dir) |
| `--framework <list>` | Comma-separated frameworks: `nist`, `cis`, `iso27001`, `soc2`. First entry is primary (drives fix-script ordering). Default: `nist` |
| `--interactive` | Force the wizard even when other flags are set |
| `--check <list>` | Run only these checks (comma-separated `check_*` ids) |
| `--skip <list>` | Skip these checks (comma-separated `check_*` ids) |
| `--verify` | Re-run only checks that failed in the most recent previous run |
| `--oscal` | Generate OSCAL 1.1.2 Assessment Results JSON |
| `--catalog <name>` | OSCAL catalog: `nist` (default) or `cis` |
| `--profile <file>` | OSCAL Profile JSON — run only checks whose controls are in the profile |
| `--ansible` | Generate an Ansible remediation playbook alongside the fix script |
| `--webhook <url>` | POST a findings summary JSON to this URL at end of run (`http://` or `https://` required) |
| `--help` | Show help and version |

You can also set `AUDIT_REPORT_DIR` as an environment variable to control the output directory.

---

## Output Files

Every run produces some or all of these files in the output directory:

| File | Always? | Description |
|------|---------|-------------|
| `sec-audit-report-*.md` | Yes | Markdown report with score, findings, remediation commands |
| `sec-audit-report-*.html` | python3 | Self-contained HTML report with score gauge and severity table (owner-read-only) |
| `sec-audit-findings-*.jsonl` | python3 | One JSON object per finding; used by delta, verify, OSCAL, and HTML generators |
| `fix-audit-*.sh` | Yes | Bash remediation script — framework-annotated and severity-sorted |
| `remediate-*.yml` | `--ansible` | Ansible playbook — severity-sorted, ready for `ansible-playbook` |
| `oscal-ar-*.json` | `--oscal` | OSCAL 1.1.2 Assessment Results (NIST or CIS catalog) |

All output files are written with restrictive permissions (owner-read-only where possible).

### Scoring

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

### Severity

Each finding is automatically classified based on its point deduction:

| Severity | Points |
|----------|--------|
| CRITICAL | ≥ 20 |
| HIGH | 10–19 |
| MEDIUM | 5–9 |
| LOW | < 5 |

---

## Compliance Frameworks

The script maps every check to one or more compliance frameworks. Select any combination with `--framework`:

| ID | Standard |
|----|----------|
| `nist` | NIST SP 800-53 Rev 5 |
| `cis` | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 |
| `iso27001` | ISO/IEC 27001:2022 Annex A |
| `soc2` | AICPA SOC 2 Trust Services Criteria 2017 |

With multi-framework selection, every fix block in the generated script shows the relevant control IDs for each framework:

```bash
# Fix 1: SSH configuration weaknesses found
# Severity      : HIGH
# NIST SP 800-53: AC-17,IA-5,SC-8,AC-3,AC-7
# ISO/IEC 27001 : A.8.5,A.8.20
# SOC 2 TSC     : CC6.1,CC6.2,CC6.6
```

---

## What It Checks

### Standard Checks (37)

| Category | Checks |
|----------|--------|
| **Patching** | Package updates, unattended-upgrades, pending reboot |
| **Network** | Firewall (UFW/nftables/iptables), open ports, IPv6 exposure, DNS security (DNSSEC/DoT) |
| **SSH** | Root login, password auth, ciphers, MACs, idle timeouts, MaxStartups, banners |
| **Access control** | Users/sudo (NOPASSWD, UID 0), cron permissions, PAM lockout, password complexity, umask |
| **File security** | Critical file permissions, home directory permissions, root PATH safety |
| **System hardening** | AppArmor, Secure Boot, GRUB password, kernel sysctl, kernel lockdown, core dumps |
| **Logging** | journald persistence, rsyslog, auditd rules |
| **Supply chain** | APT repo signing/HTTPS, unnecessary packages, Docker daemon hardening |
| **Integrity** | AIDE file integrity monitoring |
| **Intrusion detection** | Fail2Ban + SSH jail, failed login monitoring |
| **Time** | NTP/chrony/timesyncd synchronisation |
| **Virtualisation** | systemd service sandboxing (NoNewPrivileges, PrivateTmp, ProtectSystem) |
| **Vulnerability** | debsecan CVE exposure via Debian Security Tracker |
| **Secrets** | World-readable SSH keys, .env files with credentials, AWS credential files, SSL private key permissions |
| **Mount options** | `/tmp`, `/dev/shm`, `/var/tmp` noexec/nosuid/nodev |

### Deep Mode (extra)

- Non-whitelisted SUID/SGID binaries (full filesystem scan)
- World-writable files and directories
- Unowned files
- Empty passwords and weak password aging
- Package integrity verification (`debsums`)
- Rootkit scan (`rkhunter`)
- Antivirus scan (`ClamAV`)
- Full system audit (`Lynis`)
- User SSH key permission audit
- File capabilities (`getcap`)

---

## Examples

```bash
# Interactive wizard (TTY, no flags)
sudo ./ubuntu-sec-audit.sh

# NIST + ISO 27001 + SOC 2, OSCAL output
sudo ./ubuntu-sec-audit.sh --framework nist,iso27001,soc2 --oscal --output-dir /var/log/audits

# CIS benchmark, generate Ansible playbook
sudo ./ubuntu-sec-audit.sh --framework cis --ansible --output-dir /tmp/cis-audit

# Run only SSH and firewall checks
sudo ./ubuntu-sec-audit.sh --check check_ssh,check_firewall --skip-apt-update

# Skip checks not relevant to your environment
sudo ./ubuntu-sec-audit.sh --skip check_docker_hardening,check_debsecan

# After applying fixes, verify they worked
sudo ./ubuntu-sec-audit.sh --verify --output-dir /var/log/audits

# Deep audit with webhook notification
sudo ./ubuntu-sec-audit.sh --deep --webhook https://hooks.example.com/sec-audit

# OSCAL profile-filtered run (only SSH-related controls)
sudo ./ubuntu-sec-audit.sh --oscal --profile oscal/profiles/ssh-hardening.json
```

---

## Delta Report

After every run, if a previous findings file exists in the output directory, the terminal summary automatically shows what changed:

```
Changes since last run:
  ✔ Fixed       : check_updates check_unattended
  ↘ Regressed   : check_ssh
  ⚠ New failures: check_secrets
```

---

## OSCAL Integration

With `--oscal`, the script generates a valid OSCAL 1.1.2 Assessment Results document alongside the Markdown and HTML reports.

```bash
sudo ./ubuntu-sec-audit.sh --oscal --catalog nist --output-dir /var/log/audits
```

**Supporting files in `oscal/`:**

| File | Purpose |
|------|---------|
| `oscal_generate.py` | Builds the OSCAL AR from the findings JSONL |
| `update_ssp.py` | Updates an existing OSCAL SSP with assessment evidence |
| `html_report.py` | Generates the self-contained HTML report |
| `assessment_plan.json` | OSCAL Assessment Plan referenced by the AR |
| `component_definition.json` | Declares ubuntu-sec-audit as an OSCAL component |
| `profiles/ssh-hardening.json` | Profile: AC-17, IA-5, SC-8, AC-3, AC-7 |
| `profiles/logging-audit.json` | Profile: AU-2, AU-3, AU-8, AU-9, AU-12 |

ISO 27001 and SOC 2 control IDs are written as OSCAL `props` on each finding when those frameworks are selected alongside `--oscal`.

---

## Ansible Playbook

`--ansible` generates a `remediate-*.yml` file sorted CRITICAL → HIGH → MEDIUM → LOW, with per-framework control annotations on each task:

```yaml
# NIST: AC-17,IA-5,SC-8
# ISO27001: A.8.5,A.8.20
- name: "Fix: SSH configuration weaknesses found"
  ansible.builtin.shell: |
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    ...
  ignore_errors: true
  changed_when: false
```

Run locally or against a remote inventory:

```bash
# Local
ansible-playbook remediate-*.yml -i "localhost," -c local --become

# Remote fleet
ansible-playbook remediate-*.yml -i inventory --become
```

---

## Docker / CI

A `Dockerfile` is included for running audits in CI pipelines or air-gapped environments:

```bash
# Build
docker build -t ubuntu-sec-audit .

# Run
docker run --rm --privileged \
    -v /var/log/audits:/output \
    ubuntu-sec-audit \
    --oscal --catalog nist --output-dir /output
```

> `--privileged` is required for `sysctl`, `auditctl`, and `/proc` reads. For read-only CI checks use `--cap-add SYS_PTRACE` instead.

The script automatically detects Docker, LXC, and VM environments and skips checks that don't apply (Secure Boot, GRUB password, kernel lockdown).

---

## Automated Scheduling

`systemd/` contains ready-to-install unit files:

| File | Schedule |
|------|----------|
| `ubuntu-sec-audit.service/.timer` | Weekly (Sunday 02:00) with delta comparison |
| `ubuntu-sec-audit-deep.service/.timer` | Monthly (first Sunday 03:00) with ClamAV + Lynis |

```bash
sudo cp systemd/ubuntu-sec-audit.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ubuntu-sec-audit.timer
```

---

## Test Suite

`tests/` contains an integration test suite that builds a deliberately misconfigured Docker container and verifies the script detects every expected finding:

```bash
bash tests/run-tests.sh
```

Tests cover: SSH hardening, user/sudo configuration, firewall, unattended-upgrades, PAM lockout, login banners, umask, auditd, and secrets exposure.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## Disclaimer

This script is provided for **educational and defensive security purposes**. Always review the generated fix script and Ansible playbook before applying changes to a production system. Some remediations may affect running services.
