🛡️ Ubuntu Security Audit Script

**A comprehensive, CIS/Lynis-aligned security audit tool for Ubuntu LTS servers.**

Zero dependencies in **Standard mode** • Full remediation commands • Auto-generated fix script • Deep mode with ClamAV + Lynis + rkhunter + debsums

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com) 
[![Bash](https://img.shields.io/badge/Shell-bash-4EAA25.svg)](https://www.gnu.org/software/bash/)

---

## ✨ Features

- **Standard Mode** (default): Runs instantly with **zero extra packages**
- **Deep Mode** (`--deep`): Full filesystem scan + antivirus + rootkit detection + integrity checks
- **Exact remediation commands** - copy-paste ready
- **Auto-generated fix script** - one-click remediation (review first!)
- **Markdown report** with executive summary, score (A–F), and actionable sections
- **Score & grade** (0–100) based on CIS-aligned checks
- **Colorful terminal output** + verbose mode
- **Flexible output directory** via `--output-dir` or `$AUDIT_REPORT_DIR` env var
- **Safe by design**: sudo keep-alive, interrupt handling, version guards

### What it checks (50+ controls)

#### Standard Checks
- Package updates & unattended-upgrades
- UFW / nftables / iptables firewall (IPv4 + IPv6 + logging)
- Open ports & deprecated services (FTP, Telnet, etc.)
- SSH hardening (root login, password auth, ciphers, idle timeouts, MaxStartups, etc.)
- Users & sudo (NOPASSWD, plaintext passwords, UID 0)
- Critical file permissions (`/etc/shadow`, `sshd_config`, etc.)
- AppArmor, PAM lockout, password complexity (pwquality/cracklib), umask
- Kernel sysctl hardening, module blacklisting
- Core dumps, cron security, login banners
- Secure Boot, root PATH safety, journald persistence, rsyslog, APT repo security
- Unnecessary/dangerous packages, Docker daemon hardening
- NTP sync, IPv6 exposure, GRUB bootloader password
- **Fail2Ban** installation and SSH jail configuration

#### Deep Mode (extra)
- Non-whitelisted SUID/SGID binaries
- World-writable files & directories
- Unowned files
- Empty passwords & weak password aging
- Insecure mount options (`/tmp`, `/dev/shm`, `/var/tmp`)
- Package integrity (`debsums`)
- Rootkit scan (`rkhunter`)
- Antivirus scan (`ClamAV` on critical dirs)
- Full system audit (`Lynis`)
- auditd rules, file capabilities, user SSH key permissions

---

## 📋 Requirements

- **Ubuntu 20.04 LTS or newer** (tested up to 24.04)
- Run as **root** (`sudo`)
- Internet access (optional - only for Deep mode tools & updates)

---

## 🚀 Installation & Usage

### 1. Download the script

```bash
curl -L -O https://raw.githubusercontent.com/secopsxsaiyan/ubuntu-sec-audit/main/ubuntu-sec-audit.sh
chmod +x ubuntu-sec-audit.sh
```

### 2. Run it

```bash
# Standard audit (no extra packages needed)
sudo ./ubuntu-sec-audit.sh

# Deep audit (installs ClamAV, Lynis, rkhunter, debsums if missing)
sudo ./ubuntu-sec-audit.sh --deep

# Save report to a specific directory
sudo ./ubuntu-sec-audit.sh --output-dir /tmp/audit-results

# Verbose output (show detail for every check)
sudo ./ubuntu-sec-audit.sh --verbose

# Skip apt-get update (use cached package index)
sudo ./ubuntu-sec-audit.sh --skip-apt-update
```

### 3. Options

| Flag | Description |
|------|-------------|
| `--deep` | Enable Deep mode (extra checks + optional tools) |
| `--verbose` | Show detailed output for every check |
| `--quick` | Force Standard mode (default) |
| `--skip-apt-update` | Skip `apt-get update` (use cached package index) |
| `--output-dir <dir>` | Directory for report and fix script (default: home dir) |
| `--help` | Show help |

You can also set `AUDIT_REPORT_DIR` as an environment variable to control the output directory.

---

## 📄 Output

After the run you will find two files in the output directory (default: your home dir):

- `audit-report-YYYYMMDD-HHMM.md` — full Markdown report with score, findings, and remediation commands
- `fix-audit-YYYYMMDD-HHMM.sh` — auto-generated remediation script (**review before running**)

### Scoring

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

---

## ⚠️ Disclaimer

This script is provided for **educational and defensive security purposes**. Always review the generated fix script before applying changes to a production system. Some remediations may affect running services.
