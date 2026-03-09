🛡️ Ubuntu Security Audit Script

**A comprehensive, CIS/Lynis-aligned security audit tool for Ubuntu LTS servers.**

Zero dependencies in **Standard mode** • Full remediation commands • Auto-generated fix script • Deep mode with ClamAV + Lynis + rkhunter + debsums

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com) 
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
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
- **Safe by design**: sudo keep-alive, interrupt handling, version guards

### What it checks (50+ controls)

#### Standard Checks
- Package updates & unattended-upgrades
- UFW / nftables / iptables firewall (IPv4 + IPv6 + logging)
- Open ports & deprecated services (FTP, Telnet, etc.)
- SSH hardening (root login, password auth, ciphers, idle timeouts, etc.)
- Users & sudo (NOPASSWD, plaintext passwords, UID 0)
- Critical file permissions (`/etc/shadow`, `sshd_config`, etc.)
- AppArmor, PAM lockout, password complexity, umask
- Kernel sysctl hardening, module blacklisting
- Core dumps, cron security, login banners
- Secure Boot, root PATH safety, journald persistence, APT repo security
- NTP sync, GRUB bootloader password

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
