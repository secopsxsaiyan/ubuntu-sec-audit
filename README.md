# Ubuntu Security Audit

**A comprehensive, multi-framework security audit tool for Ubuntu LTS servers.**

Zero dependencies in Standard mode · Exact remediation commands · Auto-generated fix script, HTML report, and Ansible playbook · OSCAL 1.1.2 machine-readable output · Interactive setup wizard

[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![Bash](https://img.shields.io/badge/Shell-bash-4EAA25.svg)](https://www.gnu.org/software/bash/)
[![CI](https://github.com/secopsxsaiyan/ubuntu-sec-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/secopsxsaiyan/ubuntu-sec-audit/actions/workflows/ci.yml)
[![Frameworks](https://img.shields.io/badge/Frameworks-NIST%20%7C%20CIS%20%7C%20ISO%2027001%20%7C%20SOC%202-blue)](#compliance-frameworks)
[![Release](https://img.shields.io/github/v/release/secopsxsaiyan/ubuntu-sec-audit)](https://github.com/secopsxsaiyan/ubuntu-sec-audit/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

---

## Features

- **Interactive wizard** — auto-triggered on first run; guides you through framework selection, audit depth, output options
- **39 standard checks and 16 deep checks**, mapped to NIST SP 800-53 Rev 5, CIS Ubuntu 24.04 LTS v1.0.0, ISO/IEC 27001:2022 and SOC 2
- **Multi-framework support** — annotate every finding against NIST SP 800-53 r5, CIS Ubuntu, ISO/IEC 27001:2022, and/or SOC 2 TSC 2017 simultaneously
- **Severity tiers** — every finding is automatically classified CRITICAL / HIGH / MEDIUM / LOW
- **HTML report** — self-contained, browser-ready report with score gauge, severity cards, inline remediations, and the checks that were not assessed (skipped, not applicable or did not complete) with the reason (generated alongside the Markdown report when python3 is available)
- **Ansible playbook** (`--ansible`) — severity-sorted `remediate-*.yml` alongside the bash fix script; manual steps are left out and SSH tasks need `-e apply_ssh_changes=true`
- **OSCAL 1.1.2 output** (`--oscal`) — machine-readable Assessment Results JSON for NIST and CIS catalogs
- **Delta report** — compares every check with its last known result from earlier runs and prints what was fixed, regressed, or newly failing
- **Verify mode** (`--verify`) — re-run only the checks whose last known result was a failure, to confirm fixes worked
- **Webhook delivery** (`--webhook <url>` or `AUDIT_WEBHOOK_URL`) — POST a findings summary to any SIEM, Slack, or HTTP endpoint; the URL never appears in the process list
- **CI gating** (`--fail-on <severity>`) — exit with status 2 when a finding reaches that severity
- **Container awareness** — checks that cannot apply inside Docker, LXC or other containers are recorded as not applicable, never as passed
- **Secrets scan** — detects world-readable SSH keys, `.env` files with credentials, unprotected AWS credential files
- **Targeted execution** — `--check` and `--skip` flags to run specific subsets
- **Fix script** — changes nothing unless asked (`--apply`, or confirm each fix on a terminal); SSH changes roll back unless a new login is confirmed; risky steps (GRUB password, reboot, kernel lockdown, PAM, SUID bits, disk encryption, Secure Boot, DNSSEC, IP forwarding, who may use SSH) are written as manual instructions and never run
- **Deep mode** (`--deep`) — full ClamAV scan + rkhunter + Lynis + SUID/SGID sweep + debsums
- **Zero standard-mode dependencies** — the audit, findings file, delta report, verify mode, webhook payload and fix script are pure bash; python3 adds the HTML report, OSCAL output and `--profile` filtering
- **ShellCheck CI** — all shell scripts gated by ShellCheck on every push

---

## Requirements

- **Ubuntu 20.04 LTS or newer** (CI tests 20.04, 22.04, 24.04 and 26.04)
- Run as **root** (`sudo`)
- `python3` — optional (3.8 or newer), enables the HTML report, OSCAL output and `--profile` filtering
- `curl` — optional, for `--webhook`

---

## Quick Start

```bash
# Clone the latest release (leave out --branch for unreleased changes on main)
git clone --branch v2.4.0 https://github.com/secopsxsaiyan/ubuntu-sec-audit.git
cd ubuntu-sec-audit
./ubuntu-sec-audit.sh --version

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
| `--output-dir <dir>` | Directory for all output files; only root may be able to change it (default: `/var/log/ubuntu-sec-audit`) |
| `--framework <list>` | Comma-separated frameworks: `nist`, `cis`, `iso27001`, `soc2`. First entry is primary (drives fix-script ordering). Default: `nist` |
| `--interactive` | Force the wizard even when other flags are set |
| `--check <list>` | Run only these checks (comma-separated `check_*` ids) |
| `--skip <list>` | Skip these checks (comma-separated `check_*` ids) |
| `--verify` | Re-run only checks whose last known result (across earlier runs in the output directory) was a failure or an error |
| `--oscal` | Generate OSCAL 1.1.2 Assessment Results JSON |
| `--catalog <name>` | OSCAL catalog: `nist` (default) or `cis` |
| `--profile <file>` | OSCAL Profile JSON — run only checks whose controls are in the profile |
| `--ansible` | Generate an Ansible remediation playbook alongside the fix script |
| `--webhook <url>` | POST a findings summary JSON to this URL at end of run (`http://` or `https://` required). `AUDIT_WEBHOOK_URL` does the same without putting the URL on the command line |
| `--fail-on <severity>` | Exit with status 2 if any finding is at or above `critical`, `high`, `medium` or `low` |
| `--version` | Show the version |
| `--help` | Show help |

You can also set `AUDIT_REPORT_DIR` as an environment variable to control the output directory.

---

## Output Files

Every run produces some or all of these files in the output directory:

| File | Always? | Description |
|------|---------|-------------|
| `sec-audit-report-*.md` | Yes | Markdown report with score, findings, remediation commands |
| `sec-audit-report-*.html` | python3 | Self-contained HTML report with score gauge and severity table (owner-read-only) |
| `sec-audit-findings-*.jsonl` | Yes | One JSON object per finding: `satisfied`, `not-satisfied`, `error` (did not complete), `skipped` (could not be performed, e.g. tool missing) or `not-applicable`, with the reason as evidence; used by delta, verify, OSCAL, and HTML generators |
| `fix-audit-*.sh` | Yes | Bash remediation script — framework-annotated, opt-in (see [Fix Script](#fix-script)) |
| `remediate-*.yml` | `--ansible` | Ansible playbook — severity-sorted, ready for `ansible-playbook` |
| `oscal-ar-*.json` | `--oscal` | OSCAL 1.1.2 Assessment Results (NIST or CIS catalog), with `assessment-plan.json` copied next to it |

All files of one run share one run id (`YYYYMMDD-HHMMSS`) and are private to root (umask 077). The default output directory is `/var/log/ubuntu-sec-audit`.

Root writes the fix script there and runs it later, so the audit refuses an output directory that a user other than root could change: one owned by another user, or below such a directory, or below a directory others (or a group with regular users in it) can write to without the sticky bit. Otherwise that user could swap the fix script for their own, or plant a symlink so that root overwrites another file. Group-writable parents whose group holds only system accounts, such as `/var/log` (group `syslog`), are accepted. A directory reached through a symlink is used by its real path. If the output directory is not writable (read-only filesystem), a fresh private directory under `/tmp` is used.

### Scoring

Each check has a weight: the most its findings can deduct. The score is the weighted share of the assessed checks that passed, where a failing check keeps its weight minus the points it lost (never below 0). Checks that were skipped or do not apply are left out; a check that did not complete counts as failed. Fixing a finding therefore always raises the score, however many findings there are. A run limited with `--check`, `--skip`, `--verify` or `--profile` is labelled **partial run** (terminal summary, Markdown and HTML reports, and `"partial": true` in the webhook payload): its score covers only the checks that ran.

| Grade | Score |
|-------|-------|
| A | 90–100 |
| B | 80–89 |
| C | 70–79 |
| D | 60–69 |
| F | 0–59 |

### Severity

Each finding is classified by its point deduction:

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

### Standard Checks (39)

| Category | Checks |
|----------|--------|
| **Patching** | Package updates, unattended-upgrades, pending reboot |
| **Network** | Firewall (UFW/nftables/iptables), open ports, IPv6 exposure, DNS security (DNSSEC/DoT) |
| **SSH** | Root login, password auth, ciphers, MACs, idle timeouts, MaxStartups, banners, `Match` blocks that re-enable weak logins (read from the effective `sshd -T` configuration) |
| **Access control** | Users/sudo (NOPASSWD, UID 0), cron permissions, PAM lockout, password complexity, umask |
| **File security** | Critical file permissions, home directory permissions, root PATH safety |
| **System hardening** | AppArmor, Secure Boot, GRUB password, kernel sysctl, kernel lockdown, core dumps |
| **Logging** | journald persistence, rsyslog, auditd rules |
| **Supply chain** | APT repo signing/HTTPS, unnecessary packages, Docker daemon hardening |
| **Integrity** | AIDE file integrity monitoring |
| **Intrusion detection** | Fail2Ban + SSH jail, failed login monitoring |
| **Time** | NTP/chrony/timesyncd synchronisation |
| **Virtualisation** | systemd service sandboxing (NoNewPrivileges, PrivateTmp, ProtectSystem) |
| **Vulnerability** | Pending security updates (`check_security_updates`, from apt's simulation of the `-security` pocket) |
| **Secrets** | Private keys (found by content, not file name) readable by others, readable `.env` files with credentials, AWS credential files; network filesystems are skipped |
| **Mount options** | `/tmp`, `/dev/shm`, `/var/tmp` noexec/nosuid/nodev |

### Deep Mode (extra)

Each deep check has its own id, so `--check`, `--skip` and `--verify` work on them too. Checks whose tool is not installed are recorded as skipped, not passed; without a terminal (systemd timer, CI) the script never prompts to install tools.

| Check id | What it looks for |
|----------|-------------------|
| `check_deep_suid`, `check_deep_sgid` | SUID/SGID files that no installed package owns, and shell-escape binaries (shells, interpreters, editors, `find`, ...) with the bit set even when a package owns them (CRITICAL). Every local filesystem is scanned, except container and VM image storage (Docker, containerd, podman, LXC/LXD, Incus, k3s, microk8s, kubelet) |
| `check_deep_world_writable_files`, `check_deep_world_writable_dirs` | World-writable files, and world-writable directories without the sticky bit, in /etc, /var, /home |
| `check_deep_unowned` | Files and directories with no valid owner or group |
| `check_deep_empty_passwords`, `check_deep_password_aging` | Empty password fields; `PASS_MAX_DAYS` |
| `check_deep_sudo_timeout` | `timestamp_timeout` above 15 minutes (unset = sudo's default of 15) |
| `check_deep_debsums` | Package files whose checksum changed (files missing on minimized images are not counted) |
| `check_deep_rkhunter` | rkhunter warnings |
| `check_deep_clamav` | ClamAV detections; a scan that does not finish is reported |
| `check_deep_auditd_rules` | auditd running with no rules |
| `check_deep_lynis` | Lynis `warning[]` entries |
| `check_deep_authorized_keys` | Inventory of `authorized_keys` files (report only; claims no control) |
| `check_deep_user_ssh_keys` | Private keys readable by group or others in the `.ssh` of accounts whose home is outside `/home` and `/root` (service accounts; `check_secrets` covers the rest) |
| `check_deep_capabilities` | File capabilities on files no package owns |

---

## Examples

```bash
# Interactive wizard (TTY, no flags)
sudo ./ubuntu-sec-audit.sh

# NIST + ISO 27001 + SOC 2, OSCAL output
sudo ./ubuntu-sec-audit.sh --framework nist,iso27001,soc2 --oscal --output-dir /var/log/audits

# CIS benchmark, generate Ansible playbook
sudo ./ubuntu-sec-audit.sh --framework cis --ansible --output-dir /var/log/audits/cis

# Run only SSH and firewall checks
sudo ./ubuntu-sec-audit.sh --check check_ssh,check_firewall --skip-apt-update

# Skip checks not relevant to your environment
sudo ./ubuntu-sec-audit.sh --skip check_docker_hardening,check_security_updates

# After applying fixes, verify they worked
sudo ./ubuntu-sec-audit.sh --verify --output-dir /var/log/audits

# Deep audit with webhook notification
sudo ./ubuntu-sec-audit.sh --deep --webhook https://hooks.example.com/sec-audit

# OSCAL profile-filtered run (only SSH-related controls)
sudo ./ubuntu-sec-audit.sh --oscal --profile oscal/profiles/ssh-hardening.json
```

---

### Exit status

| Status | Meaning |
|--------|---------|
| 0 | The audit completed (findings do not change the status unless `--fail-on` is used) |
| 1 | The audit could not run or was interrupted |
| 2 | `--fail-on` was given and a finding reached that severity |

---

## Delta Report

After every run, if earlier findings files exist in the output directory, the terminal summary shows what changed. Each check is compared with its last known result, so a run limited with `--check` does not make earlier failures look new:

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
| `assessment-plan.json` | OSCAL Assessment Plan referenced by the AR (copied next to each AR) |
| `component_definition.json` | Declares ubuntu-sec-audit as an OSCAL component |
| `profiles/ssh-hardening.json` | Profile: AC-17, IA-5, SC-8, AC-3, AC-7 |
| `profiles/logging-audit.json` | Profile: AU-2, AU-3, AU-8, AU-9, AU-12 |

ISO 27001 and SOC 2 control IDs are written as namespaced OSCAL `props` on each observation when those frameworks are selected alongside `--oscal`.

Checks that were skipped or do not apply produce an observation that says so, with the reason, but no finding, so they never make a control look satisfied or not satisfied; controls with no assessed check are listed as excluded from the review. Checks without a control in the selected catalog also produce no finding.

Control ids in the AR follow OSCAL conventions: NIST enhancements use catalog ids (`SC-28(1)` → `sc-28.1`), and CIS recommendation numbers, which are not valid OSCAL tokens, are written as `cis_<number>` (e.g. `cis_5.1.20`). Profiles may use either form. There is one finding per mapped control (target `<control>_obj`); a check that did not complete is `not-satisfied`. The output validates against the OSCAL models in [compliance-trestle](https://github.com/oscal-compass/compliance-trestle) (`oscal_generate.py --validate`, which fails when trestle is not installed).

The CIS mapping follows **CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0** numbering; checks with no matching CIS recommendation map to none.

---

## Fix Script

The generated `fix-audit-*.sh` changes nothing unless you ask it to:

```bash
sudo ./fix-audit-*.sh              # on a terminal: asks before each fix
sudo ./fix-audit-*.sh --dry-run    # list the fixes only (the default without a terminal)
sudo ./fix-audit-*.sh --apply      # apply every fix without asking
```

- **SSH changes** are guarded: the SSH configuration is backed up, checked with `sshd -t`, and rolled back unless you confirm a new login within 5 minutes. Without a terminal the change is rolled back; use `--no-ssh-rollback` for unattended runs.
- **MANUAL** blocks are instructions, never run, even when they contain commands (a block whose first line is `# MANUAL` is written as comments): GRUB password, reboot, kernel lockdown, enabling pam_faillock/pam_tally2, NOPASSWD sudo rules, SUID/SGID bits, unowned files, who may log in over SSH (`AllowUsers`) and TCP forwarding, weakening SSH `Match` blocks, disk encryption, Secure Boot, DNSSEC/DNS over TLS, APT repository trust, IP forwarding, blacklisting kernel modules that are in use.
- The SSH fix writes only the settings that fail into `sshd_config.d/00-ubuntu-sec-audit.conf`, so stricter values set elsewhere are never weakened. SSH fixes create `/run/sshd` before validating with `sshd -t`.
- The firewall fix allows every port sshd listens on (`Port` and `ListenAddress host:port`); when they cannot be read, enabling the firewall is left to you.
- A default-deny firewall cuts off every service it does not allow, so the fix enables UFW only when nothing but SSH listens on a non-loopback address (DHCP and mDNS client ports aside, which UFW already lets through). If anything else listens, or the listening ports cannot be read, enabling the firewall is a MANUAL step with an allow rule ready for each service found; and the fix checks the listening ports again when it runs, and stops without changing anything if a new service has appeared.
- The IPv6 firewall fix (UFW active, `IPV6=no`) adds every existing UFW rule again (`ufw show added`) before the reload, so services UFW allows over IPv4 stay reachable over IPv6.
- A deprecated service (FTP, Telnet, rsh, ...) is removed only through the package that ships it (a systemd unit, or the server inetd runs); a listener run by an interpreter or runtime is left to you.
- The Docker fix reloads dockerd (turning on live-restore) and then restarts it so log options apply; on a Swarm node it sets no live-restore and does not restart.
- Permission fixes on files other users control never follow a symlink planted after the audit: a user's file is changed as that user, and a root-owned file in a directory others can write is left to you.
- Files a fix edits with `tee`, `tee -a` or `sed -i` are backed up first (`<file>.bak.<timestamp>`).
- `--disable-ipv6` additionally disables IPv6 (sysctl now; `ipv6.disable=1` after a reboot, through a `/etc/default/grub.d` drop-in that also works on cloud images).

Always review the script before applying it to a production system.

---

## Ansible Playbook

`--ansible` generates a `remediate-*.yml` file sorted CRITICAL → HIGH → MEDIUM → LOW, with per-framework control annotations on each task:

```yaml
# NIST: AC-17,IA-5,SC-8
# ISO27001: A.8.5,A.8.20
- name: "Fix: SSH configuration weaknesses found"
  ansible.builtin.shell:
    executable: /bin/bash
    cmd: |
      sudo /usr/bin/tee /etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf > /dev/null << 'SSHEOF'
      ...
  register: fix_1_result
  when: apply_ssh_changes | default(false) | bool
  ignore_errors: true
```

Every fix is attempted even if an earlier one fails; a final task then fails the play and lists the fixes that failed. MANUAL items appear only as comments. SSH tasks run only with `-e apply_ssh_changes=true`: Ansible has no confirm-or-rollback step, so try them on one host first. The playbook is built from one host's findings; review it before running it on others.

Run locally or against a remote inventory:

```bash
# Local
ansible-playbook remediate-*.yml -i "localhost," -c local --become

# Remote fleet (the playbook targets localhost unless target_hosts is set)
ansible-playbook remediate-*.yml -i inventory --become -e target_hosts=all
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

The mounted directory must be owned by root on the host (see [Output Files](#output-files)).

In a pipeline, add `--fail-on high` (or another severity) to fail the job when the audit finds something that serious.

> The image audits the container itself (its packages, configuration and services), not the host it runs on; only kernel settings such as sysctl values are shared with the host. Use it to check container images in CI, and run the script directly on a host to audit that host. `--privileged` lets the script read `/proc`, run `sysctl` and call `auditctl`.

The script detects Docker, LXC and other containers (podman, Kubernetes, ...) and records the checks that cannot apply there as not applicable: Secure Boot, GRUB password, kernel lockdown, time synchronisation (the host keeps time) and, in Docker, AppArmor. In virtual machines these checks run.

---

## Automated Scheduling

`systemd/` contains ready-to-install unit files:

| File | Schedule |
|------|----------|
| `ubuntu-sec-audit.service/.timer` | Weekly (Sunday 02:00) with delta comparison |
| `ubuntu-sec-audit-deep.service/.timer` | Monthly (first Sunday 03:00) with ClamAV + Lynis |

```bash
sudo git clone --branch v2.4.0 https://github.com/secopsxsaiyan/ubuntu-sec-audit.git /opt/ubuntu-sec-audit
sudo cp /opt/ubuntu-sec-audit/systemd/ubuntu-sec-audit*.service \
        /opt/ubuntu-sec-audit/systemd/ubuntu-sec-audit*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ubuntu-sec-audit.timer
sudo systemctl enable --now ubuntu-sec-audit-deep.timer
```

The units run `/opt/ubuntu-sec-audit/ubuntu-sec-audit.sh`; systemd does not expand variables in a program path, so edit `ExecStart=` if you install elsewhere. Enable the timers, not the services: the services have no `[Install]` section and only run when their timer fires.

To send results to a webhook from the timers, put `AUDIT_WEBHOOK_URL=https://...` in a root-only file (e.g. `/etc/ubuntu-sec-audit/webhook.env`, mode 600) and uncomment the `EnvironmentFile=` line in the service files, so the URL is neither in the unit file nor on a command line.

### Upgrading and uninstalling

To upgrade, fetch the tags and check out the newest release (the timers pick it up at their next run):

```bash
sudo git -C /opt/ubuntu-sec-audit fetch --tags
latest=$(sudo git -C /opt/ubuntu-sec-audit tag --list 'v*' --sort=-v:refname | head -n 1)
sudo git -C /opt/ubuntu-sec-audit checkout "$latest"
```

If the release changed the files in `systemd/`, copy them to `/etc/systemd/system/` again and run `sudo systemctl daemon-reload`.

To uninstall, stop the timers and any audit still running, then remove the units and the checkout:

```bash
sudo systemctl disable --now ubuntu-sec-audit.timer ubuntu-sec-audit-deep.timer
sudo systemctl stop ubuntu-sec-audit.service ubuntu-sec-audit-deep.service
sudo rm /etc/systemd/system/ubuntu-sec-audit.service /etc/systemd/system/ubuntu-sec-audit.timer \
        /etc/systemd/system/ubuntu-sec-audit-deep.service /etc/systemd/system/ubuntu-sec-audit-deep.timer
sudo systemctl daemon-reload
sudo rm -rf /opt/ubuntu-sec-audit
```

Reports stay in `/var/log/ubuntu-sec-audit`, and the webhook file in `/etc/ubuntu-sec-audit` if you made one. Delete them when you no longer need them:

```bash
sudo rm -rf /var/log/ubuntu-sec-audit /etc/ubuntu-sec-audit
```

Uninstalling does not undo fixes you applied. A file a fix edited with `tee` or `sed -i` has a `<file>.bak.<timestamp>` copy from before the fix; other changes have no backup: new drop-ins such as `/etc/ssh/sshd_config.d/00-ubuntu-sec-audit.conf` and `/etc/sysctl.d/99-hardening.conf`, permission changes, installed or removed packages, firewall rules and services.

---

## Test Suite

| Command | What it runs |
|---------|--------------|
| `make lint` | ShellCheck over every script (`tests/lint.sh`) |
| `sudo bats tests/unit` | Shell unit tests: each check against fixture files and mocked tools, the fix script, the findings pipeline, CLI, packaging (including `systemd-analyze verify` of the units), plus end-to-end runs (those need root) |
| `make python` | Python tests for the OSCAL, HTML and SSP tools; with `compliance-trestle` installed they also validate every OSCAL document |
| `make integration` | Builds a deliberately misconfigured container (`tests/Dockerfile`, release from `UBUNTU_VERSION`, default 24.04), audits it with `--oscal`, and fails unless the audit exits 0, the HTML, OSCAL and fix-script outputs are produced, and every check in `tests/expected-failures.txt` reports a finding |

The unit tests read files through `AUDIT_ROOT`, a prefix that points file-based checks at a fixture tree (empty in normal runs), and run with a PATH that holds only core utilities, so no real system tool is touched. CI runs all four on every pull request and every push to `main`: the container test on Ubuntu 20.04, 22.04, 24.04 and 26.04, and the Python tests also on Python 3.8 (Ubuntu 20.04), with compliance-trestle pinned in `tests/python/requirements-ci.txt`. It also builds the root `Dockerfile` and runs an audit in that image.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history, and [Releases](https://github.com/secopsxsaiyan/ubuntu-sec-audit/releases) for source archives with SHA-256 checksums.

---

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), not in a public issue.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, how to add a check, and how releases are made.

---

## License

ubuntu-sec-audit is free software under the [GNU General Public License v3.0](LICENSE).

---

## Disclaimer

This script is provided for **educational and defensive security purposes**. Always review the generated fix script and Ansible playbook before applying changes to a production system. Some remediations may affect running services.
