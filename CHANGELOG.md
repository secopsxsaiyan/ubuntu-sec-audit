# Changelog

All notable changes to ubuntu-sec-audit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.1.0] — 2026-04-18

### Fixed
- `check_secrets`: `find` operator precedence bug — `-maxdepth 4` now correctly applies to all name patterns via grouping parentheses
- `--verify`: removed fallback that silently read the current (empty) findings file when no previous file existed, causing "re-running 0 checks" instead of a warning
- Ansible playbook: `register` variable names now use sequential position counter (`fix_1_result`, `fix_2_result`, …) instead of arbitrary array indices

### Added
- `EUID` root guard: script now exits immediately with a clear message if not run as root, before any other work
- `SCRIPT_VERSION` constant (`2.1.0`); shown in `--help`, report header, and terminal summary
- Control mapping cache: `control-mapping.json` loaded once at startup instead of once per finding (eliminates 37+ `python3` subprocess forks per run)
- Webhook URL validation: `--webhook` now rejects values that don't match `http(s)://`
- HTML report `chmod 600`: output file now has owner-read-only permissions consistent with the Markdown report and findings JSONL
- GitHub Actions ShellCheck workflow (`.github/workflows/shellcheck.yml`) — gates on all `*.sh` changes
- `tests/expected-failures.txt`: added `check_auditd` and `check_pam_lockout` (both deliberately absent in the test container)
- `CHANGELOG.md` (this file)

---

## [2.0.0] — 2026-04-17

### Added
- Interactive setup wizard (auto-triggers on TTY with no flags)
- Multi-framework support: NIST SP 800-53 Rev 5, CIS Ubuntu 24.04, ISO/IEC 27001:2022, SOC 2 TSC 2017
- Severity tiers: CRITICAL / HIGH / MEDIUM / LOW auto-derived from point deduction
- Progress indicator (`[N/37]`) printed to stderr during checks
- Container/VM environment awareness — skips inapplicable checks in Docker, LXC, VM
- `--check` / `--skip` flags for targeted execution
- `check_secrets`: detects world-readable SSH keys, `.env` credential files, unprotected AWS credentials, SSL private keys
- `--verify` flag: re-runs only previously-failed checks
- Always-on findings JSONL (decoupled from `--oscal`); used by delta, verify, HTML, and OSCAL
- HTML report (`oscal/html_report.py`): self-contained, score gauge, severity cards, expandable remediation blocks
- Delta report: automatically compares current vs previous run, prints FIXED / REGRESSED / NEW FAILURES
- `--webhook <url>`: POST findings summary JSON to any HTTP endpoint
- `--ansible` flag: generates severity-sorted Ansible remediation playbook
- Integration test suite (`tests/`): Dockerfile with deliberate misconfigs + `run-tests.sh`
- `mappings/control-mapping.json` v1.1.0: all 43 checks mapped to all four frameworks
- `--output-dir` flag and `AUDIT_REPORT_DIR` environment variable

### Fixed
- Wizard auto-trigger suppressed correctly when any intent flag is passed (`_FLAGS_SET` sentinel)
- `local` keyword removed from top-level SSH index loop (illegal outside a function)
- `dpkg --compare-versions` replaces fragile awk string comparison for Ubuntu version check
- `sudo -v` keep-alive no longer spawned when already running as root

---

## [1.0.0] — 2026-04-14

### Added
- Initial release: 36 standard security checks, OSCAL 1.1.2 output, fix script generation
- Deep mode: ClamAV, rkhunter, Lynis, SUID/SGID sweep, debsums, world-writable files
- `systemd/` timer units for weekly standard and monthly deep audits
- `Dockerfile` for CI/air-gapped use
