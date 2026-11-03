# Changelog

All notable changes to ubuntu-sec-audit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.2.0] — 2026-11-03

### Fixed — findings data
- Every finding was recorded with check id `unknown` (`BASH_FUNCNAME` is not a bash variable), so control mapping, fix-script annotations and ordering, OSCAL control links, `--verify` and the delta report were all wrong.
- Every check, failing or not, also got a "satisfied" record (a grep without the space `json.dumps` writes). Pass/fail is now tracked in memory.
- The script exited 1 after every run without CRITICAL findings.
- One unexpected failure inside a check (e.g. `journalctl` in a container) silently ended the whole audit. Each check now runs isolated; a crash is logged and recorded as status `error`, never as passed.
- The integration test could not fail (it skipped every check); it now fails on any missing or passing expected check.

### Fixed — fix script safety
- The fix script is opt-in: `--apply`, per-fix confirmation on a terminal, or a dry run without one.
- SSH changes roll back unless a new login is confirmed (`--no-ssh-rollback` for unattended runs).
- Never applied automatically any more: GRUB password (wrote a placeholder hash, blocking every boot), `reboot` (rebooted mid-script), kernel lockdown, `visudo`, `AllowUsers`, SUID/SGID removal, unowned-file chown, `rkhunter --propupd`.
- Service sandboxing no longer targets `ssh` (it broke sudo and made the filesystem read-only in every SSH session), `cron` or `auditd`; failed restarts roll the drop-in back.
- Only system accounts lose their login shell; key-only admins (e.g. cloud `ubuntu`) are left alone.
- Docker settings are merged into `daemon.json` instead of replacing it; AppArmor profiles are not force-enforced; `aideinit` runs non-interactively.
- Backups cover `tee -a` and `sed -i` targets; titles cannot inject commands; `sudo` is optional in the fix script.

### Fixed — check accuracy
- umask and pwquality never matched under mawk (Ubuntu's awk has no `\s`); faillock settings with spaces were never read; stock journald (`#Storage=auto`) was reported volatile; DNSSEC parsing broke with systemd 249's `resolvectl` output.
- The SSH drop-in is `00-ubuntu-sec-audit.conf` so it wins over `50-cloud-init.conf`; post-quantum key exchange is kept when supported.
- auditd rules are written to `rules.d` (runtime rules were wiped by `augenrules --load`).
- sysctl: stricter values pass and are not lowered by the fix; `secure_redirects` must be 0 (CIS 3.3.6).
- Core dumps: apport is disabled and `core_pattern` set to `|/bin/false` (systemd-coredump is not installed by default).
- LVM-on-LUKS root counts as encrypted; nftables only counts when an input chain filters; `/etc/shadow` stricter than 640 passes; `readonly TMOUT=900` is recognised; `/var/tmp` is bind-mounted instead of becoming a tmpfs; home directories come from `/etc/passwd`; SSH keys only count inside `.ssh`.
- `check_debsecan` (Debian's tracker has no Ubuntu data, and "0 CVEs" was a HIGH finding) is replaced by `check_security_updates`; `check_debsecan` still works as an alias.

### Changed — deep mode and scheduling
- Deep checks are individual `check_deep_*` checks with their own ids and mappings; missing tools mean "skipped", and there are no prompts without a terminal (the monthly timer used to abort).
- SUID/SGID and capability findings exclude package-owned files; sticky world-writable directories are not flagged; ClamAV/rkhunter/Lynis results are parsed correctly.
- Timers no longer `Require` their service (that started an audit at boot); the deep timer runs on the first Sunday as documented; deep `MemoryMax` is 4G; the standard unit runs the script directly.
- The Docker image installs compliance-trestle in a venv (pip failed silently under PEP 668).

### Changed — OSCAL
- Assessment Results validate against the OSCAL models (29 errors per run before): tool component and actors, organization party, `sc-28.1`-style ids, `cis_<number>` ids, one finding per control, `import-ap` that resolves, caller's tool version, ISO 27001/SOC 2 ids as props.
- Static OSCAL documents use real UUIDs and validate; `assessment_plan.json` is now `assessment-plan.json`.
- CIS mapping remapped from the 22.04 layout to CIS Ubuntu 24.04 v1.0.0 numbers.

### Changed — engineering
- The script is split into `lib/` and `checks/` and can be sourced; `main()` runs only when executed.
- No `sudo` in probes and no keep-alive loop; `umask 077`; one run id (`YYYYMMDD-HHMMSS`) for all output files; private `/tmp` fallback directory.
- `--catalog` no longer overwrites `--framework`; unknown `--check`/`--skip` names are rejected; any flag suppresses the wizard, whose defaults reflect the flags given; the version check reads `/etc/os-release`.
- Findings JSON is encoded in bash; the mapping is loaded once; webhook URLs are redacted in output.
- Tests: bats unit tests with fixtures and mocks, Python tests with trestle validation, ShellCheck, and the container test, all in CI.

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
