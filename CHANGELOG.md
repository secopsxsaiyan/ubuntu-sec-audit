# Changelog

All notable changes to ubuntu-sec-audit are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Security
- Root wrote its output, the fix script included, into any directory it was given, and by default into the home of the user who ran sudo. Whoever could change that directory could make root overwrite and `chmod 700` any file through a planted symlink (the run id shows up as soon as the findings file is created), or swap the fix script for their own before root ran it. The audit now refuses an output directory that a user other than root could change (owned by another user, or below such a directory, or below one others, or a group with regular users in it, can write to without the sticky bit), checks before creating anything, and uses the directory's real path. The default output directory is now `/var/log/ubuntu-sec-audit`, as for the systemd timers.

### Fixed — fix script safety
- The IPv4 firewall fix enabled a default-deny UFW that allowed only SSH, cutting off every other service on the host (web, database, DNS, VPN, ...) under `--apply`. It now enables UFW by itself only when nothing but SSH listens on a non-loopback address, and checks that again when it runs (a service started after the audit stops the fix before anything changes). Otherwise enabling the firewall is a MANUAL step with an allow rule ready for each listening service, and the report names them; without `ss` it is manual too.
- The IPv6 firewall fix re-added only the SSH rule before UFW started filtering IPv6, so every other service UFW allowed became unreachable over IPv6. It now adds every existing rule again (`ufw show added`), and changes nothing if the rules cannot be listed.

---

## [2.3.0] — 2026-11-03

### Fixed — scheduling and packaging
- The systemd units never started: systemd does not expand `${SCRIPT_DIR}` in a program path ("Unit configuration has fatal error"). They now run `/opt/ubuntu-sec-audit/ubuntu-sec-audit.sh`, and a test runs `systemd-analyze verify`.
- `ubuntu-sec-audit.sh` was not executable in git, so `./ubuntu-sec-audit.sh` failed after a clone.
- Services have no `[Install]` section (enabling one ran an audit at every boot), wait for `network-online.target`, and the deep service may run for 6h instead of being killed after 1h before writing its reports. The README enables both timers.

### Fixed — SSH
- `PermitRootLogin prohibit-password` is printed by `sshd -T` as `without-password`, so every host failed and the fix could never pass.
- A failing `sshd -T` was judged as an empty, insecure configuration. Without `/run/sshd` (socket-activated ssh before the first login) it is retried in a private mount namespace; otherwise the check is skipped with sshd's error.
- The fix writes only the failing settings, so stricter values (`PermitRootLogin no`, `MaxAuthTries 2`) are no longer weakened. `AllowTcpForwarding` and `AllowUsers`/`AllowGroups` are a separate MANUAL finding; `Match` blocks that re-enable weak logins are reported. Points follow severity (10 or 5).
- Login banners: no SSH banner is required without sshd; `/etc/motd` is not required; `/etc/issue` revealing the OS fails (CIS 1.7.2); the SSH banner is set in a drop-in.

### Fixed — false results
- Private keys are found by content: public certificates (`*.pem`) were flagged as exposed keys. `.env` files are flagged only when others can read them, and secrets are found anywhere in a variable name (`AWS_SECRET_ACCESS_KEY` was missed). Network filesystems are skipped.
- Firewall: fail2ban/CrowdSec ban tables no longer count as a firewall; iptables rulesets ending in a REJECT rule do; IPv6 disabled at boot or by sysctl is recognised (firewall, kernel and IPv6 checks); GRUB drop-ins and `/proc/cmdline` are read.
- Open ports: matched on protocol and port (514/udp syslog is not rsh); the fix removes the detected service. Without `ss`/`netstat` the check is skipped, not passed.
- GRUB password without GRUB, Docker without Docker, DNS without systemd-resolved, kernel lockdown without the LSM and Secure Boot on non-UEFI hosts are not applicable instead of failing or passing.
- unattended-upgrades disabled with `Unattended-Upgrade "0"` was reported as enabled; `check_updates` counts only non-security updates apt will install (phased updates are excluded) and costs 6 points, so one security update no longer costs 22.
- APT `trusted=yes` is found with other options and only on active lines of files apt reads; Docker installed as a snap is checked and fixed in the snap's `daemon.json`.
- Users: command-restricted NOPASSWD rules are not "any command"; sudoers.d files sudo ignores are skipped; an empty password field in `/etc/passwd` is reported. Cron follows CIS 2.4.1.2–2.4.1.7 (600/700, root:root). Root PATH directories that are group-writable or not root-owned fail. `minlen` must be at least 14. An earlier `readonly TMOUT` is recognised. Failed logins are information when fail2ban protects SSH. 20.04 gets pam_tally2 instructions (no pam_faillock there).
- Deep: SUID/SGID shell-escape binaries (bash, find, python, ...) are reported even when a package owns them, on every local filesystem (container and VM image storage is skipped); debsums counts only changed files; the sudo timeout follows sudo's parse order; `check_deep_user_ssh_keys` covers service accounts instead of repeating `check_secrets`.
- Drop-ins of journald/resolved were ignored when the main `.conf` file did not exist.
- Containers other than Docker/LXC were detected as VMs; Secure Boot and kernel lockdown are checked in VMs, time sync is not applicable in containers.

### Fixed — fix script safety
- The IPv6 firewall fix could enable UFW without an SSH rule (lockout); it now only changes an active UFW, re-adding the existing SSH rule with the same action, and never opens SSH that is limited to certain sources.
- `chmod` on files other users control no longer follows a symlink planted after the audit (`_safe_chmod_cmd`).
- Never automatic any more: IP forwarding off (breaks LXD, Kubernetes, libvirt, WireGuard), blacklisting loaded kernel modules, disk encryption, Secure Boot, DNSSEC/DNS over TLS, APT repository trust; a block whose first line is `# MANUAL` is written as comments.
- Home directories are changed only when the account owns them (no `chmod 700 /var/www`); empty-password accounts lose their shell only if they are system accounts; AIDE is installed without a mail server and its scheduling fix never re-initialises the baseline; `/tmp`, `/dev/shm` and `/var/tmp` options are added to existing fstab entries instead of appending ignored duplicates.
- `--disable-ipv6` writes a GRUB drop-in, which also works on cloud images.
- The firewall fix allows every port sshd listens on, including `ListenAddress host:port`, and is manual when the ports cannot be read; SSH fixes create `/run/sshd` before `sshd -t`.
- Deprecated services are removed only through the package that ships them; listeners run by interpreters or runtimes (python, java, ...) are manual.
- The Docker fix restarts dockerd after a reload (live-restore first), so log options apply; Swarm nodes get no live-restore and no restart.
- The login banner fix rewrites only the `/etc/issue` files that fail.

### Changed — results and reporting
- Checks that could not run or do not apply are recorded as `skipped` / `not-applicable` with the reason (also checks skipped for the environment), never as passed; the reports list them.
- The score is the weighted share of assessed checks that passed, instead of 100 minus points (which reached 0 on most stock hosts). Runs limited by `--check`, `--skip`, `--verify` or `--profile` are labelled partial (summary, reports, `--partial` in the HTML, `"partial"` in the webhook payload).
- `--verify` without `--deep` leaves deep checks out instead of counting them as still failing.
- Delta and `--verify` use each check's last known result across earlier runs, so a `--check` subset run no longer produces false "new failures"; both are pure bash.
- `--fail-on <severity>` exits 2 for CI. The webhook URL can come from `AUDIT_WEBHOOK_URL` and never appears in the process list; the payload has a Slack `text` field and severity counts and is built without python3.
- The Markdown report starts with the summary and lists findings most severe first; notes show real line breaks; no colour codes outside a terminal or with `NO_COLOR`; a failed OSCAL generation no longer leaves a missing file in the summary.
- Ansible tasks run in bash, and a failing fix fails the play (it was always green).

### Changed — OSCAL and Python
- Findings that are not valid UTF-8 no longer stop the HTML, OSCAL and SSP output.
- Skipped, not-applicable and unmapped checks produce observations but no findings; `--validate` fails without trestle; the assessment plan is refreshed when it changed; `update_ssp.py` writes atomically, updates `last-modified` and keeps the last 10 history entries; profiles reference the NIST OSCAL catalog; grade and severity are escaped in the HTML report.
- Mappings: `check_fail2ban` → AC-7 (not SI-3); `check_secure_boot` → SI-7(9) (not SC-28); `check_auditd` no longer claims CIS 6.2.2.2, `check_users` no longer claims CIS 5.2.4; the authorized_keys inventory claims no controls.

### Changed — tests and CI
- Every fix above has a regression test; shared helpers moved to `lib/common.sh`.
- CI pins compliance-trestle, runs the Python tests on Python 3.8, and runs the container test on Ubuntu 20.04, 22.04, 24.04 and 26.04 with `--oscal`, failing when the audit exits non-zero or an output is missing.

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
