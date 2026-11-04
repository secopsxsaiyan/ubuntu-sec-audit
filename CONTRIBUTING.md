# Contributing

Thanks for helping. Bug reports, fixes and new checks are all welcome.

**Security problems go through [SECURITY.md](SECURITY.md), not a public issue.**

## Reporting a bug

Please include:

- the version (`./ubuntu-sec-audit.sh --version`; before 2.4.0, the first
  line of `sudo ./ubuntu-sec-audit.sh --help`) and the Ubuntu release
- the check id (`check_*`)
- the lines of the Markdown report or the findings JSONL for that check
- for a wrong result, the configuration that produced it (the relevant lines
  of `sshd -T`, `/etc/login.defs`, and so on)

## Development setup

```bash
sudo apt-get install shellcheck bats python3 python3-venv
```

| Command | What it runs |
|---------|--------------|
| `make lint` | ShellCheck over every script |
| `sudo bats tests/unit` | Shell unit tests. Without root, the ownership and end-to-end tests are skipped |
| `make python` | Python tests for the OSCAL, HTML and SSP tools |
| `make integration` | Audits a deliberately misconfigured container (needs Docker) |

For OSCAL schema validation in the Python tests, install the pinned packages
into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/python/requirements-ci.txt
.venv/bin/python -m unittest discover -s tests/python
```

CI runs all of these on every push and pull request.

## Rules every check follows

- **Read files under `${AUDIT_ROOT}`**, for example
  `"${AUDIT_ROOT}/etc/login.defs"`, never `/etc/login.defs` directly.
  `AUDIT_ROOT` is empty in normal runs, and the tests point it at fixture
  trees.
- **Change nothing.** A check only reports. The fix goes into the remediation
  text of `report_issue`, which becomes a block of the generated fix script.
- **Say when you could not check.** Call `_mark_skipped "reason"` when the
  check could not be performed (a tool is missing) and
  `_mark_not_applicable "reason"` when it does not apply to this host. Never
  report a pass you did not verify. A command that fails unexpectedly marks
  the check as "did not complete", which counts as a failure.
- **Keep risky fixes manual.** When a fix could lock someone out, needs a
  reboot or depends on the site, start its remediation with a `# MANUAL`
  line. The fix script then writes the block as comments and never runs it.
- **Write remediations like the existing ones.** Use full paths
  (`sudo /usr/bin/tee`, `sudo /bin/sed -i`); the fix script backs up any file
  written with `tee` or edited with `sed -i`. For files other users control,
  build `chmod` lines with `_chmod_fix_line MODE PATH`, so a symlink planted
  later is not followed.
- **Stay mawk-compatible.** Ubuntu's default `awk` is mawk, so no `\s` or
  `\b`. The unit tests run with mawk when it is installed.
- **Map only the controls the check verifies.** Leave a list empty when the
  framework has no matching item.

## Adding a check

1. Create `checks/check_<name>.sh` with a function `check_<name>`.
   `checks/check_umask.sh` is a short example: print an `INFO` line, inspect,
   then either call
   `report_issue POINTS "Title" "Description" "Remediation" 0` or print `OK`
   and `append_report` the passing line. Deep checks pass `1` as the fifth
   argument.
2. Source the file in `ubuntu-sec-audit.sh`, in the alphabetical list, with
   its `# shellcheck source=` line.
3. Add the id to `STANDARD_CHECKS` in `lib/runner.sh` (that is the run order),
   or to `DEEP_CHECKS` in `checks/run_deep_checks.sh`.
4. Give it a weight in `CHECK_WEIGHTS` in `lib/runner.sh`: the most points
   its findings can deduct in one run (1 for a report-only check). Points also
   set the severity: 20 or more is CRITICAL, 10–19 HIGH, 5–9 MEDIUM, below 5
   LOW.
5. Map it in `mappings/control-mapping.json`: the `nist`, `cis`, `iso27001`
   and `soc2` lists, plus a `description`.
6. If it cannot apply in a container, add it to `_env_not_applicable` in
   `lib/runner.sh`.
7. Write bats tests with `fixture` and `mock_cmd` from
   `tests/unit/test_helper.bash` (see `tests/unit/accuracy.bats`). Cover a
   pass, a fail, and that the configuration the fix writes then passes. If
   the misconfigured test container (`tests/Dockerfile`) should fail the
   check, add it to `tests/expected-failures.txt`.
8. Update the check counts and tables in `README.md`, and add a line under
   `[Unreleased]` in `CHANGELOG.md`.

The unit tests fail when a check is not sourced or has no mapping entry
(`tests/unit/structure.bats`), or has no weight (`tests/unit/reporting.bats`).

## Pull requests

- Keep each pull request to one topic.
- Add or update tests for every change in behaviour.
- Add a line under `[Unreleased]` in `CHANGELOG.md`.
- Run `make test` (and `sudo bats tests/unit` if you can) before you push.

## Releasing (maintainers)

1. In `CHANGELOG.md`, move the `[Unreleased]` entries under a new
   `## [X.Y.Z] — YYYY-MM-DD` heading, and update the compare links at the
   bottom. Set `SCRIPT_VERSION` in `ubuntu-sec-audit.sh` and the tag in the
   two `git clone --branch vX.Y.Z` commands in `README.md`. A unit test checks
   that they all agree.
2. Merge to `main`. Once CI passes there, the Release workflow tags that
   commit `vX.Y.Z` and publishes a GitHub release with the changelog section
   as notes, a source tarball and `SHA256SUMS`. It does nothing when that
   version is released already, and fails when `[Unreleased]` still lists
   changes.
