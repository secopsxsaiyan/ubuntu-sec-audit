# Security Policy

ubuntu-sec-audit runs as root, and root later runs the fix script it writes. A
bug that lets someone else steer what root does is a security problem, so
please report it privately.

## Supported versions

Only the latest release gets security fixes. Check your version with
`./ubuntu-sec-audit.sh --version` (before 2.4.0: the first line of
`sudo ./ubuntu-sec-audit.sh --help`), and upgrade before you report if you can.

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately on GitHub:
[Security → Report a vulnerability](https://github.com/secopsxsaiyan/ubuntu-sec-audit/security/advisories/new).

If that page says private reporting is not enabled, open an issue that only
asks for a private contact, with no details of the problem, and wait for a
reply there.

Please include:

- the version (`--version`, or the first line of `--help` before 2.4.0) and the
  Ubuntu release
- what an attacker can do, and what they need first (a local account, write
  access to some directory, control of a DNS name, ...)
- steps to reproduce, ideally from a fresh install
- which part is involved: the audit, the generated fix script, the Ansible
  playbook, the OSCAL/HTML tools or the systemd units

You will get a reply in the advisory. Once a fix is released, the advisory is
published and credits you, unless you would rather not be named.

## What counts

Please report these privately:

- A user other than root can change files the audit or the fix script writes,
  or can make root write somewhere else (for example through a symlink or a
  directory they control).
- Data the audit reads, such as file names, user names or configuration
  values, ends up as commands in the fix script or the Ansible playbook.
- A fix does something its block does not describe, or gets around the guards
  that stop it from locking people out (the SSH rollback, the firewall's
  listening-port check).
- Secrets leak: the webhook URL, or the contents of keys and credential files,
  appear in reports, logs, the process list or the webhook payload.

Wrong results, such as a check that passes on an insecure setting or fails
on a secure one, are ordinary bugs. Please open a public issue for those.
