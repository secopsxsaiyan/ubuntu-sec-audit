#!/usr/bin/env bats
# Remediations that could lock out or brick a host must be safe or manual.

load test_helper

setup() {
    load_audit
}

@test "service sandboxing never targets ssh, cron or auditd" {
    mock_cmd systemctl 'if [ "$1" = cat ]; then printf "[Service]\nExecStart=/usr/sbin/x\n"; exit 0; fi; exit 0'
    _run_check check_systemd_service_hardening
    assert_issue "Systemd services missing hardening directives"
    local r
    r=$(remediation_for "Systemd services missing hardening")
    [[ "$r" != *"ssh.service.d"* ]]
    [[ "$r" != *"sshd.service.d"* ]]
    [[ "$r" != *"cron.service.d"* ]]
    [[ "$r" != *"auditd.service.d"* ]]
    [[ "$r" == *"rsyslog.service.d"* ]]
    [[ "$r" == *"fail2ban.service.d"* ]]
    [[ "$r" != *"ProtectSystem=strict"* ]]
    # A service that fails to start with the drop-in gets it removed again.
    [[ "$r" == *"is-active"* ]]
}

@test "the GRUB password fix is manual" {
    fixture /boot/grub/grub.cfg "menuentry 'Ubuntu' { linux /vmlinuz }"
    _run_check check_grub_password
    assert_issue "GRUB bootloader not password protected"
    run executable_lines <<< "$(remediation_for "GRUB bootloader")"
    [ -z "$output" ]
}

@test "the reboot fix is manual" {
    fixture /var/run/reboot-required "*** System restart required ***"
    _run_check check_reboot
    assert_issue "Reboot required"
    run executable_lines <<< "$(remediation_for "Reboot required")"
    [ -z "$output" ]
}

@test "the kernel lockdown fix is manual" {
    fixture /sys/kernel/security/lockdown "[none] integrity confidentiality"
    _run_check check_kernel_lockdown
    assert_issue "Kernel lockdown mode not enabled"
    run executable_lines <<< "$(remediation_for "Kernel lockdown")"
    [ -z "$output" ]
}

@test "AllowUsers is suggested but never applied automatically" {
    fixture /etc/group "sudo:x:27:alice,bob"
    mock_cmd sshd 'printf "%s\n" "permitrootlogin yes" "passwordauthentication yes" "maxauthtries 6"'
    mock_cmd ssh 'exit 0'
    _run_check check_ssh
    local r
    r=$(remediation_for "SSH access restrictions need review")
    [[ "$r" == *"AllowUsers alice bob"* ]]
    refute grep -q AllowUsers <<< "$(remediation_for "SSH configuration weaknesses")"
    run executable_lines <<< "$r"
    [[ "$output" != *"AllowUsers"* ]]
}

@test "only system accounts lose their login shell" {
    fixture /etc/login.defs $'UID_MIN\t\t\t 1000'
    fixture /etc/passwd $'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\nsync:x:4:65534:sync:/bin:/bin/sync'
    fixture /etc/shadow $'root:*:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nubuntu:!:19000:0:99999:7:::\nsync:*:19000:0:99999:7:::'
    fixture /etc/sudoers ""
    _run_check check_users
    local r
    r=$(remediation_for "System accounts with interactive login shells")
    [[ "$r" == *"usermod -s /usr/sbin/nologin daemon"* ]]
    [[ "$r" != *"nologin ubuntu"* ]]
    [[ "$r" != *"nologin root"* ]]
    [[ "$r" != *"nologin sync"* ]]
}

@test "the NOPASSWD fix does not open an interactive editor" {
    fixture /etc/sudoers "alice ALL=(ALL) NOPASSWD: ALL"
    fixture /etc/passwd "root:x:0:0:root:/root:/bin/bash"
    fixture /etc/shadow "root:*:19000:0:99999:7:::"
    _run_check check_users
    assert_issue "Users with NOPASSWD sudo"
    run executable_lines <<< "$(remediation_for "NOPASSWD")"
    refute grep -qE '(^|[[:space:]/])visudo[[:space:]]*$' <<< "$output"
}

@test "the AppArmor fix does not force every profile into enforce mode" {
    mock_cmd aa-status 'echo "0 profiles are in enforce mode."'
    _run_check check_apparmor
    assert_issue "AppArmor"
    run executable_lines <<< "$(remediation_for "AppArmor")"
    [[ "$output" != *"aa-enforce /etc/apparmor.d/*"* ]]
}

# apply_docker_fix — run the Docker remediation against the fixture tree,
# with systemctl and docker mocked out.
apply_docker_fix() {
    local r
    r=$(remediation_for "Docker daemon not hardened")
    mock_cmd systemctl 'exit 0'
    mock_cmd sudo '"$@"'
    sed -e "s#/etc/docker#${AUDIT_ROOT}/etc/docker#g" -e "s#/bin/systemctl#systemctl#g" -e "s#/usr/bin/docker#docker#g" \
        <<< "$r" > "$BATS_TEST_TMPDIR/fix.sh"
    # The trailing "docker info | grep" verify step finds nothing with the
    # mocked docker; the JSON assertions check the outcome instead.
    bash "$BATS_TEST_TMPDIR/fix.sh" || true
}

@test "the Docker fix merges into an existing daemon.json" {
    fixture /etc/docker/daemon.json '{"data-root": "/srv/docker", "log-driver": "json-file"}'
    mock_cmd docker 'exit 0'
    _run_check check_docker_hardening
    apply_docker_fix
    run python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["data-root"] == "/srv/docker", d
assert d["log-opts"]["max-size"] == "10m", d
assert d["live-restore"] is True, d
print("ok")
' "$AUDIT_ROOT/etc/docker/daemon.json"
    [ "$output" = "ok" ]
}

@test "the Docker fix keeps a non-file log driver and adds no file-only options" {
    fixture /etc/docker/daemon.json '{"log-driver": "syslog"}'
    mock_cmd docker 'exit 0'
    _run_check check_docker_hardening
    # max-size is only valid for json-file/local; syslog is not a finding.
    [[ "$(issue_titles)" == *"Docker daemon not hardened"* ]]
    [[ "$(printf '%s\n' "${ISSUES[@]}")" != *"max-size not set"* ]]
    apply_docker_fix
    run python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d["log-driver"] == "syslog", d
assert "max-size" not in d.get("log-opts", {}), d
print("ok")
' "$AUDIT_ROOT/etc/docker/daemon.json"
    [ "$output" = "ok" ]
}

@test "the AIDE fix initialises the database non-interactively" {
    mock_cmd aide 'exit 0'
    _run_check check_aide
    [[ "$(remediation_for "AIDE file integrity monitoring incomplete")" == *"aideinit -y -f"* ]]
}
