#!/usr/bin/env bats
# The Ansible playbook mirrors the fix script's safety rules.

load test_helper

setup() {
    load_audit
    ANSIBLE_MODE=1
    _sorted_indices=()
}

add_fix() {
    TITLES+=("$1"); REMEDIATIONS+=("$2"); CHECK_IDS+=("${3:-check_fake}")
    CTRL_IDS_ALL+=(""); SEVERITIES+=("LOW")
    _sorted_indices+=("$(( ${#TITLES[@]} - 1 ))")
}

parse_playbook() {
    PATH="$ORIG_PATH" python3 -c '
import json, sys, yaml
print(json.dumps(yaml.safe_load(open(sys.argv[1]))))
' "$ANSIBLE_FILE"
}

@test "manual remediations are comments, not tasks" {
    PATH="$ORIG_PATH" python3 -c 'import yaml' 2>/dev/null || skip "PyYAML not installed"
    add_fix "Set a GRUB password" "# do it by hand"
    add_fix "Plain fix" "echo hi"
    generate_ansible >/dev/null
    run parse_playbook
    [[ "$output" != *"Set a GRUB password"* ]]
    [[ "$output" == *"Plain fix"* ]]
    grep -q "MANUAL: Set a GRUB password" "$ANSIBLE_FILE"
}

@test "SSH tasks only run when explicitly enabled" {
    PATH="$ORIG_PATH" python3 -c 'import yaml' 2>/dev/null || skip "PyYAML not installed"
    add_fix "SSH configuration weaknesses found" "echo ssh" check_ssh
    add_fix "Plain fix" "echo hi"
    generate_ansible >/dev/null
    run parse_playbook
    PATH="$ORIG_PATH" python3 -c '
import json, sys
tasks = json.loads(sys.argv[1])[0]["tasks"]
by_name = {t["name"]: t for t in tasks}
ssh = by_name["Fix: SSH configuration weaknesses found"]
assert "apply_ssh_changes" in ssh["when"], ssh
assert "when" not in by_name["Fix: Plain fix"]
' "$output"
}

@test "titles with quotes still produce valid YAML" {
    PATH="$ORIG_PATH" python3 -c 'import yaml' 2>/dev/null || skip "PyYAML not installed"
    add_fix 'Key "id_rsa" has: bad perms' "echo hi"
    generate_ansible >/dev/null
    run parse_playbook
    [ "$status" -eq 0 ]
    [[ "$output" == *'Key \"id_rsa\" has: bad perms'* ]]
}
