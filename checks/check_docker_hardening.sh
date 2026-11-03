# shellcheck shell=bash
# check_docker_hardening — standard check (sourced by ubuntu-sec-audit.sh)

check_docker_hardening() {
    # Skip silently if Docker is not present
    if ! command -v docker >/dev/null 2>&1 && ! dpkg -l docker-ce 2>/dev/null | grep -q '^ii'; then
        print_status "INFO" "Docker not detected - skipping Docker hardening check"
        return
    fi

    print_status "INFO" "Checking Docker daemon hardening..."
    local -a docker_issues=()
    local daemon_json="/etc/docker/daemon.json"

    if [[ ! -f "$daemon_json" ]]; then
        docker_issues+=("$daemon_json does not exist - no hardening configuration applied")
    else
        # Use python3 (guaranteed on Ubuntu 20.04+) for reliable JSON parsing
        local _ld _ms _lr _up
        _ld=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('log-driver',''))" 2>/dev/null || true)
        _ms=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('log-opts',{}).get('max-size',''))" 2>/dev/null || true)
        _lr=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('live-restore',False))" 2>/dev/null || true)
        _up=$(python3 -c "import json; d=json.load(open('$daemon_json')); print(d.get('userland-proxy',True))" 2>/dev/null || true)
        [[ -z "$_ld" ]]        && docker_issues+=("log-driver not set - container log format unspecified")
        [[ -z "$_ms" ]]        && docker_issues+=("log-opts.max-size not set - container logs can grow unbounded and fill /var/lib/docker")
        [[ "$_lr" != "True" ]] && docker_issues+=("live-restore is not true - all containers stop on daemon restart/upgrade")
        [[ "$_up" != "False" ]] && docker_issues+=("userland-proxy is not false - adds unnecessary network attack surface")
    fi

    if [[ ${#docker_issues[@]} -eq 0 ]]; then
        print_status "OK" "Docker daemon.json is hardened (log limits, live-restore, userland-proxy disabled)"
        append_report "## Docker Hardening\n- 🟢 daemon.json configured: log rotation, live-restore=true, userland-proxy=false"
    else
        local issue_list
        issue_list=$(printf ' - %s\n' "${docker_issues[@]}")
        print_status "WARN" "Docker hardening issues: ${#docker_issues[@]} found"
        append_report "## Docker Hardening\n- 🔴 ${#docker_issues[@]} Docker daemon hardening issue(s)"

        local docker_fix
        docker_fix='# Write hardened Docker daemon config:'$'\n'
        docker_fix+='sudo /usr/bin/tee /etc/docker/daemon.json > /dev/null << '"'"'DOCKEREOF'"'"$'\n'
        docker_fix+='{'$'\n'
        docker_fix+='    "log-driver": "json-file",'$'\n'
        docker_fix+='    "log-opts": {'$'\n'
        docker_fix+='        "max-size": "10m",'$'\n'
        docker_fix+='        "max-file": "5",'$'\n'
        docker_fix+='        "compress": "true"'$'\n'
        docker_fix+='    },'$'\n'
        docker_fix+='    "live-restore": true,'$'\n'
        docker_fix+='    "userland-proxy": false'$'\n'
        docker_fix+='}'$'\n'
        docker_fix+='DOCKEREOF'$'\n'
        docker_fix+='# reload applies config without stopping running containers; restart stops them:'$'\n'
        docker_fix+='sudo /bin/systemctl reload docker || sudo /bin/systemctl restart docker'$'\n'
        docker_fix+='# Verify:'$'\n'
        docker_fix+='sudo /usr/bin/docker info | grep -E '"'"'Logging Driver|Live Restore'"'"''

        report_issue 6 \
            "Docker daemon not hardened" \
            "Docker daemon.json absent or missing security settings - unbounded logs, no live-restore, userland-proxy enabled" \
            "$docker_fix" \
            0 \
            "Issues:\n${issue_list}\n\nNote: 'reload' applies config without stopping running containers; 'restart' stops them"
    fi
}
