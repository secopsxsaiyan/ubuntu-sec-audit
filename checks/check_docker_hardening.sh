# shellcheck shell=bash
# check_docker_hardening — standard check (sourced by ubuntu-sec-audit.sh)

check_docker_hardening() {
    # Docker from the Ubuntu/Docker apt repositories reads /etc/docker; the
    # Docker snap reads its own daemon.json under /var/snap/docker and runs
    # as snap.docker.dockerd. When both are installed, the apt one is checked.
    local apt_docker=0 snap_docker=0 docker_path
    docker_path=$(command -v docker 2>/dev/null || true)
    [[ -n "$docker_path" && "$docker_path" != /snap/* ]] && apt_docker=1
    dpkg -l docker-ce docker.io 2>/dev/null | grep -q '^ii' && apt_docker=1
    [[ -d "${AUDIT_ROOT}/var/snap/docker" || -e "${AUDIT_ROOT}/snap/bin/docker" ]] && snap_docker=1
    if [[ $apt_docker -eq 0 && $snap_docker -eq 0 ]]; then
        append_report "## Docker Hardening\n- ⚪ Docker not installed - not applicable"
        _mark_not_applicable "Docker is not installed"
        return 0
    fi

    local cfg_path="/etc/docker/daemon.json"
    [[ $apt_docker -eq 0 ]] && cfg_path="/var/snap/docker/current/config/daemon.json"

    print_status "INFO" "Checking Docker daemon hardening (${cfg_path})..."
    local -a docker_issues=()
    local daemon_json="${AUDIT_ROOT}${cfg_path}"

    if [[ ! -f "$daemon_json" ]]; then
        docker_issues+=("${cfg_path} does not exist - no hardening configuration applied")
    else
        # One python3 call; prints driver, max-size, live-restore, userland-proxy.
        local _ld _ms _lr _up
        IFS=$'\t' read -r _ld _ms _lr _up < <(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print("\t".join([d.get("log-driver", "") or "-", d.get("log-opts", {}).get("max-size", "") or "-",
                 str(d.get("live-restore", False)), str(d.get("userland-proxy", True))]))
' "$daemon_json" 2>/dev/null || echo "?")
        if [[ "$_ld" == "?" ]]; then
            docker_issues+=("${cfg_path} is not valid JSON")
        else
            [[ "$_ld" == "-" ]] && docker_issues+=("log-driver not set - container log format unspecified")
            # max-size only exists for the file-based drivers.
            if [[ "$_ld" == "-" || "$_ld" == "json-file" || "$_ld" == "local" ]] && [[ "$_ms" == "-" ]]; then
                docker_issues+=("log-opts.max-size not set - container logs can grow unbounded and fill /var/lib/docker")
            fi
            [[ "$_lr" != "True" ]] && docker_issues+=("live-restore is not true - all containers stop on daemon restart/upgrade")
            [[ "$_up" != "False" ]] && docker_issues+=("userland-proxy is not false - adds unnecessary network attack surface")
        fi
    fi

    if [[ ${#docker_issues[@]} -eq 0 ]]; then
        print_status "OK" "Docker daemon.json is hardened (log limits, live-restore, userland-proxy disabled)"
        append_report "## Docker Hardening\n- 🟢 daemon.json configured: log rotation, live-restore=true, userland-proxy=false"
        return 0
    fi

    local issue_list
    issue_list=$(printf ' - %s\n' "${docker_issues[@]}")
    print_status "WARN" "Docker hardening issues: ${#docker_issues[@]} found"
    append_report "## Docker Hardening\n- 🔴 ${#docker_issues[@]} Docker daemon hardening issue(s)"

    # Merge into the existing file: registry mirrors, data-root, runtimes and
    # other settings are kept. Log options are only added for file drivers.
    local docker_fix
    docker_fix="sudo /bin/mkdir -p ${cfg_path%/*}
sudo /usr/bin/python3 - ${cfg_path} << 'DOCKEREOF'
import json, os, sys
path = sys.argv[1]
cfg = {}
if os.path.exists(path):
    with open(path) as fh:
        cfg = json.load(fh)
driver = cfg.setdefault('log-driver', 'json-file')
if driver in ('json-file', 'local'):
    opts = cfg.setdefault('log-opts', {})
    opts.setdefault('max-size', '10m')
    opts.setdefault('max-file', '5')
cfg['live-restore'] = True
cfg['userland-proxy'] = False
tmp = path + '.tmp'
with open(tmp, 'w') as fh:
    json.dump(cfg, fh, indent=4)
    fh.write('\n')
os.replace(tmp, path)
DOCKEREOF
"
    local restart_note
    if [[ $apt_docker -eq 1 ]]; then
        docker_fix+="# log-driver, log-opts and userland-proxy need a restart; reload first turns on
# live-restore, so the restart keeps containers running (not in Swarm mode):
sudo /bin/systemctl reload docker
sudo /bin/systemctl restart docker
# Verify:
sudo /usr/bin/docker info | grep -E 'Logging Driver|Live Restore'"
        restart_note="the fix reloads (turning on live-restore) and then restarts dockerd, which keeps running containers"
    else
        docker_fix+="# The snap's daemon (snap.docker.dockerd) reads only this file:
sudo /usr/bin/snap restart docker
# Verify:
sudo /snap/bin/docker info | grep -E 'Logging Driver|Live Restore'"
        restart_note="restarting the Docker snap stops running containers"
    fi

    report_issue 6 \
        "Docker daemon not hardened" \
        "Docker daemon.json absent or missing security settings - unbounded logs, no live-restore, userland-proxy enabled" \
        "$docker_fix" \
        0 \
        "Issues:\n${issue_list}\n\nNote: live-restore is not supported in Swarm mode; ${restart_note}"
    return 0
}
